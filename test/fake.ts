// An in-process stand-in for a private MCP server and its authorization
// server: discovery, dynamic client registration, PKCE, refresh, and a
// streamable-HTTP endpoint with sessions.
import { createHash, randomUUID } from 'node:crypto';
import { createServer, type IncomingMessage, type ServerResponse } from 'node:http';
import type { AddressInfo } from 'node:net';
import type { SecretStore } from '../src/store.js';

type Pending = { challenge: string; clientId: string; redirectUri: string };
type Rpc = { jsonrpc: '2.0'; id?: string | number; method?: string; params?: unknown };

export type Fake = {
  base: string;
  mcp: URL;
  registrations: number;
  grants: string[];
  /** Tokens revoked, with the client that asked. */
  revoked: { token: string; clientId: string }[];
  initializes: number;
  protocolVersions: string[];
  /** Access tokens the server takes, so a test can expire one. */
  valid: Set<string>;
  /** Binary uploads received via PUT `/uploads/direct/<id>/<token>`. */
  uploaded: Map<string, { filename: string; bytes: Buffer; keep?: boolean }>;
  /** Forget every session, as a restarted server would. */
  forget: () => void;
  close: () => Promise<void>;
};

const rawBody = (req: IncomingMessage): Promise<Buffer> =>
  new Promise((resolve) => {
    const chunks: Buffer[] = [];
    req.on('data', (c: Buffer) => chunks.push(c));
    req.on('end', () => resolve(Buffer.concat(chunks)));
  });

const body = async (req: IncomingMessage): Promise<string> => (await rawBody(req)).toString('utf8');

const json = (res: ServerResponse, status: number, value: unknown, headers = {}) => {
  res.writeHead(status, { 'content-type': 'application/json', ...headers });
  res.end(JSON.stringify(value));
};

const base64url = (b: Buffer) => b.toString('base64url');

export const startFake = async (
  opts: {
    auth?: boolean;
    staticClient?: string;
    revocationEndpoint?: string;
    uploads?: boolean;
    uploadUrlOrigin?: string;
    ownUploadTool?: boolean;
    paginatedTools?: boolean;
  } = {},
) => {
  const requireAuth = opts.auth ?? true;
  const clients = new Set<string>(opts.staticClient ? [opts.staticClient] : []);
  const codes = new Map<string, Pending>();
  const refresh = new Map<string, string>();
  const sessions = new Set<string>();
  const pendingUploads = new Map<
    string,
    { token: string; filename: string; bytes: number; keep?: boolean }
  >();
  let n = 0;

  const fake: Fake = {
    base: '',
    mcp: new URL('http://127.0.0.1/'),
    registrations: 0,
    grants: [],
    revoked: [],
    initializes: 0,
    protocolVersions: [],
    valid: new Set(),
    uploaded: new Map(),
    forget: () => sessions.clear(),
    close: async () => undefined,
  };

  const issue = (res: ServerResponse) => {
    const access = `at-${++n}`;
    const rt = `rt-${n}`;
    fake.valid.add(access);
    refresh.set(rt, access);
    json(res, 200, {
      access_token: access,
      token_type: 'Bearer',
      expires_in: 3600,
      refresh_token: rt,
    });
  };

  const server = createServer(async (req, res) => {
    const url = new URL(req.url ?? '/', fake.base);
    const path = url.pathname;

    if (path.startsWith('/.well-known/oauth-protected-resource')) {
      json(res, 200, { resource: fake.mcp.href, authorization_servers: [fake.base] });
      return;
    }
    if (path === '/.well-known/oauth-authorization-server') {
      json(res, 200, {
        issuer: fake.base,
        authorization_endpoint: `${fake.base}/authorize`,
        token_endpoint: `${fake.base}/token`,
        registration_endpoint: `${fake.base}/register`,
        revocation_endpoint: opts.revocationEndpoint ?? `${fake.base}/revoke`,
        response_types_supported: ['code'],
        grant_types_supported: ['authorization_code', 'refresh_token'],
        code_challenge_methods_supported: ['S256'],
        token_endpoint_auth_methods_supported: ['none', 'client_secret_post'],
      });
      return;
    }
    if (path === '/register' && req.method === 'POST') {
      const meta = JSON.parse(await body(req)) as Record<string, unknown>;
      const clientId = `client-${++fake.registrations}`;
      clients.add(clientId);
      json(res, 201, { ...meta, client_id: clientId, client_id_issued_at: 1 });
      return;
    }
    if (path === '/revoke' && req.method === 'POST') {
      const p = new URLSearchParams(await body(req));
      const token = p.get('token') ?? '';
      fake.revoked.push({ token, clientId: p.get('client_id') ?? '' });
      refresh.delete(token);
      res.writeHead(200).end();
      return;
    }
    if (path === '/authorize') {
      const p = url.searchParams;
      const clientId = p.get('client_id') ?? '';
      const redirectUri = p.get('redirect_uri') ?? '';
      if (!clients.has(clientId) || p.get('code_challenge_method') !== 'S256') {
        res.writeHead(400).end();
        return;
      }
      const code = randomUUID();
      codes.set(code, { challenge: p.get('code_challenge') ?? '', clientId, redirectUri });
      const back = new URL(redirectUri);
      back.searchParams.set('code', code);
      back.searchParams.set('state', p.get('state') ?? '');
      res.writeHead(302, { location: back.href }).end();
      return;
    }
    if (path === '/token' && req.method === 'POST') {
      const p = new URLSearchParams(await body(req));
      const grant = p.get('grant_type') ?? '';
      fake.grants.push(grant);
      if (grant === 'authorization_code') {
        const pending = codes.get(p.get('code') ?? '');
        codes.delete(p.get('code') ?? '');
        const verifier = p.get('code_verifier') ?? '';
        const ok =
          pending &&
          pending.clientId === p.get('client_id') &&
          pending.redirectUri === p.get('redirect_uri') &&
          base64url(createHash('sha256').update(verifier).digest()) === pending.challenge;
        if (!ok) {
          json(res, 400, { error: 'invalid_grant' });
          return;
        }
        issue(res);
        return;
      }
      if (grant === 'refresh_token' && refresh.has(p.get('refresh_token') ?? '')) {
        refresh.delete(p.get('refresh_token') ?? '');
        issue(res);
        return;
      }
      json(res, 400, { error: 'invalid_grant' });
      return;
    }
    if (path === '/mcp') {
      if (req.method === 'GET') {
        res.writeHead(405).end();
        return;
      }
      if (req.method === 'DELETE') {
        res.writeHead(200).end();
        return;
      }
      const token = (req.headers.authorization ?? '').replace(/^Bearer /, '');
      if (requireAuth && !fake.valid.has(token)) {
        res.writeHead(401, {
          'www-authenticate': `Bearer resource_metadata="${fake.base}/.well-known/oauth-protected-resource/mcp"`,
        });
        res.end();
        return;
      }
      const msg = JSON.parse(await body(req)) as Rpc;
      if (msg.method === 'initialize') {
        fake.initializes++;
        const session = randomUUID();
        sessions.add(session);
        const version = (msg.params as { protocolVersion?: string }).protocolVersion;
        json(
          res,
          200,
          {
            jsonrpc: '2.0',
            id: msg.id,
            result: {
              protocolVersion: version,
              capabilities: { tools: {} },
              serverInfo: { name: 'fake', version: '1' },
            },
          },
          { 'mcp-session-id': session },
        );
        return;
      }
      const session = req.headers['mcp-session-id'];
      if (typeof session !== 'string' || !sessions.has(session)) {
        json(res, 404, { jsonrpc: '2.0', error: { code: -32001, message: 'Session not found' } });
        return;
      }
      const version = req.headers['mcp-protocol-version'];
      if (typeof version === 'string') fake.protocolVersions.push(version);
      if (msg.id === undefined || msg.method === undefined) {
        res.writeHead(202).end();
        return;
      }
      if (msg.method === 'tools/list') {
        const params = msg.params as { cursor?: string } | undefined;
        if (opts.paginatedTools && !params?.cursor) {
          json(res, 200, {
            jsonrpc: '2.0',
            id: msg.id,
            result: {
              tools: [{ name: 'echo', inputSchema: { type: 'object' } }],
              nextCursor: 'page-2',
            },
          });
          return;
        }
        const tools: { name: string; description?: string; inputSchema: object }[] =
          opts.paginatedTools ? [] : [{ name: 'echo', inputSchema: { type: 'object' } }];
        if (opts.uploads) {
          tools.push({
            name: 'start_upload',
            description: 'Start an upload; then call store_file with its upload_id.',
            inputSchema: {
              type: 'object',
              properties: {
                filename: { type: 'string' },
                bytes: { type: 'number' },
                keep: { type: 'boolean', description: 'A server-specific flag.' },
              },
              required: ['filename', 'bytes'],
            },
          });
        }
        if (opts.ownUploadTool) {
          tools.push({ name: 'upload_local_file', inputSchema: { type: 'object' } });
        }
        json(res, 200, {
          jsonrpc: '2.0',
          id: msg.id,
          result: { tools },
        });
        return;
      }
      if (msg.method === 'tools/call') {
        const params = msg.params as { name?: string; arguments?: Record<string, unknown> };
        if (opts.ownUploadTool && params.name === 'upload_local_file') {
          json(res, 200, {
            jsonrpc: '2.0',
            id: msg.id,
            result: {
              content: [
                {
                  type: 'text',
                  text: `server-handled:${JSON.stringify(params.arguments)}`,
                },
              ],
            },
          });
          return;
        }
        if (opts.uploads && params.name === 'start_upload') {
          const filename = String(params.arguments?.filename ?? '');
          const bytes = Number(params.arguments?.bytes ?? 0);
          const keep =
            typeof params.arguments?.keep === 'boolean' ? params.arguments.keep : undefined;
          const id = `up-${++n}`;
          const tok = `tok-${n}`;
          pendingUploads.set(id, {
            token: tok,
            filename,
            bytes,
            ...(keep !== undefined ? { keep } : {}),
          });
          const origin = opts.uploadUrlOrigin ?? fake.base;
          json(res, 200, {
            jsonrpc: '2.0',
            id: msg.id,
            result: {
              content: [
                {
                  type: 'text',
                  text: `upload_id: ${id}\nupload_url: ${origin}/uploads/direct/${id}/${tok}\n\nThen call store_file with upload_id ${id}.`,
                },
              ],
            },
          });
          return;
        }
        json(res, 200, {
          jsonrpc: '2.0',
          id: msg.id,
          result: { content: [{ type: 'text', text: JSON.stringify(params.arguments) }] },
        });
        return;
      }
      json(res, 200, {
        jsonrpc: '2.0',
        id: msg.id,
        error: { code: -32601, message: 'Method not found' },
      });
      return;
    }
    if (opts.uploads && req.method === 'PUT' && path.startsWith('/uploads/direct/')) {
      const parts = path.slice('/uploads/direct/'.length).split('/');
      const [id, tok] = parts;
      const pending = id ? pendingUploads.get(id) : undefined;
      if (!pending || pending.token !== tok) {
        res.writeHead(404).end();
        return;
      }
      pendingUploads.delete(id!);
      const data = await rawBody(req);
      if (data.length !== pending.bytes) {
        json(res, 400, { error: `${data.length} of ${pending.bytes} bytes arrived` });
        return;
      }
      fake.uploaded.set(id!, {
        filename: pending.filename,
        bytes: data,
        ...(pending.keep !== undefined ? { keep: pending.keep } : {}),
      });
      json(res, 200, { id, state: 'waiting' });
      return;
    }
    res.writeHead(404).end();
  });

  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  const { port } = server.address() as AddressInfo;
  fake.base = `http://127.0.0.1:${port}`;
  fake.mcp = new URL(`${fake.base}/mcp`);
  fake.close = () =>
    new Promise((resolve) => {
      server.closeAllConnections();
      server.close(() => resolve());
    });
  return fake;
};

/** A browser that follows the authorization redirect back to the loopback callback. */
export const browser = () => {
  const opened: string[] = [];
  const open = async (url: string) => {
    opened.push(url);
    const r = await fetch(url, { redirect: 'manual' });
    const location = r.headers.get('location');
    if (location) await fetch(location);
  };
  return { opened, open };
};

export const memoryStore = (): SecretStore & { entries: Map<string, string> } => {
  const entries = new Map<string, string>();
  return {
    entries,
    where: 'memory',
    read: async (key) => entries.get(key),
    write: async (key, value, opts) => {
      if (opts?.create === false && !entries.has(key)) return false;
      entries.set(key, value);
      return true;
    },
    remove: async (key) => entries.delete(key),
  };
};

/** A port nothing listens on. */
export const freePort = async (): Promise<number> => {
  const s = createServer();
  await new Promise<void>((resolve) => s.listen(0, '127.0.0.1', resolve));
  const { port } = s.address() as AddressInfo;
  await new Promise<void>((resolve) => s.close(() => resolve()));
  return port;
};
