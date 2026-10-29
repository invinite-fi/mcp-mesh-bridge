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
  /** Forget every session, as a restarted server would. */
  forget: () => void;
  close: () => Promise<void>;
};

const body = (req: IncomingMessage): Promise<string> =>
  new Promise((resolve) => {
    let data = '';
    req.on('data', (c: Buffer) => (data += c.toString('utf8')));
    req.on('end', () => resolve(data));
  });

const json = (res: ServerResponse, status: number, value: unknown, headers = {}) => {
  res.writeHead(status, { 'content-type': 'application/json', ...headers });
  res.end(JSON.stringify(value));
};

const base64url = (b: Buffer) => b.toString('base64url');

export const startFake = async (opts: { auth?: boolean; staticClient?: string } = {}) => {
  const requireAuth = opts.auth ?? true;
  const clients = new Set<string>(opts.staticClient ? [opts.staticClient] : []);
  const codes = new Map<string, Pending>();
  const refresh = new Map<string, string>();
  const sessions = new Set<string>();
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
        revocation_endpoint: `${fake.base}/revoke`,
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
        json(res, 200, {
          jsonrpc: '2.0',
          id: msg.id,
          result: { tools: [{ name: 'echo', inputSchema: { type: 'object' } }] },
        });
        return;
      }
      if (msg.method === 'tools/call') {
        const args = (msg.params as { arguments?: unknown }).arguments;
        json(res, 200, {
          jsonrpc: '2.0',
          id: msg.id,
          result: { content: [{ type: 'text', text: JSON.stringify(args) }] },
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
    write: async (key, value) => {
      entries.set(key, value);
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
