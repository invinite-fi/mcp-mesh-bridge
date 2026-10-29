// mcp-mesh-bridge <url> [--port N] [--client-id ID] [--login | --logout]
//
// Claude Desktop starts it with the settings of its extension in the
// environment (MCP_MESH_BRIDGE_*); the same flags work from a terminal.
import { auth, discoverOAuthServerInfo } from '@modelcontextprotocol/sdk/client/auth.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import type { FetchLike } from '@modelcontextprotocol/sdk/shared/transport.js';
import { bridge } from './bridge.js';
import { clip, guardedFetch } from './http.js';
import { configuredClient, isLoopback, openInBrowser, signIn, type Saved } from './oauth.js';
import { portFor } from './port.js';
import { keyFor, platformStore, type SecretStore } from './store.js';

export const VERSION = '0.1.0';

export const USAGE = `mcp-mesh-bridge ${VERSION}
Relays Claude Desktop to an MCP server on a private network, signing in with OAuth.

Usage: mcp-mesh-bridge <server-url> [options]

  --port <n>          the loopback port the sign-in returns to (default: one fixed per URL)
  --client-id <id>    a client registered with the server, if it has no dynamic registration
  --login             sign in now, then exit
  --logout            forget this server's sign-in, then exit
  --version, --help

Environment, as Claude Desktop sets it: MCP_MESH_BRIDGE_URL, MCP_MESH_BRIDGE_PORT,
MCP_MESH_BRIDGE_CLIENT_ID, MCP_MESH_BRIDGE_CLIENT_SECRET.`;

export type Options = {
  mode: 'bridge' | 'login' | 'logout';
  url: URL;
  port: number;
  clientId?: string;
  clientSecret?: string;
};

export type Parsed = Options | { exit: number; message: string };

/** A setting from the environment; empty, or a placeholder Claude Desktop left unfilled, is none. */
const setting = (value: string | undefined): string | undefined => {
  const v = value?.trim();
  return v && !v.startsWith('${') ? v : undefined;
};

export const parse = (argv: string[], env: NodeJS.ProcessEnv): Parsed => {
  let url = setting(env.MCP_MESH_BRIDGE_URL);
  let port = setting(env.MCP_MESH_BRIDGE_PORT);
  let clientId = setting(env.MCP_MESH_BRIDGE_CLIENT_ID);
  const clientSecret = setting(env.MCP_MESH_BRIDGE_CLIENT_SECRET);
  let mode: Options['mode'] = 'bridge';

  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i];
    const next = (): string | undefined => argv[++i];
    if (arg === '--help' || arg === '-h') return { exit: 0, message: USAGE };
    if (arg === '--version') return { exit: 0, message: VERSION };
    if (arg === '--login') mode = 'login';
    else if (arg === '--logout') mode = 'logout';
    else if (arg === '--port') port = next();
    else if (arg === '--client-id') clientId = next();
    else if (arg?.startsWith('--'))
      return { exit: 2, message: `unknown option ${arg}\n\n${USAGE}` };
    else if (arg) url = arg;
  }

  if (!url) return { exit: 2, message: `no server URL\n\n${USAGE}` };
  let parsed: URL;
  try {
    parsed = new URL(url);
  } catch {
    return { exit: 2, message: `not a URL: ${url}` };
  }
  if (parsed.protocol !== 'https:' && parsed.protocol !== 'http:') {
    return { exit: 2, message: `the server URL must be http or https: ${url}` };
  }
  const portNumber = port === undefined ? portFor(parsed.href) : Number(port);
  if (!Number.isInteger(portNumber) || portNumber < 1024 || portNumber > 65535) {
    return { exit: 2, message: `the sign-in port must be a number from 1024 to 65535: ${port}` };
  }
  return {
    mode,
    url: parsed,
    port: portNumber,
    ...(clientId ? { clientId } : {}),
    ...(clientSecret ? { clientSecret } : {}),
  };
};

const stderrLog = (message: string): void => {
  // stdout carries MCP; everything else goes to stderr, cut short.
  process.stderr.write(`[mcp-mesh-bridge] ${clip(message)}\n`);
};

type Log = (message: string) => void;

/** Whether two authorization server URLs name one server, a trailing `/` aside, as the SDK compares them. */
export const sameIssuer = (a: string, b: string): boolean => {
  const trim = (u: string) => new URL(u).href.replace(/\/$/, '');
  try {
    return trim(a) === trim(b);
  } catch {
    return false;
  }
};

/**
 * Ask the server to forget a refresh token, where its authorization server
 * offers revocation. Best effort: signing out here does not depend on it.
 * The token goes only to the server that issued it, as discovery names it
 * now, and only to a revocation endpoint on that server's own origin.
 */
const revoke = async (
  url: URL,
  saved: Saved,
  fetchFn: FetchLike,
  log: Log,
  client = saved.client,
): Promise<void> => {
  const token = saved.tokens?.refresh_token;
  if (!token || !client) return;
  const skip = (why: string) =>
    log(`not asking the server to revoke the sign-in: ${why}; it ends when the server lets it`);
  const issuer = saved.tokens?.issuer;
  if (!issuer) return skip('it does not say which server issued it');
  try {
    const info = await discoverOAuthServerInfo(url, { fetchFn });
    if (!sameIssuer(issuer, String(info.authorizationServerUrl))) {
      return skip(`${url.origin} now names another sign-in server than ${issuer}`);
    }
    // OpenID discovery documents carry it too, though the SDK types only OAuth's.
    const meta = info.authorizationServerMetadata as { revocation_endpoint?: unknown } | undefined;
    const endpoint =
      typeof meta?.revocation_endpoint === 'string' ? meta.revocation_endpoint : undefined;
    if (!endpoint) return skip('the server offers no revocation');
    if (new URL(endpoint).origin !== new URL(issuer).origin) {
      return skip(`its revocation endpoint is not on ${new URL(issuer).origin}`);
    }
    const body = new URLSearchParams({ token, token_type_hint: 'refresh_token' });
    body.set('client_id', client.client_id);
    if (client.client_secret) body.set('client_secret', client.client_secret);
    const r = await fetchFn(endpoint, { method: 'POST', body });
    log(
      r.ok
        ? `the server revoked the sign-in`
        : `the server did not revoke the sign-in (${r.status}); it ends when the server lets it`,
    );
  } catch (e) {
    log(`could not ask the server to revoke the sign-in: ${(e as Error).message}`);
  }
};

export const main = async (
  argv = process.argv.slice(2),
  env = process.env,
  store: SecretStore = platformStore(),
  log: Log = stderrLog,
): Promise<number> => {
  const parsed = parse(argv, env);
  if ('exit' in parsed) {
    (parsed.exit === 0 ? process.stdout : process.stderr).write(`${parsed.message}\n`);
    return parsed.exit;
  }
  const { url, mode } = parsed;
  const fetchFn = guardedFetch();

  if (url.protocol === 'http:' && !isLoopback(url.hostname)) {
    log(
      `${url.origin} is plain http: the bridge relies on the network between here and it, such as a mesh, to encrypt`,
    );
  }

  if (mode === 'logout') {
    const key = keyFor(url.href);
    let saved: Saved | undefined;
    try {
      const raw = await store.read(key);
      saved = raw ? (JSON.parse(raw) as Saved) : undefined;
    } catch {
      saved = undefined;
    }
    if (saved) {
      // The client the tokens were issued to, as signing in picks it.
      const client = parsed.clientId
        ? configuredClient(saved.client, parsed.clientId, parsed.clientSecret)
        : saved.client;
      await revoke(url, saved, fetchFn, log, client);
    }
    const existed = await store.remove(key);
    log(
      existed
        ? `signed out of ${url.origin}: its sign-in is gone from ${store.where}`
        : `nothing was stored for ${url.origin} in ${store.where}`,
    );
    return 0;
  }

  const session = signIn({
    serverUrl: url.href,
    port: parsed.port,
    ...(parsed.clientId ? { clientId: parsed.clientId } : {}),
    ...(parsed.clientSecret ? { clientSecret: parsed.clientSecret } : {}),
    store,
    openBrowser: openInBrowser,
    log,
  });

  if (mode === 'login') {
    try {
      if ((await auth(session.provider, { serverUrl: url, fetchFn })) === 'REDIRECT') {
        const code = await session.code();
        await auth(session.provider, { serverUrl: url, authorizationCode: code, fetchFn });
      }
      log(`signed in to ${url.origin}; kept in ${store.where}`);
      return 0;
    } finally {
      session.done();
    }
  }

  log(`relaying to ${url.href}`);
  await bridge(new StdioServerTransport(), { url, signIn: session, log });
  return 0;
};
