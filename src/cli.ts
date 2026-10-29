// mcp-mesh-bridge <url> [--port N] [--client-id ID] [--login | --logout]
//
// Claude Desktop starts it with the settings of its extension in the
// environment (MCP_MESH_BRIDGE_*); the same flags work from a terminal.
import { auth } from '@modelcontextprotocol/sdk/client/auth.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { bridge } from './bridge.js';
import { openInBrowser, signIn } from './oauth.js';
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

const log = (message: string): void => {
  // stdout carries MCP; everything else goes to stderr.
  process.stderr.write(`[mcp-mesh-bridge] ${message}\n`);
};

export const main = async (
  argv = process.argv.slice(2),
  env = process.env,
  store: SecretStore = platformStore(),
): Promise<number> => {
  const parsed = parse(argv, env);
  if ('exit' in parsed) {
    (parsed.exit === 0 ? process.stdout : process.stderr).write(`${parsed.message}\n`);
    return parsed.exit;
  }
  const { url, mode } = parsed;

  if (mode === 'logout') {
    await store.remove(keyFor(url.href));
    log(`signed out of ${url.origin}; nothing of it is kept in ${store.where}`);
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
      if ((await auth(session.provider, { serverUrl: url })) === 'REDIRECT') {
        const code = await session.code();
        await auth(session.provider, { serverUrl: url, authorizationCode: code });
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
