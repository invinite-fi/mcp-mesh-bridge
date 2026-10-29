// Signing in to a server: the OAuth client the SDK's `auth()` drives
// (discovery, dynamic client registration, PKCE, refresh), with the browser
// sent back to a loopback callback on this machine.
import { spawn } from 'node:child_process';
import { randomBytes } from 'node:crypto';
import { createServer, type Server } from 'node:http';
import type {
  OAuthClientProvider,
  OAuthDiscoveryState,
} from '@modelcontextprotocol/sdk/client/auth.js';
import type {
  OAuthClientInformationMixed,
  OAuthClientMetadata,
  OAuthTokens,
} from '@modelcontextprotocol/sdk/shared/auth.js';
import { keyFor, type SecretStore } from './store.js';

/** What a server gave the bridge, kept between runs. */
type Saved = { client?: OAuthClientInformationMixed; tokens?: OAuthTokens };

export type SignInOptions = {
  serverUrl: string;
  /** The loopback port the browser returns to. */
  port: number;
  /** A client registered with the server beforehand, for one without dynamic registration. */
  clientId?: string;
  clientSecret?: string;
  store: SecretStore;
  openBrowser: (url: string) => void | Promise<void>;
  log: (message: string) => void;
  /** How long a browser sign-in may take, in milliseconds. */
  timeout?: number;
};

export type SignIn = {
  provider: OAuthClientProvider;
  /** The authorization code, once the browser comes back with it. */
  code: () => Promise<string>;
  /** The code has been exchanged: stop listening, forget the flow. */
  done: () => void;
};

/** A browser sign-in under way. One at a time: a request meeting a 401 during it joins it. */
type Flow = {
  state: string;
  verifier?: string;
  opened: boolean;
  code: Promise<string>;
  server?: Server;
};

const CLIENT_NAME = 'MCP Mesh Bridge';
const TIMEOUT = 5 * 60_000;

const page = (title: string, text: string): string =>
  `<!doctype html><meta charset="utf-8"><title>${title}</title>` +
  `<body style="font-family:system-ui;margin:3rem"><h1>${title}</h1><p>${text}</p></body>`;

export const signIn = (opts: SignInOptions): SignIn => {
  const key = keyFor(opts.serverUrl);
  const redirectUrl = `http://127.0.0.1:${opts.port}/callback`;
  let saved: Saved | undefined;
  let discovery: OAuthDiscoveryState | undefined;
  let flow: Flow | undefined;
  let settle: { resolve: (code: string) => void; reject: (e: Error) => void } | undefined;

  const load = async (): Promise<Saved> => {
    if (!saved) {
      const raw = await opts.store.read(key);
      saved = raw ? (JSON.parse(raw) as Saved) : {};
    }
    return saved;
  };
  const persist = async (next: Saved): Promise<void> => {
    saved = next;
    await opts.store.write(key, JSON.stringify(next));
  };

  const staticClient: OAuthClientInformationMixed | undefined = opts.clientId
    ? {
        client_id: opts.clientId,
        ...(opts.clientSecret ? { client_secret: opts.clientSecret } : {}),
      }
    : undefined;

  const newFlow = (): Flow => {
    const code = new Promise<string>((resolve, reject) => {
      const timer = setTimeout(
        () => reject(new Error('the sign-in was not finished in time; try again')),
        opts.timeout ?? TIMEOUT,
      );
      settle = {
        resolve: (c) => (clearTimeout(timer), resolve(c)),
        reject: (e) => (clearTimeout(timer), reject(e)),
      };
    });
    // A flow nobody waits on must not crash the process when it times out.
    code.catch(() => undefined);
    return { state: randomBytes(16).toString('hex'), opened: false, code };
  };

  const listen = (f: Flow): Promise<void> =>
    new Promise((resolve, reject) => {
      const server = createServer((req, res) => {
        const url = new URL(req.url ?? '/', redirectUrl);
        if (url.pathname !== '/callback') {
          res.writeHead(404).end();
          return;
        }
        const fail = (status: number, why: string) => {
          res.writeHead(status, { 'content-type': 'text/html; charset=utf-8' });
          res.end(page('Not signed in', why));
        };
        if (url.searchParams.get('state') !== f.state) {
          fail(400, 'This sign-in is not the one the bridge started. Start again from Claude.');
          return;
        }
        const error = url.searchParams.get('error');
        if (error) {
          fail(400, 'The server did not sign you in. You can close this tab.');
          settle?.reject(new Error(`the server refused the sign-in (${error})`));
          return;
        }
        const code = url.searchParams.get('code');
        if (!code) {
          fail(400, 'The server sent no authorization code.');
          return;
        }
        res.writeHead(200, { 'content-type': 'text/html; charset=utf-8' });
        res.end(page('Signed in', 'You can close this tab and return to Claude.'));
        settle?.resolve(code);
      });
      server.once('error', (e: NodeJS.ErrnoException) =>
        reject(
          e.code === 'EADDRINUSE'
            ? new Error(`port ${opts.port} is in use; choose another sign-in port`)
            : e,
        ),
      );
      server.listen(opts.port, '127.0.0.1', () => {
        f.server = server;
        resolve();
      });
    });

  const provider: OAuthClientProvider = {
    get redirectUrl() {
      return redirectUrl;
    },
    get clientMetadata(): OAuthClientMetadata {
      return {
        client_name: CLIENT_NAME,
        redirect_uris: [redirectUrl],
        grant_types: ['authorization_code', 'refresh_token'],
        response_types: ['code'],
        token_endpoint_auth_method: opts.clientSecret ? 'client_secret_post' : 'none',
      };
    },
    state: () => (flow ??= newFlow()).state,
    clientInformation: async () => {
      const s = await load();
      if (!staticClient) return s.client;
      // The SDK saves a static client back with its issuer after first use.
      return s.client?.client_id === staticClient.client_id ? s.client : staticClient;
    },
    saveClientInformation: async (client) => persist({ ...(await load()), client }),
    tokens: async () => (await load()).tokens,
    saveTokens: async (tokens) => persist({ ...(await load()), tokens }),
    saveCodeVerifier: (verifier) => {
      const f = (flow ??= newFlow());
      // A request joining an opened flow keeps that flow's verifier.
      if (!f.opened) f.verifier = verifier;
    },
    codeVerifier: () => {
      if (!flow?.verifier) throw new Error('no sign-in is under way');
      return flow.verifier;
    },
    redirectToAuthorization: async (authorizationUrl) => {
      const f = (flow ??= newFlow());
      if (f.opened) return;
      f.opened = true;
      try {
        await listen(f);
      } catch (e) {
        settle?.reject(e as Error);
        throw e;
      }
      opts.log(`signing in to ${new URL(opts.serverUrl).origin} in your browser`);
      opts.log(`if no browser opens, visit ${authorizationUrl.href}`);
      await opts.openBrowser(authorizationUrl.href);
    },
    invalidateCredentials: async (scope) => {
      const s = await load();
      if (scope === 'all') {
        discovery = undefined;
        await persist({});
      } else if (scope === 'client') {
        await persist(s.tokens ? { tokens: s.tokens } : {});
      } else if (scope === 'tokens') {
        await persist(s.client ? { client: s.client } : {});
      } else if (scope === 'discovery') {
        discovery = undefined;
      } else if (flow) {
        delete flow.verifier;
      }
    },
    saveDiscoveryState: (state) => {
      discovery = state;
    },
    discoveryState: () => discovery,
  };

  return {
    provider,
    code: () => {
      if (!flow?.opened) return Promise.reject(new Error('no sign-in is under way'));
      return flow.code;
    },
    done: () => {
      flow?.server?.close();
      flow = undefined;
      settle = undefined;
    },
  };
};

/** Open a URL in the default browser, without waiting for it. */
export const openInBrowser = (url: string): void => {
  const [command, args]: [string, string[]] =
    process.platform === 'darwin'
      ? ['open', [url]]
      : process.platform === 'win32'
        ? // rundll32 takes the URL whole; `cmd /c start` would split it at `&`.
          ['rundll32', ['url.dll,FileProtocolHandler', url]]
        : ['xdg-open', [url]];
  const child = spawn(command, args, { detached: true, stdio: 'ignore', windowsHide: true });
  child.on('error', () => undefined);
  child.unref();
};
