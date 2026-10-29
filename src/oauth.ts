// Signing in to a server: the OAuth client the SDK's `auth()` drives
// (discovery, dynamic client registration, PKCE, refresh), with the browser
// sent back to a loopback callback on this machine.
import { spawn } from 'node:child_process';
import { createHash, randomBytes } from 'node:crypto';
import { existsSync } from 'node:fs';
import { createServer, type Server } from 'node:http';
import { win32 } from 'node:path';
import type {
  OAuthClientProvider,
  OAuthDiscoveryState,
} from '@modelcontextprotocol/sdk/client/auth.js';
import type {
  OAuthClientInformationMixed,
  OAuthClientMetadata,
  OAuthTokens,
} from '@modelcontextprotocol/sdk/shared/auth.js';
import { clip } from './http.js';
import { keyFor, type SecretStore } from './store.js';

/**
 * What a server gave the bridge, kept between runs. The SDK stamps the client
 * and the tokens with the `issuer` they came from.
 */
export type Saved = {
  client?: OAuthClientInformationMixed;
  /** The callback the client was registered with. */
  redirectUrl?: string;
  tokens?: OAuthTokens;
};

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
  /** The verifier of the authorization URL that was opened. */
  verifier?: string;
  opened: boolean;
  code: Promise<string>;
  server?: Server;
};

/** The entry as the store holds it now. */
type Stored = { saved: Saved } | { absent: true } | { failed: true };

const CLIENT_NAME = 'MCP Mesh Bridge';
const TIMEOUT = 5 * 60_000;

export const isLoopback = (hostname: string): boolean =>
  hostname === 'localhost' ||
  hostname === '::1' ||
  hostname === '[::1]' ||
  /^127\.\d+\.\d+\.\d+$/.test(hostname);

/**
 * Whether the browser may be sent to `target` to sign in to `server`: https,
 * or http on this machine or when the server itself is plain http.
 */
export const mayOpen = (target: URL, server: URL): boolean =>
  target.protocol === 'https:' ||
  (target.protocol === 'http:' && (isLoopback(target.hostname) || server.protocol === 'http:'));

/** A configured client, with what was saved for it, its secret only as configured now. */
export const configuredClient = (
  saved: OAuthClientInformationMixed | undefined,
  clientId: string,
  clientSecret?: string,
): OAuthClientInformationMixed => {
  const client: OAuthClientInformationMixed = {
    ...(saved?.client_id === clientId ? saved : {}),
    client_id: clientId,
  };
  if (clientSecret) client.client_secret = clientSecret;
  else delete client.client_secret;
  return client;
};

/** The S256 PKCE challenge of a verifier. */
const challengeOf = (verifier: string): string =>
  createHash('sha256').update(verifier).digest('base64url');

const page = (title: string, text: string): string =>
  `<!doctype html><meta charset="utf-8"><title>${title}</title>` +
  `<body style="font-family:system-ui;margin:3rem"><h1>${title}</h1><p>${text}</p></body>`;

export const signIn = (opts: SignInOptions): SignIn => {
  const key = keyFor(opts.serverUrl);
  const server = new URL(opts.serverUrl);
  const redirectUrl = `http://127.0.0.1:${opts.port}/callback`;
  let saved: Saved | undefined;
  /** The store held an entry when this process last read or wrote it. */
  let stored = false;
  let discovery: OAuthDiscoveryState | undefined;
  let flow: Flow | undefined;
  let settle: { resolve: (code: string) => void; reject: (e: Error) => void } | undefined;
  /** Verifiers by their challenge: the opened URL's challenge picks its own. */
  const verifiers = new Map<string, string>();

  /** An entry that is there but cannot be read is said so, and is not taken for a sign-out. */
  const readStore = async (): Promise<Stored> => {
    let raw: string | undefined;
    try {
      raw = await opts.store.read(key);
    } catch (e) {
      opts.log(
        `the stored sign-in for ${server.origin} could not be read (${clip((e as Error).message, 200)}); signing in again`,
      );
      return { failed: true };
    }
    if (raw === undefined) return { absent: true };
    try {
      return { saved: JSON.parse(raw) as Saved };
    } catch {
      opts.log(`the stored sign-in for ${server.origin} is damaged; signing in again`);
      return { failed: true };
    }
  };

  const adopt = (now: Stored): Saved => {
    stored = 'saved' in now;
    saved = 'saved' in now ? now.saved : {};
    return saved;
  };

  const load = async (): Promise<Saved> => saved ?? adopt(await readStore());

  const signedOutMeanwhile = () => {
    opts.log(`signed out of ${server.origin} meanwhile; not keeping what the server just sent`);
    adopt({ absent: true });
  };

  /**
   * Change the entry as stored now, not as this process last saw it: an entry
   * removed meanwhile, by `--logout`, stays removed; one that cannot be read
   * is written over.
   */
  const persist = async (change: (s: Saved) => Saved): Promise<void> => {
    await load();
    const now = await readStore();
    if ('absent' in now && stored) return signedOutMeanwhile();
    const base = 'saved' in now ? now.saved : {};
    const next = change(base);
    if (next === base && 'saved' in now) {
      adopt(now);
      return;
    }
    const written = await opts.store.write(key, JSON.stringify(next), {
      create: !('saved' in now),
    });
    if (!written) return signedOutMeanwhile();
    saved = next;
    stored = true;
  };

  /** Stop listening and forget the flow; with `error`, whoever waits on it gets that. */
  const end = (error?: Error): void => {
    if (error) settle?.reject(error);
    flow?.server?.closeAllConnections();
    flow?.server?.close();
    flow = undefined;
    settle = undefined;
    verifiers.clear();
  };

  const newFlow = (): Flow => {
    const code = new Promise<string>((resolve, reject) => {
      const timer = setTimeout(
        () => end(new Error('the sign-in was not finished in time; try again')),
        opts.timeout ?? TIMEOUT,
      );
      timer.unref();
      settle = {
        resolve: (c) => (clearTimeout(timer), resolve(c)),
        reject: (e) => (clearTimeout(timer), reject(e)),
      };
    });
    // A flow nobody waits on must not crash the process when it ends badly.
    code.catch(() => undefined);
    return { state: randomBytes(16).toString('hex'), opened: false, code };
  };

  const listen = (f: Flow): Promise<void> =>
    new Promise((resolve, reject) => {
      const s = createServer((req, res) => {
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
          end(new Error(`the server refused the sign-in (${clip(error, 100)})`));
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
      s.once('error', (e: NodeJS.ErrnoException) =>
        reject(
          e.code === 'EADDRINUSE' || e.code === 'EACCES'
            ? new Error(`port ${opts.port} cannot be used (${e.code}); choose another sign-in port`)
            : e,
        ),
      );
      s.listen(opts.port, '127.0.0.1', () => {
        f.server = s;
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
      // Every `auth()` asks this first, before it refreshes: take up what
      // another process stored meanwhile, such as a refresh token it rotated.
      const s = adopt(await readStore());
      if (opts.clientId) return configuredClient(s.client, opts.clientId, opts.clientSecret);
      // A client registered for another callback, as with another port, cannot sign in here.
      return s.redirectUrl === redirectUrl ? s.client : undefined;
    },
    saveClientInformation: (client) => {
      const c = { ...client };
      // A configured client's secret stays in the settings.
      if (opts.clientId && c.client_id === opts.clientId) delete c.client_secret;
      return persist((s) => ({ ...s, client: c, redirectUrl }));
    },
    tokens: async () => (await load()).tokens,
    saveTokens: (tokens) => persist((s) => ({ ...s, tokens })),
    saveCodeVerifier: (verifier) => {
      flow ??= newFlow();
      verifiers.set(challengeOf(verifier), verifier);
    },
    codeVerifier: () => {
      if (!flow?.verifier) throw new Error('no sign-in is under way');
      return flow.verifier;
    },
    redirectToAuthorization: async (authorizationUrl) => {
      const f = (flow ??= newFlow());
      // A request meeting a 401 during a sign-in joins it, keeping its verifier.
      if (f.opened) return;
      if (!mayOpen(authorizationUrl, server)) {
        const e = new Error(
          `the sign-in is at ${authorizationUrl.protocol}//${authorizationUrl.host}, which is not https; not opening it`,
        );
        end(e);
        throw e;
      }
      const verifier = verifiers.get(authorizationUrl.searchParams.get('code_challenge') ?? '');
      if (!verifier) {
        const e = new Error('the sign-in address carries no challenge this bridge made');
        end(e);
        throw e;
      }
      f.verifier = verifier;
      f.opened = true;
      try {
        await listen(f);
      } catch (e) {
        end(e as Error);
        throw e;
      }
      opts.log(`signing in to ${server.origin} at ${authorizationUrl.origin} in your browser`);
      opts.log(`if no browser opens, visit ${authorizationUrl.href}`);
      await opts.openBrowser(authorizationUrl.href);
    },
    invalidateCredentials: async (scope) => {
      if (scope === 'all') {
        discovery = undefined;
        await persist(() => ({}));
      } else if (scope === 'client') {
        await persist((s) => (s.tokens ? { tokens: s.tokens } : {}));
      } else if (scope === 'tokens') {
        // The server refused this process's refresh token. One another process
        // stored since is newer: keep it, and the SDK's retry uses it.
        const used = saved?.tokens?.refresh_token;
        await persist((s) => {
          if (s.tokens?.refresh_token !== used) return s;
          const next = { ...s };
          delete next.tokens;
          return next;
        });
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
    done: () => end(),
  };
};

/** How to open a URL in the default browser here: a fixed binary, never one found on PATH. */
export const browserCommand = (
  url: string,
  platform: NodeJS.Platform = process.platform,
  env: NodeJS.ProcessEnv = process.env,
  exists: (path: string) => boolean = existsSync,
): [string, string[]] | undefined => {
  if (platform === 'darwin') return ['/usr/bin/open', [url]];
  if (platform === 'win32') {
    // rundll32 takes the URL whole; `cmd /c start` would split it at `&`.
    return [
      win32.join(env.SystemRoot ?? 'C:\\Windows', 'System32', 'rundll32.exe'),
      ['url.dll,FileProtocolHandler', url],
    ];
  }
  const xdg = ['/usr/bin/xdg-open', '/usr/local/bin/xdg-open', '/bin/xdg-open'].find((p) =>
    exists(p),
  );
  return xdg ? [xdg, [url]] : undefined;
};

/** Open a URL in the default browser, without waiting for it. */
export const openInBrowser = (url: string): void => {
  const command = browserCommand(url);
  if (!command) return;
  const child = spawn(command[0], command[1], {
    detached: true,
    stdio: 'ignore',
    windowsHide: true,
  });
  child.on('error', () => undefined);
  child.unref();
};
