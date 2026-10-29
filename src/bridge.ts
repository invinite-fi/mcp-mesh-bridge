// The relay: every message from Claude to the server's streamable-HTTP
// endpoint, and every message back, unchanged. It knows no tools; it only
// signs in when the server asks, and starts a new session when the server has
// forgotten its own.
import { UnauthorizedError } from '@modelcontextprotocol/sdk/client/auth.js';
import {
  StreamableHTTPClientTransport,
  StreamableHTTPError,
} from '@modelcontextprotocol/sdk/client/streamableHttp.js';
import type { FetchLike, Transport } from '@modelcontextprotocol/sdk/shared/transport.js';
import {
  isInitializeRequest,
  isInitializedNotification,
  isJSONRPCErrorResponse,
  isJSONRPCRequest,
  isJSONRPCResultResponse,
  type JSONRPCMessage,
  type JSONRPCRequest,
  type RequestId,
} from '@modelcontextprotocol/sdk/types.js';
import type { SignIn } from './oauth.js';
import { sharedRefresh } from './refresh.js';

export type BridgeOptions = {
  url: URL;
  signIn: SignIn;
  log: (message: string) => void;
  fetch?: FetchLike;
};

/** Errors that mean the server could not be reached at all. */
const UNREACHABLE = new Set([
  'ECONNREFUSED',
  'ECONNRESET',
  'ENOTFOUND',
  'EAI_AGAIN',
  'ETIMEDOUT',
  'EHOSTUNREACH',
  'ENETUNREACH',
  'UND_ERR_CONNECT_TIMEOUT',
]);

const causeCode = (e: unknown): string | undefined => {
  const cause = (e as { cause?: { code?: unknown } } | undefined)?.cause;
  return typeof cause?.code === 'string' ? cause.code : undefined;
};

/** A sentence for Claude and the log; never carries a token. */
export const explain = (e: unknown, url: URL): string => {
  const code = causeCode(e);
  if (code && UNREACHABLE.has(code)) {
    return `Cannot reach ${url.origin} (${code}). Is the VPN or mesh connected?`;
  }
  if (e instanceof StreamableHTTPError) {
    return `${url.origin} answered ${e.code ?? 'an error'}: ${e.message}`;
  }
  if (e instanceof UnauthorizedError) return `Not signed in to ${url.origin}: ${e.message}`;
  return `${url.origin}: ${e instanceof Error ? e.message : String(e)}`;
};

const protocolVersionOf = (result: unknown): string | undefined => {
  const v = (result as { protocolVersion?: unknown } | undefined)?.protocolVersion;
  return typeof v === 'string' ? v : undefined;
};

/** Relay between `local` (Claude) and the server, until `local` closes. */
export const bridge = async (local: Transport, opts: BridgeOptions): Promise<void> => {
  const { url, log } = opts;
  let remote!: StreamableHTTPClientTransport;
  // As Claude sent them, to start a new session if the server forgets one.
  let initialize: JSONRPCRequest | undefined;
  let initialized: JSONRPCMessage | undefined;
  let signingIn: Promise<void> | undefined;
  let reopening: Promise<void> | undefined;
  let own = 0;
  // Answers to the bridge's own requests, which Claude never sees.
  const waiting = new Map<RequestId, (m: JSONRPCMessage) => void>();
  // Shared by every transport the bridge opens, so a refresh is too.
  const refreshOnce = sharedRefresh(opts.fetch);

  const open = async (): Promise<void> => {
    const t = new StreamableHTTPClientTransport(url, {
      authProvider: opts.signIn.provider,
      fetch: refreshOnce,
    });
    t.onmessage = (m) => {
      if (
        (isJSONRPCResultResponse(m) || isJSONRPCErrorResponse(m)) &&
        m.id !== undefined &&
        waiting.has(m.id)
      ) {
        waiting.get(m.id)?.(m);
        waiting.delete(m.id);
        return;
      }
      if (isJSONRPCResultResponse(m) && initialize && m.id === initialize.id) {
        const version = protocolVersionOf(m.result);
        if (version) t.setProtocolVersion(version);
      }
      local.send(m).catch((e: unknown) => log(`could not pass a message to Claude: ${String(e)}`));
    };
    t.onerror = (e) => log(explain(e, url));
    await t.start();
    remote = t;
  };

  const signInOnce = (): Promise<void> =>
    (signingIn ??= (async () => {
      try {
        const code = await opts.signIn.code();
        await remote.finishAuth(code);
        log(`signed in to ${url.origin}`);
      } finally {
        opts.signIn.done();
      }
    })().finally(() => {
      signingIn = undefined;
    }));

  /** Send, signing in once if the server asks for it. */
  const sendSigned = async (m: JSONRPCMessage): Promise<void> => {
    try {
      await remote.send(m);
    } catch (e) {
      if (!(e instanceof UnauthorizedError)) throw e;
      await signInOnce();
      await remote.send(m);
    }
  };

  /** A request of the bridge's own, answered to it rather than to Claude. */
  const ask = (m: JSONRPCRequest): Promise<JSONRPCMessage> =>
    new Promise((resolve, reject) => {
      waiting.set(m.id, resolve);
      sendSigned(m).catch((e: unknown) => {
        waiting.delete(m.id);
        reject(e as Error);
      });
    });

  const reopenOnce = (): Promise<void> =>
    (reopening ??= (async () => {
      log(`${url.origin} no longer knows the session; starting a new one`);
      const old = remote;
      old.onmessage = () => undefined;
      old.onerror = () => undefined;
      await old.close().catch(() => undefined);
      await open();
      if (!initialize) return;
      const answer = await ask({ ...initialize, id: `mcp-mesh-bridge-${++own}` });
      if (!isJSONRPCResultResponse(answer)) throw new Error('the server refused a new session');
      const version = protocolVersionOf(answer.result);
      if (version) remote.setProtocolVersion(version);
      if (initialized) await sendSigned(initialized);
    })().finally(() => {
      reopening = undefined;
    }));

  const deliver = async (m: JSONRPCMessage): Promise<void> => {
    await signingIn?.catch(() => undefined);
    await reopening?.catch(() => undefined);
    if (isInitializeRequest(m) && isJSONRPCRequest(m)) initialize = m;
    if (isInitializedNotification(m)) initialized = m;
    const session = remote.sessionId;
    try {
      await sendSigned(m);
    } catch (e) {
      const forgotten = e instanceof StreamableHTTPError && e.code === 404 && session !== undefined;
      if (!forgotten || isInitializeRequest(m)) throw e;
      await reopenOnce();
      await sendSigned(m);
    }
  };

  await open();

  await new Promise<void>((resolve) => {
    local.onmessage = (m) => {
      deliver(m).catch((e: unknown) => {
        const why = explain(e, url);
        log(why);
        if (isJSONRPCRequest(m)) {
          local
            .send({ jsonrpc: '2.0', id: m.id, error: { code: -32000, message: why } })
            .catch(() => undefined);
        }
      });
    };
    local.onclose = () => {
      remote.close().catch(() => undefined);
      resolve();
    };
    local.onerror = (e) => log(`Claude's side: ${e.message}`);
    local.start().catch((e: unknown) => {
      log(`could not start: ${String(e)}`);
      resolve();
    });
  });
};
