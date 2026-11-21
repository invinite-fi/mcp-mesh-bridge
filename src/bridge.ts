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
  type CallToolResult,
  type JSONRPCMessage,
  type JSONRPCRequest,
  type RequestId,
  type Tool,
} from '@modelcontextprotocol/sdk/types.js';
import type { SignIn } from './oauth.js';
import { clip, guardedFetch } from './http.js';
import {
  handleUploadLocalFile,
  pickLocalFile,
  redactUploadUrl,
  REMOTE_START_UPLOAD,
  UPLOAD_TOOL_NAME,
  uploadLocalFileTool,
} from './upload.js';

export type BridgeOptions = {
  url: URL;
  signIn: SignIn;
  log: (message: string) => void;
  fetch?: FetchLike;
  /** Override the OS file picker (for tests). */
  pickFile?: () => Promise<string | undefined>;
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

/** A sentence for Claude and the log, the server's own words cut short; never carries a token. */
export const explain = (e: unknown, url: URL): string => {
  const code = causeCode(e);
  if (code && UNREACHABLE.has(code)) {
    return `Cannot reach ${url.origin} (${code}). Is the VPN or mesh connected?`;
  }
  if (e instanceof StreamableHTTPError) {
    return clip(redactUploadUrl(`${url.origin} answered ${e.code ?? 'an error'}: ${e.message}`));
  }
  if (e instanceof UnauthorizedError) {
    return clip(redactUploadUrl(`Not signed in to ${url.origin}: ${e.message}`));
  }
  return clip(redactUploadUrl(`${url.origin}: ${e instanceof Error ? e.message : String(e)}`));
};

/** How long a transport replaced by a new session stays open for requests under way on it. */
const RETIRE = 30_000;
/** How long the bridge waits for an answer to one of its own internal MCP requests. */
const REMOTE_CALL_TIMEOUT_MS = 60_000;
/** Maximum `tools/list` pages the bridge inspects when probing upload support. */
const MAX_TOOLS_LIST_PAGES = 10;

type UploadSupport = 'unknown' | 'bridge' | 'remote' | 'unsupported';

type Waiter = {
  resolve: (m: JSONRPCMessage) => void;
  reject: (e: Error) => void;
};

const protocolVersionOf = (result: unknown): string | undefined => {
  const v = (result as { protocolVersion?: unknown } | undefined)?.protocolVersion;
  return typeof v === 'string' ? v : undefined;
};

const toolNamed = (tools: Tool[], name: string): Tool | undefined =>
  tools.find((t) => Boolean(t && typeof t === 'object' && t.name === name));

const hasToolNamed = (tools: Tool[], name: string): boolean => toolNamed(tools, name) !== undefined;

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
  const waiting = new Map<RequestId, Waiter>();
  // In-flight `tools/list` request ids (and whether they carried a pagination cursor).
  const toolsListPending = new Map<RequestId, { hasCursor: boolean }>();
  let uploadSupport: UploadSupport = 'unknown';
  let augmentedInCycle = false;
  let probingUploadSupport: Promise<UploadSupport> | undefined;
  let pickerTail: Promise<unknown> = Promise.resolve();
  // Shared by every transport the bridge opens, so a refresh is too.
  const guarded = guardedFetch(opts.fetch);

  const rawPickFile = opts.pickFile ?? (() => pickLocalFile());
  const serializedPickFile = (): Promise<string | undefined> => {
    const next = pickerTail.then(
      () => rawPickFile(),
      () => rawPickFile(),
    );
    pickerTail = next.catch(() => undefined);
    return next;
  };

  /**
   * Inspect a `tools/list` result, update `uploadSupport`, and append
   * `upload_local_file`, built from the server's `start_upload`, when the
   * server advertises `start_upload` without defining its own `upload_local_file`.
   */
  const inspectAndAugmentToolsList = (m: JSONRPCMessage, hasCursor: boolean): JSONRPCMessage => {
    if (!isJSONRPCResultResponse(m)) return m;
    const res = m.result as { tools?: unknown; nextCursor?: unknown };
    if (!Array.isArray(res.tools)) return m;
    if (!hasCursor) {
      augmentedInCycle = false;
    }
    const tools = res.tools as Tool[];
    const startUpload = toolNamed(tools, REMOTE_START_UPLOAD);
    const hasStartUpload = startUpload !== undefined;
    const hasLocalUpload = hasToolNamed(tools, UPLOAD_TOOL_NAME);
    const hasMorePages = typeof res.nextCursor === 'string' && res.nextCursor.length > 0;

    if (hasLocalUpload) {
      uploadSupport = 'remote';
      return m;
    }
    if (hasStartUpload) {
      if (uploadSupport !== 'remote') {
        uploadSupport = 'bridge';
      }
      if (augmentedInCycle) return m;
      augmentedInCycle = true;
      return {
        ...m,
        result: {
          ...res,
          tools: [...tools, uploadLocalFileTool(startUpload)],
        },
      };
    }
    if (!hasCursor && !hasMorePages) {
      uploadSupport = 'unsupported';
    } else if (!hasMorePages && uploadSupport === 'unknown') {
      uploadSupport = 'unsupported';
    }
    return m;
  };

  const open = async (): Promise<void> => {
    const t = new StreamableHTTPClientTransport(url, {
      authProvider: opts.signIn.provider,
      fetch: guarded,
    });
    t.onmessage = (m) => {
      if (
        (isJSONRPCResultResponse(m) || isJSONRPCErrorResponse(m)) &&
        m.id !== undefined &&
        waiting.has(m.id)
      ) {
        const waiter = waiting.get(m.id);
        waiting.delete(m.id);
        waiter?.resolve(m);
        return;
      }
      if (isJSONRPCResultResponse(m) && initialize && m.id === initialize.id) {
        const version = protocolVersionOf(m.result);
        if (version) t.setProtocolVersion(version);
      }
      let outgoing = m;
      if ((isJSONRPCResultResponse(m) || isJSONRPCErrorResponse(m)) && m.id !== undefined) {
        const listMeta = toolsListPending.get(m.id);
        if (listMeta !== undefined) {
          toolsListPending.delete(m.id);
          outgoing = inspectAndAugmentToolsList(m, listMeta.hasCursor);
        }
      }
      local
        .send(outgoing)
        .catch((e: unknown) => log(`could not pass a message to Claude: ${String(e)}`));
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

  /** Send on the current transport, signing in once if the server asks for it. */
  const sendSigned = async (m: JSONRPCMessage): Promise<void> => {
    try {
      await remote.send(m);
    } catch (e) {
      if (e instanceof UnauthorizedError) {
        await signInOnce();
      } else if (e instanceof StreamableHTTPError && e.code === 401) {
        // The transport keeps one "just signed in" flag for all requests: a
        // request whose 401 crossed another's refresh is refused by it,
        // though the tokens are fresh by now. Once more is enough.
        await signingIn?.catch(() => undefined);
      } else {
        throw e;
      }
      await remote.send(m);
    }
  };

  /** Wait for the response to an internal bridge request with a safety timeout. */
  const waitForAnswer = (id: RequestId, sendFn: () => Promise<void>): Promise<JSONRPCMessage> =>
    new Promise<JSONRPCMessage>((resolve, reject) => {
      const timer = setTimeout(() => {
        if (waiting.delete(id)) {
          reject(new Error('timed out waiting for the server to answer'));
        }
      }, REMOTE_CALL_TIMEOUT_MS);
      timer.unref();
      waiting.set(id, {
        resolve: (m) => {
          clearTimeout(timer);
          resolve(m);
        },
        reject: (e) => {
          clearTimeout(timer);
          reject(e);
        },
      });
      sendFn().catch((e: unknown) => {
        if (waiting.delete(id)) {
          clearTimeout(timer);
          reject(e as Error);
        }
      });
    });

  /** A request of the bridge's own, answered to it rather than to Claude. */
  const ask = (m: JSONRPCRequest): Promise<JSONRPCMessage> =>
    waitForAnswer(m.id, () => sendSigned(m));

  const reopenOnce = (): Promise<void> =>
    (reopening ??= (async () => {
      log(`${url.origin} no longer knows the session; starting a new one`);
      const old = remote;
      // Closing at once would abort requests still under way on the old
      // session, which could then run twice; they get a while to finish.
      setTimeout(() => void old.close().catch(() => undefined), RETIRE).unref();
      uploadSupport = 'unknown';
      augmentedInCycle = false;
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

  const sendWithSession = async (m: JSONRPCMessage): Promise<void> => {
    await signingIn?.catch(() => undefined);
    await reopening?.catch(() => undefined);
    const sentOn = remote;
    const session = sentOn.sessionId;
    try {
      await sendSigned(m);
    } catch (e) {
      if (isInitializeRequest(m)) throw e;
      const forgotten = e instanceof StreamableHTTPError && e.code === 404 && session !== undefined;
      // Another request may have started a new session meanwhile.
      const replaced = sentOn !== remote;
      if (!forgotten && !replaced) throw e;
      if (forgotten && !replaced) await reopenOnce();
      else await reopening?.catch(() => undefined);
      await sendSigned(m);
    }
  };

  /** Call a remote MCP tool on behalf of the bridge, handling session recovery. */
  const callRemoteTool = async (
    name: string,
    args: Record<string, unknown>,
  ): Promise<CallToolResult> => {
    const req: JSONRPCRequest = {
      jsonrpc: '2.0',
      id: `mcp-mesh-bridge-${++own}`,
      method: 'tools/call',
      params: { name, arguments: args },
    };
    const answer = await waitForAnswer(req.id, () => sendWithSession(req));
    if (isJSONRPCErrorResponse(answer)) {
      throw new Error(clip(answer.error.message));
    }
    if (!isJSONRPCResultResponse(answer)) {
      throw new Error('the server returned an unexpected response');
    }
    return answer.result as CallToolResult;
  };

  /** Probe `tools/list` if `upload_local_file` is called before `tools/list` was seen. */
  const ensureUploadSupport = (): Promise<UploadSupport> => {
    if (uploadSupport !== 'unknown') return Promise.resolve(uploadSupport);
    return (probingUploadSupport ??= (async (): Promise<UploadSupport> => {
      let cursor: string | undefined;
      let foundStart = false;
      for (let page = 0; page < MAX_TOOLS_LIST_PAGES; page++) {
        const req: JSONRPCRequest = {
          jsonrpc: '2.0',
          id: `mcp-mesh-bridge-${++own}`,
          method: 'tools/list',
          ...(cursor ? { params: { cursor } } : {}),
        };
        const answer = await waitForAnswer(req.id, () => sendWithSession(req));
        if (!isJSONRPCResultResponse(answer)) break;
        const res = answer.result as { tools?: unknown; nextCursor?: unknown };
        if (!Array.isArray(res.tools)) break;
        const tools = res.tools as Tool[];
        if (hasToolNamed(tools, UPLOAD_TOOL_NAME)) {
          uploadSupport = 'remote';
          return uploadSupport;
        }
        if (hasToolNamed(tools, REMOTE_START_UPLOAD)) {
          foundStart = true;
        }
        if (typeof res.nextCursor === 'string' && res.nextCursor.length > 0) {
          cursor = res.nextCursor;
        } else {
          break;
        }
      }
      uploadSupport = foundStart ? 'bridge' : 'unsupported';
      return uploadSupport;
    })().finally(() => {
      probingUploadSupport = undefined;
    }));
  };

  const deliver = async (m: JSONRPCMessage): Promise<void> => {
    if (isInitializeRequest(m) && isJSONRPCRequest(m)) initialize = m;
    if (isInitializedNotification(m)) initialized = m;

    // Intercept the bridge's local file upload tool before relaying to the server,
    // unless the remote server provides its own `upload_local_file` tool.
    if (isJSONRPCRequest(m) && m.method === 'tools/call') {
      const params = m.params as
        { name?: unknown; arguments?: Record<string, unknown> } | undefined;
      if (params?.name === UPLOAD_TOOL_NAME) {
        const support = await ensureUploadSupport();
        if (support === 'unsupported') {
          await local.send({
            jsonrpc: '2.0',
            id: m.id,
            result: {
              isError: true,
              content: [
                {
                  type: 'text',
                  text: `This server does not support ${UPLOAD_TOOL_NAME} (${REMOTE_START_UPLOAD} is not available).`,
                },
              ],
            },
          });
          return;
        }
        if (support === 'bridge') {
          const result = await handleUploadLocalFile(params.arguments, {
            serverUrl: url,
            fetch: guarded,
            log,
            pickFile: serializedPickFile,
            callRemoteTool,
          });
          await local.send({ jsonrpc: '2.0', id: m.id, result });
          return;
        }
        // support === 'remote': fall through and relay to the server's own tool.
      }
    }

    const isToolsList = isJSONRPCRequest(m) && m.method === 'tools/list';
    if (isToolsList) {
      const params = m.params as { cursor?: unknown } | undefined;
      const hasCursor = typeof params?.cursor === 'string' && params.cursor.length > 0;
      toolsListPending.set(m.id, { hasCursor });
    }
    try {
      await sendWithSession(m);
    } catch (e) {
      if (isToolsList) toolsListPending.delete(m.id);
      throw e;
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
      for (const [id, waiter] of waiting) {
        waiting.delete(id);
        waiter.reject(new Error('connection closed'));
      }
      toolsListPending.clear();
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
