// The fetch every request to the server and its sign-in goes through.
//
// One refresh per refresh token, and one registration per client: requests
// that meet an expired token, or a first sign-in, at the same moment each run
// the SDK's `auth()`. A server that rotates refresh tokens refuses all but the
// first refresh, which would send the user to the browser again; concurrent
// registrations would leave clients behind. So a refresh with a token, or a
// registration with metadata, already sent in the last minute gets that
// answer again, unless it was a server error.
//
// And a cap on what the server may send: a whole body, or one event of an
// event stream, over 32 MB is an error rather than memory spent.
import { createHash } from 'node:crypto';
import type { FetchLike } from '@modelcontextprotocol/sdk/shared/transport.js';

type Answer = {
  status: number;
  statusText: string;
  headers: [string, string][];
  body: string;
  url: string;
};

export const MAX_BODY = 32 * 1024 * 1024;
const KEEP = 60_000;

const hash = (s: string) => createHash('sha256').update(s).digest('hex');

/** The key a request shares its answer under, if it is a refresh or a registration. */
export const sharedKey = (url: string | URL, init?: RequestInit): string | undefined => {
  if (init?.method !== 'POST') return undefined;
  if (init.body instanceof URLSearchParams) {
    const token = init.body.get('grant_type') === 'refresh_token' && init.body.get('refresh_token');
    return token ? `refresh ${String(url)} ${hash(token)}` : undefined;
  }
  if (typeof init.body === 'string' && init.body.includes('"redirect_uris"')) {
    return `register ${String(url)} ${hash(init.body)}`;
  }
  return undefined;
};

/** A stream that errors once more than `limit` bytes pass, or for an event stream, one event. */
const capped = (limit: number, perEvent: boolean): TransformStream<Uint8Array, Uint8Array> => {
  let count = 0;
  /** The last line ended with nothing after it yet. */
  let ended = false;
  let cr = false;
  return new TransformStream({
    transform(chunk, controller) {
      const over = () =>
        controller.error(new Error(`the server sent more than ${limit} bytes in one answer`));
      if (perEvent) {
        for (const byte of chunk) {
          if (++count > limit) return over();
          // A line ends with CRLF, LF or CR; a blank line ends an event.
          if (byte === 0x0a && cr) {
            cr = false;
            continue;
          }
          cr = byte === 0x0d;
          if (byte === 0x0a || byte === 0x0d) {
            if (ended) count = 0;
            ended = true;
          } else {
            ended = false;
          }
        }
      } else if ((count += chunk.byteLength) > limit) {
        return over();
      }
      controller.enqueue(chunk);
    },
  });
};

/** `response` with its body capped at `limit` bytes. */
export const limitBody = (response: Response, limit = MAX_BODY): Response => {
  if (!response.body) return response;
  const sse = (response.headers.get('content-type') ?? '')
    .toLowerCase()
    .includes('text/event-stream');
  const limited = new Response(response.body.pipeThrough(capped(limit, sse)), {
    status: response.status,
    statusText: response.statusText,
    headers: response.headers,
  });
  Object.defineProperty(limited, 'url', { value: response.url });
  return limited;
};

export const guardedFetch = (base: FetchLike = fetch, limit = MAX_BODY): FetchLike => {
  const answers = new Map<string, Promise<Answer>>();
  const send: FetchLike = async (url, init) => limitBody(await base(url, init), limit);
  return async (url, init) => {
    const key = sharedKey(url, init);
    if (!key) return send(url, init);
    let answer = answers.get(key);
    if (!answer) {
      answer = send(url, init).then(async (r) => ({
        status: r.status,
        statusText: r.statusText,
        headers: [...r.headers],
        body: await r.text(),
        url: r.url,
      }));
      answers.set(key, answer);
      answer.then(
        (a) => {
          if (a.status >= 500) answers.delete(key);
          else setTimeout(() => answers.delete(key), KEEP).unref();
        },
        () => answers.delete(key),
      );
    }
    const a = await answer;
    const r = new Response(a.body, {
      status: a.status,
      statusText: a.statusText,
      headers: a.headers,
    });
    Object.defineProperty(r, 'url', { value: a.url });
    return r;
  };
};

/** `text` cut to `max` characters, for anything a server's words reach: a log line or Claude. */
export const clip = (text: string, max = 2048): string =>
  text.length > max ? `${text.slice(0, max)}… (${text.length - max} more characters)` : text;
