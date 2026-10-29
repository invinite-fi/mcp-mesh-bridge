// One refresh per refresh token. Requests that meet an expired access token
// at the same moment each run the SDK's `auth()`, and each would refresh with
// the same refresh token; a server that rotates refresh tokens refuses all
// but the first, and the bridge would fall back to a browser sign-in. So a
// refresh with a token already used in the last minute gets that answer again.
import { createHash } from 'node:crypto';
import type { FetchLike } from '@modelcontextprotocol/sdk/shared/transport.js';

type Answer = { status: number; statusText: string; headers: [string, string][]; body: string };

const KEEP = 60_000;

export const sharedRefresh = (base: FetchLike = fetch): FetchLike => {
  const answers = new Map<string, Promise<Answer>>();
  return async (url, init) => {
    const params = init?.body instanceof URLSearchParams ? init.body : undefined;
    const token = params?.get('grant_type') === 'refresh_token' && params.get('refresh_token');
    if (!token) return base(url, init);
    const key = `${String(url)} ${createHash('sha256').update(token).digest('hex')}`;
    let answer = answers.get(key);
    if (!answer) {
      answer = base(url, init).then(async (r) => ({
        status: r.status,
        statusText: r.statusText,
        headers: [...r.headers],
        body: await r.text(),
      }));
      answers.set(key, answer);
      setTimeout(() => answers.delete(key), KEEP).unref();
      answer.catch(() => answers.delete(key));
    }
    const a = await answer;
    return new Response(a.body, { status: a.status, statusText: a.statusText, headers: a.headers });
  };
};
