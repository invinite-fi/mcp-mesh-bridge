import assert from 'node:assert/strict';
import { test } from 'node:test';
import { clip, guardedFetch, limitBody, sharedKey } from '../src/http.js';

const refresh = (token: string): RequestInit => ({
  method: 'POST',
  body: new URLSearchParams({ grant_type: 'refresh_token', refresh_token: token }),
});

/** A server that answers with `answers` in turn, counting what it was sent. */
const counting = (answers: (() => Response)[]) => {
  let sent = 0;
  const fetchFn = async () => {
    const make = answers[Math.min(sent, answers.length - 1)];
    sent++;
    await new Promise((r) => setTimeout(r, 10));
    if (!make) throw new Error('no answer');
    return make();
  };
  return { fetchFn, sent: () => sent };
};

test('only refreshes and registrations share an answer', () => {
  const url = 'https://as.example/token';
  assert.match(sharedKey(url, refresh('rt-1')) ?? '', /^refresh /);
  assert.notEqual(sharedKey(url, refresh('rt-1')), sharedKey(url, refresh('rt-2')));
  assert.ok(!(sharedKey(url, refresh('rt-1')) ?? '').includes('rt-1'));
  const code = new URLSearchParams({ grant_type: 'authorization_code', code: 'c' });
  assert.equal(sharedKey(url, { method: 'POST', body: code }), undefined);
  const register = JSON.stringify({ redirect_uris: ['http://127.0.0.1:1/callback'] });
  assert.match(sharedKey(url, { method: 'POST', body: register }) ?? '', /^register /);
  assert.equal(sharedKey(url, { method: 'GET' }), undefined);
  assert.equal(sharedKey(url, { method: 'POST', body: '{"jsonrpc":"2.0"}' }), undefined);
});

test('refreshes with one token at once go to the server once', async () => {
  const server = counting([() => Response.json({ access_token: 'at' })]);
  const f = guardedFetch(server.fetchFn);
  const [a, b] = await Promise.all([
    f('https://as/token', refresh('rt')),
    f('https://as/token', refresh('rt')),
  ]);
  assert.equal(server.sent(), 1);
  assert.deepEqual(await a.json(), { access_token: 'at' });
  assert.deepEqual(await b.json(), { access_token: 'at' });
  // A refusal is shared too: the token has been spent.
  await f('https://as/token', refresh('rt'));
  assert.equal(server.sent(), 1);
});

test('a server error is not shared with the next refresh', async () => {
  const server = counting([
    () => new Response('busy', { status: 503 }),
    () => Response.json({ access_token: 'at' }),
  ]);
  const f = guardedFetch(server.fetchFn);
  assert.equal((await f('https://as/token', refresh('rt'))).status, 503);
  assert.equal((await f('https://as/token', refresh('rt'))).status, 200);
  assert.equal(server.sent(), 2);
});

test('a failed request is not shared with the next one', async () => {
  let sent = 0;
  const f = guardedFetch(async () => {
    if (sent++ === 0) throw new Error('offline');
    return Response.json({});
  });
  await assert.rejects(f('https://as/token', refresh('rt')), /offline/);
  assert.equal((await f('https://as/token', refresh('rt'))).status, 200);
});

test('a body over the cap is an error', async () => {
  const r = limitBody(new Response('x'.repeat(100)), 50);
  await assert.rejects(r.text(), /more than 50 bytes/);
  assert.equal(await limitBody(new Response('x'.repeat(50)), 50).text(), 'x'.repeat(50));
});

test('an event stream is capped per event', async () => {
  const sse = (text: string) =>
    new Response(text, { headers: { 'content-type': 'text/event-stream' } });
  const event = `data: ${'x'.repeat(30)}\n\n`;
  const many = event.repeat(5);
  assert.equal(await limitBody(sse(many), 50).text(), many);
  const crlf = event.replaceAll('\n', '\r\n').repeat(5);
  assert.equal(await limitBody(sse(crlf), 50).text(), crlf);
  await assert.rejects(limitBody(sse(`data: ${'x'.repeat(60)}\n\n`), 50).text());
});

test('a capped answer keeps its URL', () => {
  const r = new Response('ok');
  Object.defineProperty(r, 'url', { value: 'https://as/token' });
  assert.equal(limitBody(r).url, 'https://as/token');
});

test('long text is cut, saying how much was left out', () => {
  assert.equal(clip('short'), 'short');
  assert.equal(clip('abcdef', 3), 'abc… (3 more characters)');
});
