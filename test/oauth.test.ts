import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { afterEach, test } from 'node:test';
import { auth } from '@modelcontextprotocol/sdk/client/auth.js';
import { guardedFetch } from '../src/http.js';
import { browserCommand, mayOpen, signIn, type SignIn, type SignInOptions } from '../src/oauth.js';
import { keyFor } from '../src/store.js';
import { browser, freePort, memoryStore, startFake } from './fake.js';

const SERVER = 'https://mcp.example/mcp';
const cleanups: (() => Promise<void>)[] = [];
afterEach(async () => {
  while (cleanups.length) await cleanups.pop()?.();
});

const fake = async () => {
  const f = await startFake();
  cleanups.push(f.close);
  return f;
};

/** A sign-in to `serverUrl` with a browser that follows the redirect back. */
const session = async (serverUrl: string, extra: Partial<SignInOptions> = {}) => {
  const store = memoryStore();
  const b = browser();
  const logs: string[] = [];
  const s = signIn({
    serverUrl,
    port: await freePort(),
    store,
    openBrowser: b.open,
    log: (m) => logs.push(m),
    timeout: 10_000,
    ...extra,
  });
  cleanups.push(async () => s.done());
  return { s, store, b, logs, key: keyFor(serverUrl) };
};

/** Sign in as `--login` does. */
const login = async (s: SignIn, url: URL, fetchFn = guardedFetch()) => {
  if ((await auth(s.provider, { serverUrl: url, fetchFn })) === 'REDIRECT') {
    const code = await s.code();
    await auth(s.provider, { serverUrl: url, authorizationCode: code, fetchFn });
  }
  s.done();
};

test('the browser is sent only to https, or to http on this machine or a plain-http server', () => {
  const https = new URL(SERVER);
  const http = new URL('http://mcp.mesh.example/mcp');
  const ok = (target: string, server = https) => mayOpen(new URL(target), server);
  assert.ok(ok('https://as.example/authorize'));
  assert.ok(ok('http://127.0.0.1:9/authorize'));
  assert.ok(ok('http://localhost:9/authorize'));
  assert.ok(ok('http://[::1]:9/authorize'));
  assert.ok(!ok('http://as.example/authorize'));
  assert.ok(ok('http://as.mesh.example/authorize', http));
  for (const target of [
    'file:///etc/passwd',
    'javascript:alert(1)',
    'ms-settings:',
    'smb://host/x',
  ]) {
    assert.ok(!ok(target), target);
    assert.ok(!ok(target, http), target);
  }
});

test('the browser is opened by a fixed binary', () => {
  const url = 'https://as.example/authorize?a=1&b=2';
  assert.deepEqual(browserCommand(url, 'darwin'), ['/usr/bin/open', [url]]);
  assert.deepEqual(browserCommand(url, 'win32', { SystemRoot: 'C:\\Windows' }), [
    'C:\\Windows\\System32\\rundll32.exe',
    ['url.dll,FileProtocolHandler', url],
  ]);
  const only = (path: string) => (p: string) => p === path;
  assert.deepEqual(browserCommand(url, 'linux', {}, only('/usr/local/bin/xdg-open')), [
    '/usr/local/bin/xdg-open',
    [url],
  ]);
  assert.equal(
    browserCommand(url, 'linux', {}, () => false),
    undefined,
  );
});

test('a sign-in address that is not https is refused, and the next sign-in starts afresh', async () => {
  const f = await fake();
  const { s, b, logs } = await session(f.mcp.href);
  await s.provider.state?.();
  await assert.rejects(
    Promise.resolve(s.provider.redirectToAuthorization(new URL('file:///etc/passwd'))),
    /not https/,
  );
  assert.equal(b.opened.length, 0);
  await assert.rejects(s.code(), /no sign-in is under way/);

  await login(s, f.mcp);
  assert.equal(b.opened.length, 1);
  assert.ok(logs.includes(`signing in to ${f.base} at ${f.base} in your browser`), logs.join('\n'));
});

test('a configured static client keeps what was saved with it', async () => {
  const { s, store, key } = await session(SERVER, { clientId: 'fixed', clientSecret: 'new' });
  store.entries.set(
    key,
    JSON.stringify({
      client: { client_id: 'fixed', client_secret: 'old', client_id_issued_at: 5 },
    }),
  );
  assert.deepEqual(await s.provider.clientInformation(), {
    client_id: 'fixed',
    client_secret: 'new',
    client_id_issued_at: 5,
  });

  const other = await session(SERVER, { clientId: 'fixed' });
  other.store.entries.set(key, JSON.stringify({ client: { client_id: 'registered' } }));
  assert.deepEqual(await other.s.provider.clientInformation(), { client_id: 'fixed' });
});

test('a client registered for another callback port is registered again', async () => {
  const f = await fake();
  const { s, store, key } = await session(f.mcp.href);
  store.entries.set(
    key,
    JSON.stringify({
      client: { client_id: 'gone', redirect_uris: ['http://127.0.0.1:1/callback'] },
    }),
  );
  await login(s, f.mcp);
  assert.equal(f.registrations, 1);
  const saved = JSON.parse(store.entries.get(key) ?? '{}') as {
    client?: { client_id: string; redirect_uris?: string[] };
  };
  assert.equal(saved.client?.client_id, 'client-1');
  assert.deepEqual(saved.client?.redirect_uris, [s.provider.redirectUrl]);
});

test('first sign-ins started together register one client and open one browser', async () => {
  const f = await fake();
  const { s, b, store, key } = await session(f.mcp.href);
  const fetchFn = guardedFetch();
  const results = await Promise.all(
    [1, 2, 3].map(() => auth(s.provider, { serverUrl: f.mcp, fetchFn })),
  );
  assert.deepEqual(results, ['REDIRECT', 'REDIRECT', 'REDIRECT']);
  assert.equal(f.registrations, 1);
  assert.equal(b.opened.length, 1);
  const code = await s.code();
  assert.equal(
    await auth(s.provider, { serverUrl: f.mcp, authorizationCode: code, fetchFn }),
    'AUTHORIZED',
  );
  s.done();
  assert.ok((JSON.parse(store.entries.get(key) ?? '{}') as { tokens?: unknown }).tokens);
});

test('a callback port in use fails the sign-in, and the next one starts afresh', async () => {
  const f = await fake();
  const port = await freePort();
  const blocker = createServer();
  await new Promise<void>((resolve) => blocker.listen(port, '127.0.0.1', resolve));
  const { s, b } = await session(f.mcp.href, { port });
  await assert.rejects(
    auth(s.provider, { serverUrl: f.mcp, fetchFn: guardedFetch() }),
    new RegExp(`port ${port} cannot be used \\(EADDRINUSE\\)`),
  );
  assert.equal(b.opened.length, 0);
  await new Promise<void>((resolve) => blocker.close(() => resolve()));

  await login(s, f.mcp);
  assert.equal(b.opened.length, 1);
});

test('a sign-in not finished in time stops listening', async () => {
  const f = await fake();
  const port = await freePort();
  const opened: string[] = [];
  const { s } = await session(f.mcp.href, {
    port,
    timeout: 100,
    openBrowser: (u) => void opened.push(u),
  });
  assert.equal(await auth(s.provider, { serverUrl: f.mcp, fetchFn: guardedFetch() }), 'REDIRECT');
  assert.equal(opened.length, 1);
  await assert.rejects(s.code(), /not finished in time/);
  await assert.rejects(s.code(), /no sign-in is under way/);
  // The callback port is free again.
  const probe = createServer();
  await new Promise<void>((resolve) => probe.listen(port, '127.0.0.1', resolve));
  await new Promise<void>((resolve) => probe.close(() => resolve()));
});

test('a stored entry that cannot be read counts as none, and is said so', async () => {
  const damaged = await session(SERVER);
  damaged.store.entries.set(damaged.key, 'not json');
  assert.equal(await damaged.s.provider.tokens(), undefined);
  assert.match(damaged.logs.join('\n'), /is damaged; signing in again/);

  const unreadable = await session(SERVER);
  unreadable.store.read = () => Promise.reject(new Error('the Keychain could not be read'));
  assert.equal(await unreadable.s.provider.tokens(), undefined);
  assert.match(unreadable.logs.join('\n'), /could not be read .*; signing in again/);

  const f = await fake();
  const again = await session(f.mcp.href);
  again.store.entries.set(again.key, '{"tokens":');
  await login(again.s, f.mcp);
  assert.ok(
    (JSON.parse(again.store.entries.get(again.key) ?? '{}') as { tokens?: unknown }).tokens,
  );
});

test('a sign-out while running is not undone by what the server sends next', async () => {
  const { s, store, key, logs } = await session(SERVER);
  store.entries.set(
    key,
    JSON.stringify({
      client: { client_id: 'c' },
      tokens: { access_token: 'a', token_type: 'Bearer', refresh_token: 'r' },
    }),
  );
  assert.equal((await s.provider.tokens())?.access_token, 'a');
  store.entries.clear();
  await s.provider.saveTokens({ access_token: 'b', token_type: 'Bearer' });
  assert.equal(store.entries.size, 0);
  assert.match(logs.join('\n'), /signed out of https:\/\/mcp.example meanwhile/);
  assert.equal(await s.provider.tokens(), undefined);
});
