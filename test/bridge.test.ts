import assert from 'node:assert/strict';
import { afterEach, test } from 'node:test';
import { InMemoryTransport } from '@modelcontextprotocol/sdk/inMemory.js';
import type { JSONRPCMessage } from '@modelcontextprotocol/sdk/types.js';
import { bridge } from '../src/bridge.js';
import { signIn } from '../src/oauth.js';
import type { SecretStore } from '../src/store.js';
import { browser, freePort, memoryStore, startFake, type Fake } from './fake.js';

const VERSION = '2025-06-18';
const cleanups: (() => Promise<void>)[] = [];
afterEach(async () => {
  while (cleanups.length) await cleanups.pop()?.();
});

type Claude = {
  request: (method: string, params?: Record<string, unknown>) => Promise<JSONRPCMessage>;
  notify: (method: string) => Promise<void>;
};

/** Claude's side of a bridge to `url`. */
const connect = async (
  url: URL,
  store: SecretStore,
  open: (u: string) => Promise<void>,
  extra: { clientId?: string } = {},
): Promise<Claude> => {
  const [claude, side] = InMemoryTransport.createLinkedPair();
  const session = signIn({
    serverUrl: url.href,
    port: await freePort(),
    store,
    openBrowser: open,
    log: () => undefined,
    timeout: 10_000,
    ...extra,
  });
  const running = bridge(side, { url, signIn: session, log: () => undefined });
  const answers = new Map<string | number, (m: JSONRPCMessage) => void>();
  claude.onmessage = (m) => {
    if ('id' in m && m.id !== undefined && !('method' in m)) answers.get(m.id)?.(m);
  };
  await claude.start();
  cleanups.push(async () => {
    await claude.close();
    await running;
  });
  let id = 0;
  return {
    request: (method, params) =>
      new Promise((resolve) => {
        const rid = ++id;
        answers.set(rid, resolve);
        void claude.send({ jsonrpc: '2.0', id: rid, method, ...(params ? { params } : {}) });
      }),
    notify: (method) => claude.send({ jsonrpc: '2.0', method }),
  };
};

const initialize = (c: Claude) =>
  c.request('initialize', {
    protocolVersion: VERSION,
    capabilities: {},
    clientInfo: { name: 'test', version: '1' },
  });

const result = (m: JSONRPCMessage): Record<string, unknown> => {
  assert.ok('result' in m, `expected a result, got ${JSON.stringify(m)}`);
  return m.result as Record<string, unknown>;
};

const started = async (opts: Parameters<typeof startFake>[0] = {}): Promise<Fake> => {
  const fake = await startFake(opts);
  cleanups.push(fake.close);
  return fake;
};

test('relays a session after signing in with registration and PKCE', async () => {
  const fake = await started();
  const b = browser();
  const claude = await connect(fake.mcp, memoryStore(), b.open);

  assert.equal(result(await initialize(claude)).protocolVersion, VERSION);
  assert.equal(b.opened.length, 1, 'one browser sign-in');
  assert.equal(fake.registrations, 1);
  assert.deepEqual(fake.grants, ['authorization_code']);

  await claude.notify('notifications/initialized');
  const tools = result(await claude.request('tools/list')).tools as { name: string }[];
  assert.deepEqual(
    tools.map((t) => t.name),
    ['echo'],
  );
  const call = result(await claude.request('tools/call', { name: 'echo', arguments: { a: 1 } }));
  assert.deepEqual(call.content, [{ type: 'text', text: '{"a":1}' }]);
  // The negotiated version travels on every request after initialize.
  assert.ok(fake.protocolVersions.length >= 2);
  assert.ok(fake.protocolVersions.every((v) => v === VERSION));
});

test('a later run uses the stored sign-in without a browser', async () => {
  const fake = await started();
  const store = memoryStore();
  await initialize(await connect(fake.mcp, store, browser().open));

  const again = browser();
  const claude = await connect(fake.mcp, store, again.open);
  assert.equal(result(await initialize(claude)).protocolVersion, VERSION);
  assert.equal(again.opened.length, 0);
  assert.equal(fake.registrations, 1, 'the registration is reused');
});

test('an expired access token is refreshed without a browser', async () => {
  const fake = await started();
  const b = browser();
  const claude = await connect(fake.mcp, memoryStore(), b.open);
  await initialize(claude);
  await claude.notify('notifications/initialized');

  fake.valid.clear();
  const tools = result(await claude.request('tools/list')).tools as unknown[];
  assert.equal(tools.length, 1);
  assert.deepEqual(fake.grants, ['authorization_code', 'refresh_token']);
  assert.equal(b.opened.length, 1, 'no second browser sign-in');
});

test('a session the server forgot is started again and the request retried', async () => {
  const fake = await started();
  const claude = await connect(fake.mcp, memoryStore(), browser().open);
  await initialize(claude);
  await claude.notify('notifications/initialized');

  fake.forget();
  const tools = result(await claude.request('tools/list')).tools as unknown[];
  assert.equal(tools.length, 1);
  assert.equal(fake.initializes, 2);
});

test('a static client signs in without registering', async () => {
  const fake = await started({ staticClient: 'pre-registered' });
  const claude = await connect(fake.mcp, memoryStore(), browser().open, {
    clientId: 'pre-registered',
  });
  assert.equal(result(await initialize(claude)).protocolVersion, VERSION);
  assert.equal(fake.registrations, 0);
});

test('an unreachable server is answered with a sentence about the network', async () => {
  const url = new URL(`http://127.0.0.1:${await freePort()}/mcp`);
  const claude = await connect(url, memoryStore(), browser().open);
  const answer = await initialize(claude);
  assert.ok('error' in answer, JSON.stringify(answer));
  assert.match(answer.error.message, /Cannot reach http:\/\/127\.0\.0\.1:\d+ \(ECONNREFUSED\)/);
  assert.match(answer.error.message, /VPN or mesh/);
});
