import assert from 'node:assert/strict';
import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
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
  extra: { clientId?: string; pickFile?: () => Promise<string | undefined> } = {},
): Promise<Claude> => {
  const [claude, side] = InMemoryTransport.createLinkedPair();
  const { pickFile, ...signInExtra } = extra;
  const session = signIn({
    serverUrl: url.href,
    port: await freePort(),
    store,
    openBrowser: open,
    log: () => undefined,
    timeout: 10_000,
    ...signInExtra,
  });
  const running = bridge(side, {
    url,
    signIn: session,
    log: () => undefined,
    ...(pickFile ? { pickFile } : {}),
  });
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

test('requests meeting a forgotten session together share one new session', async () => {
  const fake = await started();
  const claude = await connect(fake.mcp, memoryStore(), browser().open);
  await initialize(claude);
  await claude.notify('notifications/initialized');

  fake.forget();
  const answers = await Promise.all([
    claude.request('tools/list'),
    claude.request('tools/call', { name: 'echo', arguments: { n: 1 } }),
    claude.request('tools/call', { name: 'echo', arguments: { n: 2 } }),
  ]);
  for (const a of answers) result(a);
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

test('advertises upload_local_file when the server offers start_upload and streams files from disk', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'mcp-mesh-bridge-e2e-'));
  cleanups.push(() => rm(dir, { recursive: true, force: true }));
  const sample = join(dir, 'Proposal.pdf');
  const bytes = Buffer.from('%PDF-1.7\nhello binary upload\n');
  await writeFile(sample, bytes);

  const fake = await started({ uploads: true });
  const claude = await connect(fake.mcp, memoryStore(), browser().open, {
    pickFile: async () => sample,
  });
  await initialize(claude);
  await claude.notify('notifications/initialized');

  const tools = result(await claude.request('tools/list')).tools as { name: string }[];
  assert.deepEqual(
    tools.map((t) => t.name),
    ['echo', 'start_upload', 'upload_local_file'],
  );

  // 1. Upload by explicit local path (with keep flag).
  const byPath = result(
    await claude.request('tools/call', {
      name: 'upload_local_file',
      arguments: { path: sample, keep: true },
    }),
  ) as { isError?: boolean; content: { text: string }[] };
  assert.notEqual(byPath.isError, true, byPath.content[0]?.text);
  const match1 = /upload_id: (\S+)/.exec(byPath.content[0]?.text ?? '');
  assert.ok(match1?.[1]);
  const stored1 = fake.uploaded.get(match1[1]);
  assert.equal(stored1?.filename, 'Proposal.pdf');
  assert.deepEqual(stored1?.bytes, bytes);
  assert.equal(stored1?.keep, true);

  // 2. Upload via native picker fallback (path omitted), even across a forgotten session.
  fake.forget();
  const byPicker = result(
    await claude.request('tools/call', {
      name: 'upload_local_file',
      arguments: {},
    }),
  ) as { isError?: boolean; content: { text: string }[] };
  assert.notEqual(byPicker.isError, true, byPicker.content[0]?.text);
  const match2 = /upload_id: (\S+)/.exec(byPicker.content[0]?.text ?? '');
  assert.ok(match2?.[1]);
  assert.deepEqual(fake.uploaded.get(match2[1])?.bytes, bytes);
  assert.equal(fake.initializes, 2, 'recovered forgotten session for bridge call');
});

test('refuses cross-origin upload_url returned by a server', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'mcp-mesh-bridge-xorigin-'));
  cleanups.push(() => rm(dir, { recursive: true, force: true }));
  const sample = join(dir, 'Deck.pptx');
  await writeFile(sample, 'PK\x03\x04deck');

  const fake = await started({ uploads: true, uploadUrlOrigin: 'https://other.example' });
  const claude = await connect(fake.mcp, memoryStore(), browser().open);
  await initialize(claude);
  await claude.notify('notifications/initialized');

  const res = result(
    await claude.request('tools/call', {
      name: 'upload_local_file',
      arguments: { path: sample },
    }),
  ) as { isError?: boolean; content: { text: string }[] };
  assert.equal(res.isError, true);
  assert.match(res.content[0]?.text ?? '', /only uploads to/);
  assert.equal(fake.uploaded.size, 0);
});

test('refuses upload_local_file without touching the picker or filesystem when start_upload is absent', async () => {
  const fake = await started({ uploads: false });
  let pickerCalled = false;
  const claude = await connect(fake.mcp, memoryStore(), browser().open, {
    pickFile: async () => {
      pickerCalled = true;
      return '/tmp/should-not-be-picked.pdf';
    },
  });
  await initialize(claude);
  await claude.notify('notifications/initialized');

  const res = result(
    await claude.request('tools/call', {
      name: 'upload_local_file',
      arguments: {},
    }),
  ) as { isError?: boolean; content: { text: string }[] };
  assert.equal(res.isError, true);
  assert.match(res.content[0]?.text ?? '', /does not support upload_local_file/);
  assert.equal(pickerCalled, false, 'must not open file picker when server lacks start_upload');
});

test('relays upload_local_file to the server when the server defines its own upload_local_file tool', async () => {
  const fake = await started({ uploads: true, ownUploadTool: true });
  const claude = await connect(fake.mcp, memoryStore(), browser().open);
  await initialize(claude);
  await claude.notify('notifications/initialized');

  const tools = result(await claude.request('tools/list')).tools as { name: string }[];
  assert.deepEqual(
    tools.map((t) => t.name),
    ['echo', 'start_upload', 'upload_local_file'],
  );

  const res = result(
    await claude.request('tools/call', {
      name: 'upload_local_file',
      arguments: { custom: 'arg' },
    }),
  ) as { isError?: boolean; content: { text: string }[] };
  assert.notEqual(res.isError, true);
  assert.equal(res.content[0]?.text, 'server-handled:{"custom":"arg"}');
});

test('augments paginated tools/list only on the page that offers start_upload', async () => {
  const fake = await started({ uploads: true, paginatedTools: true });
  const claude = await connect(fake.mcp, memoryStore(), browser().open);
  await initialize(claude);
  await claude.notify('notifications/initialized');

  const page1 = result(await claude.request('tools/list')) as {
    tools: { name: string }[];
    nextCursor?: string;
  };
  assert.deepEqual(
    page1.tools.map((t) => t.name),
    ['echo'],
  );
  assert.equal(page1.nextCursor, 'page-2');

  const page2 = result(await claude.request('tools/list', { cursor: page1.nextCursor })) as {
    tools: { name: string }[];
    nextCursor?: string;
  };
  assert.deepEqual(
    page2.tools.map((t) => t.name),
    ['start_upload', 'upload_local_file'],
  );
  assert.equal(page2.nextCursor, undefined);
});
