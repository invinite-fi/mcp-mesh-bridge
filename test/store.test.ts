import assert from 'node:assert/strict';
import { mkdtemp, rm, stat } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { test } from 'node:test';
import {
  dpapiArgs,
  dpapiStore,
  fileStore,
  keyFor,
  keychainReadArgs,
  keychainRemoveArgs,
  keychainStore,
  keychainWriteCommand,
} from '../src/store.js';

const SECRET = '{"tokens":{"access_token":"secret-value","token_type":"Bearer"}}';

test('a key is a stable hash that names no URL', () => {
  const key = keyFor('https://mcp.example.internal/mcp');
  assert.equal(key, keyFor('https://mcp.example.internal/mcp'));
  assert.match(key, /^[0-9a-f]{32}$/);
  assert.notEqual(key, keyFor('https://other.example.internal/mcp'));
});

test('the file store keeps an entry readable by its owner only', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'mesh-bridge-'));
  try {
    const store = fileStore(join(dir, 'nested'));
    assert.equal(await store.read('k'), undefined);
    await store.write('k', SECRET);
    assert.equal(await store.read('k'), SECRET);
    if (process.platform !== 'win32') {
      assert.equal((await stat(join(dir, 'nested', 'k.json'))).mode & 0o777, 0o600);
      assert.equal((await stat(join(dir, 'nested'))).mode & 0o777, 0o700);
    }
    await store.remove('k');
    assert.equal(await store.read('k'), undefined);
    await store.remove('k');
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

type Call = { command: string; args: string[]; input: string | undefined };

const recording = (answers: { code: number; stdout?: string; stderr?: string }[]) => {
  const calls: Call[] = [];
  const exec = async (command: string, args: string[], input?: string) => {
    calls.push({ command, args, input });
    const a = answers.shift() ?? { code: 0 };
    return { code: a.code, stdout: a.stdout ?? '', stderr: a.stderr ?? '' };
  };
  return { calls, exec };
};

test('the Keychain store keeps the secret off the command line', async () => {
  const { calls, exec } = recording([
    { code: 0 },
    { code: 0, stdout: `${SECRET}\n` },
    { code: 44 },
    { code: 0 },
    { code: 44 },
  ]);
  const store = keychainStore(exec);
  await store.write('abc', SECRET);
  assert.equal(await store.read('abc'), SECRET);
  assert.equal(await store.read('missing'), undefined);
  await store.remove('abc');
  await store.remove('missing');

  const write = calls[0];
  assert.deepEqual(write?.args, ['-i']);
  assert.equal(write?.input, keychainWriteCommand('abc', SECRET));
  assert.match(
    write?.input ?? '',
    /^add-generic-password -U -s mcp-mesh-bridge -a abc -X [0-9a-f]+\n$/,
  );
  assert.deepEqual(calls[1]?.args, keychainReadArgs('abc'));
  assert.deepEqual(calls[3]?.args, keychainRemoveArgs('abc'));
  for (const c of calls) assert.ok(!c.args.join(' ').includes('secret-value'));
});

test('a Keychain write that security reports on stderr fails', async () => {
  const { exec } = recording([{ code: 0, stderr: 'security: SecKeychainItemCreate: denied' }]);
  await assert.rejects(keychainStore(exec).write('k', SECRET), /could not be written/);
});

test('the DPAPI store passes the secret through stdin as base64', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'mesh-bridge-'));
  try {
    // Stand in for DPAPI with a reversible change, to see both directions.
    const flip = (b64: string) => Buffer.from(b64, 'base64').reverse().toString('base64');
    const calls: Call[] = [];
    const exec = async (command: string, args: string[], input?: string) => {
      calls.push({ command, args, input });
      return { code: 0, stdout: flip(input ?? ''), stderr: '' };
    };
    const store = dpapiStore(dir, exec);
    await store.write('k', SECRET);
    assert.equal(await store.read('k'), SECRET);
    assert.equal(calls[0]?.command, 'powershell.exe');
    assert.deepEqual(calls[0]?.args, dpapiArgs('Protect'));
    assert.deepEqual(calls[1]?.args, dpapiArgs('Unprotect'));
    for (const c of calls) assert.ok(!c.args.join(' ').includes('secret-value'));
    assert.match(dpapiArgs('Protect').join(' '), /DataProtectionScope\]::CurrentUser/);
    await store.remove('k');
    assert.equal(await store.read('k'), undefined);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test(
  'DPAPI protects and unprotects for real on Windows',
  { skip: process.platform !== 'win32' },
  async () => {
    const dir = await mkdtemp(join(tmpdir(), 'mesh-bridge-'));
    try {
      const store = dpapiStore(dir);
      await store.write('k', SECRET);
      assert.equal(await store.read('k'), SECRET);
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  },
);

test(
  'the Keychain keeps an entry for real on macOS',
  { skip: process.platform !== 'darwin' || process.env.MCP_MESH_BRIDGE_KEYCHAIN_TEST !== '1' },
  async () => {
    const store = keychainStore();
    const key = `test-${Date.now()}`;
    try {
      await store.write(key, SECRET);
      assert.equal(await store.read(key), SECRET);
    } finally {
      await store.remove(key);
    }
    assert.equal(await store.read(key), undefined);
  },
);
