import assert from 'node:assert/strict';
import { mkdir, mkdtemp, readdir, readFile, rm, stat, utimes, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { test } from 'node:test';
import {
  dpapiArgs,
  dpapiStore,
  fileStore,
  keyFor,
  keychainStore,
  powershellPath,
  run,
  seal,
  unseal,
} from '../src/store.js';

const SECRET = '{"tokens":{"access_token":"secret-value","token_type":"Bearer"}}';
/** Larger than a line `security -i` reads whole. */
const BIG = JSON.stringify({
  tokens: { access_token: `secret-value${'x'.repeat(10_000)}`, token_type: 'Bearer' },
});

const scratch = async (body: (dir: string) => Promise<void>) => {
  const dir = await mkdtemp(join(tmpdir(), 'mesh-bridge-'));
  try {
    await body(dir);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
};

const sorted = async (dir: string) => (await readdir(dir)).sort();

test('a key is a stable hash that names no URL', () => {
  const key = keyFor('https://mcp.example.internal/mcp');
  assert.equal(key, keyFor('https://mcp.example.internal/mcp'));
  assert.match(key, /^[0-9a-f]{32}$/);
  assert.notEqual(key, keyFor('https://other.example.internal/mcp'));
});

test('the file store keeps an entry readable by its owner only', () =>
  scratch(async (dir) => {
    const store = fileStore(join(dir, 'nested'));
    assert.equal(await store.read('k'), undefined);
    assert.equal(await store.write('k', SECRET), true);
    assert.equal(await store.write('k', BIG, { create: false }), true);
    assert.equal(await store.read('k'), BIG);
    assert.deepEqual(await readdir(join(dir, 'nested')), ['k.json']);
    if (process.platform !== 'win32') {
      assert.equal((await stat(join(dir, 'nested', 'k.json'))).mode & 0o777, 0o600);
      assert.equal((await stat(join(dir, 'nested'))).mode & 0o777, 0o700);
    }
    assert.equal(await store.remove('k'), true);
    assert.equal(await store.read('k'), undefined);
    assert.equal(await store.remove('k'), false);
  }));

test('an entry removed meanwhile is not written again unless it may be created', () =>
  scratch(async (dir) => {
    const store = fileStore(dir);
    assert.equal(await store.write('k', SECRET, { create: false }), false);
    assert.deepEqual(await readdir(dir), []);
  }));

test('writes to one entry are made in turn', () =>
  scratch(async (dir) => {
    const store = fileStore(dir);
    await Promise.all([store.write('k', 'one'), store.write('k', 'two'), store.write('k', BIG)]);
    assert.equal(await store.read('k'), BIG);
  }));

test('two processes writing one entry at once both succeed', () =>
  scratch(async (dir) => {
    // Two stores stand for two processes: each queues only its own writes.
    const stores = [fileStore(dir), fileStore(dir)];
    const values = Array.from({ length: 10 }, (_, i) => `${BIG}${i}`);
    await Promise.all(values.map((v, i) => stores[i % 2]?.write('k', v)));
    assert.ok(values.includes((await stores[0]?.read('k')) ?? ''));
    assert.deepEqual(await readdir(dir), ['k.json']);
  }));

test('an entry that cannot be read is an error, not an empty one', () =>
  scratch(async (dir) => {
    await mkdir(join(dir, 'k.json'));
    await assert.rejects(fileStore(dir).read('k'));
  }));

test('a failed write leaves no temporary file behind', () =>
  scratch(async (dir) => {
    // A directory in the entry's place makes the rename fail.
    await mkdir(join(dir, 'k.json', 'x'), { recursive: true });
    await assert.rejects(fileStore(dir).write('k', SECRET));
    assert.deepEqual(await readdir(dir), ['k.json']);
  }));

test('a write removes temporary files a crash left, once they are a minute old', () =>
  scratch(async (dir) => {
    const old = join(dir, '.k.json.aaaaaaaaaaaa.tmp');
    const fresh = join(dir, '.k.json.bbbbbbbbbbbb.tmp');
    await writeFile(old, 'x');
    await writeFile(fresh, 'x');
    const then = new Date(Date.now() - 2 * 60_000);
    await utimes(old, then, then);
    await fileStore(dir).write('k', SECRET);
    assert.deepEqual(await sorted(dir), ['.k.json.bbbbbbbbbbbb.tmp', 'k.json']);
  }));

test('a sealed entry opens only under its own key and name', () => {
  const key = Buffer.alloc(32, 7);
  const sealed = seal(key, 'a', SECRET);
  assert.ok(!sealed.includes('secret-value'));
  assert.equal(unseal(key, 'a', sealed), SECRET);
  assert.throws(() => unseal(key, 'b', sealed));
  assert.throws(() => unseal(Buffer.alloc(32, 8), 'a', sealed));
  const s = JSON.parse(sealed) as { data: string };
  const data = Buffer.from(s.data, 'base64');
  data[0] = (data[0] ?? 0) ^ 1;
  assert.throws(() => unseal(key, 'a', JSON.stringify({ ...s, data: data.toString('base64') })));
});

type Call = { command: string; args: string[]; input: string | undefined };
type Answer = { code: number; stdout: string; stderr: string };

/** `security` as far as the Keychain store uses it, its items in memory. */
const emulatedSecurity = () => {
  const items = new Map<string, string>();
  const calls: Call[] = [];
  const answer = (code: number, stdout = '', stderr = ''): Answer => ({ code, stdout, stderr });
  const exec = async (command: string, args: string[], input?: string): Promise<Answer> => {
    calls.push({ command, args, input });
    // Each call takes a turn, so writes from two stores interleave.
    await new Promise((r) => setImmediate(r));
    if (args[0] === '-i') {
      const m = /^add-generic-password( -U)? -s (\S+) -a (\S+) -w (\S+)\n$/.exec(input ?? '');
      if (!m) return answer(0, '', 'unknown command');
      const id = `${m[2]} ${m[3]}`;
      // As `security -i` does: exit 0, the failure on stderr.
      if (items.has(id) && !m[1]) return answer(0, '', 'The specified item already exists');
      items.set(id, m[4] ?? '');
      return answer(0);
    }
    const id = `${args[2]} ${args[4]}`;
    if (args[0] === 'find-generic-password') {
      const v = items.get(id);
      return v === undefined ? answer(44) : answer(0, `${v}\n`);
    }
    if (args[0] === 'delete-generic-password') return answer(items.delete(id) ? 0 : 44);
    return answer(1);
  };
  return { items, calls, exec };
};

test('the Keychain store keeps only a key in the Keychain, and never on a command line', () =>
  scratch(async (dir) => {
    const security = emulatedSecurity();
    const store = keychainStore({ dir, exec: security.exec });
    assert.equal(await store.read('k'), undefined);
    await store.write('k', BIG);
    assert.equal(await store.read('k'), BIG);
    await store.write('k', SECRET, { create: false });
    assert.equal(await store.read('k'), SECRET);

    const adds = security.calls.filter((c) => c.args[0] === '-i');
    assert.equal(adds.length, 1, 'the key is made once and kept');
    assert.match(
      adds[0]?.input ?? '',
      /^add-generic-password -s mcp-mesh-bridge -a k -w [0-9a-f]{64}\n$/,
    );
    for (const c of security.calls) {
      assert.equal(c.command, '/usr/bin/security');
      assert.ok(!`${c.args.join(' ')} ${c.input ?? ''}`.includes('secret-value'));
    }
    assert.ok(!(await readFile(join(dir, 'k.enc'), 'utf8')).includes('secret-value'));
    if (process.platform !== 'win32') {
      assert.equal((await stat(join(dir, 'k.enc'))).mode & 0o777, 0o600);
    }

    assert.equal(await store.remove('k'), true);
    assert.equal(security.items.size, 0);
    assert.equal(await store.read('k'), undefined);
    assert.equal(await store.remove('k'), false);
  }));

test('a Keychain entry removed meanwhile gets no new key unless it may be created', () =>
  scratch(async (dir) => {
    const security = emulatedSecurity();
    const store = keychainStore({ dir, exec: security.exec });
    assert.equal(await store.write('k', SECRET, { create: false }), false);
    assert.equal(security.items.size, 0);
    assert.deepEqual(await readdir(dir), []);

    // `--logout` removes the key first: a file left without one is an entry removed.
    await store.write('k', SECRET);
    security.items.clear();
    assert.equal(await store.read('k'), undefined);
    assert.equal(await store.write('k', SECRET, { create: false }), false);
  }));

test('a Keychain item this bridge did not make is an error to read, and replaced on a new write', () =>
  scratch(async (dir) => {
    const security = emulatedSecurity();
    const store = keychainStore({ dir, exec: security.exec });
    await store.write('k', SECRET);
    security.items.set(`mcp-mesh-bridge k`, 'not a key');
    await assert.rejects(store.read('k'), /no usable key/);
    await assert.rejects(store.write('k', SECRET, { create: false }), /no usable key/);
    await store.write('k', BIG);
    assert.equal(await store.read('k'), BIG);
    const adds = security.calls.filter((c) => c.args[0] === '-i');
    assert.match(adds.at(-1)?.input ?? '', /^add-generic-password -U /);
  }));

test('two processes writing an entry first agree on its key', () =>
  scratch(async (dir) => {
    const security = emulatedSecurity();
    const one = keychainStore({ dir, exec: security.exec });
    const two = keychainStore({ dir, exec: security.exec });
    assert.deepEqual(await Promise.all([one.write('k', 'one'), two.write('k', 'two')]), [
      true,
      true,
    ]);
    assert.equal(security.calls.filter((c) => c.args[0] === '-i').length, 2);
    assert.equal(security.items.size, 1);
    assert.ok(['one', 'two'].includes((await one.read('k')) ?? ''));
  }));

test('a Keychain write that security reports on stderr fails', () =>
  scratch(async (dir) => {
    const exec = async (_command: string, args: string[]): Promise<Answer> =>
      args[0] === '-i'
        ? { code: 0, stdout: '', stderr: 'security: SecKeychainItemCreate: denied' }
        : { code: 44, stdout: '', stderr: '' };
    await assert.rejects(keychainStore({ dir, exec }).write('k', SECRET), /could not be written/);
    assert.deepEqual(await readdir(dir), []);
  }));

test('a keychain path with a space is refused', () => {
  assert.throws(() => keychainStore({ keychain: '/tmp/a b.keychain-db' }), /space/);
});

test('Windows PowerShell is run by its full path', () => {
  assert.equal(
    powershellPath({ SystemRoot: 'D:\\Win' }),
    'D:\\Win\\System32\\WindowsPowerShell\\v1.0\\powershell.exe',
  );
  assert.equal(
    powershellPath({}),
    'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe',
  );
});

test('the DPAPI store passes the secret through stdin as base64', () =>
  scratch(async (dir) => {
    // Stand in for DPAPI with a reversible change, to see both directions.
    const flip = (b64: string) => Buffer.from(b64, 'base64').reverse().toString('base64');
    const calls: Call[] = [];
    const exec = async (command: string, args: string[], input?: string) => {
      calls.push({ command, args, input });
      return { code: 0, stdout: flip(input ?? ''), stderr: '' };
    };
    const store = dpapiStore(dir, exec);
    assert.equal(await store.write('k', SECRET, { create: false }), false);
    await store.write('k', BIG);
    assert.equal(await store.read('k'), BIG);
    assert.equal(calls[0]?.command, powershellPath());
    assert.deepEqual(calls[0]?.args, dpapiArgs('Protect'));
    assert.deepEqual(calls[1]?.args, dpapiArgs('Unprotect'));
    for (const c of calls) assert.ok(!c.args.join(' ').includes('secret-value'));
    assert.match(dpapiArgs('Protect').join(' '), /DataProtectionScope\]::CurrentUser/);
    assert.deepEqual(await readdir(dir), ['k.dat']);
    assert.equal(await store.remove('k'), true);
    assert.equal(await store.read('k'), undefined);
    assert.equal(await store.remove('k'), false);
  }));

test(
  'DPAPI protects and unprotects for real on Windows',
  { skip: process.platform !== 'win32' },
  () =>
    scratch(async (dir) => {
      const store = dpapiStore(dir);
      await store.write('k', BIG);
      assert.equal(await store.read('k'), BIG);
    }),
);

/** A keychain of the test's own, used by its path, so the login keychain is untouched. */
const throwawayKeychain = async (dir: string, body: (keychain: string) => Promise<void>) => {
  const keychain = join(dir, 'test.keychain-db');
  const made = await run('/usr/bin/security', ['create-keychain', '-p', 'test', keychain]);
  assert.equal(made.code, 0, made.stderr);
  try {
    await body(keychain);
  } finally {
    await run('/usr/bin/security', ['delete-keychain', keychain]);
  }
};

test(
  'a 10 KB entry goes through a real keychain on macOS',
  { skip: process.platform !== 'darwin' },
  () =>
    scratch((dir) =>
      throwawayKeychain(dir, async (keychain) => {
        const opts = { dir: join(dir, 'entries'), keychain };
        await keychainStore(opts).write('k', BIG);
        assert.equal(await keychainStore(opts).read('k'), BIG);
        assert.equal(await keychainStore(opts).remove('k'), true);
        assert.equal(await keychainStore(opts).read('k'), undefined);
      }),
    ),
);

test(
  'two processes writing entries first agree on their keys in a real keychain on macOS',
  { skip: process.platform !== 'darwin' },
  () =>
    scratch((dir) =>
      throwawayKeychain(dir, async (keychain) => {
        // Two stores stand for two processes: each queues only its own writes.
        const opts = { dir: join(dir, 'entries'), keychain };
        const one = keychainStore(opts);
        const two = keychainStore(opts);
        const keys = ['a', 'b', 'c', 'd', 'e'];
        await Promise.all(keys.flatMap((k) => [one.write(k, `${BIG}1`), two.write(k, `${BIG}2`)]));
        for (const k of keys) {
          assert.ok([`${BIG}1`, `${BIG}2`].includes((await keychainStore(opts).read(k)) ?? ''), k);
        }
      }),
    ),
);
