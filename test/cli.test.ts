import assert from 'node:assert/strict';
import { test } from 'node:test';
import { main, parse, sameIssuer } from '../src/cli.js';
import { portFor } from '../src/port.js';
import { keyFor } from '../src/store.js';
import { memoryStore, startFake, type Fake } from './fake.js';

const URL_A = 'https://mcp.example.internal/mcp';

test('a port is stable per URL and in range', () => {
  assert.equal(portFor(URL_A), portFor(URL_A));
  for (const u of [URL_A, 'http://127.0.0.1:1/x', 'https://a.b/c?d=e']) {
    const p = portFor(u);
    assert.ok(p >= 3335 && p < 49150, String(p));
  }
});

test('the URL and flags come from the command line', () => {
  const o = parse([URL_A, '--port', '4000', '--client-id', 'abc', '--login'], {});
  assert.ok(!('exit' in o));
  assert.equal(o.url.href, URL_A);
  assert.equal(o.port, 4000);
  assert.equal(o.clientId, 'abc');
  assert.equal(o.mode, 'login');
});

test('Claude Desktop settings come from the environment, unfilled ones ignored', () => {
  const o = parse([], {
    MCP_MESH_BRIDGE_URL: URL_A,
    MCP_MESH_BRIDGE_PORT: '${user_config.callback_port}',
    MCP_MESH_BRIDGE_CLIENT_ID: '',
    MCP_MESH_BRIDGE_CLIENT_SECRET: 's3cret',
  });
  assert.ok(!('exit' in o));
  assert.equal(o.mode, 'bridge');
  assert.equal(o.port, portFor(URL_A));
  assert.equal(o.clientId, undefined);
  assert.equal(o.clientSecret, 's3cret');
});

test('bad input is refused with a reason', () => {
  const missing = parse([], {});
  assert.ok('exit' in missing && missing.exit === 2 && /no server URL/.test(missing.message));
  const scheme = parse(['ftp://x/y'], {});
  assert.ok('exit' in scheme && /http or https/.test(scheme.message));
  const port = parse([URL_A, '--port', '80'], {});
  assert.ok('exit' in port && /1024 to 65535/.test(port.message));
  const flag = parse([URL_A, '--nope'], {});
  assert.ok('exit' in flag && /unknown option/.test(flag.message));
  const help = parse(['--help'], {});
  assert.ok('exit' in help && help.exit === 0);
});

/** A stored sign-in to `fake`, as the SDK stamps it. */
const signedIn = (
  store: ReturnType<typeof memoryStore>,
  fake: Fake,
  refreshToken: string,
  issuer: string | null = fake.base,
) => {
  const stamp = issuer === null ? {} : { issuer };
  store.entries.set(
    keyFor(fake.mcp.href),
    JSON.stringify({
      client: { client_id: 'client-x', ...stamp },
      tokens: { access_token: 'at', token_type: 'Bearer', refresh_token: refreshToken, ...stamp },
    }),
  );
};

test('logout revokes the refresh token and says what it removed', async () => {
  const fake = await startFake();
  try {
    const store = memoryStore();
    signedIn(store, fake, 'rt-x');
    const logs: string[] = [];
    const log = (m: string) => void logs.push(m);
    assert.equal(await main(['--logout', fake.mcp.href], {}, store, log), 0);
    assert.deepEqual(fake.revoked, [{ token: 'rt-x', clientId: 'client-x' }]);
    assert.equal(store.entries.size, 0);
    assert.deepEqual(logs, [
      'the server revoked the sign-in',
      `signed out of ${fake.base}: its sign-in is gone from memory`,
    ]);

    logs.length = 0;
    assert.equal(await main(['--logout', fake.mcp.href], {}, store, log), 0);
    assert.equal(fake.revoked.length, 1);
    assert.deepEqual(logs, [`nothing was stored for ${fake.base} in memory`]);

    // A configured client is the one the tokens were issued to.
    signedIn(store, fake, 'rt-y');
    await main(['--logout', fake.mcp.href, '--client-id', 'fixed'], {}, store, log);
    assert.deepEqual(fake.revoked[1], { token: 'rt-y', clientId: 'fixed' });
  } finally {
    await fake.close();
  }
});

test('logout sends the token only to the server that issued it', async () => {
  const elsewhere = 'https://other.example/revoke';
  const fake = await startFake();
  const moved = await startFake({ revocationEndpoint: elsewhere });
  try {
    const cases: [Fake, string | null, RegExp][] = [
      [fake, null, /it does not say which server issued it/],
      [fake, 'https://as.example', /now names another sign-in server than https:\/\/as.example/],
      [moved, moved.base, /its revocation endpoint is not on http:\/\/127\.0\.0\.1:\d+/],
    ];
    for (const [server, issuer, why] of cases) {
      const store = memoryStore();
      signedIn(store, server, 'rt-z', issuer);
      const logs: string[] = [];
      await main(['--logout', server.mcp.href], {}, store, (m) => void logs.push(m));
      assert.equal(server.revoked.length, 0);
      assert.match(logs[0] ?? '', /^not asking the server to revoke the sign-in: /);
      assert.match(logs[0] ?? '', why);
      assert.match(logs[1] ?? '', /^signed out of /);
      assert.equal(store.entries.size, 0);
    }
  } finally {
    await fake.close();
    await moved.close();
  }
});

test('issuers compare as URLs, a trailing slash aside', () => {
  assert.ok(sameIssuer('https://as.example', 'https://as.example/'));
  assert.ok(sameIssuer('HTTPS://AS.example:443/', 'https://as.example'));
  assert.ok(!sameIssuer('https://as.example', 'https://as.example/tenant'));
  assert.ok(!sameIssuer('https://as.example', 'http://as.example'));
  assert.ok(!sameIssuer('not a url', 'not a url'));
});

test('plain http to another machine is warned about', async () => {
  const logs: string[] = [];
  const log = (m: string) => void logs.push(m);
  await main(['--logout', 'http://mcp.mesh.example/mcp'], {}, memoryStore(), log);
  assert.match(logs[0] ?? '', /^http:\/\/mcp.mesh.example is plain http/);
  logs.length = 0;
  await main(['--logout', 'http://127.0.0.1:9/mcp'], {}, memoryStore(), log);
  assert.ok(!logs.some((m) => m.includes('plain http')));
});
