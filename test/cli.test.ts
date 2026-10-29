import assert from 'node:assert/strict';
import { test } from 'node:test';
import { parse } from '../src/cli.js';
import { portFor } from '../src/port.js';

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
