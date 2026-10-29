import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { test } from 'node:test';
import { startFake } from './fake.js';

// BRIDGE_MAIN runs the same test against the bundle the .mcpb ships.
const MAIN = process.env.BRIDGE_MAIN
  ? resolve(process.env.BRIDGE_MAIN)
  : fileURLToPath(new URL('../src/main.js', import.meta.url));

test('the command relays over stdio as Claude Desktop starts it', async () => {
  const fake = await startFake({ auth: false });
  const child = spawn(process.execPath, [MAIN], {
    env: { ...process.env, MCP_MESH_BRIDGE_URL: fake.mcp.href, XDG_CONFIG_HOME: '/nonexistent' },
    stdio: ['pipe', 'pipe', 'pipe'],
  });
  try {
    const lines: string[] = [];
    let buffer = '';
    const next = () =>
      new Promise<Record<string, unknown>>((resolve, reject) => {
        const timer = setTimeout(() => reject(new Error('no answer on stdout')), 10_000);
        const check = () => {
          const line = lines.shift();
          if (line !== undefined) {
            clearTimeout(timer);
            resolve(JSON.parse(line) as Record<string, unknown>);
          } else setTimeout(check, 10);
        };
        check();
      });
    child.stdout.on('data', (d: Buffer) => {
      buffer += d.toString('utf8');
      let i: number;
      while ((i = buffer.indexOf('\n')) >= 0) {
        lines.push(buffer.slice(0, i));
        buffer = buffer.slice(i + 1);
      }
    });
    const send = (m: unknown) => child.stdin.write(`${JSON.stringify(m)}\n`);

    send({
      jsonrpc: '2.0',
      id: 1,
      method: 'initialize',
      params: {
        protocolVersion: '2025-06-18',
        capabilities: {},
        clientInfo: { name: 't', version: '1' },
      },
    });
    const init = await next();
    assert.equal((init.result as { serverInfo: { name: string } }).serverInfo.name, 'fake');
    send({ jsonrpc: '2.0', method: 'notifications/initialized' });
    send({ jsonrpc: '2.0', id: 2, method: 'tools/list' });
    const tools = await next();
    assert.equal(tools.id, 2);
    assert.equal((tools.result as { tools: unknown[] }).tools.length, 1);
  } finally {
    child.stdin.end();
    child.kill();
    await fake.close();
  }
});
