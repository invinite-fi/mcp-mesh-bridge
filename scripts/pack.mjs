// Build the .mcpb: the bridge bundled into one file with esbuild, the
// manifest, and the license, packed by Anthropic's mcpb CLI.
//
//   yarn bundle
//   yarn bundle:branded --name "Example Knowledge" --url https://mcp.example.internal/mcp \
//     --icon icon.png --out dist/example-knowledge.mcpb
//
// A branded build gets its own display name and its server URL built in, so it
// asks nothing at install: Claude Desktop keeps a settings dialog's Save off
// until a field changes, even when every default is good. Branded builds stay
// on the machine that made them: they are not committed or released.
import { execFileSync } from 'node:child_process';
import { copyFile, mkdir, readFile, rm, writeFile } from 'node:fs/promises';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { parseArgs } from 'node:util';
import { build } from 'esbuild';

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const { values } = parseArgs({
  options: {
    name: { type: 'string' },
    url: { type: 'string' },
    icon: { type: 'string' },
    out: { type: 'string' },
  },
});

const PNG = Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]);

const manifest = JSON.parse(await readFile(join(root, 'manifest.json'), 'utf8'));
if (values.name) {
  manifest.display_name = values.name;
  manifest.name = values.name
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, '-')
    .replace(/^-|-$/g, '');
}
if (values.url) {
  new URL(values.url);
  delete manifest.user_config;
  manifest.server.mcp_config.env = { MCP_MESH_BRIDGE_URL: values.url };
}

const stage = join(root, 'dist', 'stage');
await rm(stage, { recursive: true, force: true });
await mkdir(join(stage, 'server'), { recursive: true });

await build({
  entryPoints: [join(root, 'src', 'main.ts')],
  bundle: true,
  platform: 'node',
  target: 'node20',
  format: 'esm',
  outfile: join(stage, 'server', 'index.mjs'),
  // Some of the SDK's dependencies are CommonJS and call require().
  banner: {
    js: "import { createRequire } from 'node:module'; const require = createRequire(import.meta.url);",
  },
  legalComments: 'external',
  logLevel: 'warning',
});

// One `icon`: Claude's organisation allowlist checks a manifest against the DXT
// schema, which refuses the newer themed `icons`. A logo that would vanish on a
// dark theme belongs on a tile of its own colour.
if (values.icon) {
  const icon = await readFile(resolve(values.icon));
  if (!icon.subarray(0, 8).equals(PNG)) throw new Error(`${values.icon} is not a PNG`);
  await writeFile(join(stage, 'icon.png'), icon);
  manifest.icon = 'icon.png';
}

await writeFile(join(stage, 'manifest.json'), `${JSON.stringify(manifest, null, 2)}\n`);
await copyFile(join(root, 'LICENSE'), join(stage, 'LICENSE'));

const out = resolve(root, values.out ?? join('dist', `${manifest.name}-${manifest.version}.mcpb`));
await mkdir(dirname(out), { recursive: true });
const mcpb = join(root, 'node_modules', '.bin', process.platform === 'win32' ? 'mcpb.cmd' : 'mcpb');
const run = (args) =>
  execFileSync(mcpb, args, { stdio: 'inherit', shell: process.platform === 'win32' });
run(['validate', join(stage, 'manifest.json')]);
run(['pack', stage, out]);
console.log(`packed ${out}`);
