// Build the .mcpb: the bridge bundled into one file with esbuild, the
// manifest, and the license, packed by Anthropic's mcpb CLI.
//
//   npm run pack
//   npm run pack:branded -- --name "Example Knowledge" --url https://mcp.example.internal/mcp \
//     --out dist/example-knowledge.mcpb
//
// A branded build gets its own display name and the URL as the server URL's
// default. Branded builds stay on the machine that made them: they are not
// committed or released.
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
    out: { type: 'string' },
  },
});

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
  manifest.user_config.server_url.default = values.url;
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
