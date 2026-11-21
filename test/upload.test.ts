import assert from 'node:assert/strict';
import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { afterEach, test } from 'node:test';
import {
  handleUploadLocalFile,
  parseStartUpload,
  parseStartUploadResult,
  rememberUploadUrl,
  uploadLocalFileTool,
  pickerCommand,
  pickLocalFile,
  redactUploadUrl,
  resolveLocalPath,
  validateUploadUrl,
  windowsPickerScript,
  type UploadContext,
} from '../src/upload.js';

const dirs: string[] = [];
afterEach(async () => {
  while (dirs.length) {
    const d = dirs.pop();
    if (d) await rm(d, { recursive: true, force: true });
  }
});

const tempDir = async (): Promise<string> => {
  const d = await mkdtemp(join(tmpdir(), 'mcp-mesh-bridge-upload-'));
  dirs.push(d);
  return d;
};

test('parseStartUpload reads upload_id and upload_url from plain, markdown, and JSON outputs', () => {
  const parsed = parseStartUpload(
    'upload_id: up-123\nupload_url: https://kb.example/uploads/direct/up-123/tok\n\nSingle-use URL',
  );
  assert.deepEqual(parsed, {
    uploadId: 'up-123',
    uploadUrl: 'https://kb.example/uploads/direct/up-123/tok',
  });
  assert.deepEqual(
    parseStartUpload(
      '- **upload_id**: `up-456`\n- **upload_url**: <https://kb.example/uploads/direct/up-456/tok2>',
    ),
    {
      uploadId: 'up-456',
      uploadUrl: 'https://kb.example/uploads/direct/up-456/tok2',
    },
  );
  assert.deepEqual(
    parseStartUpload(
      JSON.stringify({
        upload_id: 'up-789',
        upload_url: 'https://kb.example/uploads/direct/up-789/tok3',
      }),
    ),
    {
      uploadId: 'up-789',
      uploadUrl: 'https://kb.example/uploads/direct/up-789/tok3',
    },
  );
  assert.equal(parseStartUpload('upload_id: up-123 only'), undefined);
  assert.equal(parseStartUpload(''), undefined);
});

test('validateUploadUrl only allows the configured server origin without credentials', () => {
  const server = new URL('https://kb.invinite.app/mcp');
  assert.equal(
    validateUploadUrl('https://kb.invinite.app/uploads/direct/a/b', server).pathname,
    '/uploads/direct/a/b',
  );
  assert.throws(
    () => validateUploadUrl('https://evil.example/uploads/direct/a/b', server),
    /only uploads to https:\/\/kb\.invinite\.app/,
  );
  assert.throws(
    () => validateUploadUrl('http://kb.invinite.app/uploads/direct/a/b', server),
    /only uploads to https:\/\/kb\.invinite\.app/,
  );
  assert.throws(
    () => validateUploadUrl('https://user:pass@kb.invinite.app/uploads/direct/a/b', server),
    /embedded credentials/,
  );
  assert.throws(() => validateUploadUrl('file:///etc/passwd', server), /unsupported scheme/);
  assert.throws(() => validateUploadUrl('not a url', server), /invalid upload URL/);
});

test('redactUploadUrl strips upload tokens from direct and custom URLs', () => {
  const target = new URL('https://kb.example/uploads/direct/up-1/SECRET_TOKEN_1?sig=SECRET_2');
  const redacted = redactUploadUrl(
    `Fetch failed for ${target.href} (path ${target.pathname})`,
    target,
    target.href,
  );
  assert.ok(!redacted.includes('SECRET_TOKEN_1'), redacted);
  assert.ok(!redacted.includes('SECRET_2'), redacted);
});

test('resolveLocalPath expands leading tilde', () => {
  // Native to the platform: on Windows a rooted path resolves onto the current drive.
  const home = resolve('/home/alice');
  assert.equal(resolveLocalPath('~/Docs/report.pdf', home), join(home, 'Docs', 'report.pdf'));
  assert.equal(resolveLocalPath('~\\Docs\\report.pdf', home), resolve(home, 'Docs\\report.pdf'));
  assert.equal(resolveLocalPath('~', home), home);
});

test('pickerCommand uses fixed system binary paths, never PATH, and activates dialog focus', () => {
  const mac = pickerCommand('darwin');
  assert.equal(mac?.command, '/usr/bin/osascript');
  assert.ok(mac?.args.includes('activate'));

  const win = pickerCommand('win32', { SystemRoot: 'C:\\Windows' });
  assert.equal(win?.command, 'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe');
  assert.equal(win?.base64Output, true);
  assert.match(windowsPickerScript(), /TopMost = \$true/);
  assert.match(windowsPickerScript(), /ShowDialog\(\$f\)/);

  const linux = pickerCommand('linux', {}, (p) => p === '/usr/bin/zenity');
  assert.equal(linux?.command, '/usr/bin/zenity');

  const kde = pickerCommand('linux', {}, (p) => p === '/usr/bin/kdialog');
  assert.equal(kde?.command, '/usr/bin/kdialog');

  const none = pickerCommand('linux', {}, () => false);
  assert.equal(none, undefined);
});

test('pickLocalFile handles base64 paths, cancel exit codes, GTK warnings, display errors, and output caps', async () => {
  const node = process.execPath;

  // 1. Base64-encoded UTF-8 path (Windows mode)
  const expectedPath = '/tmp/Tärkeä sopimus.pdf';
  const b64 = Buffer.from(expectedPath, 'utf8').toString('base64');
  const picked = await pickLocalFile('win32', {}, () => true, {
    command: node,
    args: ['-e', `process.stdout.write(${JSON.stringify(b64)})`],
    base64Output: true,
  });
  assert.equal(picked, expectedPath);

  // 2. macOS AppleScript cancel (-128 on stderr, exit 1)
  const macCancel = await pickLocalFile('darwin', {}, () => true, {
    command: node,
    args: [
      '-e',
      'process.stderr.write("36:91: execution error: User canceled. (-128)\\n"); process.exit(1);',
    ],
    base64Output: false,
  });
  assert.equal(macCancel, undefined);

  // 3. Linux zenity cancel with harmless GTK warning on stderr (exit 1, empty stdout)
  const linuxCancelWithGtkWarn = await pickLocalFile('linux', {}, () => true, {
    command: node,
    args: [
      '-e',
      'process.stderr.write("Gtk-Message: GtkDialog mapped without a transient parent.\\n"); process.exit(1);',
    ],
    base64Output: false,
  });
  assert.equal(linuxCancelWithGtkWarn, undefined);

  // 4. Linux display failure (exit 1 with cannot open display) rejects instead of swallowing as cancel
  await assert.rejects(
    () =>
      pickLocalFile('linux', {}, () => true, {
        command: node,
        args: ['-e', 'process.stderr.write("Cannot open display:\\n"); process.exit(1);'],
        base64Output: false,
      }),
    /Cannot open display/i,
  );

  // 5. Output cap (> 64 KB) rejects
  await assert.rejects(
    () =>
      pickLocalFile('linux', {}, () => true, {
        command: node,
        args: ['-e', 'process.stdout.write("a".repeat(100_000))'],
        base64Output: false,
      }),
    /exceeded maximum length/,
  );
});

test('handleUploadLocalFile refuses missing files, directories, empty files, and picker cancel', async () => {
  const dir = await tempDir();
  const empty = join(dir, 'empty.pdf');
  await writeFile(empty, '');

  const baseCtx = (): UploadContext => ({
    serverUrl: new URL('https://kb.example/mcp'),
    fetch: async () => new Response('unexpected', { status: 500 }),
    log: () => undefined,
    pickFile: async () => undefined,
    callRemoteTool: async () => ({ content: [{ type: 'text', text: '' }] }),
  });

  const cancelled = await handleUploadLocalFile({}, baseCtx());
  assert.equal(cancelled.isError, true);
  assert.match((cancelled.content[0] as { text: string }).text, /cancelled/i);

  const missing = await handleUploadLocalFile({ path: join(dir, 'nope.pdf') }, baseCtx());
  assert.equal(missing.isError, true);
  assert.match((missing.content[0] as { text: string }).text, /not found/i);

  const isDir = await handleUploadLocalFile({ path: dir }, baseCtx());
  assert.equal(isDir.isError, true);
  assert.match((isDir.content[0] as { text: string }).text, /Not a regular file/);

  const isEmpty = await handleUploadLocalFile({ path: empty }, baseCtx());
  assert.equal(isEmpty.isError, true);
  assert.match((isEmpty.content[0] as { text: string }).text, /empty/i);
});

test('handleUploadLocalFile never logs the upload token and rejects cross-origin upload URLs', async () => {
  const dir = await tempDir();
  const pdf = join(dir, 'Secret.pdf');
  await writeFile(pdf, '%PDF-1.7 sample');

  const logs: string[] = [];
  let fetched = false;
  const res = await handleUploadLocalFile(
    { path: pdf },
    {
      serverUrl: new URL('https://kb.example/mcp'),
      fetch: async () => {
        fetched = true;
        return new Response('{}', { status: 200 });
      },
      log: (m) => logs.push(m),
      pickFile: async () => undefined,
      callRemoteTool: async () => ({
        content: [
          {
            type: 'text',
            text: 'upload_id: up-9\nupload_url: https://attacker.example/uploads/direct/up-9/SECRET_TOKEN\n',
          },
        ],
      }),
    },
  );
  assert.equal(res.isError, true);
  assert.equal(fetched, false, 'must not stream to another origin');
  assert.ok(logs.every((l) => !l.includes('SECRET_TOKEN')));
  assert.ok(!(res.content[0] as { text: string }).text.includes('SECRET_TOKEN'));
});

test('handleUploadLocalFile redacts upload URLs from fetch errors and detects mid-setup file size changes', async () => {
  const dir = await tempDir();
  const pdf = join(dir, 'Changing.pdf');
  await writeFile(pdf, '%PDF-1.7 initial content');

  // 1. Fetch rejection whose message contains the full upload URL + token
  const fetchFailed = await handleUploadLocalFile(
    { path: pdf },
    {
      serverUrl: new URL('https://kb.example/mcp'),
      fetch: async (u) => {
        throw new Error(`network failure while PUTting to ${String(u)}`);
      },
      log: () => undefined,
      pickFile: async () => undefined,
      callRemoteTool: async () => ({
        content: [
          {
            type: 'text',
            text: 'upload_id: up-10\nupload_url: https://kb.example/uploads/direct/up-10/TOP_SECRET_TOK\n',
          },
        ],
      }),
    },
  );
  assert.equal(fetchFailed.isError, true);
  const errText = (fetchFailed.content[0] as { text: string }).text;
  assert.ok(!errText.includes('TOP_SECRET_TOK'), errText);

  // 2. File truncated on disk while start_upload is in flight
  const sizeChanged = await handleUploadLocalFile(
    { path: pdf },
    {
      serverUrl: new URL('https://kb.example/mcp'),
      fetch: async () => new Response('{}', { status: 200 }),
      log: () => undefined,
      pickFile: async () => undefined,
      callRemoteTool: async () => {
        await writeFile(pdf, '%PDF');
        return {
          content: [
            {
              type: 'text',
              text: 'upload_id: up-11\nupload_url: https://kb.example/uploads/direct/up-11/tok11\n',
            },
          ],
        };
      },
    },
  );
  assert.equal(sizeChanged.isError, true);
  assert.match((sizeChanged.content[0] as { text: string }).text, /changed size/i);
});

test('parseStartUploadResult prefers structuredContent', () => {
  assert.deepEqual(
    parseStartUploadResult({
      content: [{ type: 'text', text: 'Upload started.' }],
      structuredContent: { upload_id: 'u-1', upload_url: 'https://files.example/put/u-1/t' },
    }),
    { uploadId: 'u-1', uploadUrl: 'https://files.example/put/u-1/t' },
  );
  assert.deepEqual(
    parseStartUploadResult({
      content: [{ type: 'text', text: 'upload_id: u-2\nupload_url: https://files.example/u-2' }],
    }),
    { uploadId: 'u-2', uploadUrl: 'https://files.example/u-2' },
  );
});

test('uploadLocalFileTool follows the server, naming nothing of any one server', () => {
  const plain = uploadLocalFileTool();
  assert.deepEqual(Object.keys(plain.inputSchema.properties ?? {}), ['path']);
  assert.doesNotMatch(JSON.stringify(plain), /add_source|keep|PowerPoint/);

  const tool = uploadLocalFileTool({
    name: 'start_upload',
    description: 'Starts one.',
    inputSchema: {
      type: 'object',
      properties: {
        filename: { type: 'string' },
        bytes: { type: 'integer' },
        path: { type: 'string', description: 'the server would take this' },
        folder: { type: 'string' },
      },
      required: ['filename', 'bytes', 'folder'],
    },
  });
  assert.deepEqual(Object.keys(tool.inputSchema.properties ?? {}).sort(), ['folder', 'path']);
  assert.deepEqual(tool.inputSchema.required, ['folder']);
  assert.match(tool.description ?? '', /Starts one\./);
});

test('redactUploadUrl strips an issued upload URL wherever it is said, whatever its path', () => {
  rememberUploadUrl(new URL('https://files.example/any/shape/SECRET_ISSUED?sig=SIG_ISSUED'));
  const said = redactUploadUrl(
    'PUT https://files.example/any/shape/SECRET_ISSUED?sig=SIG_ISSUED failed',
  );
  assert.ok(!said.includes('SECRET_ISSUED'), said);
  assert.ok(!said.includes('SIG_ISSUED'), said);
});

test('handleUploadLocalFile passes on structuredContent.next alone when the server gives it', async () => {
  const dir = await tempDir();
  const file = join(dir, 'a.bin');
  await writeFile(file, 'abc');
  const res = await handleUploadLocalFile(
    { path: file },
    {
      serverUrl: new URL('https://srv.example/mcp'),
      fetch: async () => new Response('', { status: 200 }),
      log: () => undefined,
      pickFile: async () => undefined,
      callRemoteTool: async () => ({
        content: [{ type: 'text', text: 'PUT it with curl -T to https://srv.example/u/1/TOK' }],
        structuredContent: {
          upload_id: 'u-1',
          upload_url: 'https://srv.example/u/1/TOK',
          next: 'Then call store_it with upload_id u-1.',
        },
      }),
    },
  );
  const said = (res.content[0] as { text: string }).text;
  assert.notEqual(res.isError, true, said);
  assert.match(said, /upload_id: u-1/);
  assert.match(said, /Then call store_it/);
  assert.doesNotMatch(said, /curl|TOK/);
});
