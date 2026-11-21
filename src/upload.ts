// Local file upload helper for servers that advertise `start_upload`.
//
// Lets Claude Desktop stream a binary file from the user's machine straight to
// the configured server's single-use upload URL without passing file bytes
// through the LLM conversation. Only ever sends to the configured server's own
// origin, never follows redirects, and launches native file pickers only by
// fixed system binary paths (never via PATH).
import { spawn } from 'node:child_process';
import { constants, existsSync } from 'node:fs';
import { open, type FileHandle } from 'node:fs/promises';
import { homedir } from 'node:os';
import { basename, resolve } from 'node:path';
import { Readable } from 'node:stream';
import type { FetchLike } from '@modelcontextprotocol/sdk/shared/transport.js';
import type { CallToolResult, Tool } from '@modelcontextprotocol/sdk/types.js';
import { clip } from './http.js';
import { powershellPath } from './store.js';

export const UPLOAD_TOOL_NAME = 'upload_local_file';
export const REMOTE_START_UPLOAD = 'start_upload';

/** How long the user has to choose a file in the OS picker dialog. */
const PICKER_TIMEOUT_MS = 5 * 60_000;
/** Maximum stdout/stderr bytes buffered from the native file picker process. */
const MAX_PICKER_OUTPUT = 64 * 1024;

/**
 * The `_meta` key a server may set on its `start_upload` to say it implements
 * this upload flow, whatever its schema: `{ "version": 1 }`.
 */
export const UPLOAD_META_KEY = 'fi.invinite/mcp-mesh-bridge-upload';
/** The version of the upload flow this bridge speaks. */
export const UPLOAD_META_VERSION = 1;

const typeIs = (property: unknown, ...types: string[]): boolean => {
  const t = (property as { type?: unknown } | undefined)?.type;
  return Array.isArray(t)
    ? t.some((x) => typeof x === 'string' && types.includes(x))
    : typeof t === 'string' && types.includes(t);
};

/**
 * Whether `tool` is a `start_upload` the bridge can drive: named so, and either
 * marked in its `_meta` with a version of the flow the bridge speaks, or
 * taking a string `filename` and a numeric `bytes`. A tool of that name for
 * something else gets no `upload_local_file`.
 */
export const isUploadStart = (tool: Tool | undefined): boolean => {
  if (!tool || typeof tool !== 'object' || tool.name !== REMOTE_START_UPLOAD) return false;
  const marker = (tool._meta as Record<string, unknown> | undefined)?.[UPLOAD_META_KEY];
  if (marker !== undefined) {
    return (marker as { version?: unknown } | null)?.version === UPLOAD_META_VERSION;
  }
  const props = (tool.inputSchema as { properties?: Record<string, unknown> } | undefined)
    ?.properties;
  return typeIs(props?.filename, 'string') && typeIs(props?.bytes, 'integer', 'number');
};

/** What the bridge itself fills in of `start_upload`'s arguments, from the file. */
const BRIDGE_START_ARGS = new Set(['filename', 'bytes']);
/** The bridge's own argument, never passed on to `start_upload`. */
const PATH_ARG = 'path';

const PATH_PROPERTY = {
  type: 'string',
  description:
    'Path to a local file on this machine (a leading `~` expands to the home folder). ' +
    'Omit to open the system file picker.',
};

const UPLOAD_DESCRIPTION =
  'Upload a file from this machine straight to the server, without passing its bytes through ' +
  "the chat. Omit `path` to open the system's file picker so the user can choose a file, or pass " +
  "a local file path. Returns the server's `upload_id` and what the server says to do with it.";

/**
 * `upload_local_file` for a server whose `start_upload` is `start`: `path`, and
 * every argument of `start_upload` but the `filename` and `bytes` the bridge
 * fills in, passed on as given.
 */
export const uploadLocalFileTool = (start?: Tool): Tool => {
  const schema = start?.inputSchema as
    { properties?: Record<string, unknown>; required?: unknown } | undefined;
  const extra = Object.fromEntries(
    Object.entries(schema?.properties ?? {}).filter(
      ([k]) => !BRIDGE_START_ARGS.has(k) && k !== PATH_ARG,
    ),
  );
  const required = (Array.isArray(schema?.required) ? schema.required : []).filter(
    (k): k is string => typeof k === 'string' && !BRIDGE_START_ARGS.has(k) && k !== PATH_ARG,
  );
  const about = start?.description?.trim();
  return {
    name: UPLOAD_TOOL_NAME,
    description: about
      ? `${UPLOAD_DESCRIPTION}\n\nThe server's ${REMOTE_START_UPLOAD}, which this calls: ${about}`
      : UPLOAD_DESCRIPTION,
    inputSchema: {
      type: 'object',
      properties: { ...extra, [PATH_ARG]: PATH_PROPERTY },
      ...(required.length > 0 ? { required } : {}),
    },
    annotations: {
      readOnlyHint: false,
      destructiveHint: false,
      openWorldHint: false,
    },
  };
};

/** `upload_local_file` before the server's `start_upload` is known. */
export const UPLOAD_LOCAL_FILE_TOOL: Tool = uploadLocalFileTool();

export type StartUploadResult = {
  uploadId: string;
  uploadUrl: string;
};

const cleanFieldValue = (raw: string): string =>
  raw
    .trim()
    .replace(/^[`"'<]+|[`"'>]+$/g, '')
    .trim();

const fromFields = (json: Record<string, unknown>): StartUploadResult | undefined => {
  const field = (snake: string, camel: string): string =>
    typeof json[snake] === 'string'
      ? cleanFieldValue(json[snake])
      : typeof json[camel] === 'string'
        ? cleanFieldValue(json[camel])
        : '';
  const id = field('upload_id', 'uploadId');
  const url = field('upload_url', 'uploadUrl');
  return id && url && !/\s/.test(id) && !/\s/.test(url)
    ? { uploadId: id, uploadUrl: url }
    : undefined;
};

/**
 * The upload a `start_upload` result names: its `structuredContent`, else its
 * text as JSON or as `upload_id:` and `upload_url:` lines.
 */
export const parseStartUploadResult = (res: CallToolResult): StartUploadResult | undefined => {
  const structured = res.structuredContent;
  if (structured && typeof structured === 'object') {
    const found = fromFields(structured);
    if (found) return found;
  }
  return parseStartUpload(textFromResult(res));
};

/** Parse `upload_id:` and `upload_url:` lines (or JSON) returned by the remote `start_upload` tool. */
export const parseStartUpload = (text: string): StartUploadResult | undefined => {
  const trimmed = text.trim();
  if (trimmed.startsWith('{')) {
    try {
      const found = fromFields(JSON.parse(trimmed) as Record<string, unknown>);
      if (found) return found;
    } catch {
      // Fall through to line-by-line parsing.
    }
  }
  let uploadId: string | undefined;
  let uploadUrl: string | undefined;
  for (const raw of text.split(/\r?\n/)) {
    const line = raw.trim().replace(/^[-*•]\s+/, '');
    const match = /^\*{0,2}upload_(id|url)\*{0,2}\s*:\s*(.+)$/i.exec(line);
    if (!match) continue;
    const kind = match[1]?.toLowerCase();
    const value = cleanFieldValue(match[2] ?? '');
    if (!value || /\s/.test(value)) continue;
    if (kind === 'id' && !uploadId) {
      uploadId = value;
    } else if (kind === 'url' && !uploadUrl) {
      uploadUrl = value;
    }
  }
  return uploadId && uploadUrl ? { uploadId, uploadUrl } : undefined;
};

/**
 * Verify that `uploadUrl` points strictly at the configured server's own origin
 * so a remote server can never redirect local file bytes to a third party.
 */
export const validateUploadUrl = (uploadUrl: string, serverUrl: URL): URL => {
  let parsed: URL;
  try {
    parsed = new URL(uploadUrl);
  } catch {
    throw new Error('the server returned an invalid upload URL');
  }
  if (parsed.protocol !== 'https:' && parsed.protocol !== 'http:') {
    throw new Error(`refused upload URL with unsupported scheme ${parsed.protocol}`);
  }
  if (parsed.username || parsed.password) {
    throw new Error('refused upload URL with embedded credentials');
  }
  if (parsed.origin !== serverUrl.origin) {
    throw new Error(
      `refused upload URL on ${parsed.origin}: the bridge only uploads to ${serverUrl.origin}`,
    );
  }
  return parsed;
};

/** Upload URLs servers issued lately, redacted from whatever the bridge says. */
const issued: URL[] = [];
const MAX_ISSUED = 32;

/** Remember an upload URL a server issued, so that no message passes it on. */
export const rememberUploadUrl = (url: URL): void => {
  issued.push(url);
  if (issued.length > MAX_ISSUED) issued.shift();
};

const redactTarget = (text: string, target: URL): string => {
  let out = text.split(target.href).join(`${target.origin}/<redacted-upload-url>`);
  if (target.search.length > 1) {
    out = out.split(target.search).join('?<redacted>');
  }
  if (target.hash.length > 1) {
    out = out.split(target.hash).join('#<redacted>');
  }
  if (target.pathname.length > 1) {
    out = out.split(target.pathname).join('/<redacted-upload-path>');
  }
  return out;
};

/** Strip any single-use upload URL or path token from an error message or log line. */
export const redactUploadUrl = (text: string, target?: URL, rawUrl?: string): string => {
  let out = text;
  if (rawUrl) {
    out = out
      .split(rawUrl)
      .join(target ? `${target.origin}/<redacted-upload-url>` : '<redacted-upload-url>');
  }
  for (const url of target ? [target, ...issued] : issued) {
    out = redactTarget(out, url);
  }
  return out;
};

/** Expand a leading `~` or `~/` (or `~\` on Windows) against `home`, then resolve. */
export const resolveLocalPath = (input: string, home: string = homedir()): string => {
  const trimmed = input.trim();
  if (trimmed === '~') return resolve(home);
  if (trimmed.startsWith('~/') || trimmed.startsWith('~\\')) {
    return resolve(home, trimmed.slice(2));
  }
  return resolve(trimmed);
};

/** PowerShell script for a Windows file picker, returning the chosen UTF-8 path as base64. */
export const windowsPickerScript = (): string =>
  [
    'Add-Type -AssemblyName System.Windows.Forms',
    '$f = New-Object System.Windows.Forms.Form',
    '$f.TopMost = $true',
    '$d = New-Object System.Windows.Forms.OpenFileDialog',
    '$d.Title = "Choose a file to upload"',
    '$d.CheckFileExists = $true',
    '$d.Multiselect = $false',
    'try {',
    '  if ($d.ShowDialog($f) -eq [System.Windows.Forms.DialogResult]::OK) {',
    '    [Console]::Out.Write([Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($d.FileName)))',
    '  }',
    '} finally {',
    '  $d.Dispose()',
    '  $f.Dispose()',
    '}',
  ].join('; ');

export type PickerCommand = {
  command: string;
  args: string[];
  base64Output: boolean;
};

/** Native OS file picker using a fixed system binary path, never PATH lookup. */
export const pickerCommand = (
  platform: NodeJS.Platform = process.platform,
  env: NodeJS.ProcessEnv = process.env,
  exists: (p: string) => boolean = existsSync,
): PickerCommand | undefined => {
  if (platform === 'darwin') {
    return {
      command: '/usr/bin/osascript',
      args: [
        '-e',
        'activate',
        '-e',
        'POSIX path of (choose file with prompt "Choose a file to upload")',
      ],
      base64Output: false,
    };
  }
  if (platform === 'win32') {
    return {
      command: powershellPath(env),
      args: ['-NoProfile', '-NonInteractive', '-STA', '-Command', windowsPickerScript()],
      base64Output: true,
    };
  }
  const zenity = ['/usr/bin/zenity', '/usr/local/bin/zenity'].find((p) => exists(p));
  if (zenity) {
    return {
      command: zenity,
      args: ['--file-selection', '--title=Choose a file to upload'],
      base64Output: false,
    };
  }
  const kdialog = ['/usr/bin/kdialog', '/usr/local/bin/kdialog'].find((p) => exists(p));
  if (kdialog) {
    return {
      command: kdialog,
      args: ['--getopenfilename', homedir(), '--title', 'Choose a file to upload'],
      base64Output: false,
    };
  }
  return undefined;
};

const isLinuxDisplayFailure = (stderr: string): boolean =>
  /cannot open display|could not connect to display|unable to init server|no display/i.test(stderr);

/** Open the native OS file picker and return the chosen path, or `undefined` if cancelled. */
export const pickLocalFile = async (
  platform: NodeJS.Platform = process.platform,
  env: NodeJS.ProcessEnv = process.env,
  exists: (p: string) => boolean = existsSync,
  specOverride?: PickerCommand,
): Promise<string | undefined> => {
  const spec = specOverride ?? pickerCommand(platform, env, exists);
  if (!spec) {
    throw new Error('no system file picker is available here; pass `path` explicitly instead');
  }
  return new Promise((resolvePromise, rejectPromise) => {
    const child = spawn(spec.command, spec.args, {
      stdio: ['ignore', 'pipe', 'pipe'],
      windowsHide: true,
    });
    const out: Buffer[] = [];
    const err: Buffer[] = [];
    let outBytes = 0;
    let errBytes = 0;
    let settled = false;
    const finish = (fn: () => void) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      fn();
    };
    const timer = setTimeout(() => {
      child.kill();
      finish(() => rejectPromise(new Error('file picker timed out')));
    }, PICKER_TIMEOUT_MS);
    timer.unref();

    child.stdout.on('data', (c: Buffer) => {
      outBytes += c.byteLength;
      if (outBytes > MAX_PICKER_OUTPUT) {
        child.kill();
        finish(() => rejectPromise(new Error('file picker output exceeded maximum length')));
        return;
      }
      out.push(c);
    });
    child.stderr.on('data', (c: Buffer) => {
      if (errBytes < MAX_PICKER_OUTPUT) {
        const slice = c.subarray(0, MAX_PICKER_OUTPUT - errBytes);
        err.push(slice);
        errBytes += slice.byteLength;
      }
    });
    child.on('error', (e) => finish(() => rejectPromise(e)));
    child.on('close', (code) => {
      finish(() => {
        const stdout = Buffer.concat(out).toString('utf8').trim();
        const stderr = Buffer.concat(err).toString('utf8').trim();
        if (code !== 0) {
          // macOS AppleScript returns exit 1 with -128 when the user clicks Cancel;
          // zenity/kdialog return exit 1 on Cancel (sometimes with harmless GTK/Qt stderr warnings).
          const macCancelled =
            stderr.includes('-128') || stderr.toLowerCase().includes('user canceled');
          const linuxCancelled =
            platform !== 'darwin' &&
            code === 1 &&
            stdout === '' &&
            (stderr === '' || !isLinuxDisplayFailure(stderr));
          if (macCancelled || linuxCancelled) {
            resolvePromise(undefined);
            return;
          }
          rejectPromise(new Error(clip(stderr || `file picker exited with code ${String(code)}`)));
          return;
        }
        if (!stdout) {
          resolvePromise(undefined);
          return;
        }
        const chosen = spec.base64Output
          ? Buffer.from(stdout, 'base64').toString('utf8').trim()
          : stdout;
        resolvePromise(chosen || undefined);
      });
    });
  });
};

const toolError = (message: string): CallToolResult => ({
  isError: true,
  content: [{ type: 'text', text: message }],
});

const toolText = (message: string): CallToolResult => ({
  content: [{ type: 'text', text: message }],
});

const textFromResult = (res: CallToolResult): string =>
  (Array.isArray(res?.content) ? res.content : [])
    .filter(
      (c): c is { type: 'text'; text: string } =>
        c?.type === 'text' && typeof (c as { text?: unknown }).text === 'string',
    )
    .map((c) => c.text)
    .join('\n');

/**
 * What the server's `start_upload` said to do with the upload: its
 * `structuredContent.next`, else its text less the URL, which the bridge has
 * used and Claude never needs.
 */
const nextStep = (started: CallToolResult, parsed: StartUploadResult, target: URL): string => {
  // A server may say the step after the PUT on its own, as `structuredContent.next`.
  const next = (started.structuredContent as { next?: unknown } | undefined)?.next;
  if (typeof next === 'string' && next.trim()) {
    return clip(redactUploadUrl(next.trim(), target, parsed.uploadUrl), 2000);
  }
  const rest = textFromResult(started)
    .split(/\r?\n/)
    .filter((line) => !/^[-*•\s]*\*{0,2}upload_(id|url)\*{0,2}\s*:/i.test(line.trim()))
    .join('\n')
    .trim();
  const safe = rest.startsWith('{') ? '' : redactUploadUrl(rest, target, parsed.uploadUrl);
  return safe
    ? 'The file has been sent: any instructions below for sending it are done. What the server ' +
        `said when the upload started, for what to do next:\n${clip(safe, 2000)}`
    : `Pass upload_id "${parsed.uploadId}" to the server's tool that takes it.`;
};

export type UploadContext = {
  serverUrl: URL;
  fetch: FetchLike;
  log: (message: string) => void;
  pickFile: () => Promise<string | undefined>;
  callRemoteTool: (name: string, args: Record<string, unknown>) => Promise<CallToolResult>;
};

export const handleUploadLocalFile = async (
  rawArgs: Record<string, unknown> | undefined,
  ctx: UploadContext,
): Promise<CallToolResult> => {
  const pathArg = rawArgs?.path;
  if (pathArg !== undefined && typeof pathArg !== 'string') {
    return toolError('`path` must be a string');
  }

  let localPath: string;
  if (pathArg && pathArg.trim()) {
    localPath = resolveLocalPath(pathArg);
  } else {
    let picked: string | undefined;
    try {
      picked = await ctx.pickFile();
    } catch (e) {
      return toolError(`Could not open file picker: ${(e as Error).message}`);
    }
    if (!picked) {
      return toolError('File selection cancelled.');
    }
    localPath = resolveLocalPath(picked);
  }

  // Open the file handle first and fstat it so the path cannot be swapped
  // between stat and streaming (TOCTOU), and O_NONBLOCK prevents blocking on a FIFO.
  let fh: FileHandle;
  try {
    fh = await open(localPath, constants.O_RDONLY | (constants.O_NONBLOCK ?? 0));
  } catch (e) {
    const code = (e as NodeJS.ErrnoException).code;
    if (code === 'ENOENT') return toolError(`File not found: ${localPath}`);
    if (code === 'EISDIR') return toolError(`Not a regular file: ${localPath}`);
    if (code === 'EACCES' || code === 'EPERM') {
      return toolError(`Permission denied reading: ${localPath}`);
    }
    return toolError(`Cannot read ${localPath}: ${(e as Error).message}`);
  }

  let streamCreated = false;
  try {
    const info = await fh.stat();
    if (!info.isFile()) {
      return toolError(`Not a regular file: ${localPath}`);
    }
    const size = info.size;
    if (size <= 0) {
      return toolError(`File is empty: ${basename(localPath)}`);
    }

    const filename = basename(localPath);
    // The server's own arguments go on as given; the file's name and size are the bridge's.
    const startArgs: Record<string, unknown> = Object.fromEntries(
      Object.entries(rawArgs ?? {}).filter(([k]) => k !== PATH_ARG && !BRIDGE_START_ARGS.has(k)),
    );
    startArgs.filename = filename;
    startArgs.bytes = size;

    let started: CallToolResult;
    try {
      started = await ctx.callRemoteTool(REMOTE_START_UPLOAD, startArgs);
    } catch (e) {
      return toolError(
        `Could not start upload on ${ctx.serverUrl.origin}: ${(e as Error).message}`,
      );
    }
    if (started.isError) {
      return started;
    }

    const parsed = parseStartUploadResult(started);
    if (!parsed) {
      return toolError('The server did not return an upload_id and upload_url from start_upload.');
    }

    let target: URL;
    try {
      target = validateUploadUrl(parsed.uploadUrl, ctx.serverUrl);
    } catch (e) {
      return toolError(redactUploadUrl((e as Error).message, undefined, parsed.uploadUrl));
    }
    rememberUploadUrl(target);

    const currentInfo = await fh.stat();
    if (!currentInfo.isFile() || currentInfo.size !== size) {
      return toolError(
        `File ${filename} changed size while preparing the upload (${size} -> ${currentInfo.size} bytes); please try again.`,
      );
    }

    // Never log `target.href`: it carries a single-use upload token.
    ctx.log(`uploading ${filename} (${size} bytes) to ${ctx.serverUrl.origin}`);

    streamCreated = true;
    const fileStream = fh.createReadStream({ start: 0, end: size - 1, autoClose: true });
    let sent = 0;
    const checkedStream = (Readable.toWeb(fileStream) as ReadableStream<Uint8Array>).pipeThrough(
      new TransformStream<Uint8Array, Uint8Array>({
        transform(chunk, controller) {
          sent += chunk.byteLength;
          if (sent > size) {
            controller.error(new Error(`File ${filename} grew beyond ${size} bytes during upload`));
            return;
          }
          controller.enqueue(chunk);
        },
        flush(controller) {
          if (sent !== size) {
            controller.error(
              new Error(
                `File ${filename} changed size during upload (${sent} of ${size} bytes read)`,
              ),
            );
          }
        },
      }),
    );
    const body = checkedStream as unknown as NonNullable<RequestInit['body']>;
    let response: Response;
    try {
      const init = {
        method: 'PUT',
        body,
        duplex: 'half',
        redirect: 'error',
        headers: {
          'content-length': String(size),
          'content-type': 'application/octet-stream',
        },
      } as RequestInit;
      response = await ctx.fetch(target.href, init);
    } catch (e) {
      const reason = redactUploadUrl((e as Error).message, target, parsed.uploadUrl);
      return toolError(`Upload to ${ctx.serverUrl.origin} failed: ${reason}`);
    } finally {
      if (!fileStream.closed) {
        fileStream.destroy();
        await new Promise<void>((r) => fileStream.once('close', r));
      }
    }

    const responseText = await response.text().catch(() => '');
    if (!response.ok) {
      const safeDetail = responseText
        ? `: ${clip(redactUploadUrl(responseText, target, parsed.uploadUrl), 500)}`
        : '';
      return toolError(
        `${ctx.serverUrl.origin} refused the upload (HTTP ${response.status})${safeDetail}`,
      );
    }

    let state = 'waiting';
    if (responseText) {
      try {
        const json = JSON.parse(responseText) as { state?: unknown; error?: unknown };
        if (typeof json.state === 'string') state = json.state;
        if (json.state === 'failed') {
          const rawReason =
            typeof json.error === 'string' ? json.error : 'the server rejected the file';
          const reason = redactUploadUrl(rawReason, target, parsed.uploadUrl);
          return toolError(`Upload ${parsed.uploadId} failed: ${clip(reason, 500)}`);
        }
      } catch {
        // Non-JSON 2xx answers still mean the PUT succeeded.
      }
    }

    return toolText(
      `Uploaded ${filename} (${size} bytes).\n` +
        `upload_id: ${parsed.uploadId}\n` +
        `state: ${state}\n\n` +
        nextStep(started, parsed, target),
    );
  } finally {
    if (!streamCreated) {
      await fh.close().catch(() => undefined);
    }
  }
};
