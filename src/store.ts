// Where the bridge keeps what a server gave it: its client registration and
// its tokens, one entry per server URL.
//
// - macOS: the entry in a file, encrypted with AES-256-GCM under a random key
//   kept in the login Keychain. Only the 64-character key goes through
//   `security`, whose interactive mode cuts longer lines.
// - Windows: the entry in a file, encrypted with DPAPI for the current user.
// - Elsewhere: the entry in a file only its owner can read.
//
// Files are written to a temporary name and renamed into place, so a crash
// leaves the old entry or the new one, never half of one. A secret never goes
// on a command line, where other processes could read it.
import { spawn } from 'node:child_process';
import { createCipheriv, createDecipheriv, createHash, randomBytes } from 'node:crypto';
import { chmod, mkdir, readFile, rename, rm, writeFile } from 'node:fs/promises';
import { homedir } from 'node:os';
import { join, win32 } from 'node:path';

export type SecretStore = {
  /** Where entries are kept, for messages. */
  readonly where: string;
  read: (key: string) => Promise<string | undefined>;
  write: (key: string, value: string) => Promise<void>;
  /** Whether there was anything to remove. */
  remove: (key: string) => Promise<boolean>;
};

const NAME = 'mcp-mesh-bridge';

/** The entry key for a server URL: a hash, so no URL reaches a file name or a command. */
export const keyFor = (serverUrl: string): string =>
  createHash('sha256').update(serverUrl).digest('hex').slice(0, 32);

type Run = (
  command: string,
  args: string[],
  input?: string,
) => Promise<{ code: number; stdout: string; stderr: string }>;

/** Run a command, optionally writing `input` to its stdin. */
export const run: Run = (command, args, input) =>
  new Promise((resolve, reject) => {
    const child = spawn(command, args, { stdio: ['pipe', 'pipe', 'pipe'], windowsHide: true });
    let stdout = '';
    let stderr = '';
    child.stdout.on('data', (d: Buffer) => (stdout += d.toString('utf8')));
    child.stderr.on('data', (d: Buffer) => (stderr += d.toString('utf8')));
    child.on('error', reject);
    child.on('close', (code) => resolve({ code: code ?? -1, stdout, stderr }));
    child.stdin.end(input ?? '');
  });

// --- Files --------------------------------------------------------------------

const isMissing = (e: unknown) => (e as NodeJS.ErrnoException | undefined)?.code === 'ENOENT';

/** A file's text, or undefined when there is no such file; any other failure is an error. */
export const readIfThere = async (path: string): Promise<string | undefined> => {
  try {
    return await readFile(path, 'utf8');
  } catch (e) {
    if (isMissing(e)) return undefined;
    throw e;
  }
};

/** Write `name` in `dir` whole or not at all, readable by its owner only. */
export const writeAtomic = async (dir: string, name: string, data: string): Promise<void> => {
  await mkdir(dir, { recursive: true, mode: 0o700 });
  await chmod(dir, 0o700);
  const temp = join(dir, `.${name}.${randomBytes(6).toString('hex')}.tmp`);
  try {
    await writeFile(temp, data, { encoding: 'utf8', mode: 0o600 });
    await chmod(temp, 0o600);
    await rename(temp, join(dir, name));
  } catch (e) {
    await rm(temp, { force: true });
    throw e;
  }
};

/** Remove a file; whether it was there. */
const removeIfThere = async (path: string): Promise<boolean> => {
  try {
    await rm(path);
    return true;
  } catch (e) {
    if (isMissing(e)) return false;
    throw e;
  }
};

export const fileStore = (
  dir = join(process.env.XDG_CONFIG_HOME ?? join(homedir(), '.config'), NAME),
): SecretStore => ({
  where: `${dir}, readable by its owner only`,
  read: (key) => readIfThere(join(dir, `${key}.json`)),
  write: (key, value) => writeAtomic(dir, `${key}.json`, value),
  remove: (key) => removeIfThere(join(dir, `${key}.json`)),
});

// --- macOS: AES-256-GCM, its key in the Keychain ------------------------------

const SECURITY = '/usr/bin/security';
/** `security` exits so when an item is not in the keychain. */
const NOT_FOUND = 44;

/** Seal `plain` under `key`, bound to the entry's name so files cannot be swapped. */
export const seal = (key: Buffer, entry: string, plain: string): string => {
  const iv = randomBytes(12);
  const cipher = createCipheriv('aes-256-gcm', key, iv);
  cipher.setAAD(Buffer.from(entry, 'utf8'));
  const data = Buffer.concat([cipher.update(plain, 'utf8'), cipher.final()]);
  return JSON.stringify({
    v: 1,
    iv: iv.toString('base64'),
    tag: cipher.getAuthTag().toString('base64'),
    data: data.toString('base64'),
  });
};

export const unseal = (key: Buffer, entry: string, sealed: string): string => {
  const s = JSON.parse(sealed) as { v?: number; iv?: string; tag?: string; data?: string };
  if (s.v !== 1 || !s.iv || !s.tag || !s.data)
    throw new Error('the entry is not one this bridge wrote');
  const decipher = createDecipheriv('aes-256-gcm', key, Buffer.from(s.iv, 'base64'));
  decipher.setAAD(Buffer.from(entry, 'utf8'));
  decipher.setAuthTag(Buffer.from(s.tag, 'base64'));
  return Buffer.concat([decipher.update(Buffer.from(s.data, 'base64')), decipher.final()]).toString(
    'utf8',
  );
};

/** The arguments that read an entry's key; it is printed to stdout. */
export const keychainReadArgs = (key: string, keychain?: string): string[] => [
  'find-generic-password',
  '-s',
  NAME,
  '-a',
  key,
  '-w',
  ...(keychain ? [keychain] : []),
];

/** The arguments that delete an entry's key. */
export const keychainRemoveArgs = (key: string, keychain?: string): string[] => [
  'delete-generic-password',
  '-s',
  NAME,
  '-a',
  key,
  ...(keychain ? [keychain] : []),
];

/** The command `security -i` reads from stdin to add or update an entry's key. */
export const keychainWriteCommand = (key: string, hex: string, keychain?: string): string =>
  `add-generic-password -U -s ${NAME} -a ${key} -w ${hex}${keychain ? ` ${keychain}` : ''}\n`;

export type KeychainOptions = {
  /** Where the encrypted entries go. */
  dir?: string;
  /** A keychain file to use instead of the login keychain; no spaces, as `security -i` splits at them. */
  keychain?: string;
  exec?: Run;
};

export const keychainStore = (opts: KeychainOptions = {}): SecretStore => {
  if (opts.keychain && /\s/.test(opts.keychain)) {
    throw new Error(`a keychain path with a space cannot be used: ${opts.keychain}`);
  }
  const dir = opts.dir ?? join(homedir(), 'Library', 'Application Support', NAME);
  const exec = opts.exec ?? run;
  const path = (key: string) => join(dir, `${key}.enc`);

  const readKey = async (key: string): Promise<Buffer | undefined> => {
    const r = await exec(SECURITY, keychainReadArgs(key, opts.keychain));
    if (r.code === NOT_FOUND) return undefined;
    if (r.code !== 0) throw new Error(`the Keychain could not be read (exit ${r.code})`);
    const hex = r.stdout.trim();
    if (!/^[0-9a-f]{64}$/.test(hex)) throw new Error('the Keychain holds no usable key for it');
    return Buffer.from(hex, 'hex');
  };

  return {
    where: `${dir}, encrypted with a key in the macOS Keychain`,
    read: async (key) => {
      const sealed = await readIfThere(path(key));
      if (sealed === undefined) return undefined;
      const k = await readKey(key);
      if (!k) throw new Error('the key for the stored sign-in is missing from the Keychain');
      return unseal(k, key, sealed);
    },
    write: async (key, value) => {
      let k = await readKey(key).catch(() => undefined);
      if (!k) {
        k = randomBytes(32);
        const r = await exec(
          SECURITY,
          ['-i'],
          keychainWriteCommand(key, k.toString('hex'), opts.keychain),
        );
        // `security -i` reports a failed command on stderr but exits 0.
        if (r.code !== 0 || r.stderr.trim() !== '') {
          throw new Error(`the Keychain could not be written (exit ${r.code})`);
        }
      }
      await writeAtomic(dir, `${key}.enc`, seal(k, key, value));
    },
    remove: async (key) => {
      const had = await removeIfThere(path(key));
      const r = await exec(SECURITY, keychainRemoveArgs(key, opts.keychain));
      if (r.code !== 0 && r.code !== NOT_FOUND) {
        throw new Error(`the Keychain entry could not be removed (exit ${r.code})`);
      }
      return had || r.code === 0;
    },
  };
};

// --- Windows: DPAPI, through Windows PowerShell -------------------------------

/** Windows PowerShell by its full path, so no other `powershell.exe` on PATH is run. */
export const powershellPath = (env: NodeJS.ProcessEnv = process.env): string =>
  win32.join(
    env.SystemRoot ?? 'C:\\Windows',
    'System32',
    'WindowsPowerShell',
    'v1.0',
    'powershell.exe',
  );

/**
 * A PowerShell script that reads base64 from stdin, protects or unprotects it
 * with DPAPI for the current user, and writes base64 to stdout. Base64 both
 * ways keeps console encodings out of it.
 */
export const dpapiScript = (direction: 'Protect' | 'Unprotect'): string =>
  [
    'Add-Type -AssemblyName System.Security',
    '$in = [Console]::In.ReadToEnd().Trim()',
    '$bytes = [Convert]::FromBase64String($in)',
    `$out = [Security.Cryptography.ProtectedData]::${direction}($bytes, $null, [Security.Cryptography.DataProtectionScope]::CurrentUser)`,
    '[Console]::Out.Write([Convert]::ToBase64String($out))',
  ].join('; ');

export const dpapiArgs = (direction: 'Protect' | 'Unprotect'): string[] => [
  '-NoProfile',
  '-NonInteractive',
  '-Command',
  dpapiScript(direction),
];

export const dpapiStore = (
  dir = join(process.env.APPDATA ?? join(homedir(), 'AppData', 'Roaming'), NAME),
  exec: Run = run,
): SecretStore => {
  const path = (key: string) => join(dir, `${key}.dat`);
  const dpapi = async (direction: 'Protect' | 'Unprotect', base64: string) => {
    const r = await exec(powershellPath(), dpapiArgs(direction), base64);
    if (r.code !== 0)
      throw new Error(`DPAPI could not ${direction.toLowerCase()} (exit ${r.code})`);
    return r.stdout.trim();
  };
  return {
    where: `${dir}, encrypted for the current Windows user`,
    read: async (key) => {
      const sealed = await readIfThere(path(key));
      if (sealed === undefined) return undefined;
      return Buffer.from(await dpapi('Unprotect', sealed.trim()), 'base64').toString('utf8');
    },
    write: async (key, value) => {
      const sealed = await dpapi('Protect', Buffer.from(value, 'utf8').toString('base64'));
      await writeAtomic(dir, `${key}.dat`, sealed);
    },
    remove: (key) => removeIfThere(path(key)),
  };
};

/** The store for this platform. */
export const platformStore = (): SecretStore => {
  if (process.platform === 'darwin') return keychainStore();
  if (process.platform === 'win32') return dpapiStore();
  return fileStore();
};
