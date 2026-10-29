// Where the bridge keeps what a server gave it: its client registration and
// its tokens, one entry per server URL. The macOS Keychain, Windows DPAPI for
// the current user, or a file only its owner can read. A secret never goes
// on a command line, where other processes could read it.
import { spawn } from 'node:child_process';
import { createHash } from 'node:crypto';
import { mkdir, readFile, rm, writeFile } from 'node:fs/promises';
import { homedir } from 'node:os';
import { join } from 'node:path';

export type SecretStore = {
  /** Where entries are kept, for messages. */
  readonly where: string;
  read: (key: string) => Promise<string | undefined>;
  write: (key: string, value: string) => Promise<void>;
  remove: (key: string) => Promise<void>;
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

// --- macOS Keychain, through /usr/bin/security -------------------------------

const SECURITY = '/usr/bin/security';
/** `security` exits so when an item is not in the keychain. */
const NOT_FOUND = 44;

/** The arguments that read an entry; the password is printed to stdout. */
export const keychainReadArgs = (key: string): string[] => [
  'find-generic-password',
  '-s',
  NAME,
  '-a',
  key,
  '-w',
];

/** The arguments that delete an entry. */
export const keychainRemoveArgs = (key: string): string[] => [
  'delete-generic-password',
  '-s',
  NAME,
  '-a',
  key,
];

/**
 * The command `security -i` reads from stdin to add or update an entry. The
 * value travels as hex (`-X`), so it needs no quoting and stays off argv.
 */
export const keychainWriteCommand = (key: string, value: string): string =>
  `add-generic-password -U -s ${NAME} -a ${key} -X ${Buffer.from(value, 'utf8').toString('hex')}\n`;

export const keychainStore = (exec: Run = run): SecretStore => ({
  where: 'the macOS Keychain',
  read: async (key) => {
    const r = await exec(SECURITY, keychainReadArgs(key));
    if (r.code === NOT_FOUND) return undefined;
    if (r.code !== 0) throw new Error(`the Keychain could not be read (exit ${r.code})`);
    return r.stdout.replace(/\n$/, '');
  },
  write: async (key, value) => {
    const r = await exec(SECURITY, ['-i'], keychainWriteCommand(key, value));
    // `security -i` reports a failed command on stderr but exits 0.
    if (r.code !== 0 || r.stderr.trim() !== '') {
      throw new Error(`the Keychain could not be written (exit ${r.code})`);
    }
  },
  remove: async (key) => {
    const r = await exec(SECURITY, keychainRemoveArgs(key));
    if (r.code !== 0 && r.code !== NOT_FOUND) {
      throw new Error(`the Keychain entry could not be removed (exit ${r.code})`);
    }
  },
});

// --- Windows DPAPI, through Windows PowerShell -------------------------------

const POWERSHELL = 'powershell.exe';

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

const dpapi = async (exec: Run, direction: 'Protect' | 'Unprotect', base64: string) => {
  const r = await exec(POWERSHELL, dpapiArgs(direction), base64);
  if (r.code !== 0) throw new Error(`DPAPI could not ${direction.toLowerCase()} (exit ${r.code})`);
  return r.stdout.trim();
};

export const dpapiStore = (
  dir = join(process.env.APPDATA ?? join(homedir(), 'AppData', 'Roaming'), NAME),
  exec: Run = run,
): SecretStore => {
  const path = (key: string) => join(dir, `${key}.dat`);
  return {
    where: `${dir}, encrypted for the current Windows user`,
    read: async (key) => {
      let sealed: string;
      try {
        sealed = (await readFile(path(key), 'utf8')).trim();
      } catch {
        return undefined;
      }
      const plain = await dpapi(exec, 'Unprotect', sealed);
      return Buffer.from(plain, 'base64').toString('utf8');
    },
    write: async (key, value) => {
      const sealed = await dpapi(exec, 'Protect', Buffer.from(value, 'utf8').toString('base64'));
      await mkdir(dir, { recursive: true });
      await writeFile(path(key), sealed, 'utf8');
    },
    remove: async (key) => {
      await rm(path(key), { force: true });
    },
  };
};

// --- A file only its owner can read ------------------------------------------

export const fileStore = (
  dir = join(process.env.XDG_CONFIG_HOME ?? join(homedir(), '.config'), NAME),
): SecretStore => {
  const path = (key: string) => join(dir, `${key}.json`);
  return {
    where: `${dir}, readable by its owner only`,
    read: async (key) => {
      try {
        return await readFile(path(key), 'utf8');
      } catch {
        return undefined;
      }
    },
    write: async (key, value) => {
      await mkdir(dir, { recursive: true, mode: 0o700 });
      await writeFile(path(key), value, { encoding: 'utf8', mode: 0o600 });
    },
    remove: async (key) => {
      await rm(path(key), { force: true });
    },
  };
};

/** The store for this platform. */
export const platformStore = (): SecretStore => {
  if (process.platform === 'darwin') return keychainStore();
  if (process.platform === 'win32') return dpapiStore();
  return fileStore();
};
