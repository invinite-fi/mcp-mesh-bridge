// The loopback port the sign-in returns to. Derived from the server URL so it
// stays the same across runs: a server that registered the bridge's redirect
// URI keeps accepting it.
const LOW = 3335;
const HIGH = 49150;

/** A stable port for a server URL, between 3335 and 49150. */
export const portFor = (url: string): number => {
  // FNV-1a, 32 bits.
  let hash = 0x811c9dc5;
  for (const byte of new TextEncoder().encode(url)) {
    hash ^= byte;
    hash = Math.imul(hash, 0x01000193) >>> 0;
  }
  return LOW + (hash % (HIGH - LOW));
};
