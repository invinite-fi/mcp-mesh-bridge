#!/usr/bin/env node
import { main } from './cli.js';

main().then(
  (code) => process.exit(code),
  (e: unknown) => {
    process.stderr.write(`[mcp-mesh-bridge] ${e instanceof Error ? e.message : String(e)}\n`);
    process.exit(1);
  },
);
