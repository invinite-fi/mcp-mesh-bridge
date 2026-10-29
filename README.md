# mcp-mesh-bridge

A Claude Desktop extension that reaches an MCP server on a private network, such as a VPN or a
mesh, and signs you in with OAuth.

## Why

Claude Desktop's connectors call MCP servers from Anthropic's cloud. A server that only your VPN
or mesh can reach is out of their reach.

This bridge runs on your own machine instead. Claude Desktop starts it as a local MCP server. It
passes every message on to the server's streamable-HTTP endpoint, unchanged, and passes the answers
back. Your machine is on the private network, so the server is in reach.

The bridge knows no tools of its own. Whatever the server offers, Claude sees.

## Install

Download the `.mcpb` file from the [latest release](https://github.com/invinite-fi/mcp-mesh-bridge/releases/latest)
and open it. Claude Desktop asks for the server's URL, then installs the extension.

In a Claude Team or Enterprise organisation, an owner can upload the `.mcpb` to the organisation's
allowlist: **Organization settings → Connectors → Desktop**. People then install it from inside
Claude Desktop.

It runs on macOS and Windows. Claude Desktop brings the Node.js it needs.

## Configure

| Setting       | What it is                                                                                     |
| ------------- | ---------------------------------------------------------------------------------------------- |
| Server URL    | The server's streamable-HTTP address, such as `https://mcp.example.internal/mcp`. Required.    |
| Sign-in port  | The port on your machine the browser returns to after signing in. Empty: one chosen per URL.   |
| Client ID     | Only for a server that does not let clients register themselves: the client registered for it. |
| Client secret | Only if that client has a secret. Claude Desktop keeps it in your system's keychain.           |

## Signing in

The first time Claude uses the server, the bridge opens your browser at the server's sign-in. When
you are done, the browser returns to `http://127.0.0.1:<port>/callback` on your own machine, and the
bridge takes over from there.

The bridge finds the server's sign-in itself (OAuth protected resource and authorization server
metadata), registers itself as a client if the server allows it, and uses PKCE. It refreshes the
access token when it expires, so you sign in again only when the server asks you to.

The server must accept a loopback redirect URI (`http://127.0.0.1:<port>/callback`). Most servers
built for MCP clients do.

What the server gives the bridge, its client registration and tokens, is kept per server URL:

- **macOS:** in `~/Library/Application Support/mcp-mesh-bridge/`, encrypted with AES-256-GCM. The
  key is in your login Keychain, under the service name `mcp-mesh-bridge`.
- **Windows:** in `%APPDATA%\mcp-mesh-bridge\`, encrypted with Windows' data protection for your
  user account.
- **Elsewhere:** in `~/.config/mcp-mesh-bridge/`.

Only your user can read these folders and files. The bridge writes a file whole or not at all.

If a stored sign-in can't be read, the bridge says so on stderr and signs you in again.

## Signing out

Forget a server's sign-in with:

```sh
node server/index.mjs https://mcp.example.internal/mcp --logout
```

Run it from the extension's folder, or use `node build/src/main.js` from a clone of this repository.

If the server offers token revocation, the bridge asks it to revoke the sign-in first. It asks only
the sign-in server that issued it, at that server's own address. It then says whether anything was
stored. A bridge still running doesn't store the sign-in again.

## Command line

The bridge also runs outside Claude Desktop:

```text
mcp-mesh-bridge <server-url> [--port <n>] [--client-id <id>] [--login | --logout]
```

- With no option, it relays on stdin and stdout, as Claude Desktop runs it.
- `--login` signs in now and exits.
- `--logout` forgets the server's sign-in and exits.

It writes its own messages to stderr only. Stdout carries MCP.

## A branded build

An organisation can build its own copy, with its own name and its server's URL built in. It asks
nothing at install; the sign-in port is chosen from the URL.

```sh
npm ci
npm run pack:branded -- --name "Example Knowledge" --url https://mcp.example.internal/mcp \
  --out dist/example-knowledge.mcpb
```

Upload that file to your organisation's allowlist. Keep it out of this repository and its releases:
it names your private server.

## Security

- The bridge listens only on `127.0.0.1`, and only while a sign-in is under way.
- It sends nothing anywhere but the server you configure and that server's sign-in.
- It never writes a token to a log, and keeps no secret on a command line.
- It has one runtime dependency, the official MCP TypeScript SDK, bundled into the extension.

**The browser.** The bridge opens a sign-in address only if it is `https:`. It also opens `http:`
when the address is on your own machine, or when the server URL is `http:` itself. It logs where
the sign-in is. It starts the browser with a fixed program: `/usr/bin/open` on macOS,
`rundll32.exe` from Windows' `System32`, or `xdg-open` from a system folder. It never runs a
program found on `PATH`.

**What the Keychain protects.** On macOS the key is a Keychain item that `/usr/bin/security`
created. Any program running as you can read it with that same tool, without asking you. So the
Keychain protects the stored sign-in only from a copy of the file taken elsewhere, such as a backup.
Windows' data protection is the same: any program running as you can decrypt the file.

**Plain http.** An `http:` server URL that isn't on your own machine gets a warning on stderr. The
bridge still allows it, since a mesh network encrypts the traffic itself. Use `https:` anywhere
else.

**Limits.** The bridge refuses an answer over 32 MB, or one event over 32 MB in a stream. It cuts
what the server says to 2 KB before it reaches a log or Claude.

**Releases.** The `.mcpb` in a release isn't signed yet. Signing comes later.

## Development

```sh
npm ci
npm run validate   # typecheck, lint, format check, tests
npm run pack       # dist/mcp-mesh-bridge-<version>.mcpb
```

A `v*` tag that matches `manifest.json`'s version publishes the `.mcpb` as a GitHub release.

## License

MIT. Copyright Invinite Oy.
