# Verdifax MCP server

verdifax-mcp lets an AI assistant work with Verdifax through the Model Context Protocol (MCP). The assistant can read your account's records, sign-offs and signal feed, check saved records with the open-source verifier on your own machine, test a policy without sealing anything, and seal a decision through your policy. It runs on your machines; Verdifax hosts no MCP server.

- **One contract, three languages.** [mcp-tools.json](mcp-tools.json) defines the ten tools. The TypeScript, Python and Go servers in this repository serve exactly those tools, and each language's tests fail when its tools differ.
- **Proof, not judgment.** Verdifax proves which checks ran and what was decided. It does not judge whether a decision is right, fair, safe or lawful, and neither does this server.
- **Status.** Version 0.1.0. It is not yet on npm, PyPI or a GitHub release; until it is, build it from this repository (see [Install](#install)).

## What it does

| Tool | What it does | Changes anything at Verdifax? |
|---|---|---|
| `verify_record` | Runs your installed `verdifax-verify --json` on a saved record or receipt | No. It runs offline |
| `verify_feed` | Runs your installed `verdifax-verify --json --signals` on a saved feed | No. It runs offline |
| `get_record` | Reads one run's sealed bundle | No |
| `list_records` | Lists this key's runs | No |
| `read_feed` | Reads one page of the account's signal feed | No |
| `list_pending_signoffs` | Lists runs whose rule requires a person's sign-off and that have no approval in force, computed on this machine from the whole feed | No |
| `get_signoffs` | Reads the sign-offs on one run | No |
| `test_policy` | Shows which rule would fire on sample inputs (a dry run) | No. The server seals nothing |
| `seal_decision` | Seals one decision through your active policy | **Yes. The only tool that does** |
| `prepare_signoff` | Prints the command a person runs to sign off with their own key | No. It makes no request at all |

## What it never does

- **Never signs off.** A sign-off is a person's decision, signed with a key only that person holds. `prepare_signoff` prints the exact command for the person to run on their own machine; this server signs nothing for them.
- **Never holds owner powers.** At startup it checks `VERDIFAX_API_KEY` on `GET /stats`, a read that seals nothing. An owner key gets the server's documented owner-key error there, and this server then refuses to start. It also refuses to start when `VERDIFAX_OWNER_KEY` is in its environment.
- **Never loads an approver key.** It refuses to start when `VERDIFAX_APPROVER_KEY` or `VERDIFAX_APPROVER_KEY_FILE` is in its environment.
- **Never verifies through Verdifax's server.** The verify tools run the `verdifax-verify` program installed on your machine, offline. This server never calls the server-side check `GET /runs/{id}/verify`, and reading a record is never presented as verification.
- **Never takes a secret as a tool input.** Keys come only from environment variables and key files. No tool's input schema has a key or secret field, and every answer and error passes through a redactor that hides the configured keys and anything shaped like a Verdifax key.
- **Never reads a file outside the working folder.** Every path is relative to `VERDIFAX_MCP_WORKDIR`; a `..` segment, an absolute path or a link that leads outside is refused before the verifier runs.

## How record text is kept from steering the assistant

Records can hold text written by anyone, including text that tries to give the assistant instructions.

- **Quoted fields only.** Record text comes back only inside structured, quoted JSON fields, never as prose from this server.
- **Hidden characters removed.** Control characters, zero-width characters, direction overrides and Unicode tag characters are removed from every string and key; line breaks become spaces. The list is in the contract, so all three languages remove the same characters.
- **A standing notice.** Every answer that carries record data says the strings are data, not instructions.
- **Nothing hidden is sealed.** `seal_decision` refuses any input holding such a character, so what is sealed is what a person can read.

## What seal_decision seals

- **Your policy decides.** The server applies your account's active policy. A refused or halted run gets a sealed receipt, which the answer returns.
- **Signed on this machine.** When `VERDIFAX_REQUEST_KEY_FILE` is set, the request is signed here with signature version 2 over the exact text sent. The key never leaves this machine.
- **The assistant's declared name and version.** They come from the MCP client's own `clientInfo`, are cleaned to printable ASCII of at most 128 bytes each, and are sealed in `attested_context.client_name` and `attested_context.client_version` as caller-declared setup facts. The tool's answer labels them `declared, not verified`. The assistant states them; Verdifax does not check them.
- **A declared data-use basis, when given.** `policy_context.data_use` takes the customer's own short codes for purpose, basis and categories, and an optional keyed reference. Verdifax seals the declaration as made and does not check it.
- **Verifier needed.** Records that carry `client_name`, `client_version` or `data_use` need `verdifax-verify` v0.38.0 or later; older releases refuse such a record instead of passing it.

## Tools the key's owner granted

When the Verdifax server reports a tool list for the member key, in the `X-Verdifax-Allowed-Tools` header of its `GET /stats` answer, this server reads it at startup and tells the assistant which tools were granted. It refuses every other tool that uses the key before any request is sent. When the server reports no list, this server says so and assumes no extra rights: the Verdifax server applies its own limits to every request.

## Install

### Requirements

- **The verifier.** `verdifax-verify` from [its releases](https://github.com/Verdifax/verdifax-verify/releases/latest), on your PATH or named by `VERDIFAX_VERIFY_PATH`. The optional installer below checks it first.
- **One runtime.** Node.js 22 or later, Python 3.11 or later, or Go 1.27 or later. Linux or macOS.

### Build from this repository

1. **TypeScript.** In `typescript/`, run `npm ci && npm run build`. The command is `node /path/to/verdifax-mcp/typescript/dist/main.js`.
2. **Python.** Run `pip install ./python`. The command is `verdifax-mcp`.
3. **Go.** In `go/`, run `go build -o verdifax-mcp ./cmd/verdifax-mcp`. The command is the `verdifax-mcp` binary.

### R users

R has no official MCP toolkit. R users run the Go binary, which needs no R package: once this repository makes releases, each release attaches the Go server for Linux and macOS with a SHA-256 checksum and a Sigstore bundle, signed by [.github/workflows/release.yml](.github/workflows/release.yml). Check a download before running it:

```bash
cosign verify-blob \
  --bundle verdifax-mcp-linux-amd64.bundle \
  --certificate-identity-regexp '^https://github.com/Verdifax/verdifax-mcp/' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  verdifax-mcp-linux-amd64
```

### Optional: install the verifier with both checks

[scripts/install-verifier.sh](scripts/install-verifier.sh) downloads one named verifier release for this machine and installs it only if two checks pass:

1. **SHA-256.** The binary matches the checksum published beside it, which shows the download is whole.
2. **Sigstore.** `cosign` verifies the release's Sigstore bundle, which shows the verifier repository's release workflow signed it.

```bash
scripts/install-verifier.sh <tag of the latest release> "$HOME/.local/bin"
```

## Configure

| Variable | What it is |
|---|---|
| `VERDIFAX_API_KEY` | A member key of the account. An owner key is refused at startup |
| `VERDIFAX_FEED_KEY` | A feed key, for `read_feed` and `list_pending_signoffs` |
| `VERDIFAX_REQUEST_KEY_FILE` | Optional: the member key's request key file (32 raw bytes, 64 hex characters or base64). Refused unless only you can read it (`chmod 600`) |
| `VERDIFAX_MCP_WORKDIR` | The working folder for every file a tool reads |
| `VERDIFAX_VERIFY_PATH` | Optional: the verifier to run, as an absolute path |
| `VERDIFAX_BASE_URL` | Optional: the API address; `https://api.verdifax.com` by default |
| `VERDIFAX_MCP_HTTP_TOKEN` | Optional: a bearer token of 32 characters or more for HTTP mode |

Keep any file that holds these values private and out of version control.

### Claude Code

Add it with the CLI (the `local` and `user` scopes keep the values in `~/.claude.json`):

```bash
claude mcp add --transport stdio --scope user \
  --env VERDIFAX_API_KEY=YOUR_MEMBER_KEY \
  --env VERDIFAX_FEED_KEY=YOUR_FEED_KEY \
  --env VERDIFAX_MCP_WORKDIR=/absolute/path/to/records \
  verdifax -- verdifax-mcp
```

Or share it with a project in `.mcp.json`, which reads the values from your shell's environment so no key is written in the file:

```json
{
  "mcpServers": {
    "verdifax": {
      "command": "verdifax-mcp",
      "env": {
        "VERDIFAX_API_KEY": "${VERDIFAX_API_KEY}",
        "VERDIFAX_FEED_KEY": "${VERDIFAX_FEED_KEY}",
        "VERDIFAX_MCP_WORKDIR": "${VERDIFAX_MCP_WORKDIR}"
      }
    }
  }
}
```

### Claude Desktop

Edit `claude_desktop_config.json` (Settings, then Developer, then Edit Config; on macOS it is in `~/Library/Application Support/Claude/`). Use the absolute path to the command:

```json
{
  "mcpServers": {
    "verdifax": {
      "command": "/absolute/path/to/verdifax-mcp",
      "env": {
        "VERDIFAX_API_KEY": "YOUR_MEMBER_KEY",
        "VERDIFAX_FEED_KEY": "YOUR_FEED_KEY",
        "VERDIFAX_MCP_WORKDIR": "/absolute/path/to/records"
      }
    }
  }
}
```

### Cursor

In `.cursor/mcp.json` for one project, or `~/.cursor/mcp.json` for all:

```json
{
  "mcpServers": {
    "verdifax": {
      "command": "verdifax-mcp",
      "env": {
        "VERDIFAX_API_KEY": "${env:VERDIFAX_API_KEY}",
        "VERDIFAX_FEED_KEY": "${env:VERDIFAX_FEED_KEY}",
        "VERDIFAX_MCP_WORKDIR": "${env:VERDIFAX_MCP_WORKDIR}"
      }
    }
  }
}
```

### Any other MCP client

Run `verdifax-mcp` as a stdio server with the variables above in its environment.

### HTTP mode, on your own machines

For a web assistant your company runs, start it with `--http`:

1. **On this machine only.** `verdifax-mcp --http` listens on `http://127.0.0.1:8765/mcp` and rejects requests whose Host header names another machine.
2. **Beyond this machine.** `--host` with another address needs `VERDIFAX_MCP_HTTP_TOKEN`; every request must then carry `Authorization: Bearer <token>`. Put it behind your own TLS.

## MCP versions

| Language | Official MCP SDK | Protocol versions it accepts |
|---|---|---|
| TypeScript | `@modelcontextprotocol/sdk` 1.32.2 | 2025-06-18 and 2025-11-25 (and older) |
| Python | `mcp` 2.3.0 | 2025-06-18, 2025-11-25 and 2026-07-28 (and older) |
| Go | `github.com/modelcontextprotocol/go-sdk` v1.8.0 | 2025-06-18, 2025-11-25 and 2026-07-28 (and older) |

Each is built on the Verdifax SDK of its language: `verdifax` on npm, `verdifax` on PyPI and `github.com/Verdifax/verdifax-sdk-go`, at 1.17.0.

## Development

1. **TypeScript.** In `typescript/`: `npm ci`, then `npm test`.
2. **Python.** `pip install -e "./python[test]"`, then `python -m pytest python/tests`.
3. **Go.** In `go/`: `go test ./...`. Inside a folder with a parent `go.work`, set `GOWORK=off` first.
4. **Parity.** Build all three, then run `python scripts/stdio-parity.py "node typescript/dist/main.js" "python -m verdifax_mcp" "go/verdifax-mcp"`. It fails unless the three servers list the contract's tools and give the same answers over stdio.

The tests use a local stand-in for the Verdifax API and a stand-in verifier ([testdata/fake-verdifax-verify](testdata/fake-verdifax-verify)); none reaches a Verdifax server. To change a tool, edit [mcp-tools.json](mcp-tools.json), copy it to `typescript/`, `python/verdifax_mcp/` and `go/`, and change all three implementations in the same change.

## License

MIT. See [LICENSE](LICENSE).
