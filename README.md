# 🔐 SecretSafe MCP

**Let Claude, Cursor and any MCP agent use your API keys — without ever seeing them.**

Today, giving an AI agent an API key means pasting it into a prompt, a `.env` the agent can read, or an MCP config. From there it ends up in context windows, chat logs, screenshots and prompt-injection payloads.

SecretSafe stores your keys in **Terminal 3's T3 Network** (hardware-secured TEE vault), bound to **your own `did:t3n` identity**. The agent only ever sees a *name* (`openai`, `github`, `stripe`) and writes a placeholder `{{secret}}`. SecretSafe fetches the key from your vault at call time, sends it **only to the hosts you allowed**, and scrubs it from every response.

```
Agent (Claude / Cursor)          SecretSafe MCP (your machine)              Terminal 3 T3N (TEE)
───────────────────────          ─────────────────────────────              ────────────────────
secure_request(                  1. authenticate as your did:t3n   ───────▶ org secret "openai"
  secret: "openai",              2. read secret (reader = your DID) ◀─────── {value, hosts, header}
  url: https://api.openai.com/…  3. host on allow-list? else DENY
)                                4. inject key → HTTPS request ───────────▶ api.openai.com
◀── response, key [REDACTED] ─── 5. redact raw/url/base64 echoes, audit log
```

## Why

| Without SecretSafe | With SecretSafe |
|---|---|
| Key pasted into chat / `.env` / MCP config | Key lives in a T3N TEE vault under your DID |
| Agent can send it anywhere (prompt injection → exfiltration) | Only exact, allow-listed hosts; https only; no redirects followed |
| Key appears in context, logs, transcripts | Agent sees `[REDACTED:openai]` at most |
| No idea which agent used what | Local audit log of every use + metered, DID-attributed reads on T3N |

## Quick start (3 minutes)

**1. Get a free T3 account + API key** (self-serve, includes free testnet credits):
<https://www.terminal3.io/claim-page>. Your "API key" is the private key of the wallet you registered — it never leaves your machine, it only signs the login challenge.

**2. Install & create your vault**

```bash
git clone https://github.com/ElTanque81/secretsafe.git && cd secretsafe
npm install && npm run build && npm link      # provides the `secretsafe` command

export T3N_API_KEY=0x...                       # your T3 key
secretsafe init                                # → your did:t3n + personal vault
```

**3. Store a key** (value is read hidden, never as a CLI argument):

```bash
secretsafe add openai --host api.openai.com --header "Authorization: Bearer {{secret}}" --note "personal"
secretsafe add github --host api.github.com --header "Authorization: Bearer {{secret}}"
secretsafe add gemini --host generativelanguage.googleapis.com --query key
# or pipe it:  pbpaste | secretsafe add stripe --host api.stripe.com --header "Authorization: Bearer {{secret}}"
```

**4. Connect your agent** — `secretsafe config` prints the snippet:

```json
{
  "mcpServers": {
    "secretsafe": {
      "command": "node",
      "args": ["/path/to/secretsafe/dist/cli.js", "serve"],
      "env": { "T3N_API_KEY": "0x...", "T3N_ENV": "testnet" }
    }
  }
}
```

- **Claude Desktop:** `~/Library/Application Support/Claude/claude_desktop_config.json`
- **Cursor:** `~/.cursor/mcp.json`
- **Claude Code:** `claude mcp add secretsafe -e T3N_API_KEY=0x... -- node /path/to/dist/cli.js serve`

Then just ask: *"List my GitHub repos using my github secret."*

## MCP tools

| Tool | What it does |
|---|---|
| `list_secrets` | Names, allowed hosts and default injection of your secrets. **Never values.** |
| `secure_request` | HTTPS request with `{{secret}}` placed in a header, query value or body (or default injection). Denied unless the host is allow-listed. Response is redacted. |
| `vault_status` | Your `did:t3n`, vault org and remaining T3 credits. |

## CLI

```
secretsafe init | add | list | remove | status | audit | config | serve
--lang en|de    --env testnet|production
```

The CLI speaks **English and German** (`--lang de` or `SECRETSAFE_LANG=de`).

## Security model — what is and isn't protected

**Protected:**
- The key is stored encrypted in T3N, readable only by your `did:t3n` (reader/manager ACL = your DID).
- The key **never enters the agent's context**: tools return names and redacted responses only.
- **Exfiltration control:** exact-host allow-list per secret, https only, port 443 only, no userinfo, redirects never followed, placeholder forbidden in host/path, CR/LF header injection blocked.
- **Redaction:** raw, URL-encoded, base64 and base64url echoes of the key are replaced in body, headers and error messages. `Set-Cookie` and other sensitive response headers are dropped.
- **Audit:** every use (ok / denied / error) is appended to `~/.secretsafe/audit.jsonl` — without the value.

**Not (yet) protected:**
- The SecretSafe process on your machine briefly holds the key in memory to make the request. Malware on your machine could read it. *Roadmap:* move the outbound call itself into a T3N TEE contract with `contract_allowlist` + agent egress, so the value never leaves the enclave.
- An allowed host is trusted. If you allow `api.example.com`, an agent can send *that* host anything.

## Roadmap

- [ ] Execute the outbound request inside a Rust/WASM T3N tenant contract with TEE placeholder substitution + user-granted egress (`member-delegation-update`), so the key never leaves the TEE
- [ ] Per-agent delegated DIDs (one DID per Claude/Cursor instance) with revocable grants
- [ ] Rate limits & spend caps per secret
- [ ] One-click installer (`npx secretsafe-mcp init`) and Smithery/MCP registry listing
- [ ] Team vaults (shared org, role-based readers)

## Development

```bash
npm install
npm test        # unit + MCP protocol tests (no network, MemoryVault)
```

Built with [`@terminal3/t3n-sdk`](https://www.npmjs.com/package/@terminal3/t3n-sdk) and the [Model Context Protocol SDK](https://github.com/modelcontextprotocol/typescript-sdk). Built for the [Terminal 3 Build+Scale Agent Micro Grant](https://dorahacks.io/hackathon/t3-build-scale-grant/detail). Tag [@terminal3io](https://x.com/terminal3io).

---

### 🇩🇪 Kurz auf Deutsch

SecretSafe lässt Claude, Cursor & Co. deine API-Keys benutzen, **ohne dass der Agent sie je sieht**. Die Keys liegen im TEE-Tresor von Terminal 3, gebunden an deine eigene `did:t3n`. Der Agent schreibt nur `{{secret}}`. SecretSafe setzt den Key ein, schickt ihn ausschließlich an freigegebene Hosts und schwärzt ihn in jeder Antwort. Start: `secretsafe init --lang de`.

MIT License
