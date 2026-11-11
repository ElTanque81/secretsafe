# SecretSafe MCP — DoraHacks submission (Terminal 3 Build+Scale Agent Micro Grant)

**One-liner:** Let Claude, Cursor and any MCP agent use your API keys without ever seeing them. Keys live in Terminal 3's TEE vault under your own `did:t3n`.

## Problem
Every developer using AI agents hands them API keys: pasted in chat, in `.env` files the agent reads, in MCP configs. Keys leak into context windows, transcripts and logs, and a single prompt injection can exfiltrate them to any server.

## Solution
SecretSafe is an MCP server backed by the T3 Network:
- Each user runs `secretsafe init` → authenticates with their T3 key → gets their own **did:t3n** and a personal vault (T3 organisation).
- Secrets are stored as T3N org secrets, readable only by the user's DID.
- The agent sees only names and writes `{{secret}}`. SecretSafe reads the key from T3N at call time, enforces a per-secret **exact-host allow-list**, sends the HTTPS request and **redacts** the key from the response.
- Every use is audited; every vault read is an authenticated, metered call attributed to the user's DID.

## Terminal 3 integration
- `@terminal3/t3n-sdk`: `T3nClient` handshake + ETH auth (`did:t3n`), `createOrganisation`, `SessionOrgDataClient.secretWrite/secretGet/secretList/secretDelete` (reader/manager ACL = user DID), `getBalance`.
- Enclave attestation pinning via `resolveTrustAnchor` (operator-signed trust manifest).

## Traction
- Unique DIDs: _fill in_
- secure_request calls / T3 credits consumed: _fill in_
- Links: GitHub, npm, X posts, Reddit/HN threads: _fill in_

## Links
- GitHub: https://github.com/ElTanque81/secretsafe
- Demo video: _fill in_
- X: _fill in_ (tagging @terminal3io)

## Roadmap
Outbound request executed inside a T3N TEE contract (key never leaves the enclave), per-agent delegated DIDs, spend caps, team vaults.
