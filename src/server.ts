import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import {
  buildRequest,
  redact,
  filterResponseHeaders,
  normaliseName,
  PolicyError,
  PLACEHOLDER,
  type AgentRequest,
} from "./inject.js";
import type { Vault } from "./vault.js";
import { appendAudit, type AuditEntry } from "./config.js";

export const VERSION = "0.1.0";
const MAX_RESPONSE_CHARS = 100_000;
const TIMEOUT_MS = 30_000;

export interface SecureRequestDeps {
  vault: Vault;
  fetchImpl?: typeof fetch;
  audit?: (e: AuditEntry) => void;
  client?: string;
}

export interface SecureRequestResult {
  ok: boolean;
  status: number | null;
  headers: Record<string, string>;
  body: string;
  truncated: boolean;
  injectedInto: string[];
  error?: string;
}

/**
 * The core operation: fetch the secret from the vault, build the real request,
 * send it, and return a response that is guaranteed not to contain the secret.
 */
export async function secureRequest(secretName: string, req: AgentRequest, deps: SecureRequestDeps): Promise<SecureRequestResult> {
  const fetchImpl = deps.fetchImpl ?? fetch;
  const audit = deps.audit ?? appendAudit;
  const name = normaliseName(secretName);
  let path = "";
  let host = "";
  try {
    const u = new URL(req.url);
    path = u.pathname;
    host = u.hostname;
  } catch {
    /* buildRequest reports it */
  }
  const base: Omit<AuditEntry, "status" | "outcome"> = {
    ts: new Date().toISOString(),
    secret: name,
    method: (req.method || "GET").toUpperCase(),
    host,
    path,
    client: deps.client,
  };

  let policyValue = "";
  try {
    const policy = await deps.vault.get(name);
    policyValue = policy.value;
    const built = buildRequest(req, policy);

    const ctrl = new AbortController();
    const timer = setTimeout(() => ctrl.abort(), TIMEOUT_MS);
    let res: Response;
    try {
      res = await fetchImpl(built.url, {
        method: built.method,
        headers: built.headers,
        body: built.body,
        redirect: "manual", // never follow a redirect to a host that is not allow-listed
        signal: ctrl.signal,
      });
    } finally {
      clearTimeout(timer);
    }

    const raw = built.method === "HEAD" ? "" : await res.text();
    let body = redact(raw, policy.value, name);
    const truncated = body.length > MAX_RESPONSE_CHARS;
    if (truncated) body = body.slice(0, MAX_RESPONSE_CHARS);
    const headers = filterResponseHeaders(res.headers.entries());
    for (const k of Object.keys(headers)) headers[k] = redact(headers[k], policy.value, name);

    audit({ ...base, status: res.status, outcome: "ok" });
    return { ok: res.ok, status: res.status, headers, body, truncated, injectedInto: built.injectedInto };
  } catch (err) {
    const denied = err instanceof PolicyError;
    let msg = err instanceof Error ? err.message : String(err);
    if (policyValue) msg = redact(msg, policyValue, name);
    audit({ ...base, status: null, outcome: denied ? "denied" : "error", detail: msg.slice(0, 300) });
    return { ok: false, status: null, headers: {}, body: "", truncated: false, injectedInto: [], error: msg };
  }
}

function text(obj: unknown) {
  return { content: [{ type: "text" as const, text: typeof obj === "string" ? obj : JSON.stringify(obj, null, 2) }] };
}

export function createServer(deps: SecureRequestDeps): McpServer {
  const server = new McpServer({ name: "secretsafe", version: VERSION });

  server.registerTool(
    "list_secrets",
    {
      title: "List available secrets",
      description:
        "List the API keys/tokens the user has stored in SecretSafe (Terminal 3 TEE vault). Returns only names, allowed hosts and the default injection. Values are never returned. Call this first to know which secret name to use with secure_request.",
      inputSchema: {},
      annotations: { readOnlyHint: true },
    },
    async () => {
      const items = await deps.vault.list();
      const out = [];
      for (const it of items) {
        try {
          const p = await deps.vault.get(it.name);
          out.push({
            name: it.name,
            allowed_hosts: p.hosts,
            default_injection: p.header ? `header ${p.header.split(":")[0]}` : p.query ? `query ${p.query}` : `none (use ${PLACEHOLDER})`,
            note: p.note ?? "",
          });
        } catch {
          out.push({ name: it.name, allowed_hosts: [], default_injection: "unreadable", note: "" });
        }
      }
      return text({ owner_did: deps.vault.did, secrets: out });
    },
  );

  server.registerTool(
    "secure_request",
    {
      title: "HTTPS request with a stored secret",
      description: [
        "Make an HTTPS request that needs one of the user's secrets WITHOUT seeing it.",
        `Write the literal placeholder ${PLACEHOLDER} where the secret belongs (a header value, a query value or the body).`,
        "If you omit the placeholder, the secret's default header/query injection is used (e.g. Authorization: Bearer).",
        "The request is only sent if the URL host is on that secret's allow-list. Any echo of the secret in the response is replaced with [REDACTED:<name>].",
        "Never ask the user to paste the key into the chat; use this tool instead.",
      ].join(" "),
      inputSchema: {
        secret: z.string().describe("Secret name from list_secrets, e.g. 'openai'"),
        method: z.enum(["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD"]).default("GET"),
        url: z.string().describe("Full https:// URL. Do not put the placeholder in the host or path."),
        headers: z.record(z.string(), z.string()).optional().describe(`Request headers. Use ${PLACEHOLDER} in a value to place the secret.`),
        query: z.record(z.string(), z.string()).optional().describe("Extra query parameters (merged into the URL)."),
        body: z.string().optional().describe("Raw request body (e.g. JSON string). May contain the placeholder."),
      },
      annotations: { openWorldHint: true },
    },
    async ({ secret, method, url, headers, query, body }) => {
      const r = await secureRequest(secret, { method, url, headers, query, body }, deps);
      return { ...text(r), isError: !!r.error };
    },
  );

  server.registerTool(
    "vault_status",
    {
      title: "SecretSafe vault status",
      description: "Show the user's did:t3n identity, the vault organisation and the remaining Terminal 3 credit balance.",
      inputSchema: {},
      annotations: { readOnlyHint: true },
    },
    async () => text({ did: deps.vault.did, vault: deps.vault.orgDid, balance: await deps.vault.balance(), version: VERSION }),
  );

  return server;
}
