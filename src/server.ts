import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { randomUUID } from "node:crypto";
import { z } from "zod";
import {
  buildRequest,
  redact,
  redactCount,
  filterResponseHeaders,
  normaliseName,
  PolicyError,
  PLACEHOLDER,
  placementOf,
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

/** What happened, without the secret: enough for an agent to fix, retry or stop on its own. */
export interface Receipt {
  request_id: string;
  tool_call_id: string | null;
  ts: string;
  secret: string;
  method: string;
  host: string;
  path: string;
  /** sent = request went out with the key; refused = policy said no, key never used; error = could not complete */
  decision: "sent" | "refused" | "error";
  injected_into: string[];
  /** how many echoes of the key (raw, URL-encoded, base64) were scrubbed from the response */
  redactions: number;
  status: number | null;
  refusal_code: string | null;
  refusal_reason: string | null;
  /** true if the same request may succeed later (timeouts, 429, 5xx); false if the request itself must change */
  retryable: boolean;
}

export interface SecureRequestResult {
  ok: boolean;
  status: number | null;
  headers: Record<string, string>;
  body: string;
  truncated: boolean;
  injectedInto: string[];
  error?: string;
  receipt: Receipt;
}

function classifyError(err: unknown): { code: string; retryable: boolean } {
  if (err instanceof PolicyError) return { code: err.code, retryable: false };
  const msg = err instanceof Error ? err.message : String(err);
  const name = err instanceof Error ? err.name : "";
  if (name === "AbortError" || /timed? ?out/i.test(msg)) return { code: "TIMEOUT", retryable: true };
  if (/unknown secret|not found|no such secret/i.test(msg)) return { code: "UNKNOWN_SECRET", retryable: false };
  if (/session|vault|t3n|organisation|organization/i.test(msg)) return { code: "VAULT_ERROR", retryable: true };
  return { code: "NETWORK_ERROR", retryable: true };
}

/**
 * The core operation: fetch the secret from the vault, build the real request,
 * send it, and return a response that is guaranteed not to contain the secret,
 * plus a receipt describing every decision that was made.
 */
export async function secureRequest(
  secretName: string,
  req: AgentRequest,
  deps: SecureRequestDeps,
  toolCallId: string | null = null,
): Promise<SecureRequestResult> {
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
  const receipt: Receipt = {
    request_id: randomUUID(),
    tool_call_id: toolCallId,
    ts: new Date().toISOString(),
    secret: name,
    method: (req.method || "GET").toUpperCase(),
    host,
    path,
    decision: "error",
    injected_into: [],
    redactions: 0,
    status: null,
    refusal_code: null,
    refusal_reason: null,
    retryable: false,
  };
  const writeAudit = (outcome: AuditEntry["outcome"], detail?: string) =>
    audit({
      ts: receipt.ts, secret: name, method: receipt.method, host, path, status: receipt.status, outcome, detail, client: deps.client,
      request_id: receipt.request_id, tool_call_id: receipt.tool_call_id ?? undefined, code: receipt.refusal_code ?? undefined,
      injected_into: receipt.injected_into, redactions: receipt.redactions,
    });

  let policyValue = "";
  try {
    const policy = await deps.vault.get(name);
    policyValue = policy.value;
    const built = buildRequest(req, policy);
    receipt.injected_into = built.injectedInto;

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
    const rb = redactCount(raw, policy.value, name);
    let body = rb.text;
    let redactions = rb.count;
    const truncated = body.length > MAX_RESPONSE_CHARS;
    if (truncated) body = body.slice(0, MAX_RESPONSE_CHARS);
    const headers = filterResponseHeaders(res.headers.entries());
    for (const k of Object.keys(headers)) {
      const rh = redactCount(headers[k], policy.value, name);
      headers[k] = rh.text;
      redactions += rh.count;
    }

    receipt.decision = "sent";
    receipt.status = res.status;
    receipt.redactions = redactions;
    receipt.retryable = res.status === 429 || res.status >= 500;
    if (res.status === 401 || res.status === 403) {
      receipt.refusal_code = "UPSTREAM_AUTH_FAILED";
      receipt.refusal_reason = `The API rejected the stored key (HTTP ${res.status}). It may be expired, revoked or lack the needed scope; ask the user to rotate it.`;
    }
    writeAudit("ok");
    return { ok: res.ok, status: res.status, headers, body, truncated, injectedInto: built.injectedInto, receipt };
  } catch (err) {
    const { code, retryable } = classifyError(err);
    let msg = err instanceof Error ? err.message : String(err);
    if (policyValue) msg = redact(msg, policyValue, name);
    const denied = err instanceof PolicyError;
    receipt.decision = denied ? "refused" : "error";
    receipt.refusal_code = code;
    receipt.refusal_reason = msg.slice(0, 300);
    receipt.retryable = retryable;
    writeAudit(denied ? "denied" : "error", receipt.refusal_reason);
    return { ok: false, status: null, headers: {}, body: "", truncated: false, injectedInto: [], error: msg, receipt };
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
        "List the API keys/tokens the user has stored in SecretSafe (Terminal 3 TEE vault). Returns only names, allowed hosts, allowed methods/paths, where {{secret}} may be placed and the default injection. Values are never returned. Call this first to know which secret name to use with secure_request.",
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
            allowed_requests: p.allow ?? ["any method, any path"],
            placeholder_allowed_in: placementOf(p),
            default_injection: p.header ? `header ${p.header.split(":")[0]}` : p.query ? `query ${p.query}` : `none (use ${PLACEHOLDER})`,
            note: p.note ?? "",
            ...(p.allow ? {} : { warning: "No method/path rules: any request to the allowed hosts is possible. Owner: add --allow rules or --read-only." }),
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
        `Write the literal placeholder ${PLACEHOLDER} where the secret belongs: a header value, a query value or, only if placeholder_allowed_in (list_secrets) includes it, the body.`,
        "If you omit the placeholder, the secret's default header/query injection is used (e.g. Authorization: Bearer).",
        "The request is only sent if the URL host is on that secret's allow-list and, if the secret has method/path rules (allowed_requests in list_secrets), the method and path match one of them. Any echo of the secret in the response is replaced with [REDACTED:<name>].",
        "Every result includes a receipt (request_id, decision sent/refused/error, injected_into, redactions, refusal_code, retryable). If retryable is false, change the request or ask the user instead of retrying.",
        "Never ask the user to paste the key into the chat; use this tool instead.",
      ].join(" "),
      inputSchema: {
        secret: z.string().describe("Secret name from list_secrets, e.g. 'openai'"),
        method: z.enum(["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD"]).default("GET"),
        url: z.string().describe("Full https:// URL. Do not put the placeholder in the host or path."),
        headers: z.record(z.string(), z.string()).optional().describe(`Request headers. Use ${PLACEHOLDER} in a value to place the secret.`),
        query: z.record(z.string(), z.string()).optional().describe("Extra query parameters (merged into the URL)."),
        body: z.string().optional().describe("Raw request body (e.g. JSON string). May contain the placeholder only if the secret allows body placement."),
      },
      annotations: { openWorldHint: true },
    },
    async ({ secret, method, url, headers, query, body }, extra) => {
      const toolCallId = extra?.requestId !== undefined ? String(extra.requestId) : null;
      const r = await secureRequest(secret, { method, url, headers, query, body }, deps, toolCallId);
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
