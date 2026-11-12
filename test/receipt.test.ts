import { test } from "node:test";
import assert from "node:assert/strict";
import { validatePolicy } from "../src/inject.js";
import { MemoryVault } from "../src/vault.js";
import { secureRequest } from "../src/server.js";
import type { AuditEntry } from "../src/config.js";

const KEY = "sk-test-RECEIPT-0123456789abcdef";
const pol = validatePolicy({ value: KEY, hosts: ["api.example.com"], header: "Authorization: Bearer {{secret}}", allow: ["GET /v1/**"] });

async function setup() {
  const vault = new MemoryVault();
  await vault.put("demo", pol);
  const audits: AuditEntry[] = [];
  return { vault, audits, audit: (e: AuditEntry) => audits.push(e) };
}

test("sent: receipt has id, injection, redaction count; audit mirrors it", async () => {
  const { vault, audits, audit } = await setup();
  const enc = Buffer.from(KEY).toString("base64");
  const fetchImpl = (async () => new Response(`{"a":"${KEY}","b":"${enc}"}`, { status: 200, headers: { "x-request-id": KEY } })) as unknown as typeof fetch;
  const r = await secureRequest("demo", { method: "GET", url: "https://api.example.com/v1/models" }, { vault, fetchImpl, audit }, "call-7");
  assert.equal(r.receipt.decision, "sent");
  assert.equal(r.receipt.tool_call_id, "call-7");
  assert.match(r.receipt.request_id, /^[0-9a-f-]{36}$/);
  assert.deepEqual(r.receipt.injected_into, ["header:Authorization"]);
  assert.equal(r.receipt.redactions, 3); // raw + base64 in body, raw in header
  assert.equal(r.receipt.retryable, false);
  assert.ok(!JSON.stringify(r).includes(KEY));
  assert.equal(audits[0].request_id, r.receipt.request_id);
  assert.equal(audits[0].redactions, 3);
});

test("refused: machine-readable codes, not retryable, key never used", async () => {
  const { vault, audit } = await setup();
  let calls = 0;
  const fetchImpl = (async () => { calls++; return new Response(""); }) as unknown as typeof fetch;
  const host = await secureRequest("demo", { method: "GET", url: "https://evil.example.net/x" }, { vault, fetchImpl, audit });
  const rule = await secureRequest("demo", { method: "POST", url: "https://api.example.com/v1/x", body: "{}" }, { vault, fetchImpl, audit });
  const unknown = await secureRequest("nope", { method: "GET", url: "https://api.example.com/v1/x" }, { vault, fetchImpl, audit });
  assert.equal(calls, 0);
  assert.equal(host.receipt.decision, "refused");
  assert.equal(host.receipt.refusal_code, "HOST_NOT_ALLOWED");
  assert.equal(rule.receipt.refusal_code, "RULE_NOT_ALLOWED");
  assert.equal(host.receipt.retryable, false);
  assert.equal(unknown.receipt.refusal_code, "UNKNOWN_SECRET");
  assert.equal(unknown.receipt.decision, "error");
});

test("upstream 401 and 503 are flagged correctly", async () => {
  const { vault, audit } = await setup();
  const mk = (status: number) => (async () => new Response("x", { status })) as unknown as typeof fetch;
  const a = await secureRequest("demo", { method: "GET", url: "https://api.example.com/v1/x" }, { vault, fetchImpl: mk(401), audit });
  const b = await secureRequest("demo", { method: "GET", url: "https://api.example.com/v1/x" }, { vault, fetchImpl: mk(503), audit });
  assert.equal(a.receipt.refusal_code, "UPSTREAM_AUTH_FAILED");
  assert.equal(a.receipt.retryable, false);
  assert.equal(b.receipt.retryable, true);
});

test("timeouts are retryable", async () => {
  const { vault, audit } = await setup();
  const fetchImpl = (async () => { const e = new Error("aborted"); e.name = "AbortError"; throw e; }) as unknown as typeof fetch;
  const r = await secureRequest("demo", { method: "GET", url: "https://api.example.com/v1/x" }, { vault, fetchImpl, audit });
  assert.equal(r.receipt.refusal_code, "TIMEOUT");
  assert.equal(r.receipt.retryable, true);
});
