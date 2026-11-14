import { test } from "node:test";
import assert from "node:assert/strict";
import { buildRequest, redact, validatePolicy, normaliseHost, PolicyError, type SecretPolicy } from "../src/inject.js";
import { MemoryVault } from "../src/vault.js";
import { secureRequest } from "../src/server.js";
import type { AuditEntry } from "../src/config.js";

const KEY = "sk-test-SUPERSECRET-1234567890";
const policy: SecretPolicy = validatePolicy({ value: KEY, hosts: ["api.example.com"], header: "Authorization: Bearer {{secret}}" });

test("default header injection", () => {
  const r = buildRequest({ method: "GET", url: "https://api.example.com/v1/models" }, policy);
  assert.equal(r.headers.Authorization, `Bearer ${KEY}`);
  assert.deepEqual(r.injectedInto, ["header:Authorization"]);
});

test("explicit placeholder in header, query and body (body explicitly allowed)", () => {
  const withBody = validatePolicy({ ...policy, placement: ["header", "query", "body"] });
  const r = buildRequest(
    {
      method: "POST",
      url: "https://api.example.com/x?key={{secret}}",
      headers: { "x-api-key": "{{secret}}" },
      body: '{"token":"{{secret}}"}',
    },
    withBody,
  );
  assert.equal(r.headers["x-api-key"], KEY);
  assert.ok(r.url.includes(encodeURIComponent(KEY)));
  assert.equal(r.body, `{"token":"${KEY}"}`);
  assert.equal(r.headers.Authorization, undefined, "default injection skipped when placeholder used");
});

test("rejects hosts not on the allow-list", () => {
  assert.throws(() => buildRequest({ method: "GET", url: "https://evil.example.net/steal" }, policy), PolicyError);
  assert.throws(() => buildRequest({ method: "GET", url: "https://api.example.com.evil.net/" }, policy), PolicyError);
});

test("rejects http, ports, userinfo and placeholder in path", () => {
  assert.throws(() => buildRequest({ method: "GET", url: "http://api.example.com/" }, policy), PolicyError);
  assert.throws(() => buildRequest({ method: "GET", url: "https://api.example.com:8443/" }, policy), PolicyError);
  assert.throws(() => buildRequest({ method: "GET", url: "https://u:p@api.example.com/" }, policy), PolicyError);
  assert.throws(() => buildRequest({ method: "GET", url: "https://api.example.com/{{secret}}" }, policy), PolicyError);
});

test("rejects header injection via newlines", () => {
  assert.throws(() => buildRequest({ method: "GET", url: "https://api.example.com/", headers: { a: "x\r\nHost: evil" } }, policy), PolicyError);
});

test("host normalisation", () => {
  assert.equal(normaliseHost("API.Example.com."), "api.example.com");
  assert.throws(() => normaliseHost("https://api.example.com"));
  assert.throws(() => normaliseHost("*.example.com"));
});

test("redaction covers raw, url-encoded and base64 forms", () => {
  const b64 = Buffer.from(KEY).toString("base64");
  const s = redact(`a ${KEY} b ${encodeURIComponent(KEY)} c ${b64}`, KEY, "openai");
  assert.ok(!s.includes(KEY) && !s.includes(b64));
  assert.equal(s.split("[REDACTED:openai]").length - 1, 3);
});

test("secureRequest end-to-end: secret sent upstream, never returned", async () => {
  const vault = new MemoryVault();
  await vault.put("openai", policy);
  const audits: AuditEntry[] = [];
  let seenAuth = "";
  const fakeFetch = (async (_url: string, init: RequestInit) => {
    seenAuth = (init.headers as Record<string, string>).Authorization;
    return new Response(JSON.stringify({ echo: seenAuth, ok: true }), { status: 200, headers: { "content-type": "application/json", "set-cookie": "s=1" } });
  }) as unknown as typeof fetch;

  const r = await secureRequest("openai", { method: "GET", url: "https://api.example.com/v1/models" }, { vault, fetchImpl: fakeFetch, audit: (e) => audits.push(e) });
  assert.equal(seenAuth, `Bearer ${KEY}`);
  assert.equal(r.status, 200);
  assert.ok(!JSON.stringify(r).includes(KEY), "result must not contain the secret");
  assert.ok(r.body.includes("[REDACTED:openai]"));
  assert.equal(r.headers["set-cookie"], undefined);
  assert.equal(audits[0].outcome, "ok");
  assert.ok(!JSON.stringify(audits).includes(KEY));
});

test("secureRequest denies and audits a disallowed host without calling fetch", async () => {
  const vault = new MemoryVault();
  await vault.put("openai", policy);
  const audits: AuditEntry[] = [];
  let called = false;
  const fakeFetch = (async () => {
    called = true;
    return new Response("");
  }) as unknown as typeof fetch;
  const r = await secureRequest("openai", { method: "GET", url: "https://attacker.io/x" }, { vault, fetchImpl: fakeFetch, audit: (e) => audits.push(e) });
  assert.equal(called, false);
  assert.ok(r.error);
  assert.equal(audits[0].outcome, "denied");
});
