import { test } from "node:test";
import assert from "node:assert/strict";
import { buildRequest, validatePolicy, placementOf, PolicyError, DEFAULT_PLACEMENT } from "../src/inject.js";
import { MemoryVault } from "../src/vault.js";
import { secureRequest } from "../src/server.js";
import type { AuditEntry } from "../src/config.js";

const KEY = "ghp_TESTONLY0123456789abcdefghijklmnopqrstu";
const github = validatePolicy({ value: KEY, hosts: ["api.github.com"], header: "Authorization: Bearer {{secret}}" });
const gist = { method: "POST", url: "https://api.github.com/gists", body: '{"public":true,"files":{"x.txt":{"content":"{{secret}}"}}}' };

test("body placement is off by default", () => {
  assert.deepEqual(placementOf(github), DEFAULT_PLACEMENT);
  assert.throws(() => buildRequest(gist, github), (e: unknown) => e instanceof PolicyError && e.code === "PLACEMENT_NOT_ALLOWED");
});

test("default header injection still works with a body that has no placeholder", () => {
  const r = buildRequest({ method: "POST", url: "https://api.github.com/gists", body: '{"public":false}' }, github);
  assert.equal(r.headers.Authorization, `Bearer ${KEY}`);
  assert.ok(!r.body?.includes(KEY));
});

test("body placement works only when the owner allows it", () => {
  const p = validatePolicy({ ...github, placement: ["body"] });
  const r = buildRequest({ method: "POST", url: "https://api.github.com/x", body: '{"t":"{{secret}}"}' }, p);
  assert.equal(r.body, `{"t":"${KEY}"}`);
  assert.throws(() => buildRequest({ method: "GET", url: "https://api.github.com/x", headers: { "x-k": "{{secret}}" } }, p), /not allowed/);
  assert.throws(() => buildRequest({ method: "GET", url: "https://api.github.com/x?k={{secret}}" }, p), /not allowed/);
});

test("placement is validated and normalised", () => {
  assert.deepEqual(validatePolicy({ ...github, placement: ["BODY", " header", "body"] as never }).placement, ["header", "body"]);
  assert.throws(() => validatePolicy({ ...github, placement: ["url"] as never }), /Invalid placement/);
  assert.equal(validatePolicy(github).placement, undefined);
});

test("secureRequest refuses the gist exfiltration without calling fetch", async () => {
  const vault = new MemoryVault();
  await vault.put("github", github);
  const audit: AuditEntry[] = [];
  let called = false;
  const r = await secureRequest("github", gist, { vault, fetchImpl: (async () => { called = true; return new Response("{}"); }) as typeof fetch, audit: (e: AuditEntry) => audit.push(e) });
  assert.equal(called, false);
  assert.equal(r.receipt.refusal_code, "PLACEMENT_NOT_ALLOWED");
  assert.ok(!JSON.stringify(r).includes(KEY));
});
