import { test } from "node:test";
import assert from "node:assert/strict";
import { buildRequest, validatePolicy, pathMatches, parseRule, PolicyError, READ_ONLY_RULES } from "../src/inject.js";
import { MemoryVault } from "../src/vault.js";
import { secureRequest } from "../src/server.js";

const KEY = "ghp_" + "aB1cD2eF3gH4iJ5kL6mN7oP8qR9sT0uV1wX2";

test("path globs", () => {
  assert.ok(pathMatches("/user", "/user"));
  assert.ok(pathMatches("/user", "/user/"));
  assert.ok(!pathMatches("/user", "/user/emails"));
  assert.ok(pathMatches("/repos/*/*", "/repos/ElTanque81/secretsafe"));
  assert.ok(!pathMatches("/repos/*/*", "/repos/ElTanque81/secretsafe/issues"));
  assert.ok(pathMatches("/repos/**", "/repos/ElTanque81/secretsafe/issues/1"));
  assert.ok(pathMatches("/repos/**", "/repos"));
  assert.ok(pathMatches("/v1/*/completions", "/v1/chat/completions"));
  assert.ok(pathMatches("/**", "/"));
  assert.ok(pathMatches("/files/*.json", "/files/a.json"));
  assert.ok(!pathMatches("/files/*.json", "/files/a.txt"));
});

test("rule parsing + validation", () => {
  assert.deepEqual(parseRule("get /user"), { methods: ["GET"], path: "/user" });
  assert.deepEqual(parseRule("GET|HEAD /repos/**"), { methods: ["GET", "HEAD"], path: "/repos/**" });
  assert.throws(() => parseRule("FETCH /x"), PolicyError);
  assert.throws(() => parseRule("GET repos"), PolicyError);
  assert.throws(() => parseRule("GET /a**b"), PolicyError);
  const p = validatePolicy({ value: KEY, hosts: ["api.github.com"], allow: [" GET   /user ", "GET /user"] });
  assert.deepEqual(p.allow, ["GET /user"]);
});

const ro = validatePolicy({ value: KEY, hosts: ["api.github.com"], header: "Authorization: Bearer {{secret}}", allow: ["GET|HEAD /user", "GET /repos/**", "GET /user/repos"] });

test("read-only GitHub policy: GETs pass, writes are refused", () => {
  assert.ok(buildRequest({ method: "GET", url: "https://api.github.com/repos/ElTanque81/secretsafe/issues" }, ro));
  assert.ok(buildRequest({ method: "GET", url: "https://api.github.com/user" }, ro));
  assert.throws(() => buildRequest({ method: "POST", url: "https://api.github.com/repos/ElTanque81/secretsafe/issues", body: "{}" }, ro), /not allowed/);
  assert.throws(() => buildRequest({ method: "DELETE", url: "https://api.github.com/repos/ElTanque81/secretsafe" }, ro), /not allowed/);
  assert.throws(() => buildRequest({ method: "GET", url: "https://api.github.com/orgs/acme/members" }, ro), /not allowed/);
});

test("traversal and encoded-slash tricks are refused", () => {
  // URL parser normalises ../ before matching
  assert.throws(() => buildRequest({ method: "GET", url: "https://api.github.com/repos/../orgs/acme/members" }, ro), /not allowed/);
  assert.throws(() => buildRequest({ method: "GET", url: "https://api.github.com/repos/a%2F..%2F..%2Forgs" }, ro), /Encoded slashes/);
});

test("--read-only shortcut", () => {
  const p = validatePolicy({ value: KEY, hosts: ["api.github.com"], header: "Authorization: Bearer {{secret}}", allow: READ_ONLY_RULES });
  assert.ok(buildRequest({ method: "GET", url: "https://api.github.com/anything/deep" }, p));
  assert.ok(buildRequest({ method: "HEAD", url: "https://api.github.com/" }, p));
  assert.throws(() => buildRequest({ method: "PATCH", url: "https://api.github.com/user", body: "{}" }, p), /not allowed/);
});

test("policies without rules keep old behaviour", () => {
  const p = validatePolicy({ value: KEY, hosts: ["api.github.com"], header: "Authorization: Bearer {{secret}}" });
  assert.equal(p.allow, undefined);
  assert.ok(buildRequest({ method: "DELETE", url: "https://api.github.com/repos/a/b" }, p));
});

test("secureRequest audits a denied write as 'denied' without calling fetch", async () => {
  const vault = new MemoryVault();
  await vault.put("github", ro);
  let called = false;
  const audits: { outcome: string }[] = [];
  const r = await secureRequest("github", { method: "POST", url: "https://api.github.com/user/repos", body: "{}" }, {
    vault, fetchImpl: (async () => { called = true; return new Response(""); }) as unknown as typeof fetch, audit: (e) => audits.push(e),
  });
  assert.equal(called, false);
  assert.match(r.error ?? "", /not allowed/);
  assert.equal(audits[0].outcome, "denied");
});
