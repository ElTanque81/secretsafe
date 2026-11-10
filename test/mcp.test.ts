import { test } from "node:test";
import assert from "node:assert/strict";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import { createServer } from "../src/server.js";
import { MemoryVault } from "../src/vault.js";

test("MCP: tools are listed and secure_request never leaks the key", async () => {
  const KEY = "ghp_ABCDEFGHIJKLMNOPQRSTUV123456";
  const vault = new MemoryVault();
  await vault.put("github", { value: KEY, hosts: ["api.github.com"], header: "Authorization: Bearer {{secret}}", note: "repo read" });
  const fakeFetch = (async (_u: string, init: RequestInit) =>
    new Response(`{"login":"ElTanque81","debug":"${(init.headers as Record<string, string>).Authorization}"}`, { status: 200 })) as unknown as typeof fetch;

  const server = createServer({ vault, fetchImpl: fakeFetch, audit: () => {} });
  const [a, b] = InMemoryTransport.createLinkedPair();
  const client = new Client({ name: "test", version: "1" });
  await Promise.all([server.connect(a), client.connect(b)]);

  const tools = await client.listTools();
  assert.deepEqual(tools.tools.map((t) => t.name).sort(), ["list_secrets", "secure_request", "vault_status"]);

  const list = await client.callTool({ name: "list_secrets", arguments: {} });
  const listText = JSON.stringify(list);
  assert.ok(listText.includes("api.github.com") && !listText.includes(KEY));

  const res = await client.callTool({ name: "secure_request", arguments: { secret: "github", method: "GET", url: "https://api.github.com/user" } });
  const resText = JSON.stringify(res);
  assert.ok(resText.includes("ElTanque81"));
  assert.ok(!resText.includes(KEY));
  assert.ok(resText.includes("[REDACTED:github]"));

  const denied = await client.callTool({ name: "secure_request", arguments: { secret: "github", url: "https://webhook.site/x" } });
  assert.equal(denied.isError, true);
});
