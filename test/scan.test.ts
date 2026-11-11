import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, writeFileSync, mkdirSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { scanText, scanPath, extractValue, fingerprint } from "../src/scan.js";

const OPENAI = "sk-proj-" + "Ab3dE5gH7jK9mN1pQ3sT5vX7zA9cE1gI3kM5oQ7s";
const ANTH = "sk-ant-api03-" + "Zx9Yw8Vu7Ts6Rq5Po4Nm3Lk2Ji1Hg0FeDcBa98765";
const GH = "ghp_" + "aB1cD2eF3gH4iJ5kL6mN7oP8qR9sT0uV1wX2";

test("detects known providers, never exposes values", () => {
  const f = scanText(`OPENAI_API_KEY=${OPENAI}\nconst a = "${ANTH}";\ntoken: '${GH}'\n`, ".env");
  const ids = f.map((x) => x.detector);
  assert.deepEqual(ids, ["openai", "anthropic", "github"]);
  assert.equal(f[0].variable, "OPENAI_API_KEY");
  for (const x of f) {
    assert.ok(!x.preview.includes(x.value.slice(x.value.length - 8)), "preview must not contain secret body");
    assert.equal(x.fp, fingerprint(x.value));
  }
});

test("generic assignment + placeholders ignored", () => {
  const f = scanText(`MY_SERVICE_TOKEN=Zq8x1Lm4Np7Rt0Wv3Ys6\nAPI_KEY=your_api_key_here\nSECRET=xxxxxxxxxxxxxxxxxxxx\nAPI_KEY=\${API_KEY}\n`, ".env");
  assert.equal(f.length, 1);
  assert.equal(f[0].detector, "generic");
  assert.equal(f[0].suggestedName, "my-service");
});

test("anthropic key is not double-reported as openai", () => {
  const f = scanText(`KEY=${ANTH}`, ".env");
  assert.equal(f.filter((x) => x.detector !== "generic").length, 1);
  assert.equal(f.length, 1);
});

test("scanPath skips node_modules and strips values; extractValue picks by fingerprint", () => {
  const dir = mkdtempSync(join(tmpdir(), "ss-scan-"));
  writeFileSync(join(dir, ".env"), `OPENAI_API_KEY=${OPENAI}\nGITHUB_TOKEN=${GH}\n`);
  mkdirSync(join(dir, "node_modules"));
  writeFileSync(join(dir, "node_modules", "x.js"), `const k="${GH}"`);
  const res = scanPath(dir);
  assert.equal(res.length, 2);
  assert.ok(!JSON.stringify(res).includes(OPENAI) && !JSON.stringify(res).includes(GH));
  const gh = res.find((r) => r.detector === "github")!;
  const { value } = extractValue(join(dir, ".env"), { fp: gh.fp });
  assert.equal(value, GH);
  assert.equal(extractValue(join(dir, ".env"), { variable: "OPENAI_API_KEY" }).value, OPENAI);
  assert.throws(() => extractValue(join(dir, ".env"), { fp: "000000000000" }));
});

import { looksLikeWalletSecret } from "../src/scan.js";

const EVM = "0x4c0883a69102937d6231471b5dbb6204fe5129617082792ae468d01a3f362318";
const ANVIL0 = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";
const SOL = "5MaiiCavjCmn9Hs1o3eznqDEhRwxo7pXiAYez7keQUviUkauRiTMD8DrESdrNjN8zd9mTmVhRvBJeRuhTCD6gjsu"; // 88 chars base58 (dummy)
const SEED = "abandon ability able about above absent absorb abstract absurd abuse access accident";

test("wallet secrets are detected and masked", () => {
  const txt = [
    `PRIVATE_KEY=${EVM}`,
    `deployer: { accounts: ["${ANVIL0}"] }`,
    `SOLANA_SECRET_KEY=${SOL}`,
    `MNEMONIC="${SEED}"`,
    `[${Array.from({ length: 64 }, (_, i) => (i * 7) % 256).join(",")}]`,
    `const TX_HASH = "${EVM}";`, // no wallet-ish name -> still flagged? TX_HASH has no key word
  ].join("\n");
  const f = scanText(txt, "x");
  const ids = f.map((x) => `${x.line}:${x.detector}`);
  assert.ok(ids.includes("1:evm-private-key"));
  assert.ok(ids.includes("2:evm-private-key"));
  assert.ok(ids.includes("3:solana-private-key"));
  assert.ok(ids.includes("4:seed-phrase"));
  assert.ok(ids.includes("5:solana-private-key"));
  assert.ok(!ids.some((x) => x.startsWith("6:")), "plain tx hash line without key-ish name is not flagged");
  const anvil = f.find((x) => x.line === 2)!;
  assert.match(anvil.label, /Anvil\/Hardhat/);
  for (const x of f) {
    assert.ok(x.note, "wallet findings carry a warning note");
    assert.ok(!x.preview.includes(x.value.slice(-10)));
  }
});

test("looksLikeWalletSecret", () => {
  assert.equal(looksLikeWalletSecret(EVM), "evm-private-key");
  assert.equal(looksLikeWalletSecret(SOL), "solana-private-key");
  assert.equal(looksLikeWalletSecret(SEED), "seed-phrase");
  assert.equal(looksLikeWalletSecret("sk-proj-abc123def456ghi789jkl012mno345"), null);
});
