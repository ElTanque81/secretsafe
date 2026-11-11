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
