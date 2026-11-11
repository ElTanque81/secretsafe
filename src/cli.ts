#!/usr/bin/env node
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { createInterface } from "node:readline";
import { Writable } from "node:stream";
import { fileURLToPath } from "node:url";
import { execFileSync, spawnSync } from "node:child_process";
import { userInfo } from "node:os";
import type { Environment } from "@terminal3/t3n-sdk";
import { t, setLang } from "./i18n.js";
import { loadConfig, saveConfig, readAudit, auditPath } from "./config.js";
import { normaliseName, validatePolicy } from "./inject.js";
import { T3Vault } from "./vault.js";
import { createServer, VERSION } from "./server.js";
import { scanPath, extractValue, looksLikeWalletSecret, WALLET_DETECTORS } from "./scan.js";
import { resolve, relative, join } from "node:path";

interface Parsed {
  cmd: string;
  pos: string[];
  flags: Record<string, string[]>;
}

function parse(argv: string[]): Parsed {
  const pos: string[] = [];
  const flags: Record<string, string[]> = {};
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a.startsWith("--")) {
      const [k, inline] = a.slice(2).split(/=(.*)/s, 2);
      const v = inline !== undefined ? inline : argv[i + 1] && !argv[i + 1].startsWith("--") ? argv[++i] : "true";
      (flags[k] ??= []).push(v);
    } else pos.push(a);
  }
  return { cmd: pos.shift() ?? "help", pos, flags };
}

const one = (p: Parsed, k: string) => p.flags[k]?.[p.flags[k].length - 1];
const err = (s: string) => process.stderr.write(s + "\n");
const out = (s: string) => process.stdout.write(s + "\n");

function envOf(p: Parsed): Environment {
  const e = (one(p, "env") ?? process.env.T3N_ENV ?? loadConfig()?.env ?? "testnet").toLowerCase();
  if (e !== "testnet" && e !== "sandbox" && e !== "production") throw new Error(`Unknown env "${e}"`);
  return e as Environment;
}

const KEYCHAIN_SERVICE = "secretsafe-t3n";

/** T3 key from the environment, or (macOS) from the login Keychain - never from a file. */
function apiKey(): string {
  const k = process.env.T3N_API_KEY?.trim();
  if (k) return k;
  if (process.platform === "darwin") {
    try {
      const v = execFileSync("security", ["find-generic-password", "-s", KEYCHAIN_SERVICE, "-a", userInfo().username, "-w"], {
        encoding: "utf8",
        stdio: ["ignore", "pipe", "ignore"],
      }).trim();
      if (v) return v;
    } catch {
      /* not stored */
    }
  }
  throw new Error(t("missingKey"));
}

async function openVault(p: Parsed, log: (s: string) => void) {
  const cfg = loadConfig();
  const env = envOf(p);
  if (!cfg?.orgDid || cfg.env !== env) throw new Error(t("notInitialised"));
  const { vault } = await T3Vault.open({ apiKey: apiKey(), env, orgDid: cfg.orgDid, log });
  return vault;
}

/** Read a secret without echoing it. Accepts piped stdin too (e.g. `pbpaste | secretsafe add ...`). */
async function readHidden(prompt: string): Promise<string> {
  if (!process.stdin.isTTY) {
    const chunks: Buffer[] = [];
    for await (const c of process.stdin) chunks.push(c as Buffer);
    return Buffer.concat(chunks).toString("utf8").trim();
  }
  process.stderr.write(prompt);
  const muted = new Writable({ write: (_c, _e, cb) => cb() });
  const rl = createInterface({ input: process.stdin, output: muted, terminal: true });
  const value = await new Promise<string>((res) => rl.question("", (a) => res(a)));
  rl.close();
  process.stderr.write("\n");
  return value.trim();
}

async function main() {
  const p = parse(process.argv.slice(2));
  setLang(one(p, "lang") ?? process.env.SECRETSAFE_LANG ?? (process.env.LANG?.startsWith("de") ? "de" : "en"));
  const log = (s: string) => err(s);

  switch (p.cmd) {
    case "help":
    case "--help":
    case "-h":
      out(t("help"));
      return;

    case "version":
    case "--version":
      out(VERSION);
      return;

    case "login": {
      if (process.platform !== "darwin") throw new Error("login (Keychain) is macOS-only; set T3N_API_KEY instead.");
      err(t("keychainPrompt"));
      // `-w` as last flag makes `security` prompt for the value itself (hidden, never in argv/history).
      const r = spawnSync("security", ["add-generic-password", "-s", KEYCHAIN_SERVICE, "-a", userInfo().username, "-U", "-w"], { stdio: "inherit" });
      if (r.status !== 0) throw new Error("Keychain write failed");
      out(t("keychainSaved"));
      return;
    }

    case "register": {
      // Opt-in: opens a pre-filled public GitHub issue with ONLY public identifiers (DIDs, version).
      const cfg = loadConfig();
      if (!cfg?.did || !cfg.orgDid) throw new Error(t("notInitialised"));
      const handle = one(p, "handle") ?? "";
      const body = [
        "<!-- SecretSafe DID registration (opt-in). Only public identifiers are included. -->",
        `did: ${cfg.did}`,
        `vault: ${cfg.orgDid}`,
        `network: ${cfg.env}`,
        `version: ${VERSION}`,
        `client: ${process.platform}`,
        handle ? `handle: ${handle}` : "handle: (optional, e.g. your X or GitHub handle)",
      ].join("\n");
      const url =
        "https://github.com/ElTanque81/secretsafe/issues/new?" +
        new URLSearchParams({ template: "did-registration.md", title: `DID registration: ${cfg.did.slice(-8)}`, labels: "did-registration", body }).toString();
      out(t("registerInfo", { did: cfg.did }));
      out(url);
      if (one(p, "no-open") === undefined) {
        const opener = process.platform === "darwin" ? "open" : process.platform === "win32" ? "explorer" : "xdg-open";
        spawnSync(opener, [url], { stdio: "ignore" });
      }
      return;
    }

    case "init": {
      const env = envOf(p);
      err(t("connecting", { env }));
      const cfg = loadConfig();
      const existing = cfg?.env === env ? cfg.orgDid : undefined;
      const { vault, created } = await T3Vault.open({ apiKey: apiKey(), env, orgDid: existing, log }, true);
      out(t("authenticated", { did: vault.did }));
      if (created) err(t("creatingVault"));
      saveConfig({ env, did: vault.did, orgDid: vault.orgDid });
      out(created ? t("vaultReady", { org: vault.orgDid }) : t("vaultExists", { org: vault.orgDid }));
      out(t("initDone"));
      out(t("registerHint"));
      return;
    }

    case "add": {
      const name = normaliseName(p.pos[0] ?? "");
      const hosts = p.flags.host ?? [];
      if (hosts.length === 0) throw new Error(t("needHost"));
      const value = await readHidden(t("enterValue", { name }));
      const w = looksLikeWalletSecret(value);
      if (w && !(w === "evm-private-key" && one(p, "not-a-wallet-key") !== undefined)) throw new Error(t("walletRefused", { kind: w }));
      const vault = await openVault(p, log);
      const policy = validatePolicy({ value, hosts, header: one(p, "header"), query: one(p, "query"), note: one(p, "note") });
      await vault.put(name, policy);
      out(t("added", { name, hosts: policy.hosts.join(", ") }));
      return;
    }

    case "scan": {
      // Never prints secret values: only public prefixes, length and a fingerprint.
      const root = resolve(p.pos[0] ?? ".");
      const findings = scanPath(root);
      if (one(p, "json") !== undefined) {
        out(JSON.stringify({ root, count: findings.length, findings }, null, 2));
        return;
      }
      if (findings.length === 0) return out(t("scanNone", { root }));
      out(t("scanHeader", { n: findings.length, root }));
      for (const f of findings) {
        out(`\n  ${f.file}:${f.line}  ${f.label}${f.variable ? `  (${f.variable})` : ""}`);
        out(`    ${f.preview}   fp:${f.fp}`);
        if (f.note) out(`    ⚠ ${f.note}`);
        else {
          const inj = f.header ? ` --header "${f.header}"` : f.query ? ` --query ${f.query}` : ` --header "Authorization: Bearer {{secret}}"`;
          const rel = relative(process.cwd(), join(root, f.file)) || f.file;
          out(`    → secretsafe import ${f.suggestedName} --file ${JSON.stringify(rel)} --fp ${f.fp} --host ${f.host ?? "<api.host.com>"}${inj}`);
        }
      }
      out("\n" + t("scanFooter"));
      return;
    }

    case "import": {
      // Moves a secret straight from a file into the T3N vault. The value never reaches stdout or argv.
      const name = normaliseName(p.pos[0] ?? "");
      const file = one(p, "file");
      if (!file) throw new Error("--file is required");
      const hosts = p.flags.host ?? [];
      if (hosts.length === 0) throw new Error(t("needHost"));
      const { value, finding } = extractValue(resolve(file), { fp: one(p, "fp"), variable: one(p, "var") });
      if (WALLET_DETECTORS.has(finding.detector) || (looksLikeWalletSecret(value) && one(p, "not-a-wallet-key") === undefined)) {
        throw new Error(t("walletRefused", { kind: finding.detector }));
      }
      const policy = validatePolicy({ value, hosts, header: one(p, "header"), query: one(p, "query"), note: one(p, "note") ?? `imported from ${file}:${finding.line}` });
      const vault = await openVault(p, log);
      await vault.put(name, policy);
      out(t("imported", { name, file, line: finding.line, fp: finding.fp, hosts: policy.hosts.join(", ") }));
      out(t("importNext", { file, line: finding.line }));
      return;
    }

    case "list":
    case "ls": {
      const vault = await openVault(p, log);
      const items = await vault.list();
      if (one(p, "json") !== undefined) {
        const rows = [];
        for (const it of items) {
          const pol = await vault.get(it.name);
          rows.push({ name: it.name, version: it.version, updatedAt: it.updatedAt, hosts: pol.hosts, injection: pol.header ? `header ${pol.header.split(":")[0]}` : pol.query ? `query ${pol.query}` : "placeholder", note: pol.note ?? "" });
        }
        out(JSON.stringify({ did: vault.did, vault: vault.orgDid, secrets: rows }, null, 2));
        return;
      }
      if (items.length === 0) return out(t("noSecrets"));
      out(t("listHeader"));
      for (const it of items) {
        const pol = await vault.get(it.name);
        out(`  • ${it.name.padEnd(20)} → ${pol.hosts.join(", ")}${pol.note ? `   (${pol.note})` : ""}`);
      }
      return;
    }

    case "remove":
    case "rm": {
      const name = normaliseName(p.pos[0] ?? "");
      const vault = await openVault(p, log);
      await vault.remove(name);
      out(t("removed", { name }));
      return;
    }

    case "status": {
      const vault = await openVault(p, log);
      out(t("authenticated", { did: vault.did }));
      out(t("vaultExists", { org: vault.orgDid }));
      out(t("balance", { balance: await vault.balance() }));
      return;
    }

    case "audit": {
      let rows = readAudit(Number(one(p, "limit") ?? 20));
      const sec = one(p, "secret");
      const since = one(p, "since");
      if (sec) rows = rows.filter((r) => r.secret === sec);
      if (since) {
        const m = since.match(/^(\d+)([hd])$/);
        const cutoff = m ? Date.now() - Number(m[1]) * (m[2] === "h" ? 3_600_000 : 86_400_000) : Date.parse(since);
        if (!Number.isNaN(cutoff)) rows = rows.filter((r) => Date.parse(r.ts) >= cutoff);
      }
      if (one(p, "json") !== undefined) {
        out(JSON.stringify({ path: auditPath(), count: rows.length, entries: rows }, null, 2));
        return;
      }
      if (rows.length === 0) return out(t("auditEmpty"));
      out(t("auditHeader", { path: auditPath() }));
      for (const r of rows) {
        out(`  ${r.ts}  ${r.outcome.padEnd(6)} ${String(r.status ?? "-").padEnd(4)} ${r.secret.padEnd(14)} ${r.method} ${r.host}${r.path}${r.detail ? `  — ${r.detail}` : ""}`);
      }
      return;
    }

    case "config": {
      const entry = fileURLToPath(import.meta.url);
      const env: Record<string, string> = { T3N_ENV: envOf(p) };
      if (process.platform !== "darwin") env.T3N_API_KEY = "0x... (your T3 key)";
      out(t("mcpConfig"));
      out(JSON.stringify({ mcpServers: { secretsafe: { command: process.execPath, args: [entry, "serve", "--lang", "en"], env } } }, null, 2));
      if (process.platform === "darwin") out(t("keychainNote"));
      return;
    }

    case "serve": {
      // stdout belongs to the MCP protocol; all logs go to stderr.
      const vault = await openVault(p, log);
      const server = createServer({ vault, client: one(p, "client") ?? "mcp" });
      await server.connect(new StdioServerTransport());
      log(`[secretsafe] MCP server ${VERSION} ready · ${vault.did}`);
      return;
    }

    default:
      throw new Error(t("unknownCommand", { cmd: p.cmd }) + "\n\n" + t("help"));
  }
}

main().catch((e) => {
  err(t("error", { msg: e instanceof Error ? e.message : String(e) }));
  process.exit(1);
});
