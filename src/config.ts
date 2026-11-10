import { mkdirSync, readFileSync, writeFileSync, appendFileSync, existsSync, chmodSync } from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";

/** Local, non-secret state. The T3 key stays in the environment; secret values live only in T3N. */
export interface LocalConfig {
  env: string;
  did?: string;
  orgDid?: string;
}

export function homeDir(): string {
  const dir = process.env.SECRETSAFE_HOME || join(homedir(), ".secretsafe");
  mkdirSync(dir, { recursive: true, mode: 0o700 });
  return dir;
}

export function configPath(): string {
  return join(homeDir(), "config.json");
}

export function auditPath(): string {
  return join(homeDir(), "audit.jsonl");
}

export function loadConfig(): LocalConfig | null {
  const p = configPath();
  if (!existsSync(p)) return null;
  try {
    return JSON.parse(readFileSync(p, "utf8")) as LocalConfig;
  } catch {
    return null;
  }
}

export function saveConfig(c: LocalConfig): void {
  const p = configPath();
  writeFileSync(p, JSON.stringify(c, null, 2) + "\n", { mode: 0o600 });
  try {
    chmodSync(p, 0o600);
  } catch {
    /* best effort */
  }
}

export interface AuditEntry {
  ts: string;
  secret: string;
  method: string;
  host: string;
  path: string;
  status: number | null;
  outcome: "ok" | "denied" | "error";
  detail?: string;
  client?: string;
}

/** Append-only local audit log. Never contains secret values (callers pass redacted data only). */
export function appendAudit(e: AuditEntry): void {
  appendFileSync(auditPath(), JSON.stringify(e) + "\n", { mode: 0o600 });
}

export function readAudit(limit = 20): AuditEntry[] {
  const p = auditPath();
  if (!existsSync(p)) return [];
  const lines = readFileSync(p, "utf8").trim().split("\n").filter(Boolean);
  return lines.slice(-limit).map((l) => JSON.parse(l) as AuditEntry);
}
