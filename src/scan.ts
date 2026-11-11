/**
 * Secret scanner. Finds likely API keys in a project WITHOUT ever outputting them:
 * findings carry a masked preview (known public prefix only), length and a SHA-256 fingerprint.
 * `import` re-scans the file and picks the value by fingerprint, so the value never passes
 * through the agent, the terminal output or argv.
 */
import { createHash } from "node:crypto";
import { readdirSync, readFileSync, statSync } from "node:fs";
import { join, relative, basename } from "node:path";

export interface Detector {
  id: string;
  label: string;
  re: RegExp; // must have a capture group 1 = the secret
  prefix: number; // how many leading chars are a public, non-secret prefix (safe to show)
  host?: string; // suggested allow-listed host
  header?: string; // suggested header template
  query?: string; // suggested query param
  note?: string;
}

const B = "(?<![A-Za-z0-9_-])"; // left boundary
const E = "(?![A-Za-z0-9_-])"; // right boundary

export const DETECTORS: Detector[] = [
  { id: "anthropic", label: "Anthropic API key", re: new RegExp(`${B}(sk-ant-[A-Za-z0-9_-]{20,})${E}`, "g"), prefix: 7, host: "api.anthropic.com", header: "x-api-key: {{secret}}" },
  { id: "openai", label: "OpenAI API key", re: new RegExp(`${B}(sk-(?:proj-|svcacct-|admin-)?[A-Za-z0-9_-]{20,})${E}`, "g"), prefix: 3, host: "api.openai.com", header: "Authorization: Bearer {{secret}}" },
  { id: "github", label: "GitHub token", re: new RegExp(`${B}((?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{40,})${E}`, "g"), prefix: 4, host: "api.github.com", header: "Authorization: Bearer {{secret}}" },
  { id: "stripe", label: "Stripe key", re: new RegExp(`${B}((?:sk|rk)_(?:live|test)_[A-Za-z0-9]{16,})${E}`, "g"), prefix: 8, host: "api.stripe.com", header: "Authorization: Bearer {{secret}}" },
  { id: "google", label: "Google API key (Gemini etc.)", re: new RegExp(`${B}(AIza[A-Za-z0-9_-]{35})${E}`, "g"), prefix: 4, host: "generativelanguage.googleapis.com", query: "key" },
  { id: "slack", label: "Slack token", re: new RegExp(`${B}(xox[abposr]-[A-Za-z0-9-]{10,})${E}`, "g"), prefix: 5, host: "slack.com", header: "Authorization: Bearer {{secret}}" },
  { id: "huggingface", label: "Hugging Face token", re: new RegExp(`${B}(hf_[A-Za-z0-9]{30,})${E}`, "g"), prefix: 3, host: "huggingface.co", header: "Authorization: Bearer {{secret}}" },
  { id: "groq", label: "Groq API key", re: new RegExp(`${B}(gsk_[A-Za-z0-9]{40,})${E}`, "g"), prefix: 4, host: "api.groq.com", header: "Authorization: Bearer {{secret}}" },
  { id: "sendgrid", label: "SendGrid API key", re: new RegExp(`${B}(SG\\.[A-Za-z0-9_-]{16,}\\.[A-Za-z0-9_-]{16,})${E}`, "g"), prefix: 3, host: "api.sendgrid.com", header: "Authorization: Bearer {{secret}}" },
  { id: "resend", label: "Resend API key", re: new RegExp(`${B}(re_[A-Za-z0-9]{8,}_[A-Za-z0-9]{16,})${E}`, "g"), prefix: 3, host: "api.resend.com", header: "Authorization: Bearer {{secret}}" },
  { id: "aws", label: "AWS access key id", re: new RegExp(`${B}(AKIA[0-9A-Z]{16})${E}`, "g"), prefix: 4, note: "AWS uses request signing (SigV4); SecretSafe cannot inject it. Rotate it and use AWS's own credential tooling." },
  { id: "private-key", label: "Private key block", re: /(-----BEGIN [A-Z ]*PRIVATE KEY-----)/g, prefix: 0, note: "Private keys are not API keys; move them out of the repo and rotate them." },
];

/** Generic `NAME=value` / `NAME: "value"` assignments whose name looks secret, for keys without a known prefix. */
const GENERIC_ASSIGN = /(?:^|[\s,{;(])["']?([A-Z0-9_]*(?:API_?KEY|TOKEN|SECRET|ACCESS_KEY|AUTH)[A-Z0-9_]*)["']?\s*[:=]\s*["']?([^\s"'`,;#]{16,})/gim;

export interface Finding {
  file: string; // relative path
  line: number;
  detector: string;
  label: string;
  variable?: string; // env/assignment name if detectable
  preview: string; // public prefix + mask, never the secret body
  length: number;
  fp: string; // sha256 fingerprint (first 12 hex)
  suggestedName: string;
  host?: string;
  header?: string;
  query?: string;
  note?: string;
}

export function fingerprint(value: string): string {
  return createHash("sha256").update(value, "utf8").digest("hex").slice(0, 12);
}

export function mask(value: string, prefix: number): string {
  return `${value.slice(0, prefix)}${"•".repeat(6)} (${value.length} chars)`;
}

const SKIP_DIRS = new Set(["node_modules", ".git", "dist", "build", ".next", "out", "coverage", ".venv", "venv", "__pycache__", "target", ".turbo", ".cache", "dist-test"]);
const MAX_BYTES = 1_000_000;

function isProbablyText(buf: Buffer): boolean {
  const n = Math.min(buf.length, 4096);
  for (let i = 0; i < n; i++) if (buf[i] === 0) return false;
  return true;
}

const PLACEHOLDER_RE = /^(x+|\*+|your[_-]?|<|\$\{|\{\{|changeme|example|placeholder|test[_-]?key|dummy|xxx)/i;

function looksLikePlaceholder(v: string): boolean {
  if (PLACEHOLDER_RE.test(v)) return true;
  if (/(.)\1{7,}/.test(v)) return true; // aaaaaaaa…
  if (v.includes("...") || v.includes("•")) return true;
  return false;
}

function varNameAt(lineText: string, index: number): string | undefined {
  const before = lineText.slice(0, index);
  const m = before.match(/["']?([A-Za-z_][A-Za-z0-9_]*)["']?\s*[:=]\s*["']?$/);
  return m?.[1];
}

function suggestName(detector: string, variable?: string): string {
  if (detector !== "generic") return detector;
  const v = (variable ?? "secret").toLowerCase().replace(/_?(api_?key|token|secret|access_key|auth)$/, "").replace(/_/g, "-");
  return (v || "secret").slice(0, 48).replace(/^-+|-+$/g, "") || "secret";
}

/** Scan one text for findings (exported for tests). */
export function scanText(text: string, file: string): (Finding & { value: string })[] {
  const out: (Finding & { value: string })[] = [];
  const seen = new Set<string>();
  const lines = text.split(/\r?\n/);
  lines.forEach((lineText, i) => {
    for (const d of DETECTORS) {
      d.re.lastIndex = 0;
      let m: RegExpExecArray | null;
      while ((m = d.re.exec(lineText))) {
        const value = m[1];
        if (d.id !== "private-key" && looksLikePlaceholder(value.slice(d.prefix))) continue;
        const key = `${i}:${value}`;
        if (seen.has(key)) continue;
        // anthropic keys also match the openai pattern; the anthropic detector runs first
        if ([...seen].some((s) => s.startsWith(`${i}:`) && s.endsWith(value))) continue;
        seen.add(key);
        const variable = varNameAt(lineText, m.index + m[0].indexOf(value));
        out.push({
          file, line: i + 1, detector: d.id, label: d.label, variable,
          preview: d.id === "private-key" ? value : mask(value, d.prefix), length: value.length, fp: fingerprint(value),
          suggestedName: suggestName(d.id, variable), host: d.host, header: d.header, query: d.query, note: d.note, value,
        });
      }
    }
    GENERIC_ASSIGN.lastIndex = 0;
    let g: RegExpExecArray | null;
    while ((g = GENERIC_ASSIGN.exec(lineText))) {
      const [, variable, value] = g;
      if (looksLikePlaceholder(value)) continue;
      if (/^(true|false|null|undefined|process\.env|os\.environ|env\.|import|require)/i.test(value)) continue;
      if ([...seen].some((s) => s.startsWith(`${i}:`) && (s.endsWith(value) || value.includes(s.slice(s.indexOf(":") + 1))))) continue;
      seen.add(`${i}:${value}`);
      out.push({
        file, line: i + 1, detector: "generic", label: "Secret-looking assignment", variable,
        preview: mask(value, 0), length: value.length, fp: fingerprint(value), suggestedName: suggestName("generic", variable), value,
      });
    }
  });
  return out;
}

/** Walk a directory and scan all text files. */
export function scanPath(root: string, maxFiles = 20_000): Finding[] {
  const findings: Finding[] = [];
  let files = 0;
  const walk = (dir: string) => {
    let entries: string[];
    try {
      entries = readdirSync(dir);
    } catch {
      return;
    }
    for (const name of entries) {
      if (files >= maxFiles) return;
      const full = join(dir, name);
      let st;
      try {
        st = statSync(full);
      } catch {
        continue;
      }
      if (st.isDirectory()) {
        if (!SKIP_DIRS.has(name)) walk(full);
      } else if (st.isFile() && st.size <= MAX_BYTES) {
        if (/\.(lock|png|jpe?g|gif|webp|ico|pdf|zip|gz|mp4|mov|wasm|woff2?|ttf|otf)$/i.test(name) || name === "package-lock.json") continue;
        files++;
        const buf = readFileSync(full);
        if (!isProbablyText(buf)) continue;
        for (const f of scanText(buf.toString("utf8"), relative(root, full) || basename(full))) {
          const { value: _v, ...safe } = f;
          findings.push(safe);
        }
      }
    }
  };
  const st = statSync(root);
  if (st.isFile()) {
    for (const f of scanText(readFileSync(root, "utf8"), basename(root))) {
      const { value: _v, ...safe } = f;
      findings.push(safe);
    }
  } else walk(root);
  return findings;
}

/** Re-read a file and return the secret value whose fingerprint matches (or that is assigned to `variable`). */
export function extractValue(file: string, sel: { fp?: string; variable?: string }): { value: string; finding: Finding } {
  const text = readFileSync(file, "utf8");
  const matches = scanText(text, basename(file)).filter(
    (f) => (sel.fp ? f.fp === sel.fp.toLowerCase() : true) && (sel.variable ? f.variable === sel.variable : true),
  );
  if (matches.length === 0) throw new Error(`No secret matching ${sel.fp ? `fingerprint ${sel.fp}` : `variable ${sel.variable}`} found in ${file}.`);
  const uniq = new Set(matches.map((m) => m.fp));
  if (uniq.size > 1) throw new Error(`More than one secret matches in ${file}; pass --fp to pick one.`);
  const { value, ...finding } = matches[0];
  return { value, finding };
}
