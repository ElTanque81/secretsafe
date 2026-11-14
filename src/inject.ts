/**
 * Pure request-building and redaction logic. No network, no vault:
 * everything here is unit-tested.
 */

export const PLACEHOLDER = "{{secret}}";

/** What SecretSafe stores in the T3N vault for one secret (as a `json` secret). */
export interface SecretPolicy {
  /** The raw secret value (API key, token, ...). */
  value: string;
  /** Exact, lowercase hostnames the secret may be sent to. */
  hosts: string[];
  /**
   * Optional default injection when the agent does not use the placeholder,
   * e.g. "Authorization: Bearer {{secret}}" or "x-api-key: {{secret}}".
   */
  header?: string;
  /** Optional query-parameter name to inject the secret into, e.g. "key". */
  query?: string;
  /** Free-text note for the human owner (never contains the value). */
  note?: string;
  /**
   * Optional method + path rules, e.g. ["GET /user", "GET /repos/**"]. If set, a request must match
   * at least one rule (in addition to the host allow-list). `*` = one path segment, `**` = any depth,
   * method `*` = any method. Absent/empty = any method and path on the allowed hosts.
   */
  allow?: string[];
  /**
   * Where the agent may put {{secret}} itself: any of "header", "query", "body".
   * Absent = ["header", "query"]: body placement is off unless the owner turns it on, because a
   * secret in a request body can be stored by the API (e.g. a public gist) even though the response is redacted.
   * The owner-defined default injection (header/query template) is always allowed.
   */
  placement?: Placement[];
}

export type Placement = "header" | "query" | "body";
export const PLACEMENTS: Placement[] = ["header", "query", "body"];
export const DEFAULT_PLACEMENT: Placement[] = ["header", "query"];

/** Where the agent may place {{secret}} for this secret (falls back to the safe default). */
export function placementOf(p: SecretPolicy): Placement[] {
  return p.placement ?? DEFAULT_PLACEMENT;
}

export interface AgentRequest {
  method: string;
  url: string;
  headers?: Record<string, string>;
  query?: Record<string, string>;
  body?: string;
}

export interface BuiltRequest {
  method: string;
  url: string;
  headers: Record<string, string>;
  body?: string;
  host: string;
  injectedInto: string[];
}

/** Machine-readable refusal codes, so agents can decide to fix, retry or stop without seeing the secret. */
export type RefusalCode =
  | "HOST_NOT_ALLOWED"
  | "RULE_NOT_ALLOWED"
  | "METHOD_NOT_ALLOWED"
  | "INVALID_URL"
  | "HTTPS_REQUIRED"
  | "PORT_NOT_ALLOWED"
  | "CREDENTIALS_IN_URL"
  | "PLACEHOLDER_POSITION"
  | "PLACEMENT_NOT_ALLOWED"
  | "ENCODED_SLASH"
  | "INVALID_HEADER"
  | "BODY_NOT_ALLOWED"
  | "NO_INJECTION_TARGET"
  | "INVALID_POLICY";

export class PolicyError extends Error {
  constructor(message: string, readonly code: RefusalCode = "INVALID_POLICY") {
    super(message);
    this.name = "PolicyError";
  }
}

const METHODS = new Set(["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD"]);
const HOST_RE = /^(?=.{1,253}$)([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)(\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+$/;

/** Validate and normalise a hostname for the allow-list (no scheme, port, path or wildcard). */
export function normaliseHost(input: string): string {
  const h = input.trim().toLowerCase().replace(/\.$/, "");
  if (!HOST_RE.test(h)) {
    throw new PolicyError(`Invalid host "${input}". Use a bare hostname like api.openai.com (no https://, port, path or *).`);
  }
  return h;
}

/** Secret names: short, safe identifiers the agent can reference. */
export function normaliseName(input: string): string {
  const n = input.trim().toLowerCase();
  if (!/^[a-z0-9][a-z0-9_-]{0,47}$/.test(n)) {
    throw new PolicyError(`Invalid secret name "${input}". Use 1-48 chars: a-z, 0-9, - or _.`);
  }
  return n;
}

/** Parse "Header-Name: template" into [name, template]. */
export function parseHeaderTemplate(tpl: string): [string, string] {
  const i = tpl.indexOf(":");
  if (i <= 0) throw new PolicyError(`Header template must look like "Authorization: Bearer ${PLACEHOLDER}".`);
  const name = tpl.slice(0, i).trim();
  const value = tpl.slice(i + 1).trim();
  if (!/^[A-Za-z0-9-]+$/.test(name)) throw new PolicyError(`Invalid header name "${name}".`);
  if (!value.includes(PLACEHOLDER)) throw new PolicyError(`Header template must contain ${PLACEHOLDER}.`);
  return [name, value];
}

const RULE_RE = /^(\*|GET|POST|PUT|PATCH|DELETE|HEAD)(?:\|(?:GET|POST|PUT|PATCH|DELETE|HEAD))*\s+(\/[A-Za-z0-9\-._~!$&'()+,;=:@%*\/]*)$/;

/** Parse "GET /repos/**" or "GET|HEAD /user" into methods + path pattern. */
export function parseRule(rule: string): { methods: string[]; path: string } {
  const r = rule.trim().replace(/\s+/, " ");
  const [m, path] = r.split(" ");
  const upper = `${(m ?? "").toUpperCase()} ${path ?? ""}`;
  if (!RULE_RE.test(upper)) {
    throw new PolicyError(`Invalid allow rule "${rule}". Use "METHOD /path", e.g. "GET /repos/**" or "GET|HEAD /user" or "* /v1/**".`);
  }
  if (path.split("/").some((seg) => seg.includes("**") && seg !== "**")) {
    throw new PolicyError(`"**" must be a whole path segment in "${rule}".`);
  }
  return { methods: m.toUpperCase().split("|"), path };
}

function segMatch(pattern: string, seg: string): boolean {
  if (pattern === "*") return seg.length > 0;
  if (!pattern.includes("*")) return pattern === seg;
  const re = new RegExp("^" + pattern.split("*").map((x) => x.replace(/[.+?^${}()|[\]\\]/g, "\\$&")).join("[^/]*") + "$");
  return re.test(seg);
}

/** Glob match on path segments: `*` = one segment (or part of one), `**` = zero or more segments. */
export function pathMatches(pattern: string, path: string): boolean {
  const p = pattern.split("/").filter((x, i) => i > 0 || x !== "");
  const s = path.split("/").filter((x, i) => i > 0 || x !== "");
  const go = (i: number, j: number): boolean => {
    if (i === p.length) return j === s.length || (j === s.length - 1 && s[j] === "" && p.length > 0 && p[p.length - 1] !== "");
    if (p[i] === "**") {
      for (let k = j; k <= s.length; k++) if (go(i + 1, k)) return true;
      return false;
    }
    return j < s.length && segMatch(p[i], s[j]) && go(i + 1, j + 1);
  };
  return go(0, 0);
}

export function ruleAllows(rules: string[] | undefined, method: string, path: string): boolean {
  if (!rules || rules.length === 0) return true;
  return rules.some((r) => {
    const { methods, path: pat } = parseRule(r);
    return (methods.includes("*") || methods.includes(method)) && pathMatches(pat, path);
  });
}

export const READ_ONLY_RULES = ["GET|HEAD /**"];

export function validatePolicy(p: SecretPolicy): SecretPolicy {
  if (typeof p.value !== "string" || p.value.length === 0) throw new PolicyError("Secret value is empty.");
  if (p.value.length > 8192) throw new PolicyError("Secret value is too long (max 8192 chars).");
  if (/[\r\n]/.test(p.value)) throw new PolicyError("Secret value must not contain line breaks.");
  if (!Array.isArray(p.hosts) || p.hosts.length === 0) throw new PolicyError("At least one allowed host is required.");
  const hosts = [...new Set(p.hosts.map(normaliseHost))];
  if (p.header) parseHeaderTemplate(p.header);
  if (p.query !== undefined && !/^[A-Za-z0-9_.-]{1,64}$/.test(p.query)) throw new PolicyError(`Invalid query parameter name "${p.query}".`);
  let allow: string[] | undefined;
  if (p.allow !== undefined) {
    if (!Array.isArray(p.allow)) throw new PolicyError("allow must be a list of rules.");
    allow = [...new Set(p.allow.map((r) => r.trim().replace(/\s+/, " ")))];
    allow.forEach(parseRule);
    if (allow.length === 0) allow = undefined;
  }
  let placement: Placement[] | undefined;
  if (p.placement !== undefined) {
    if (!Array.isArray(p.placement)) throw new PolicyError("placement must be a list of: header, query, body.");
    const set = new Set(p.placement.map((x) => String(x).trim().toLowerCase()));
    for (const x of set) if (!PLACEMENTS.includes(x as Placement)) throw new PolicyError(`Invalid placement "${x}". Use header, query and/or body.`);
    placement = PLACEMENTS.filter((x) => set.has(x));
  }
  const out: SecretPolicy = { ...p, hosts };
  if (allow) out.allow = allow; else delete out.allow;
  if (placement) out.placement = placement; else delete out.placement;
  return out;
}

function fill(s: string, value: string): string {
  return s.split(PLACEHOLDER).join(value);
}

/**
 * Turn the agent's request (which only contains `{{secret}}` placeholders)
 * into the real outbound request. Throws PolicyError on anything the policy forbids.
 */
export function buildRequest(req: AgentRequest, policy: SecretPolicy): BuiltRequest {
  const method = (req.method || "GET").toUpperCase();
  if (!METHODS.has(method)) throw new PolicyError(`Method ${method} is not allowed.`, "METHOD_NOT_ALLOWED");

  let url: URL;
  try {
    url = new URL(req.url);
  } catch {
    throw new PolicyError(`Invalid URL "${req.url}".`, "INVALID_URL");
  }
  if (url.protocol !== "https:") throw new PolicyError("Only https:// URLs are allowed.", "HTTPS_REQUIRED");
  if (url.username || url.password) throw new PolicyError("Credentials in the URL are not allowed.", "CREDENTIALS_IN_URL");
  if (url.port && url.port !== "443") throw new PolicyError("Custom ports are not allowed.", "PORT_NOT_ALLOWED");
  if (url.hostname.includes(PLACEHOLDER) || req.url.split("?")[0].includes(PLACEHOLDER)) {
    // Placeholders in scheme/host/path would let the value leak into DNS, proxies and logs.
    throw new PolicyError(`${PLACEHOLDER} is only allowed in headers, query values and the body.`, "PLACEHOLDER_POSITION");
  }
  const host = url.hostname.toLowerCase();
  if (!policy.hosts.includes(host)) {
    throw new PolicyError(`Host "${host}" is not on this secret's allow-list (${policy.hosts.join(", ")}).`, "HOST_NOT_ALLOWED");
  }
  if (policy.allow && policy.allow.length > 0) {
    // url.pathname is already dot-segment-normalised by the URL parser. Encoded slashes/backslashes could be
    // decoded differently by the server, so they are refused when path rules are active.
    if (/%2f|%5c|\\/i.test(url.pathname)) throw new PolicyError("Encoded slashes are not allowed in the path when method/path rules are set.", "ENCODED_SLASH");
    if (!ruleAllows(policy.allow, method, url.pathname)) {
      throw new PolicyError(`${method} ${url.pathname} is not allowed for this secret (rules: ${policy.allow.join(", ")}).`, "RULE_NOT_ALLOWED");
    }
  }

  const injectedInto: string[] = [];
  const allowed = placementOf(policy);
  const refusePlacement = (where: Placement) => {
    throw new PolicyError(
      `${PLACEHOLDER} in the ${where} is not allowed for this secret (allowed: ${allowed.join(", ") || "none, default injection only"}). ` +
        (where === "body" ? "A secret in a request body can be stored by the API. The owner can allow it with --placement body." : `The owner can allow it with --placement ${where}.`),
      "PLACEMENT_NOT_ALLOWED",
    );
  };

  // Query: existing query values + agent-supplied query map.
  const params = new URLSearchParams(url.search);
  for (const [k, v] of Object.entries(req.query ?? {})) params.set(k, String(v));
  for (const [k, v] of [...params.entries()]) {
    if (v.includes(PLACEHOLDER)) {
      if (!allowed.includes("query")) refusePlacement("query");
      params.set(k, fill(v, policy.value));
      injectedInto.push(`query:${k}`);
    }
  }

  const headers: Record<string, string> = {};
  for (const [k, v] of Object.entries(req.headers ?? {})) {
    if (!/^[A-Za-z0-9-]+$/.test(k)) throw new PolicyError(`Invalid header name "${k}".`, "INVALID_HEADER");
    const val = String(v);
    if (/[\r\n]/.test(val)) throw new PolicyError(`Header "${k}" contains a line break.`, "INVALID_HEADER");
    if (val.includes(PLACEHOLDER)) {
      if (!allowed.includes("header")) refusePlacement("header");
      headers[k] = fill(val, policy.value);
      injectedInto.push(`header:${k}`);
    } else {
      headers[k] = val;
    }
  }

  let body = req.body;
  if (body !== undefined && body.includes(PLACEHOLDER)) {
    if (!allowed.includes("body")) refusePlacement("body");
    body = fill(body, policy.value);
    injectedInto.push("body");
  }

  // Default injection when the agent did not place the secret itself.
  if (injectedInto.length === 0) {
    if (policy.header) {
      const [name, tpl] = parseHeaderTemplate(policy.header);
      headers[name] = fill(tpl, policy.value);
      injectedInto.push(`header:${name}`);
    } else if (policy.query) {
      params.set(policy.query, policy.value);
      injectedInto.push(`query:${policy.query}`);
    } else {
      throw new PolicyError(
        `Nowhere to put the secret. Use ${PLACEHOLDER} in a header, query value or the body, or store the secret with a default header/query.`,
        "NO_INJECTION_TARGET",
      );
    }
  }

  const search = params.toString();
  url.search = search ? `?${search}` : "";
  if ((method === "GET" || method === "HEAD") && body !== undefined && body !== "") {
    throw new PolicyError(`${method} requests cannot have a body.`, "BODY_NOT_ALLOWED");
  }
  return { method, url: url.toString(), headers, body, host, injectedInto };
}

/** Every form in which the secret could appear in a response or error. */
export function secretVariants(value: string): string[] {
  const v = new Set<string>([value]);
  v.add(encodeURIComponent(value));
  v.add(Buffer.from(value, "utf8").toString("base64"));
  v.add(Buffer.from(value, "utf8").toString("base64url"));
  return [...v].filter((s) => s.length >= 4).sort((a, b) => b.length - a.length);
}

/** Replace every occurrence of the secret (and its encodings) with a marker. */
export function redact(text: string, value: string, name: string): string {
  return redactCount(text, value, name).text;
}

/** Like redact(), but also reports how many occurrences were replaced (for the receipt). */
export function redactCount(text: string, value: string, name: string): { text: string; count: number } {
  let out = text;
  let count = 0;
  for (const variant of secretVariants(value)) {
    const parts = out.split(variant);
    count += parts.length - 1;
    out = parts.join(`[REDACTED:${name}]`);
  }
  return { text: out, count };
}

/** Response headers worth showing the agent (cookies and auth echoes are dropped). */
const SAFE_RESPONSE_HEADERS = new Set([
  "content-type",
  "content-length",
  "date",
  "retry-after",
  "x-request-id",
  "x-ratelimit-limit",
  "x-ratelimit-remaining",
  "x-ratelimit-reset",
  "location",
]);

export function filterResponseHeaders(h: Iterable<[string, string]>): Record<string, string> {
  const out: Record<string, string> = {};
  for (const [k, v] of h) {
    const key = k.toLowerCase();
    if (SAFE_RESPONSE_HEADERS.has(key) || key.startsWith("x-ratelimit")) out[key] = v;
  }
  return out;
}
