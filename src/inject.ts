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

export class PolicyError extends Error {
  constructor(message: string) {
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

export function validatePolicy(p: SecretPolicy): SecretPolicy {
  if (typeof p.value !== "string" || p.value.length === 0) throw new PolicyError("Secret value is empty.");
  if (p.value.length > 8192) throw new PolicyError("Secret value is too long (max 8192 chars).");
  if (/[\r\n]/.test(p.value)) throw new PolicyError("Secret value must not contain line breaks.");
  if (!Array.isArray(p.hosts) || p.hosts.length === 0) throw new PolicyError("At least one allowed host is required.");
  const hosts = [...new Set(p.hosts.map(normaliseHost))];
  if (p.header) parseHeaderTemplate(p.header);
  if (p.query !== undefined && !/^[A-Za-z0-9_.-]{1,64}$/.test(p.query)) throw new PolicyError(`Invalid query parameter name "${p.query}".`);
  return { ...p, hosts };
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
  if (!METHODS.has(method)) throw new PolicyError(`Method ${method} is not allowed.`);

  let url: URL;
  try {
    url = new URL(req.url);
  } catch {
    throw new PolicyError(`Invalid URL "${req.url}".`);
  }
  if (url.protocol !== "https:") throw new PolicyError("Only https:// URLs are allowed.");
  if (url.username || url.password) throw new PolicyError("Credentials in the URL are not allowed.");
  if (url.port && url.port !== "443") throw new PolicyError("Custom ports are not allowed.");
  if (url.hostname.includes(PLACEHOLDER) || req.url.split("?")[0].includes(PLACEHOLDER)) {
    // Placeholders in scheme/host/path would let the value leak into DNS, proxies and logs.
    throw new PolicyError(`${PLACEHOLDER} is only allowed in headers, query values and the body.`);
  }
  const host = url.hostname.toLowerCase();
  if (!policy.hosts.includes(host)) {
    throw new PolicyError(`Host "${host}" is not on this secret's allow-list (${policy.hosts.join(", ")}).`);
  }

  const injectedInto: string[] = [];

  // Query: existing query values + agent-supplied query map.
  const params = new URLSearchParams(url.search);
  for (const [k, v] of Object.entries(req.query ?? {})) params.set(k, String(v));
  for (const [k, v] of [...params.entries()]) {
    if (v.includes(PLACEHOLDER)) {
      params.set(k, fill(v, policy.value));
      injectedInto.push(`query:${k}`);
    }
  }

  const headers: Record<string, string> = {};
  for (const [k, v] of Object.entries(req.headers ?? {})) {
    if (!/^[A-Za-z0-9-]+$/.test(k)) throw new PolicyError(`Invalid header name "${k}".`);
    const val = String(v);
    if (/[\r\n]/.test(val)) throw new PolicyError(`Header "${k}" contains a line break.`);
    if (val.includes(PLACEHOLDER)) {
      headers[k] = fill(val, policy.value);
      injectedInto.push(`header:${k}`);
    } else {
      headers[k] = val;
    }
  }

  let body = req.body;
  if (body !== undefined && body.includes(PLACEHOLDER)) {
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
      );
    }
  }

  const search = params.toString();
  url.search = search ? `?${search}` : "";
  if ((method === "GET" || method === "HEAD") && body !== undefined && body !== "") {
    throw new PolicyError(`${method} requests cannot have a body.`);
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
  let out = text;
  for (const variant of secretVariants(value)) {
    out = out.split(variant).join(`[REDACTED:${name}]`);
  }
  return out;
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
