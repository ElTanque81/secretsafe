import {
  T3nClient,
  loadWasmComponent,
  createEthAuthInput,
  eth_get_address,
  metamask_sign,
  fetchTrustedManifest,
  createOrgDataClientFromSession,
  NODE_URLS,
  SessionExpiredError,
  formatTokens,
  type Environment,
} from "@terminal3/t3n-sdk";
import { validatePolicy, type SecretPolicy } from "./inject.js";

export interface SecretSummary {
  name: string;
  version: number;
  updatedAt: string;
}

/** Storage backend for secret policies. The real one is T3N; MemoryVault is for tests. */
export interface Vault {
  readonly did: string;
  readonly orgDid: string;
  put(name: string, policy: SecretPolicy): Promise<void>;
  get(name: string): Promise<SecretPolicy>;
  list(): Promise<SecretSummary[]>;
  remove(name: string): Promise<void>;
  balance(): Promise<string>;
}

export class MemoryVault implements Vault {
  readonly did = "did:t3n:0000000000000000000000000000000000000000";
  readonly orgDid = "did:t3n:1111111111111111111111111111111111111111";
  private store = new Map<string, { p: SecretPolicy; v: number; at: number }>();
  async put(name: string, policy: SecretPolicy) {
    const prev = this.store.get(name);
    this.store.set(name, { p: validatePolicy(policy), v: (prev?.v ?? 0) + 1, at: Date.now() });
  }
  async get(name: string) {
    const e = this.store.get(name);
    if (!e) throw new Error(`Unknown secret "${name}".`);
    return e.p;
  }
  async list() {
    return [...this.store.entries()].map(([name, e]) => ({ name, version: e.v, updatedAt: new Date(e.at).toISOString() }));
  }
  async remove(name: string) {
    this.store.delete(name);
  }
  async balance() {
    return "∞ (memory vault)";
  }
}

export interface T3VaultOptions {
  apiKey: string;
  env: Environment;
  orgDid?: string;
  log?: (msg: string) => void;
}

/** Session handle on T3N, re-established automatically when it expires. */
class T3Session {
  private client: T3nClient | null = null;
  private didValue: string | null = null;
  constructor(private readonly opts: T3VaultOptions) {}

  get baseUrl(): string {
    return NODE_URLS[this.opts.env];
  }

  async connect(): Promise<{ client: T3nClient; did: string }> {
    if (this.client && this.didValue) return { client: this.client, did: this.didValue };
    const key = this.opts.apiKey.startsWith("0x") ? this.opts.apiKey : `0x${this.opts.apiKey}`;
    const address = eth_get_address(key);
    let trustAnchor: Awaited<ReturnType<typeof fetchTrustedManifest>> | { unsafe_trust_server: true };
    try {
      trustAnchor = await fetchTrustedManifest(this.opts.env, { baseUrl: this.baseUrl });
    } catch (err) {
      // Signed manifests are not published on every network yet (see SDK docs).
      // We only fall back on testnet, and only with a loud warning.
      if (this.opts.env !== "production" || process.env.SECRETSAFE_UNSAFE_TRUST === "1") {
        this.opts.log?.(`[secretsafe] warning: could not verify T3N trust manifest (${(err as Error).message}); continuing without enclave attestation pinning on ${this.opts.env}.`);
        trustAnchor = { unsafe_trust_server: true };
      } else {
        throw err;
      }
    }
    const client = new T3nClient({
      baseUrl: this.baseUrl,
      trustAnchor,
      wasmComponent: await loadWasmComponent(),
      handlers: { EthSign: metamask_sign(address, undefined, key) },
    });
    await client.handshake();
    const did = await client.authenticate(createEthAuthInput(address));
    this.client = client;
    this.didValue = did.toString();
    return { client, did: this.didValue };
  }

  reset() {
    this.client = null;
    this.didValue = null;
  }

  /** Run fn with a live session; on session expiry reconnect once and retry. */
  async run<T>(fn: (client: T3nClient) => Promise<T>): Promise<T> {
    const { client } = await this.connect();
    try {
      return await fn(client);
    } catch (err) {
      if (err instanceof SessionExpiredError) {
        this.reset();
        const again = await this.connect();
        return fn(again.client);
      }
      throw err;
    }
  }
}

/**
 * Secrets live as `json` org secrets in the user's own T3 organisation, readable only
 * by the user's own did:t3n. Each read is an authenticated, metered call on T3N.
 */
export class T3Vault implements Vault {
  private session: T3Session;
  private _did = "";
  private _org = "";

  private constructor(private readonly opts: T3VaultOptions) {
    this.session = new T3Session(opts);
  }

  get did() {
    return this._did;
  }
  get orgDid() {
    return this._org;
  }

  /** Connect, and create the personal vault org on first use. */
  static async open(opts: T3VaultOptions, createIfMissing = false): Promise<{ vault: T3Vault; created: boolean }> {
    const v = new T3Vault(opts);
    const { client, did } = await v.session.connect();
    v._did = did;
    let created = false;
    if (opts.orgDid) {
      v._org = opts.orgDid;
    } else if (createIfMissing) {
      const org = await client.createOrganisation(`SecretSafe vault ${did.slice(-8)}`);
      v._org = org.toString();
      created = true;
    } else {
      throw new Error("No vault organisation configured. Run: secretsafe init");
    }
    return { vault: v, created };
  }

  async put(name: string, policy: SecretPolicy): Promise<void> {
    const p = validatePolicy(policy);
    await this.session.run(async (client) => {
      const od = createOrgDataClientFromSession(client, this.session.baseUrl);
      await od.secretWrite({
        orgDid: this._org,
        name,
        kind: "json",
        value: JSON.stringify(p),
        readerDids: [this._did],
        managerDids: [this._did],
      });
    });
  }

  async get(name: string): Promise<SecretPolicy> {
    const rec = await this.session.run(async (client) =>
      createOrgDataClientFromSession(client, this.session.baseUrl).secretGet({ orgDid: this._org, name }),
    );
    const parsed = JSON.parse(rec.value) as SecretPolicy;
    return validatePolicy(parsed);
  }

  async list(): Promise<SecretSummary[]> {
    const views = await this.session.run(async (client) =>
      createOrgDataClientFromSession(client, this.session.baseUrl).secretList({ orgDid: this._org }),
    );
    return views.map((v) => ({ name: v.name, version: v.version, updatedAt: new Date(v.updated_at_secs * 1000).toISOString() }));
  }

  async remove(name: string): Promise<void> {
    await this.session.run(async (client) =>
      createOrgDataClientFromSession(client, this.session.baseUrl).secretDelete({ orgDid: this._org, name }),
    );
  }

  async balance(): Promise<string> {
    const row = await this.session.run((client) => client.getBalance());
    return `${formatTokens(row.available)} T3N credits${row.credit_exhausted ? " (exhausted!)" : ""}`;
  }
}
