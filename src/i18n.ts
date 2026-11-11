/** Tiny i18n for CLI output. English is the default; German via SECRETSAFE_LANG=de or --lang de. */

export type Lang = "en" | "de";

const en = {
  missingKey: "T3N_API_KEY is not set. Claim your free T3 account + API key at https://www.terminal3.io/claim-page, then: export T3N_API_KEY=0x...",
  connecting: "Connecting to Terminal 3 network ({env})...",
  authenticated: "Authenticated as {did}",
  creatingVault: "Creating your personal vault (T3 organisation)...",
  vaultReady: "Vault ready: {org}",
  vaultExists: "Vault already set up: {org}",
  initDone: "Done. Next: secretsafe add <name> --host <api.host.com> --header \"Authorization: Bearer {{secret}}\"",
  notInitialised: "No vault yet. Run: secretsafe init",
  enterValue: "Paste the secret value for \"{name}\" (input hidden, then Enter): ",
  added: "Stored \"{name}\" in your T3N vault. Allowed hosts: {hosts}",
  removed: "Removed \"{name}\".",
  noSecrets: "No secrets stored yet.",
  listHeader: "Secrets in your vault (values never shown):",
  balance: "Credit balance: {balance}",
  auditEmpty: "No secret usage recorded yet.",
  auditHeader: "Recent secret usage (local audit log, {path}):",
  mcpConfig: "Add this to your MCP client config (Claude Desktop: claude_desktop_config.json, Cursor: ~/.cursor/mcp.json):",
  needHost: "At least one --host is required.",
  walletRefused: "Refused: this looks like a wallet secret ({kind}). SecretSafe sends stored secrets to API servers, so a private key or seed phrase must never be stored here. If it is really a 64-hex API secret (not a wallet key), re-run with --not-a-wallet-key.",
  scanNone: "No secrets found in {root}.",
  scanHeader: "Found {n} possible secret(s) in {root}. Values are never shown, only a public prefix and a fingerprint:",
  scanFooter: "Review each finding, then run the suggested import command (adjust name/host if needed). After importing: remove the value from the file and rotate any key that was ever committed or shared.",
  imported: "Imported \"{name}\" from {file}:{line} (fp:{fp}) into your T3N vault. Allowed hosts: {hosts}",
  importNext: "Next: delete the value from {file}:{line} (replace it with a reference to SecretSafe or an env var) and rotate the key if it was ever committed.",
  registerHint: "Optional: support the project with `secretsafe register` (shares only your public DID, nothing else).",
  registerInfo: "Opening a pre-filled GitHub issue to register your public DID {did}. Nothing is sent until you click \"Submit\". Issues are public; no keys or secrets are included.",
  keychainPrompt: "Paste your T3 key (0x...) when asked for the password; it is stored in your macOS login Keychain, not in a file.",
  keychainSaved: "T3 key saved in the macOS Keychain (service: secretsafe-t3n). T3N_API_KEY is no longer needed.",
  keychainNote: "No key in this config: SecretSafe reads it from your macOS Keychain (run `secretsafe login` once).",
  unknownCommand: "Unknown command: {cmd}",
  error: "Error: {msg}",
  help: `SecretSafe MCP - your agents use API keys without ever seeing them.

Usage:
  secretsafe login                        (macOS) Store your T3 key in the Keychain
  secretsafe init                         Log in with your T3 key, create your did:t3n vault
  secretsafe add <name> --host <host> [--host <host2>]
             [--header "Authorization: Bearer {{secret}}"] [--query key] [--note "..."]
                                          Store a secret (value is read hidden from stdin)
  secretsafe scan [path] [--json]         Find hard-coded keys (masked, never printed)
  secretsafe import <name> --file <f> --fp <fp> --host <host> [...]
                                          Move a found key straight from the file into the vault
  secretsafe list [--json]                List secret names + allowed hosts
  secretsafe remove <name>                Delete a secret from the vault
  secretsafe status                       Show your DID, vault and T3 credit balance
  secretsafe audit [--limit 20] [--secret n] [--since 7d] [--json]
                                          Show what your agents used, when, where
  secretsafe register [--handle @you]     Opt-in: register your public DID (GitHub issue)
  secretsafe config                       Print the MCP client config snippet
  secretsafe serve                        Run the MCP server (stdio) - used by Claude/Cursor

Options: --lang en|de   --env testnet|production
Env:     T3N_API_KEY (or macOS Keychain)  T3N_ENV  SECRETSAFE_LANG  SECRETSAFE_HOME`,
};

const de: typeof en = {
  missingKey: "T3N_API_KEY ist nicht gesetzt. Hol dir kostenlos ein T3-Konto + API-Key unter https://www.terminal3.io/claim-page, dann: export T3N_API_KEY=0x...",
  connecting: "Verbinde mit dem Terminal-3-Netzwerk ({env})...",
  authenticated: "Angemeldet als {did}",
  creatingVault: "Lege deinen persönlichen Tresor an (T3-Organisation)...",
  vaultReady: "Tresor bereit: {org}",
  vaultExists: "Tresor ist schon eingerichtet: {org}",
  initDone: "Fertig. Weiter mit: secretsafe add <name> --host <api.host.com> --header \"Authorization: Bearer {{secret}}\"",
  notInitialised: "Noch kein Tresor. Führe aus: secretsafe init",
  enterValue: "Geheimen Wert für \"{name}\" einfügen (Eingabe unsichtbar, dann Enter): ",
  added: "\"{name}\" im T3N-Tresor gespeichert. Erlaubte Hosts: {hosts}",
  removed: "\"{name}\" gelöscht.",
  noSecrets: "Noch keine Secrets gespeichert.",
  listHeader: "Secrets in deinem Tresor (Werte werden nie angezeigt):",
  balance: "Credit-Guthaben: {balance}",
  auditEmpty: "Noch keine Nutzung protokolliert.",
  auditHeader: "Letzte Nutzungen (lokales Audit-Log, {path}):",
  mcpConfig: "Füge das in die Konfiguration deines MCP-Clients ein (Claude Desktop: claude_desktop_config.json, Cursor: ~/.cursor/mcp.json):",
  needHost: "Mindestens ein --host ist nötig.",
  walletRefused: "Abgelehnt: Das sieht nach einem Wallet-Secret aus ({kind}). SecretSafe schickt gespeicherte Secrets an API-Server, deshalb dürfen Private Keys oder Seed-Phrasen hier nie gespeichert werden. Falls es wirklich ein 64-stelliges Hex-API-Secret ist (kein Wallet-Key), mit --not-a-wallet-key erneut ausführen.",
  scanNone: "Keine Secrets in {root} gefunden.",
  scanHeader: "{n} mögliche(s) Secret(s) in {root} gefunden. Werte werden nie angezeigt, nur ein öffentlicher Präfix und ein Fingerabdruck:",
  scanFooter: "Prüfe jeden Fund und führe dann den vorgeschlagenen import-Befehl aus (Name/Host ggf. anpassen). Danach: Wert aus der Datei entfernen und jeden Key erneuern, der je committet oder geteilt wurde.",
  imported: "\"{name}\" aus {file}:{line} (fp:{fp}) in deinen T3N-Tresor importiert. Erlaubte Hosts: {hosts}",
  importNext: "Als Nächstes: Wert aus {file}:{line} löschen (durch Verweis auf SecretSafe oder eine Env-Variable ersetzen) und den Key erneuern, falls er je committet wurde.",
  registerHint: "Optional: Unterstütze das Projekt mit `secretsafe register` (teilt nur deine öffentliche DID, sonst nichts).",
  registerInfo: "Öffne ein vorausgefülltes GitHub-Issue, um deine öffentliche DID {did} zu registrieren. Es wird erst gesendet, wenn du auf \"Submit\" klickst. Issues sind öffentlich; keine Keys oder Secrets enthalten.",
  keychainPrompt: "Füge deinen T3-Key (0x...) ein, wenn nach dem Passwort gefragt wird; er wird im macOS-Schlüsselbund gespeichert, nicht in einer Datei.",
  keychainSaved: "T3-Key im macOS-Schlüsselbund gespeichert (Dienst: secretsafe-t3n). T3N_API_KEY wird nicht mehr gebraucht.",
  keychainNote: "Kein Key in dieser Konfiguration: SecretSafe liest ihn aus deinem macOS-Schlüsselbund (einmal `secretsafe login` ausführen).",
  unknownCommand: "Unbekannter Befehl: {cmd}",
  error: "Fehler: {msg}",
  help: `SecretSafe MCP - deine Agents nutzen API-Keys, ohne sie je zu sehen.

Nutzung:
  secretsafe login                        (macOS) T3-Key im Schlüsselbund speichern
  secretsafe init                         Mit T3-Key anmelden, did:t3n-Tresor anlegen
  secretsafe add <name> --host <host> [--host <host2>]
             [--header "Authorization: Bearer {{secret}}"] [--query key] [--note "..."]
                                          Secret speichern (Wert wird unsichtbar eingelesen)
  secretsafe scan [pfad] [--json]         Fest eingetragene Keys finden (maskiert, nie angezeigt)
  secretsafe import <name> --file <f> --fp <fp> --host <host> [...]
                                          Gefundenen Key direkt aus der Datei in den Tresor schieben
  secretsafe list [--json]                Secret-Namen + erlaubte Hosts anzeigen
  secretsafe remove <name>                Secret aus dem Tresor löschen
  secretsafe status                       DID, Tresor und T3-Guthaben anzeigen
  secretsafe audit [--limit 20] [--secret n] [--since 7d] [--json]
                                          Zeigt, was deine Agents wann wo genutzt haben
  secretsafe register [--handle @du]      Freiwillig: öffentliche DID registrieren (GitHub-Issue)
  secretsafe config                       MCP-Konfigurations-Schnipsel ausgeben
  secretsafe serve                        MCP-Server starten (stdio) - für Claude/Cursor

Optionen: --lang en|de   --env testnet|production
Umgebung: T3N_API_KEY (oder macOS-Schlüsselbund)  T3N_ENV  SECRETSAFE_LANG  SECRETSAFE_HOME`,
};

const dicts: Record<Lang, typeof en> = { en, de };
export type MsgKey = keyof typeof en;

let current: Lang = "en";

export function setLang(l: string | undefined): void {
  const v = (l ?? "").toLowerCase().slice(0, 2);
  current = v === "de" ? "de" : "en";
}

export function getLang(): Lang {
  return current;
}

export function t(key: MsgKey, vars: Record<string, string | number> = {}): string {
  let s = dicts[current][key];
  for (const [k, v] of Object.entries(vars)) s = s.split(`{${k}}`).join(String(v));
  return s;
}
