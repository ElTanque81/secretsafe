#!/usr/bin/env node
// Collect opt-in DID registrations from public GitHub issues (label did-registration or title "DID registration...").
// Usage: node scripts/collect-dids.mjs [owner/repo]   ->  prints a deduplicated DID list for the T3 traction form.
const repo = process.argv[2] ?? "ElTanque81/secretsafe";
const dids = new Map();
for (let page = 1; ; page++) {
  const res = await fetch(`https://api.github.com/repos/${repo}/issues?state=all&per_page=100&page=${page}`, {
    headers: { Accept: "application/vnd.github+json", ...(process.env.GITHUB_TOKEN ? { Authorization: `Bearer ${process.env.GITHUB_TOKEN}` } : {}) },
  });
  if (!res.ok) throw new Error(`GitHub API ${res.status}`);
  const items = await res.json();
  if (items.length === 0) break;
  for (const it of items) {
    const isReg = (it.labels ?? []).some((l) => l.name === "did-registration") || /^DID registration/i.test(it.title ?? "");
    if (!isReg || it.pull_request) continue;
    const body = it.body ?? "";
    const did = body.match(/^did:\s*(did:t3n:[0-9a-f]{40})/m)?.[1];
    const vault = body.match(/^vault:\s*(did:t3n:[0-9a-f]{40})/m)?.[1];
    if (did && !dids.has(did)) dids.set(did, { vault, user: it.user?.login, date: it.created_at.slice(0, 10) });
  }
}
console.log(`${dids.size} unique DIDs\n`);
for (const [did, v] of dids) console.log(`${did}  vault=${v.vault ?? "-"}  github=@${v.user}  ${v.date}`);
