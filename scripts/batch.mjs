// ColdRead daily batch, run from the operator's box (outside Cloudflare).
//   node scripts/batch.mjs [--date YYYY-MM-DD] [--no-anchor] [--no-payers] [--extra 0xpayto,...]
// 1. Payer cache: public Base RPC (publicnode) rate-limits Cloudflare's shared egress, so live payer summaries often
//    fail inside the Worker. This job reads the day's stored reports, collects payTos whose summary failed, computes
//    the summary here, and writes KV key p:<payTo> (TTL 3 days). The Worker then serves it, labelled "cached".
// 2. Anchor: writes the day's report digests to the buildlog repo (coldread/<date>/digests.txt), stamps it with
//    OpenTimestamps and pushes. A digest in an anchored file proves the report existed by that Bitcoin block.
import { build } from "esbuild";
import { spawnSync } from "node:child_process";
import { mkdirSync, writeFileSync, existsSync, readFileSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";

const HERE = dirname(fileURLToPath(import.meta.url));
const ROOT = join(HERE, "..");
const BASE = "https://coldread.something-agent.workers.dev";
const NS = "248bb33d9ebe41f9918d7f8874ba4a5b";
const BUILDLOG = process.env.BUILDLOG_DIR ?? join(ROOT, "..", "buildlog");
const OTS = process.env.OTS_BIN ?? join(ROOT, "..", "venv", "bin", "ots");
const UA = { headers: { "user-agent": "coldread-selftest/1 (batch)" } };
const arg = (k) => { const i = process.argv.indexOf(k); return i > 0 ? process.argv[i + 1] : undefined; };
const has = (k) => process.argv.includes(k);
const date = arg("--date") ?? new Date().toISOString().slice(0, 10);
const log = (...a) => console.error("[batch]", ...a);

await build({ stdin: { contents: 'export { payerSummary } from "./src/payers"; export { payerCacheKey } from "./src/check";', resolveDir: ROOT, loader: "ts" }, bundle: true, format: "esm", platform: "neutral", outfile: "/tmp/coldread-batch.mjs", logLevel: "error", mainFields: ["module", "main"] });
const { payerSummary, payerCacheKey } = await import("/tmp/coldread-batch.mjs?" + Date.now());

const digests = (await (await fetch(`${BASE}/v1/digests?date=${date}`, UA)).json()).digests ?? [];
log(`${digests.length} stored report(s) on ${date}`);

if (!has("--no-payers")) {
  const keys = new Map();
  for (const d of digests) {
    const env = await (await fetch(`${BASE}/v1/report/${d}`, UA)).json().catch(() => null);
    const p = env?.report?.parts?.payers;
    if (p && (p.status === "rpc_error" || p.status === "cached" || p.note) && Array.isArray(p.pay_to) && p.pay_to.length) keys.set(payerCacheKey(p.pay_to), p.pay_to);
  }
  for (const x of (arg("--extra") ?? "").split(",").filter(Boolean)) keys.set(payerCacheKey([x]), [x.toLowerCase()]);
  log(`${keys.size} payTo set(s) to summarise`);
  for (const [k, pts] of keys) {
    try {
      const summary = await payerSummary(pts, fetch);
      const val = JSON.stringify({ computed_at: new Date().toISOString(), summary });
      const r = spawnSync(join(HERE, "cf.sh"), ["kv", "key", "put", k, val, `--namespace-id=${NS}`, "--ttl=259200", "--remote"], { encoding: "utf8" });
      log(k, r.status === 0 ? `cached (${summary.inbound?.transfers ?? 0} inbound)` : `KV put failed: ${(r.stderr || r.stdout).split("\n").filter((l) => /error/i.test(l)).join(" ").slice(0, 200)}`);
    } catch (e) { log(k, "summary failed:", e.message.slice(0, 160)); }
    await new Promise((r) => setTimeout(r, 1500));
  }
}

if (!has("--no-anchor") && digests.length) {
  const dir = join(BUILDLOG, "coldread", date);
  mkdirSync(dir, { recursive: true });
  const f = join(dir, "digests.txt");
  const prev = existsSync(f) ? readFileSync(f, "utf8").trim().split("\n").filter(Boolean) : [];
  const all = [...new Set([...prev, ...digests])].sort();
  if (all.length === prev.length && existsSync(f + ".ots")) log("no new digests; anchor unchanged");
  else {
    writeFileSync(f, all.join("\n") + "\n");
    const sh = (cmd, args, cwd = BUILDLOG) => spawnSync(cmd, args, { cwd, encoding: "utf8" });
    sh("rm", ["-f", f + ".ots"]);
    const s = sh(OTS, ["stamp", f]);
    log("ots stamp:", s.status === 0 ? "ok" : (s.stderr || "").slice(0, 200));
    sh("git", ["add", join("coldread", date)]);
    const c = sh("git", ["commit", "-m", `coldread: ${all.length} report digest(s) for ${date}, OTS-stamped`]);
    if (c.status === 0) {
      const p = spawnSync("git", ["push", "origin", "HEAD"], { cwd: BUILDLOG, encoding: "utf8", env: { ...process.env, GIT_ASKPASS: join(ROOT, "..", "tools", "askpass.sh"), GIT_TERMINAL_PROMPT: "0" } });
      log("push:", p.status === 0 ? "ok" : (p.stderr || "").split("\n").slice(-2).join(" "));
    } else log("commit:", (c.stdout + c.stderr).slice(0, 160));
  }
}
