// Run a ColdRead check from outside Cloudflare (the operator's box) and sign it with the report key.
// Used for our own services, which the hosted Worker cannot reach (same-account workers.dev 404), and for dev.
//   node scripts/check-from-box.mjs <url> [GET|POST|auto] [out.json]
// Signing needs COLDREAD_KEY_FILE (the report key JSON); without it the report is unsigned.
import { build } from "esbuild";
import { readFileSync, writeFileSync } from "node:fs";
const tmp = "/tmp/coldread-box.mjs";
await build({ stdin: { contents: 'export { signedReport } from "./src/report"; export { parseInput } from "./src/check"; export { loadReportKey } from "./src/sign";', resolveDir: process.cwd(), loader: "ts" }, bundle: true, format: "esm", platform: "neutral", outfile: tmp, logLevel: "error", mainFields: ["module", "main"] });
const { signedReport, parseInput, loadReportKey } = await import(tmp + "?" + Date.now());
const [url, method, out] = process.argv.slice(2);
const kf = process.env.COLDREAD_KEY_FILE;
const key = kf ? await loadReportKey(readFileSync(kf, "utf8")) : null;
const env = await signedReport(parseInput({ url, method }), { fetchImpl: fetch, key, keysUrl: "https://coldread.something-agent.workers.dev/.well-known/coldread-keys.json", runFrom: "box" });
const s = JSON.stringify(env, null, 2);
if (out) writeFileSync(out, s + "\n"); else console.log(s);
console.error(`${env.report.overall} ${env.digest.hex}${key ? "" : " (unsigned)"}`);
