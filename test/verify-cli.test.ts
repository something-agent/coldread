import { describe, it, expect } from "vitest";
import { spawnSync, spawn } from "node:child_process";
import { createServer } from "node:http";
import { writeFileSync, mkdtempSync, readFileSync, readdirSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { seal } from "../src/envelope";
import { loadReportKey } from "../src/sign";
import { fixtureText } from "./helpers";
import VERSIONS from "../src/vendor/VERSIONS.json";

const run = (file: string) => spawnSync(process.execPath, [join(__dirname, "..", "verify.mjs"), file], { encoding: "utf8" });
const runAsync = (args: string[]) => new Promise<{ status: number | null; stdout: string }>((res) => {
  const c = spawn(process.execPath, [join(__dirname, "..", "verify.mjs"), ...args]); let out = "";
  c.stdout.on("data", (d) => (out += d)); c.on("close", (status) => res({ status, stdout: out }));
});

describe("verify.mjs CLI", () => {
  it("--help prints the exit-code table and exits 0", () => {
    const r = run("--help");
    expect(r.status).toBe(0);
    for (const s of ["0 valid", "1 bad", "2 unreadable", "3 stale", "4 unknown", "5 timeout", "--timeout", "--warn-only"]) expect(r.stdout).toContain(s);
  });
  it("exit 1 for a report signed by an unpublished key, 1 for a tampered one, 2 for unreadable input", async () => {
    const dir = mkdtempSync(join(tmpdir(), "cr-"));
    const env: any = await seal({ report_version: "coldread/1", checked_at: "2026-10-28T00:00:00Z" }, await loadReportKey(fixtureText("test-key.json")), "u");
    writeFileSync(join(dir, "a.json"), JSON.stringify(env));
    const a = run(join(dir, "a.json"));
    expect(a.status).toBe(1);
    expect(JSON.parse(a.stdout)).toMatchObject({ digest_ok: true, signature_ok: true, key_ok: false });
    writeFileSync(join(dir, "b.json"), JSON.stringify({ ...env, report: { ...env.report, x: 1 } }));
    expect(JSON.parse(run(join(dir, "b.json")).stdout).digest_ok).toBe(false);
    expect(run(join(dir, "missing.json")).status).toBe(2);
  });
  it("--timeout kills a hung --live read and reports state timeout (bad signature still exits 1, never 3/4)", async () => {
    const srv = createServer(() => {}); // never answers
    await new Promise<void>((r) => srv.listen(0, "127.0.0.1", () => r()));
    const url = `http://127.0.0.1:${(srv.address() as any).port}/pay`;
    const dir = mkdtempSync(join(tmpdir(), "cr-"));
    const env: any = await seal({ report_version: "coldread/1", checked_at: "2026-10-28T00:00:00Z", subject: { url, method: "GET" } }, await loadReportKey(fixtureText("test-key.json")), "u");
    writeFileSync(join(dir, "h.json"), JSON.stringify(env));
    const t0 = Date.now();
    const r = await runAsync([join(dir, "h.json"), "--live", "--timeout", "300"]);
    srv.close();
    expect(Date.now() - t0).toBeLessThan(5000);
    expect(JSON.parse(r.stdout)).toMatchObject({ state: "timeout", timeout_ms: 300 });
    expect(r.status).toBe(1); // test key is not a published key; a valid report would exit 5
    expect((await runAsync([join(dir, "h.json"), "--live", "--timeout", "x"])).status).toBe(2);
  });
});

describe("vendored libraries", () => {
  it("match their source repos except the User-Agent line and the files named in scripts/vendor-patches (run scripts/sync-vendor.sh after upstream changes)", () => {
    const patched = new Set<string>();
    for (const pf of readdirSync(join(__dirname, "..", "scripts", "vendor-patches"))) for (const m of readFileSync(join(__dirname, "..", "scripts", "vendor-patches", pf), "utf8").matchAll(/^\+\+\+ b\/src\/vendor\/(\w+)\/(\w+)\.ts/gm)) patched.add(`${m[1]}/${m[2]}`);
    expect([...patched].sort()).toEqual(["proofcheck/jws", "proofcheck/verify"]);
    const pairs: [string, string[]][] = [["proofcheck", ["auth", "bytes", "chain", "did", "eip712", "jws", "probe", "safe", "util", "verify"]], ["x402lint", ["bytes", "directories", "known", "lint", "safe"]]];
    let checked = 0;
    for (const [lib, files] of pairs) for (const f of files) {
      let up: string;
      try { up = readFileSync(join(__dirname, "..", "..", lib, "src", f + ".ts"), "utf8"); } catch { return; } // upstream not checked out next to this repo
      const strip = (s: string) => s.split("\n").filter((l) => !l.startsWith("export const UA = ")).join("\n");
      const mine = readFileSync(join(__dirname, "..", "src", "vendor", lib, f + ".ts"), "utf8");
      if (patched.has(`${lib}/${f}`)) expect(mine.length, `${lib}/${f}`).toBeGreaterThan(up.length * 0.9);
      else expect(strip(mine), `${lib}/${f}`).toBe(strip(up));
      checked++;
    }
    expect(checked).toBe(15);
    expect(VERSIONS.proofcheck.version).toMatch(/^\d+\.\d+\.\d+$/);
  });
});
