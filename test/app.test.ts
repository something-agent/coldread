import { describe, it, expect } from "vitest";
import { buildApp, Env } from "../src/app";
import { stubFetch, fakeRpc, seller, GOOD_PR, memKV, fixtureText, json } from "./helpers";
// @ts-ignore plain JS module
import { verifyReport } from "../verify.mjs";

const secret = fixtureText("test-key.json");
const pub = JSON.parse(secret).public_raw_b64url;
let n = 0;
const ipHdr = () => ({ "cf-connecting-ip": `10.0.0.${++n}`, "user-agent": "test-agent/1", "content-type": "application/json" });
function setup(extra: any[] = []) {
  const { f } = stubFetch([...extra, seller("api.example.com", GOOD_PR()), seller("demo.something-agent.workers.dev", GOOD_PR()), fakeRpc({})]);
  const app = buildApp({ fetchImpl: f, now: () => new Date("2026-10-28T12:00:00Z") });
  const kv = memKV();
  const env: Env = { REPORTS: kv.kv, REPORT_KEY: secret, CALLER_SALT: "salt" };
  const req = (path: string, init: RequestInit = {}) => app.request(path, { ...init, headers: { ...ipHdr(), ...(init.headers as any) } }, env);
  return { app, env, kv, req };
}

describe("HTTP", () => {
  it("docs, landing, keys and server card", async () => {
    const { req } = setup();
    expect((await req("/")).status).toBe(200);
    expect(await (await req("/llms.txt")).text()).toMatch(/coldread_check/);
    expect((await (await req("/openapi.json")).json() as any).paths["/v1/check"].post.operationId).toBe("coldread_check");
    const k: any = await (await req("/.well-known/coldread-keys.json")).json();
    expect(k.keys[0]).toMatchObject({ kid: "coldread-2026-10-28", alg: "Ed25519", status: "active" });
    expect(k.purpose).toMatch(/hold no funds/);
    expect((await (await req("/.well-known/mcp-server-card.json")).json() as any).name).toBe("io.github.something-agent/coldread");
  });
  it("POST /v1/check returns a signed, stored report that round-trips through /v1/report and /v1/verify", async () => {
    const { req, kv } = setup();
    const r = await req("/v1/check", { method: "POST", body: JSON.stringify({ url: "https://api.example.com/data" }) });
    expect(r.status).toBe(200);
    const env: any = await r.json();
    expect(env.stored).toBe(true);
    expect(env.signature).toMatchObject({ alg: "Ed25519", key_id: "test-key", public_key: pub });
    expect(env.anchor.status).toBe("pending");
    expect(verifyReport(env, [{ kid: "test-key", public_key: pub }]).valid).toBe(true);
    const stored: any = await (await req(`/v1/report/${env.digest.hex}`)).json();
    expect(stored.digest.hex).toBe(env.digest.hex);
    const meta = [...kv.m.values()][0].meta;
    expect(meta).toMatchObject({ d: "2026-10-28", u: "agent", t: "http", h: "api.example.com" });
    expect(meta.c).toMatch(/^[0-9a-f]{16}$/);
    expect(JSON.stringify(meta)).not.toContain("10.0.0");
    // /v1/verify with the production key list: signature fine but key not published
    const v: any = await (await req("/v1/verify", { method: "POST", body: JSON.stringify({ envelope: env }) })).json();
    expect(v).toMatchObject({ digest_ok: true, signature_ok: true, key_known: false, valid: false });
    const d: any = await (await req("/v1/digests?date=2026-10-28")).json();
    expect(d.digests).toEqual([env.digest.hex]);
    expect((await req("/v1/digests?date=yesterday")).status).toBe(400);
    expect((await req(`/v1/report/${"0".repeat(64)}`)).status).toBe(404);
  });
  it("GET form, bad input 400, SSRF refused, rate limit 429", async () => {
    const { req, app, env } = setup();
    expect((await req("/v1/check?url=" + encodeURIComponent("https://api.example.com/data"))).status).toBe(200);
    expect((await req("/v1/check", { method: "POST", body: "{" })).status).toBe(400);
    const s = await req("/v1/check", { method: "POST", body: JSON.stringify({ url: "http://10.1.2.3/admin" }) });
    expect(s.status).toBe(400);
    expect(((await s.json()) as any).detail).toMatch(/refused/);
    const h = { "cf-connecting-ip": "9.9.9.9", "content-type": "application/json" };
    const codes: number[] = [];
    for (let i = 0; i < 14; i++) codes.push((await app.request("/v1/check", { method: "POST", headers: h, body: JSON.stringify({ url: "https://api.example.com/data" }) }, env)).status);
    expect(codes.slice(0, 12).every((c) => c === 200)).toBe(true);
    expect(codes[13]).toBe(429);
  });
  it("still returns the signed report when storage is over its cap", async () => {
    const { req, kv } = setup();
    kv.setFailPut(true);
    const env: any = await (await req("/v1/check", { method: "POST", body: JSON.stringify({ url: "https://api.example.com/data" }) })).json();
    expect(env.stored).toBe(false);
    expect(env.stored_note).toMatch(/write cap/);
    expect(env.signature.value).toBeTruthy();
  });
  it("discloses a conflict of interest for our own services", async () => {
    const { req } = setup();
    const env: any = await (await req("/v1/check", { method: "POST", body: JSON.stringify({ url: "https://demo.something-agent.workers.dev/data" }) })).json();
    expect(env.report.conflict_of_interest).toMatch(/self-assessment/);
  });
  it("stats count outside callers and exclude self-tests", async () => {
    const { req } = setup();
    const body = JSON.stringify({ url: "https://api.example.com/data" });
    await req("/v1/check", { method: "POST", body, headers: { "user-agent": "coldread-selftest/1" } });
    await req("/v1/check", { method: "POST", body, headers: { "user-agent": "claude-mcp-client" } });
    await req("/v1/check", { method: "POST", body, headers: { "user-agent": "curl/8" } });
    const s: any = await (await req("/v1/stats")).json();
    expect(s.totals).toMatchObject({ checks: 3, outside_checks: 2 });
    expect(s.days["2026-10-28"].by_ua).toEqual({ self: 1, agent: 1, script: 1 });
  });
});

describe("MCP", () => {
  const rpc = (req: any, method: string, params: any = {}, id: any = 1) => req("/mcp", { method: "POST", body: JSON.stringify({ jsonrpc: "2.0", id, method, params }) }).then((r: Response) => r.json());
  it("initialize, tools/list, coldread_check, get_report, verify_report", async () => {
    const { req } = setup();
    const init: any = await rpc(req, "initialize", { protocolVersion: "2025-06-18" });
    expect(init.result.serverInfo.name).toBe("coldread");
    const tl: any = await rpc(req, "tools/list");
    expect(tl.result.tools.map((t: any) => t.name)).toEqual(["coldread_check", "coldread_get_report", "coldread_verify_report"]);
    const c: any = await rpc(req, "tools/call", { name: "coldread_check", arguments: { url: "https://api.example.com/data" } });
    expect(c.result.isError).toBe(false);
    const env = c.result.structuredContent;
    expect(env.report.report_version).toBe("coldread/1");
    const g: any = await rpc(req, "tools/call", { name: "coldread_get_report", arguments: { digest: env.digest.hex } });
    expect(g.result.structuredContent.digest.hex).toBe(env.digest.hex);
    const v: any = await rpc(req, "tools/call", { name: "coldread_verify_report", arguments: { envelope: env } });
    expect(v.result.structuredContent).toMatchObject({ digest_ok: true, signature_ok: true });
    const bad: any = await rpc(req, "tools/call", { name: "coldread_check", arguments: { url: "http://127.0.0.1/" } });
    expect(bad.result.isError).toBe(true);
    expect((await rpc(req, "nope")).error.code).toBe(-32601);
  });
  it("one coldread_check per batch; notifications get 202", async () => {
    const { req } = setup();
    const call = (id: number) => ({ jsonrpc: "2.0", id, method: "tools/call", params: { name: "coldread_check", arguments: { url: "https://api.example.com/data" } } });
    const out: any = await (await req("/mcp", { method: "POST", body: JSON.stringify([call(1), call(2)]) })).json();
    expect(out[0].result.isError).toBe(false);
    expect(out[1].result.isError).toBe(true);
    expect((await req("/mcp", { method: "POST", body: JSON.stringify({ jsonrpc: "2.0", method: "notifications/initialized" }) })).status).toBe(202);
  });
});
