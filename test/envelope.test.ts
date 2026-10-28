import { describe, it, expect } from "vitest";
import { seal, verifyEnvelope } from "../src/envelope";
import { loadReportKey } from "../src/sign";
import { KEYS } from "../src/keys";
import { fixtureText } from "./helpers";
import { readFileSync } from "node:fs";
// @ts-ignore plain JS module
import { verifyReport } from "../verify.mjs";

const secret = fixtureText("test-key.json");
const pub = JSON.parse(secret).public_raw_b64url;
const pinned = [{ kid: "test-key", public_key: pub, revoked_at: null }];
const report = { report_version: "coldread/1", checked_at: "2026-10-28T12:00:00.000Z", subject: { url: "https://a.example/x" }, overall: "no_red_flags", n: [1, 2.5] };

describe("seal and verify", () => {
  it("signs sha256(JCS(report)) and verifies in the Worker and in verify.mjs", async () => {
    const k = await loadReportKey(secret);
    const env = await seal(report, k, "https://x/keys");
    expect(env.digest.hex).toMatch(/^[0-9a-f]{64}$/);
    expect(env.signature!.key_id).toBe("test-key");
    const v = await verifyEnvelope(env, pinned);
    expect(v.valid).toBe(true);
    const j = verifyReport(JSON.parse(JSON.stringify(env)), pinned);
    expect(j).toMatchObject({ valid: true, digest_ok: true, signature_ok: true, key_ok: true });
  });
  it("detects a modified report, a wrong key, an unpublished key and a revoked key", async () => {
    const k = await loadReportKey(secret);
    const env: any = JSON.parse(JSON.stringify(await seal(report, k, "u")));
    const tampered = { ...env, report: { ...env.report, overall: "red_flags" } };
    expect((await verifyEnvelope(tampered, pinned)).digest_ok).toBe(false);
    expect(verifyReport(tampered, pinned).valid).toBe(false);
    const forged = { ...env, signature: { ...env.signature, public_key: KEYS.keys[0].public_key } };
    expect((await verifyEnvelope(forged, pinned)).signature_ok).toBe(false);
    expect((await verifyEnvelope(env, KEYS.keys)).key_known).toBe(false); // test key is not a published key
    expect(verifyReport(env).key_ok).toBe(false); // verify.mjs pins only the production key
    const revoked = [{ ...pinned[0], revoked_at: "2026-10-01T00:00:00Z" }];
    expect((await verifyEnvelope(env, revoked)).valid).toBe(false);
    expect(verifyReport(env, revoked).valid).toBe(false);
  });
  it("signs only the prefixed digest, so the signature cannot be reused as a raw-digest signature", async () => {
    const k = await loadReportKey(secret);
    const env: any = await seal(report, k, "u");
    const key = await crypto.subtle.importKey("raw", Buffer.from(pub, "base64url"), { name: "Ed25519" }, false, ["verify"]);
    const raw = await crypto.subtle.verify({ name: "Ed25519" }, key, Buffer.from(env.signature.value, "base64url"), new TextEncoder().encode(env.digest.hex));
    expect(raw).toBe(false);
  });
  it("published key is the same everywhere: keys.ts, verify.mjs pin, PUBLIC_KEY.txt", () => {
    const txt = readFileSync(__dirname + "/../PUBLIC_KEY.txt", "utf8").trim();
    const vm = readFileSync(__dirname + "/../verify.mjs", "utf8");
    expect(KEYS.keys[0].public_key).toBe(txt);
    expect(vm).toContain(`public_key: "${txt}"`);
    expect(vm).toContain(`kid: "${KEYS.keys[0].kid}"`);
    expect(Buffer.from(txt, "base64url").length).toBe(32);
  });
});
