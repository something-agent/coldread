import { describe, it, expect } from "vitest";
import { runCheck, parseInput, BadRequest, budgetFetch, partRunner, plain, Parts, termsFingerprint } from "../src/check";
import { stubFetch, fakeRpc, json, fixture, fixtureText, seller, GOOD_PR, PAYTO, CAPTURED, b64 } from "./helpers";

const REG = "0x8004A169FB4a3325136EB29fA0ceB6D2e539a432";
const regJson = (host: string, id = "42") => json({ registrations: [{ agentRegistry: `eip155:8453:${REG}`, agentId: Number(id) }] });
const agentUri = (host: string) => "data:application/json," + encodeURIComponent(JSON.stringify({ type: "https://eips.ethereum.org/EIPS/eip-8004#registration-v1", name: "Example", services: [{ name: "web", endpoint: `https://${host}/` }], x402Support: true }));

describe("input", () => {
  it("validates url, method, pay_to and agent; refuses private targets", () => {
    expect(parseInput({ url: "https://a.example/x" })).toMatchObject({ url: "https://a.example/x", method: "auto" });
    expect(parseInput({ url: "https://a.example/x", method: "post", pay_to: PAYTO.toUpperCase().replace("0X", "0x"), agent_id: "7" })).toMatchObject({ method: "POST", agent: { chain_id: 8453, agent_id: "7" } });
    for (const bad of [{}, { url: 5 }, { url: "ftp://a/b" }, { url: "http://127.0.0.1/x" }, { url: "http://localhost/x" }, { url: "http://169.254.169.254/latest" }, { url: "http://[::1]/" }, { url: "https://a.example/x", method: "PUT" }, { url: "https://a.example/x", pay_to: "0x12" }, { url: "https://a.example/x", agent: { chain_id: 999999, agent_id: "1" } }, { url: "https://a.example/x", agent: { agent_id: "1; drop" } }])
      expect(() => parseInput(bad), JSON.stringify(bad)).toThrow(BadRequest);
  });
  it("budgetFetch refuses beyond the budget", async () => {
    const { fetch: f, st } = budgetFetch((async () => new Response("ok")) as any, 2);
    await f("https://a"); await f("https://b");
    await expect(f("https://c")).rejects.toThrow(/budget/);
    expect(st).toEqual({ used: 2, refused: 1 });
  });
});

describe("runCheck", () => {
  it("clean seller with a two-way ERC-8004 binding whose wallet is the payTo, and a real buyer", async () => {
    const host = "api.example.com";
    const { f, calls } = stubFetch([
      seller(host, GOOD_PR()),
      (u) => (u === `https://${host}/.well-known/agent-registration.json` ? regJson(host) : undefined),
      fakeRpc({ agents: { "42": { owner: "0x1111111111111111111111111111111111111111", wallet: PAYTO, uri: agentUri(host) } }, transfers: [1, 2, 3].map((i) => ({ from: "0x00000000000000000000000000000000000b0b0b", to: PAYTO, usdc: 0.01, block: 40_000_000 - i })) }),
    ]);
    const r: any = await runCheck(parseInput({ url: `https://${host}/data` }), { fetchImpl: f, now: new Date("2026-10-28T12:00:00Z") });
    expect(r.report_version).toBe("coldread/1");
    expect(r.checked_at).toBe("2026-10-28T12:00:00.000Z");
    expect(r.parts.live_challenge.accepts[0].pay_to.toLowerCase()).toBe(PAYTO);
    expect(r.parts.erc8004).toMatchObject({ status: "found", source: "host_well_known", agent_id: "42", wallet_matches_pay_to: true, matched_by: "agentWallet", binding: "two_way" });
    expect(r.parts.payers.inbound.transfers).toBe(3);
    expect(r.signals.map((s: any) => s.id)).toEqual(expect.arrayContaining(["I003", "P003"]));
    expect(["no_red_flags", "attention"]).toContain(r.overall);
    expect(r.signals.some((s: any) => s.severity === "red")).toBe(false);
    // 0.1.6: fetch evidence for the subject URL (hashes only), never for RPC or registration fetches
    const ev = r.freshness.fetch_evidence;
    expect(ev.length).toBeGreaterThan(0);
    expect(ev.every((e: any) => new URL(e.url).hostname === host && /^[0-9a-f]{64}$/.test(e.body_sha256) && e.fetched_at && e.status)).toBe(true);
    expect(ev.some((e: any) => e.part === "probe" && e.url === `https://${host}/data` && e.status === 402)).toBe(true);
    expect(ev.some((e: any) => e.url.includes("agent-registration"))).toBe(false);
    expect(r.freshness).toMatchObject({ checked_at: r.checked_at, challenge_pay_tos: [PAYTO], suggested_max_age_hours: 24 });
    expect(Array.isArray(r.freshness.discovery_pay_tos) || r.freshness.discovery_pay_tos === null).toBe(true);
    expect(r.freshness.terms_fingerprint.hex).toBe(await termsFingerprint(r.parts.live_challenge.accepts));
    expect(r.method_notes.subrequests_used).toBe(calls.length);
    expect(r.method_notes.subrequests_used).toBeLessThanOrEqual(45);
    expect(r.cannot_check.join(" ")).toMatch(/never pays/);
  });
  it("red flags: caller's expected payTo differs, and the caller-supplied agent does not exist", async () => {
    const host = "api.example.com";
    const { f } = stubFetch([seller(host, GOOD_PR()), fakeRpc({ agents: {} })]);
    const r: any = await runCheck(parseInput({ url: `https://${host}/data`, pay_to: "0x2222222222222222222222222222222222222222", agent: { chain_id: 8453, agent_id: "5" } }), { fetchImpl: f });
    expect(r.overall).toBe("red_flags");
    expect(r.signals.filter((s: any) => s.severity === "red").map((s: any) => s.id).sort()).toEqual(["E005", "I004"]);
    // payer summary follows the caller's pay_to, not the live one
    expect(r.parts.payers.pay_to).toEqual(["0x2222222222222222222222222222222222222222"]);
  });
  it("amber when every payer is self or a documented sweeper", async () => {
    const host = "api.example.com";
    const { f } = stubFetch([seller(host, GOOD_PR()), fakeRpc({ transfers: [{ from: PAYTO, to: PAYTO, usdc: 0.01, block: 39_999_990 }, { from: "0x7722dfae6bbed2fd02dc07455c2f5bf14be25e4a", to: PAYTO, usdc: 0.001, block: 39_999_000 }] })]);
    const r: any = await runCheck(parseInput({ url: `https://${host}/data` }), { fetchImpl: f });
    expect(r.signals.find((s: any) => s.id === "P001")?.severity).toBe("amber");
    expect(r.overall).toBe("attention");
    expect(r.parts.erc8004.status).toBe("none_published");
  });
  it("real captured mart402 402: signed JWS offer authorized by did:web", async () => {
    const { f } = stubFetch([
      (u, i) => (u.startsWith("https://mart402.com/v1/extract") && (i?.method ?? "GET") === "POST" ? fixture("mart402") : undefined),
      (u) => (u === "https://mart402.com/.well-known/did.json" ? new Response(fixtureText("mart402.did.json"), { headers: { "content-type": "application/json" } }) : undefined),
      (u) => (u.startsWith("https://mart402.com/v1/extract") ? json({ error: "method" }, 405) : undefined),
      fakeRpc({}),
    ]);
    const r: any = await runCheck(parseInput({ url: "https://mart402.com/v1/extract" }), { fetchImpl: f, now: CAPTURED });
    expect(r.subject.method).toBe("POST");
    expect(r.parts.signed_offers.has_extension).toBe(true);
    expect(r.parts.signed_offers.results[0].verdict).toBe("valid_authorized");
    expect(r.signals.some((s: any) => s.id === "S002")).toBe(true);
    expect(r.overall).not.toBe("unreachable");
  });
  it("unreachable when there is no 402, without throwing; RPC failures land in cannot_check", async () => {
    const { f } = stubFetch([(u) => (u.startsWith("https://free.example/") ? json({ ok: true }) : undefined), (u) => (u.includes("rpc") || u.includes("drpc") ? json({}, 503) : undefined)]);
    const r: any = await runCheck(parseInput({ url: "https://free.example/x" }), { fetchImpl: f });
    expect(r.overall).toBe("unreachable");
    expect(r.parts.payers.status).toBe("not_applicable");
    expect(r.freshness.terms_fingerprint).toBeNull();
  });
  it("invalid signed offer is a red flag", async () => {
    const pr = GOOD_PR({ extensions: { bazaar: {}, "offer-receipt": { info: { offers: [{ format: "jws", signature: "eyJhbGciOiJFZERTQSJ9.eyJ4IjoxfQ.AAAA" }] } } } });
    const { f } = stubFetch([seller("api.example.com", pr), fakeRpc({})]);
    const r: any = await runCheck(parseInput({ url: "https://api.example.com/data" }), { fetchImpl: f });
    expect(r.signals.find((s: any) => s.part === "signed_offers")?.severity).toBe("red");
    expect(r.overall).toBe("red_flags");
  });
  it("host lists an agent whose wallet is someone else: amber, not red", async () => {
    const host = "api.example.com";
    const { f } = stubFetch([seller(host, GOOD_PR()), (u) => (u.endsWith("/.well-known/agent-registration.json") ? regJson(host, "9") : undefined), fakeRpc({ agents: { "9": { owner: "0x3333333333333333333333333333333333333333", wallet: "0x3333333333333333333333333333333333333333", uri: agentUri("other.example") } } })]);
    const r: any = await runCheck(parseInput({ url: `https://${host}/data` }), { fetchImpl: f });
    expect(r.parts.erc8004).toMatchObject({ binding: "host_only", wallet_matches_pay_to: false, registration_lists_host: false });
    expect(r.signals.find((s: any) => s.id === "I001")?.severity).toBe("amber");
  });
  it("falls back to a fresh box-computed payer summary when live RPC is rate-limited, and ignores a stale one", async () => {
    const mk = () => stubFetch([seller("api.example.com", GOOD_PR()), (u) => (u.includes("publicnode") ? json({ error: "rate" }, 429) : undefined)]);
    const now = new Date("2026-10-28T12:00:00Z");
    const summary = { status: "ok", window: { from_block: 1, to_block: 50_000, approx_hours: 27.8 }, inbound: { transfers: 2, usdc: 0.02, distinct_payers: 1 }, self_payments: { transfers: 0, usdc: 0 }, by_label: { self: { transfers: 0 }, known_sweeper: { transfers: 0 }, broad_payer: { transfers: 0 }, repeat_or_narrow: { transfers: 2 }, unclassified: { transfers: 0 } } };
    const keys: string[] = [];
    const cache = (at: string) => async (k: string) => { keys.push(k); return { computed_at: at, summary }; };
    const r: any = await runCheck(parseInput({ url: "https://api.example.com/data" }), { fetchImpl: mk().f, now, payerCache: cache("2026-10-28T02:00:00Z") });
    expect(keys[0]).toBe("p:" + PAYTO);
    expect(r.parts.payers.status).toBe("cached");
    expect(r.parts.payers.source).toMatchObject({ kind: "box_batch", age_hours: 10 });
    expect(r.parts.payers.source.why).toMatch(/429/);
    expect(r.signals.map((s: any) => s.id)).toEqual(expect.arrayContaining(["P009", "P003"]));
    const r2: any = await runCheck(parseInput({ url: "https://api.example.com/data" }), { fetchImpl: mk().f, now, payerCache: cache("2026-10-20T00:00:00Z") });
    expect(r2.parts.payers).toMatchObject({ status: "rpc_error", queued_for_batch: true });
    expect(r2.cannot_check.join(" ")).toMatch(/payer summary unavailable/);
  }, 15_000);
});

describe("split execution (one invocation per part)", () => {
  it("gives the same verdicts when each part runs separately and its output crosses a structured-clone boundary", async () => {
    const host = "api.example.com";
    const mkFetch = () => stubFetch([
      seller(host, GOOD_PR()),
      (u) => (u === `https://${host}/.well-known/agent-registration.json` ? regJson(host) : undefined),
      fakeRpc({ agents: { "42": { owner: "0x1111111111111111111111111111111111111111", wallet: PAYTO, uri: agentUri(host) } }, transfers: [1, 2].map((i) => ({ from: "0x00000000000000000000000000000000000b0b0b", to: PAYTO, usdc: 0.01, block: 40_000_000 - i })) }),
    ]).f;
    const now = new Date("2026-10-28T12:00:00Z");
    const one: any = await runCheck(parseInput({ url: `https://${host}/data` }), { fetchImpl: mkFetch(), now });
    const local = partRunner(mkFetch());
    const remote: Parts = {
      lint: async (...a) => { const x = await local.lint(...a); return structuredClone({ ...x, r: plain(x.r) }); },
      probe: async (...a) => { const x = await local.probe(...a); return structuredClone({ ...x, r: plain(x.r) }); },
      erc8004: async (...a) => { const x = await local.erc8004(...a); return structuredClone({ ...x, r: plain(x.r) }); },
      payers: async (...a) => { const x = await local.payers(...a); return structuredClone({ ...x, r: plain(x.r) }); },
    };
    const split: any = await runCheck(parseInput({ url: `https://${host}/data` }), { fetchImpl: mkFetch(), now, parts: remote });
    expect(split.overall).toBe(one.overall);
    expect(split.signals.map((x: any) => x.id)).toEqual(one.signals.map((x: any) => x.id));
    expect(split.parts.erc8004).toEqual(one.parts.erc8004);
    expect(split.method_notes.execution).toMatch(/separate Worker invocation/);
    expect(split.method_notes.subrequests_used).toBeGreaterThan(4);
  });
  it("a failing part degrades to an error field, not a thrown check", async () => {
    const boom: Parts = { lint: async () => ({ error: "x", used: 0, refused: 0 }), probe: async () => ({ error: "down", used: 1, refused: 0 }), erc8004: async () => ({ error: "e", used: 0, refused: 0 }), payers: async () => ({ error: "429", used: 0, refused: 0 }) };
    const r: any = await runCheck(parseInput({ url: "https://a.example/x" }), { fetchImpl: (async () => new Response("")) as any, parts: boom });
    expect(r.overall).toBe("unreachable");
    expect(r.parts.payers.status).toBe("rpc_error");
    expect(r.parts.erc8004.status).toBe("error");
  });
});

