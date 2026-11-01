import { describe, it, expect } from "vitest";
import { clusterFundings } from "../src/funders";
const F = (payer: string, funder: string | null, block: number) => ({ payer, funder, block, usdc: 1 });
describe("clusterFundings (northtape)", () => {
  it("collapses payers funded by the same funder close together", () => {
    const c = clusterFundings([F("0xa", "0xf", 100), F("0xb", "0xf", 900), F("0xc", "0xg", 100)], new Set());
    expect(c).toEqual([{ funder: "0xf", payers: ["0xa", "0xb"], blocks: [100, 900], usdc: [1, 1] }]);
  });
  it("same funder hours apart is noise; hubs never collapse; null funders ignored", () => {
    expect(clusterFundings([F("0xa", "0xf", 100), F("0xb", "0xf", 100 + 1801)], new Set())).toEqual([]);
    expect(clusterFundings([F("0xa", "0xh", 100), F("0xb", "0xh", 101)], new Set(["0xh"]))).toEqual([]);
    expect(clusterFundings([F("0xa", null, 100), F("0xb", null, 101)], new Set())).toEqual([]);
  });
  it("chains a run of fundings each within the gap", () => {
    const c = clusterFundings([F("0xa", "0xf", 0), F("0xb", "0xf", 1800), F("0xc", "0xf", 3600)], new Set());
    expect(c[0].payers).toEqual(["0xa", "0xb", "0xc"]);
  });
});
