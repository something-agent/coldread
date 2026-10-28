import { secp256k1 } from "@noble/curves/secp256k1";
/** Smaller precompute window for secp256k1's base point. The default (W=8) builds a table on the first
 *  signature recovery in each isolate that costs ~45 ms of CPU, 4x the Workers Free budget; W=4 costs ~13 ms
 *  once and ~3 ms per recovery after that. Results are identical (test/jws-fast.test.ts). */
let done = false;
export function tuneCurves() { if (done) return; done = true; try { secp256k1.ProjectivePoint.BASE._setWindowSize(4); } catch { /* already precomputed */ } }
tuneCurves();
