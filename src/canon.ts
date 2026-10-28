/** RFC 8785 (JCS) canonical JSON for the values a report contains, plus sha256. No dependencies, so the
 *  public verify script can carry an identical copy. */
export function canonicalize(v: unknown): string {
  if (v === null || typeof v === "boolean" || typeof v === "string") return JSON.stringify(v);
  if (typeof v === "number") {
    if (!Number.isFinite(v)) throw new Error("JCS: non-finite number");
    return JSON.stringify(v); // ECMAScript number serialisation is what JCS specifies
  }
  if (Array.isArray(v)) return "[" + v.map((x) => (x === undefined ? "null" : canonicalize(x))).join(",") + "]";
  if (typeof v === "object") {
    const o = v as Record<string, unknown>;
    // JCS sorts by UTF-16 code units, which is JavaScript's default string ordering.
    const keys = Object.keys(o).filter((k) => o[k] !== undefined).sort();
    return "{" + keys.map((k) => JSON.stringify(k) + ":" + canonicalize(o[k])).join(",") + "}";
  }
  throw new Error(`JCS: unsupported type ${typeof v}`);
}

export async function sha256Hex(s: string | Uint8Array): Promise<string> {
  const b = typeof s === "string" ? new TextEncoder().encode(s) : s;
  const d = new Uint8Array(await crypto.subtle.digest("SHA-256", b));
  return Array.from(d, (x) => x.toString(16).padStart(2, "0")).join("");
}
