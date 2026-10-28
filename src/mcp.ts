/** Remote MCP server (Streamable HTTP, stateless, JSON responses). */
export const MCP_TOOLS = [
  { name: "coldread_check", title: "ColdRead check", description: "Before paying an x402 seller: one signed, independent report combining a 402-challenge lint, signed-offer and signer-authorization checks, an ERC-8004 identity lookup and a labelled Base USDC payer summary over the last ~28 h. Read-only; never pays. Free.", inputSchema: { type: "object", properties: { url: { type: "string", description: "The x402 endpoint URL" }, method: { type: "string", enum: ["auto", "GET", "POST"], description: "Default auto (tries both)" }, pay_to: { type: "string", description: "Optional payTo you expect; a mismatch is a red flag" }, agent: { type: "object", description: "Optional ERC-8004 agent to check against the host", properties: { chain_id: { type: "integer" }, agent_id: { type: "string" } }, required: ["agent_id"] } }, required: ["url"] }, annotations: { readOnlyHint: true, openWorldHint: true } },
  { name: "coldread_get_report", title: "Fetch a stored ColdRead report", description: "Fetch a stored signed report by its sha256 digest (reports are kept 90 days).", inputSchema: { type: "object", properties: { digest: { type: "string" } }, required: ["digest"] }, annotations: { readOnlyHint: true } },
  { name: "coldread_verify_report", title: "Verify a ColdRead report", description: "Check that a ColdRead report envelope is unmodified (JCS + sha256) and signed by a published ColdRead key. Pass the whole envelope {report, digest, signature}.", inputSchema: { type: "object", properties: { envelope: { type: "object" } }, required: ["envelope"] }, annotations: { readOnlyHint: true } },
] as const;

const SUPPORTED = ["2025-11-25", "2025-06-18", "2025-03-26"];
export type ToolRunner = (name: string, args: any) => Promise<any>;
export class ToolError extends Error {}

export async function handleMcp(msg: any, run: ToolRunner, version: string): Promise<any | null> {
  const id = msg?.id;
  const reply = (result: any) => ({ jsonrpc: "2.0", id, result });
  const error = (code: number, message: string) => ({ jsonrpc: "2.0", id: id ?? null, error: { code, message } });
  if (!msg || msg.jsonrpc !== "2.0" || typeof msg.method !== "string") return error(-32600, "Invalid Request");
  if (id === undefined) return null;
  switch (msg.method) {
    case "initialize": {
      const want = msg.params?.protocolVersion;
      return reply({ protocolVersion: SUPPORTED.includes(want) ? want : SUPPORTED[1], capabilities: { tools: { listChanged: false } }, serverInfo: { name: "coldread", title: "ColdRead - independent pre-payment check for x402 sellers", version }, instructions: "Call coldread_check with an x402 URL before paying it. You get one Ed25519-signed report (overall, signals, per-part evidence, cannot_check). Read-only, never pays, free." });
    }
    case "ping": return reply({});
    case "tools/list": return reply({ tools: MCP_TOOLS });
    case "tools/call": {
      const name = String(msg.params?.name);
      if (!MCP_TOOLS.some((t) => t.name === name)) return error(-32602, `Unknown tool: ${name}`);
      try {
        const out = await run(name, msg.params?.arguments ?? {});
        return reply({ content: [{ type: "text", text: JSON.stringify(out) }], structuredContent: out, isError: false });
      } catch (e) {
        return reply({ content: [{ type: "text", text: e instanceof ToolError ? e.message : `tool failed: ${(e as Error).message}` }], isError: true });
      }
    }
    default: return error(-32601, `Method not found: ${msg.method}`);
  }
}
