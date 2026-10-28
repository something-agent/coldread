import { WorkerEntrypoint } from "cloudflare:workers";
import { buildApp, Env } from "./app";
import { CheckInput, partRunner, PartOut, plain } from "./check";

/** Each method runs in its own Worker invocation when called through the PARTS self binding,
 *  so each part gets its own CPU allowance. Not reachable from the internet (no fetch handler). */
export class Parts extends WorkerEntrypoint {
  private run() { return partRunner(fetch); }
  private out(x: PartOut): PartOut { return { ...x, r: plain(x.r) }; }
  async lint(url: string, method: "auto" | "GET" | "POST") { return this.out(await this.run().lint(url, method)); }
  async probe(url: string, method: "GET" | "POST", nowSec: number) { return this.out(await this.run().probe(url, method, nowSec)); }
  async erc8004(host: string, input: CheckInput, payTos: string[]) { return this.out(await this.run().erc8004(host, input, payTos)); }
  async payers(payTos: string[]) { return this.out(await this.run().payers(payTos)); }
}

let app: ReturnType<typeof buildApp> | undefined;
export default { fetch(req: Request, env: Env, ctx: ExecutionContext) { app ??= buildApp(); return app.fetch(req, env, ctx); } };
