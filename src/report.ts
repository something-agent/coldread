/** Build and sign one report. Shared by the Worker and the box CLI (scripts/check-from-box.mjs). */
import { CheckInput, Parts, PayerCache, runCheck } from "./check";
import { seal } from "./envelope";
import { ReportKey } from "./sign";

export const OWN_HOSTS = /(^|\.)something-agent\.workers\.dev$/;

export async function signedReport(input: CheckInput, o: { fetchImpl: typeof fetch; now?: Date; key: ReportKey | null; keysUrl: string; runFrom: "cloudflare_worker" | "box"; payerCache?: PayerCache; parts?: Parts }) {
  const report: any = await runCheck(input, { fetchImpl: o.fetchImpl, now: o.now, payerCache: o.payerCache, parts: o.parts });
  report.method_notes.run_from = o.runFrom;
  if (OWN_HOSTS.test(report.subject.host)) {
    report.conflict_of_interest = "This endpoint is run by ColdRead's own operator. Treat this report as self-assessment.";
    if (o.runFrom === "cloudflare_worker") report.cannot_check.push("the hosted ColdRead Worker cannot fetch other Workers on the same workers.dev account (Cloudflare returns 404), so this result for our own service is not meaningful; reports for our services are produced from outside Cloudflare and published in the buildlog repo");
  }
  report.disclaimer = "Not a rating agency: this describes software behaviour and public chain facts at checked_at, not creditworthiness, and is not financial advice.";
  return seal(report, o.key, o.keysUrl);
}
