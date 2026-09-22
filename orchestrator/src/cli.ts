import OpenAI from "openai";
import { observeOpenAI } from "@langfuse/openai";
import { runBeat } from "./beat.js";

const env = process.env as Record<string, string | undefined>;
const dryRun = process.argv.includes("--dry-run");

const baseURL = env.SAHW_PROFILE === "prod" ? env.SAGEMAKER_BASE_URL : env.OPENROUTER_BASE_URL;
// prod issues a short-lived credential from the AI Gateway (spec 4.1); SAGEMAKER_API_KEY
// is a dev-only fallback until that gateway exists.
const apiKey = env.SAHW_PROFILE === "prod" ? env.SAGEMAKER_API_KEY : env.SAHW_OPENROUTER_KEY;

// observeOpenAI wraps the CLI edge only — runBeat/runAgent keep taking a plain
// MinimalClient so the existing stubbed tests are untouched. It is safe to apply
// unconditionally: with no LANGFUSE_PUBLIC_KEY/SECRET_KEY configured, the spans it
// creates are no-ops (see src/obs/langfuse.ts) and every call still reaches OpenAI
// exactly as before.
const client = observeOpenAI(new OpenAI({
  baseURL,
  apiKey: apiKey ?? "unset",
  timeout: Number(env.SAHW_REQUEST_TIMEOUT_MS ?? 3_600_000),
  maxRetries: Number(env.SAHW_MAX_RETRIES ?? 0),
}));

if (dryRun) {
  console.log(JSON.stringify({ dryRun: true, scope: env.SAHW_SCOPE, profile: env.SAHW_PROFILE ?? "test" }));
  process.exit(0);
}

// A transient network fault must not destroy a beat's results.
//
// Beat 5 crashed with an unhandled `TypeError: terminated` (cause: EHOSTUNREACH)
// from an in-flight fetch while the target was blipping. The process died before
// printing anything, so four CONFIRMED findings survived only because each is
// written to the stores as it is confirmed rather than batched at the end.
// A transport hiccup is an operational event, not a reason to lose evidence.
let lateFault: unknown = null;
process.on("unhandledRejection", (reason) => { lateFault = reason; });
process.on("uncaughtException",  (err)    => { lateFault = err; });

let out: Awaited<ReturnType<typeof runBeat>> | null = null;
let failure: unknown = null;
try {
  out = await runBeat({ env, client });
} catch (err) {
  failure = err;
}

if (out) {
  // Report the beat honestly, including a fault that arrived after it finished.
  const payload = lateFault
    ? { ...out, late_fault: String((lateFault as Error)?.message ?? lateFault) }
    : out;
  console.log(JSON.stringify(payload, null, 2));
  process.exit(out.exitCode);
}

// runBeat itself threw: emit a valid result describing the failure rather than a
// bare stack trace, so a caller can still parse the outcome.
console.log(JSON.stringify({
  exitCode: 1,
  findings: [],
  stalled: false,
  reason: `beat aborted: ${String((failure as Error)?.message ?? failure)}`,
  fatal: true,
}, null, 2));
console.error(failure);
process.exit(1);
