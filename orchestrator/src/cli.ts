import OpenAI from "openai";
import { runBeat } from "./beat.js";

const env = process.env as Record<string, string | undefined>;
const dryRun = process.argv.includes("--dry-run");

const baseURL = env.SAHW_PROFILE === "prod" ? env.SAGEMAKER_BASE_URL : env.OPENROUTER_BASE_URL;
// prod issues a short-lived credential from the AI Gateway (spec 4.1); SAGEMAKER_API_KEY
// is a dev-only fallback until that gateway exists.
const apiKey = env.SAHW_PROFILE === "prod" ? env.SAGEMAKER_API_KEY : env.SAHW_OPENROUTER_KEY;

const client = new OpenAI({
  baseURL,
  apiKey: apiKey ?? "unset",
  timeout: Number(env.SAHW_REQUEST_TIMEOUT_MS ?? 3_600_000),
  maxRetries: Number(env.SAHW_MAX_RETRIES ?? 0),
});

if (dryRun) {
  console.log(JSON.stringify({ dryRun: true, scope: env.SAHW_SCOPE, profile: env.SAHW_PROFILE ?? "test" }));
  process.exit(0);
}

const out = await runBeat({ env, client });
console.log(JSON.stringify(out, null, 2));
process.exit(out.exitCode);
