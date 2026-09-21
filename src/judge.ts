/**
 * Judge — the autonomous half of the Axiom. An LLM reads the finding + verbatim
 * exploit/control evidence and decides if the invariant is genuinely violated.
 * Strictness is encoded in the prompt (differential required) and enforced by
 * the Axiom (high confidence bar + deterministic veto on no-differential).
 */

import { OpenRouterLlm } from "./llm.js";
import type { AxiomInput, VerdictStatus } from "./axiom.js";

export interface JudgeVerdict {
  invariant_violated: boolean;
  verdict: VerdictStatus;
  confidence: number; // 0..1
  reasoning: string;
}

export interface Judge {
  judge(input: AxiomInput): Promise<JudgeVerdict>;
}

const JUDGE_PROMPT = `You are a strict vulnerability-validation judge for an authorized penetration-test framework.
Your ONLY job is to eliminate false positives. A finding is real ONLY IF the exploit response clearly demonstrates the vulnerability AND the control response (a benign/malformed request) does NOT show the same effect (a true differential).

Rules:
- CONFIRMED only with clear, verbatim differential evidence: exploit shows the effect, control does not.
- If the control is missing, empty, or shows the same effect, return FALSE_POSITIVE or NEEDS_REVIEW — never CONFIRMED.
- If you are not sure, return NEEDS_REVIEW (a human will decide).
- Do not be swayed by the reporter's prose; judge only the actual evidence excerpts and status codes.

Respond with ONLY a JSON object, no prose:
{"invariant_violated": <bool>, "verdict": "CONFIRMED"|"FALSE_POSITIVE"|"NEEDS_REVIEW", "confidence": <0..1>, "reasoning": "<one short sentence>"}`;

function extractJson(text: string): unknown | null {
  const open = text.indexOf("{");
  if (open === -1) return null;
  const close = text.lastIndexOf("}");
  if (close <= open) return null;
  try {
    return JSON.parse(text.slice(open, close + 1));
  } catch {
    return null;
  }
}

export class LlmJudge implements Judge {
  constructor(
    private readonly llm: OpenRouterLlm,
    private readonly model: string,
  ) {}

  async judge(input: AxiomInput): Promise<JudgeVerdict> {
    const resp = await this.llm.complete({
      model: this.model,
      messages: [
        { role: "system", content: JUDGE_PROMPT },
        { role: "user", content: JSON.stringify(input, null, 2).slice(0, 12_000) },
      ],
      temperature: 0,
    });

    const parsed = extractJson(resp.content) as Partial<JudgeVerdict> | null;
    if (!parsed) {
      return {
        invariant_violated: false,
        verdict: "NEEDS_REVIEW",
        confidence: 0,
        reasoning: "judge returned no parseable verdict",
      };
    }

    const verdict: VerdictStatus =
      parsed.verdict === "CONFIRMED" || parsed.verdict === "FALSE_POSITIVE" || parsed.verdict === "NEEDS_REVIEW"
        ? parsed.verdict
        : "NEEDS_REVIEW";
    const confidence = typeof parsed.confidence === "number" ? Math.max(0, Math.min(1, parsed.confidence)) : 0;

    return {
      invariant_violated: parsed.invariant_violated === true,
      verdict,
      confidence,
      reasoning: typeof parsed.reasoning === "string" ? parsed.reasoning : "",
    };
  }
}
