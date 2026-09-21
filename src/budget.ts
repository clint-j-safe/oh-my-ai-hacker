/**
 * Budget Governor — deterministic USD / turns / tokens accounting.
 *
 * Watches spend from outside the loop. Each `record` call is one turn; the
 * token total is input + output + reasoning + cache read + cache write
 * (matching AssistantMessage.tokens from the OpenCode SDK).
 */

export interface TokenUsage {
  input: number;
  output: number;
  reasoning: number;
  cache: { read: number; write: number };
}

export interface BudgetLimits {
  usd: number;
  turns: number;
  tokens: number;
}

export interface BudgetUsage {
  usd: number;
  turns: number;
  tokens: number;
}

export type BreachKind = "usd" | "turns" | "tokens";

export interface BudgetCheck {
  ok: boolean;
  breach?: BreachKind;
}

export function tokenTotal(t: TokenUsage): number {
  return t.input + t.output + t.reasoning + t.cache.read + t.cache.write;
}

export class Budget {
  readonly limits: BudgetLimits;
  private state: BudgetUsage = { usd: 0, turns: 0, tokens: 0 };

  constructor(limits: BudgetLimits) {
    this.limits = limits;
  }

  /** Record one turn's cost and token usage. */
  record(turn: { cost: number; tokens: TokenUsage }): void {
    this.state.usd += turn.cost;
    this.state.tokens += tokenTotal(turn.tokens);
    this.state.turns += 1;
  }

  usage(): BudgetUsage {
    return { ...this.state };
  }

  check(): BudgetCheck {
    if (this.state.usd > this.limits.usd) return { ok: false, breach: "usd" };
    if (this.state.turns > this.limits.turns) return { ok: false, breach: "turns" };
    if (this.state.tokens > this.limits.tokens) return { ok: false, breach: "tokens" };
    return { ok: true };
  }

  /** True only while strictly under every limit (safe to take another turn). */
  canContinue(): boolean {
    return (
      this.state.usd < this.limits.usd &&
      this.state.turns < this.limits.turns &&
      this.state.tokens < this.limits.tokens
    );
  }

  reset(): void {
    this.state = { usd: 0, turns: 0, tokens: 0 };
  }
}
