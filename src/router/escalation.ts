/**
 * Escalation routing — draft a response on a cheap tier, judge it, and
 * escalate ONCE to a stronger tier if the draft looks weak. Lets an operator
 * stretch capacity: most requests get answered cheaply, only the ones that
 * actually need it pay for the expensive model.
 *
 * Pure judging logic lives here (no I/O, no server coupling) so verdicts are
 * unit-testable in isolation. The orchestration (draft forward -> judge ->
 * escalate forward, with breaker integration, usage accounting, and audit) is
 * in server.ts, since it needs the request pipeline's breaker/endpoint
 * machinery and the egress-gated forwardBufferedRequest (provider.ts).
 *
 * Streaming requests bypass escalation entirely (see server.ts) — the whole
 * point is to judge the draft BEFORE anything reaches the client, which is
 * impossible once tokens are already streaming out.
 */

import type { EscalationConfig, EscalationJudgeConfig, Tier } from "./types.js";

/** Sensible generic refusal/deflection patterns (regex source strings, case-insensitive). */
export const DEFAULT_REFUSAL_PATTERNS: string[] = [
  "i cannot help with that",
  "i can'?t help with that",
  "i'?m sorry,?\\s*(but\\s*)?i (can(not|'?t)|won'?t|am unable to)",
  "as an ai( language model)?,? i (cannot|can'?t|am not able to)",
  "i (must|have to) decline",
  "i am not able to assist",
  "i'?m not able to (help|assist) with",
  "i don'?t have (enough|sufficient) information to",
];

const DEFAULT_TIMEOUT_MS = 10_000;
const DEFAULT_MIN_DRAFT_CHARS = 1;

export type ResolvedJudgeConfig = {
  mode: "heuristic" | "model";
  model?: string;
  timeoutMs: number;
  minDraftChars: number;
  refusalPatterns: string[];
};

/** Fill in judge defaults (timeoutMs, minDraftChars, refusalPatterns). */
export function resolveJudgeConfig(judge: EscalationJudgeConfig): ResolvedJudgeConfig {
  return {
    mode: judge.mode,
    model: judge.model,
    timeoutMs: judge.timeoutMs ?? DEFAULT_TIMEOUT_MS,
    minDraftChars: judge.minDraftChars ?? DEFAULT_MIN_DRAFT_CHARS,
    refusalPatterns: judge.refusalPatterns ?? DEFAULT_REFUSAL_PATTERNS,
  };
}

/**
 * Validate an escalation config. Returns human-readable errors; empty = valid.
 * Rules: enabled requires non-empty fromTiers; toTier must not be one of
 * fromTiers; mode "model" requires judge.model.
 */
export function validateEscalationConfig(cfg: EscalationConfig | undefined): string[] {
  const errors: string[] = [];
  if (!cfg || !cfg.enabled) return errors;

  if (!cfg.fromTiers || cfg.fromTiers.length === 0) {
    errors.push("experiments.escalation.fromTiers must be non-empty when experiments.escalation.enabled is true");
  }
  if (cfg.toTier && cfg.fromTiers?.includes(cfg.toTier)) {
    errors.push(`experiments.escalation.toTier (${cfg.toTier}) must not also be a fromTiers entry`);
  }
  if (!cfg.judge) {
    errors.push("experiments.escalation.judge is required when enabled");
  } else {
    if (cfg.judge.mode === "model" && !cfg.judge.model) {
      errors.push('experiments.escalation.judge.model is required when judge.mode === "model"');
    }
    if (cfg.judge.mode !== "heuristic" && cfg.judge.mode !== "model") {
      errors.push(`experiments.escalation.judge.mode must be "heuristic" or "model" (got ${JSON.stringify(cfg.judge.mode)})`);
    }
    if (cfg.judge.timeoutMs !== undefined && !(cfg.judge.timeoutMs > 0)) {
      errors.push("experiments.escalation.judge.timeoutMs must be > 0");
    }
    if (cfg.judge.minDraftChars !== undefined && cfg.judge.minDraftChars < 0) {
      errors.push("experiments.escalation.judge.minDraftChars must be >= 0");
    }
  }
  return errors;
}

/** Whether escalation applies to this request. */
export function escalationApplies(cfg: EscalationConfig | undefined, tier: string, stream: boolean): boolean {
  if (!cfg || !cfg.enabled) return false;
  if (stream) return false; // draft must be judged before anything reaches the client
  if (tier === "EXPLICIT") return false;
  return cfg.fromTiers.includes(tier as Tier);
}

export type Verdict = {
  escalate: boolean;
  /** Short deterministic reason string naming which check fired (or "accept"). */
  reason: string;
};

/**
 * Heuristic judge — no extra LLM call. Escalates when the draft is empty, was
 * truncated (finishReason === "length"), matches a configured refusal pattern,
 * or is shorter than minDraftChars. Checked in that order; the first match
 * names the reason.
 */
export function heuristicVerdict(
  text: string,
  finishReason: string | undefined,
  judge: Pick<ResolvedJudgeConfig, "minDraftChars" | "refusalPatterns">,
): Verdict {
  if (!text || text.trim() === "") {
    return { escalate: true, reason: "empty_draft" };
  }
  if (finishReason === "length") {
    return { escalate: true, reason: "truncated_finish_reason" };
  }
  for (const pattern of judge.refusalPatterns) {
    let re: RegExp;
    try {
      re = new RegExp(pattern, "i");
    } catch {
      continue; // a malformed pattern shouldn't crash judging
    }
    if (re.test(text)) {
      return { escalate: true, reason: `refusal_pattern:${pattern}` };
    }
  }
  if (text.length < judge.minDraftChars) {
    return { escalate: true, reason: "draft_too_short" };
  }
  return { escalate: false, reason: "accept" };
}

/** System prompt for the model-judge rubric. Fixed — not principal-selectable. */
export const JUDGE_SYSTEM_PROMPT =
  'You are a strict quality judge. Decide whether the ASSISTANT ANSWER adequately addresses the USER REQUEST. ' +
  'Reply with EXACTLY one line: either "ACCEPT" or "ESCALATE: <short reason>". No other text.';

const JUDGE_PROMPT_CAP = 4000;

/** Build the judge's user-turn input: the (truncated) user prompt + the draft. */
export function buildJudgeInput(userPrompt: string, draftText: string, cap = JUDGE_PROMPT_CAP): string {
  const truncatedPrompt = userPrompt.length > cap ? `${userPrompt.slice(0, cap)}…(truncated)` : userPrompt;
  return `USER REQUEST:\n${truncatedPrompt}\n\nASSISTANT ANSWER:\n${draftText}`;
}

/**
 * Parse a model-judge's raw reply. Returns null when the output doesn't parse
 * as "ACCEPT" or "ESCALATE: ..." — callers must fail OPEN (accept the draft)
 * on null, matching judge timeout/error handling.
 */
export function parseJudgeVerdict(output: string): Verdict | null {
  const trimmed = output.trim();
  if (/^ACCEPT\b/i.test(trimmed)) return { escalate: false, reason: "accept" };
  const m = /^ESCALATE\s*:\s*(.*)$/is.exec(trimmed);
  if (m) return { escalate: true, reason: (m[1] || "unspecified").trim().slice(0, 200) };
  return null;
}
