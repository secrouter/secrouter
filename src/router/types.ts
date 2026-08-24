/**
 * Smart Router Types — derived from an MIT-licensed upstream router (see NOTICE).
 * No payment layer.
 *
 * Four classification tiers — REASONING is distinct from COMPLEX because
 * reasoning tasks need different models (o3, deepseek-reasoner) than general
 * complex tasks (gpt-4o, sonnet-4).
 *
 * Scoring uses weighted float dimensions with sigmoid confidence calibration.
 */

export type Tier = "SIMPLE" | "MEDIUM" | "COMPLEX" | "REASONING";

export type ScoringResult = {
  score: number; // weighted float (roughly [-0.3, 0.4])
  tier: Tier | null; // null = ambiguous, needs fallback
  confidence: number; // sigmoid-calibrated [0, 1]
  signals: string[];
  agenticScore?: number; // 0-1 agentic task score for auto-switching to agentic tiers
};

export type RoutingDecision = {
  model: string;
  tier: Tier;
  confidence: number;
  method: "rules" | "llm";
  reasoning: string;
  costEstimate: number;
  baselineCost: number;
  savings: number; // 0-1 percentage
};

export type TierConfig = {
  primary: string;
  fallback: string[];
};

export type ScoringConfig = {
  tokenCountThresholds: { simple: number; complex: number };
  codeKeywords: string[];
  reasoningKeywords: string[];
  simpleKeywords: string[];
  technicalKeywords: string[];
  creativeKeywords: string[];
  imperativeVerbs: string[];
  constraintIndicators: string[];
  outputFormatKeywords: string[];
  referenceKeywords: string[];
  negationKeywords: string[];
  domainSpecificKeywords: string[];
  agenticTaskKeywords: string[];
  dimensionWeights: Record<string, number>;
  tierBoundaries: {
    simpleMedium: number;
    mediumComplex: number;
    complexReasoning: number;
  };
  confidenceSteepness: number;
  confidenceThreshold: number;
};

export type ClassifierConfig = {
  llmModel: string;
  llmMaxTokens: number;
  llmTemperature: number;
  promptTruncationChars: number;
  cacheTtlMs: number;
};

export type OverridesConfig = {
  maxTokensForceComplex: number;
  structuredOutputMinTier: Tier;
  ambiguousDefaultTier: Tier;
  agenticMode?: boolean;
};

// ─── Experiments: split routing (A/B) + escalation routing ───

/** One weighted candidate model within a tier's split. */
export type SplitVariant = {
  model: string; // "provider/model" form
  weight: number; // > 0; relative weight (need not sum to 1 or 100)
};

export type SplitTierConfig = {
  variants: SplitVariant[]; // >= 2
};

/**
 * Split (A/B) routing: for a given tier, weighted-random-pick one of several
 * candidate models instead of always using the tier's configured primary.
 * Used to benchmark models against real traffic. See router/split.ts.
 */
export type SplitConfig = {
  enabled: boolean;
  name: string; // experiment name, echoed in headers/audit/reasoning
  tiers: Partial<Record<Tier, SplitTierConfig>>;
};

export type EscalationJudgeConfig = {
  mode: "heuristic" | "model";
  /** Required when mode === "model". "provider/model" form. */
  model?: string;
  /** Judge call timeout, ms. Default 10_000. */
  timeoutMs?: number;
  /** Minimum acceptable draft length (chars); shorter drafts escalate. Default 1. */
  minDraftChars?: number;
  /** Regex source strings tested against the draft text; a match escalates. */
  refusalPatterns?: string[];
};

/**
 * Escalation routing: draft a cheap-tier response, judge it, and escalate once
 * to a stronger tier if the draft looks weak. See router/escalation.ts.
 */
export type EscalationConfig = {
  enabled: boolean;
  fromTiers: Tier[]; // tiers eligible to be drafted-then-judged
  toTier: Tier; // escalation target; must not be one of fromTiers
  judge: EscalationJudgeConfig;
};

export type ExperimentsConfig = {
  split?: SplitConfig;
  escalation?: EscalationConfig;
};

export type RoutingConfig = {
  version: string;
  classifier: ClassifierConfig;
  scoring: ScoringConfig;
  tiers: Record<Tier, TierConfig>;
  agenticTiers?: Record<Tier, TierConfig>;
  overrides: OverridesConfig;
  experiments?: ExperimentsConfig;
};
