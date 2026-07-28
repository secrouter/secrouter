/**
 * Model Definitions — Direct API (No BlockRun/x402)
 *
 * Maps YOUR provider models with pricing for the cost calculator.
 * These match the models configured in your openclaw.json.
 *
 * Pricing is in USD per 1M tokens.
 * Add/remove models as you add providers to openclaw.json.
 */

import { getConfig } from "./config.js";

export type ModelDef = {
  /** OpenClaw model ID: "provider/model-id" */
  id: string;
  name: string;
  inputPrice: number;   // $/1M input tokens
  outputPrice: number;  // $/1M output tokens
  contextWindow: number;
  maxOutput: number;
  reasoning?: boolean;
  vision?: boolean;
  agentic?: boolean;
  kind?: "chat" | "embedding";
};

// ─── YOUR CONFIGURED MODELS ───

export const MODELS: ModelDef[] = [
  // ═══ Claude on Amazon Bedrock — AWS GovCloud (FedRAMP High / IL4-5) ═══
  // The CUI-authorized path. Model ids match Bedrock; verify availability in
  // the GovCloud console at deploy time. Pricing per Bedrock public rates.
  {
    id: "bedrock/anthropic.claude-opus-4-20250514-v1:0",
    name: "Claude Opus 4 (Bedrock GovCloud)",
    inputPrice: 15,
    outputPrice: 75,
    contextWindow: 200_000,
    maxOutput: 32_000,
    reasoning: true,
    vision: true,
    agentic: true,
  },
  {
    id: "bedrock/anthropic.claude-3-5-sonnet-20241022-v2:0",
    name: "Claude 3.5 Sonnet v2 (Bedrock GovCloud)",
    inputPrice: 3,
    outputPrice: 15,
    contextWindow: 200_000,
    maxOutput: 8_192,
    vision: true,
    agentic: true,
  },
  {
    id: "bedrock/anthropic.claude-3-5-haiku-20241022-v1:0",
    name: "Claude 3.5 Haiku (Bedrock GovCloud)",
    inputPrice: 0.8,
    outputPrice: 4,
    contextWindow: 200_000,
    maxOutput: 8_192,
    agentic: true,
  },

  // ═══ Self-hosted / air-gapped (OpenAI-compatible, inside the boundary) ═══
  // No per-token cost — runs on your own compute. Set baseUrl to your vLLM/TGI.
  {
    id: "local/llama-3.3-70b-instruct",
    name: "Llama 3.3 70B (self-hosted)",
    inputPrice: 0,
    outputPrice: 0,
    contextWindow: 128_000,
    maxOutput: 8_192,
    agentic: true,
  },

  // ═══ Commercial direct APIs — NOT CUI-authorized; reference pricing only ═══
  // Reachable only if explicitly added to the egress allow-list for a
  // non-CUI classification. The default hardened config does NOT list these.
  {
    id: "anthropic/claude-opus-4-6",
    name: "Claude Opus 4 (commercial — non-CUI)",
    inputPrice: 15,
    outputPrice: 75,
    contextWindow: 200_000,
    maxOutput: 32_000,
    reasoning: true,
    vision: true,
    agentic: true,
  },

  // ═══ OpenAI (API key available — add to openclaw.json) ═══
  {
    id: "openai/gpt-4o",
    name: "GPT-4o",
    inputPrice: 2.5,
    outputPrice: 10,
    contextWindow: 128_000,
    maxOutput: 16_384,
    vision: true,
    agentic: true,
  },
  {
    id: "openai/gpt-4o-mini",
    name: "GPT-4o Mini",
    inputPrice: 0.15,
    outputPrice: 0.6,
    contextWindow: 128_000,
    maxOutput: 16_384,
  },
  {
    id: "openai/o3",
    name: "o3",
    inputPrice: 2.0,
    outputPrice: 8.0,
    contextWindow: 200_000,
    maxOutput: 100_000,
    reasoning: true,
  },
  {
    id: "openai/o3-mini",
    name: "o3-mini",
    inputPrice: 1.1,
    outputPrice: 4.4,
    contextWindow: 128_000,
    maxOutput: 65_536,
    reasoning: true,
  },

  // ═══ Google (service account available — add to openclaw.json) ═══
  {
    id: "google/gemini-2.5-pro",
    name: "Gemini 2.5 Pro",
    inputPrice: 1.25,
    outputPrice: 10,
    contextWindow: 1_050_000,
    maxOutput: 65_536,
    reasoning: true,
    vision: true,
  },
  {
    id: "google/gemini-2.5-flash",
    name: "Gemini 2.5 Flash",
    inputPrice: 0.15,
    outputPrice: 0.6,
    contextWindow: 1_000_000,
    maxOutput: 65_536,
  },
];

/**
 * Effective model catalog: the hardcoded MODELS overlaid with any config
 * `models[]` entries (config wins by id). This is how on-prem / locally
 * registered models get pricing and metadata for cost tracking. Defaults for a
 * config-only model: prices 0 (self-hosted compute), 8K context / 4K output.
 */
export function getModelCatalog(): ModelDef[] {
  const byId = new Map<string, ModelDef>();
  for (const m of MODELS) byId.set(m.id, m);
  for (const c of getConfig().models ?? []) {
    if (!c?.id) continue;
    const base = byId.get(c.id);
    byId.set(c.id, {
      id: c.id,
      name: c.name ?? base?.name ?? c.id,
      inputPrice: c.inputPrice ?? base?.inputPrice ?? 0,
      outputPrice: c.outputPrice ?? base?.outputPrice ?? 0,
      contextWindow: c.contextWindow ?? base?.contextWindow ?? 8_192,
      maxOutput: c.maxOutput ?? base?.maxOutput ?? 4_096,
      reasoning: c.reasoning ?? base?.reasoning,
      vision: c.vision ?? base?.vision,
      agentic: c.agentic ?? base?.agentic,
      kind: c.kind ?? base?.kind,
    });
  }
  return [...byId.values()];
}

/**
 * Build the pricing map used by the router.
 */
export function buildPricingMap(): Map<string, { inputPrice: number; outputPrice: number }> {
  const map = new Map<string, { inputPrice: number; outputPrice: number }>();
  for (const m of getModelCatalog()) {
    map.set(m.id, { inputPrice: m.inputPrice, outputPrice: m.outputPrice });
  }
  return map;
}

/**
 * Get context window for a model ID.
 */
export function getContextWindow(modelId: string): number | undefined {
  return getModelCatalog().find((m) => m.id === modelId)?.contextWindow;
}

/**
 * Check if a model supports reasoning.
 */
export function isReasoningModel(modelId: string): boolean {
  return getModelCatalog().find((m) => m.id === modelId)?.reasoning ?? false;
}

/**
 * Check if a model is optimized for agentic workflows.
 */
export function isAgenticModel(modelId: string): boolean {
  return getModelCatalog().find((m) => m.id === modelId)?.agentic ?? false;
}
