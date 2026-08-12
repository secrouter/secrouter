/**
 * buildOpenAIRequestBody — the forwarded-field allow-list for the OpenAI-compatible
 * upstream path (provider.ts forwardToOpenAI). Regression guard: `tools`/`tool_choice`
 * (and `stop`) MUST be forwarded verbatim, or tool-calling is SILENTLY broken for every
 * OpenAI-compatible backend (MLX / vLLM / Ollama / TGI / Bedrock-openai / Azure) — the
 * model just narrates the tool in prose and never returns a structured call. Regression
 * for the bug where the OpenAI body was built with only model/messages/stream/max_tokens/
 * temperature/top_p while the Anthropic path already forwarded tools.
 *
 * Run: npx tsx test/security/openai-forward.test.ts
 */

import { buildOpenAIRequestBody, resolveSecllmModel, type ChatRequest } from "../../src/provider.js";

let pass = 0;
let fail = 0;
function ok(name: string, cond: boolean, extra = "") {
  if (cond) {
    pass++;
    console.log(`  ✓ ${name}`);
  } else {
    fail++;
    console.error(`  ✗ ${name} ${extra}`);
  }
}

const TOOLS = [
  {
    type: "function",
    function: {
      name: "get_weather",
      description: "Get current weather",
      parameters: { type: "object", properties: { city: { type: "string" } }, required: ["city"] },
    },
  },
];

console.log("tools + tool_choice are forwarded verbatim (the core regression):");
{
  const body = buildOpenAIRequestBody(
    { model: "client-asked", messages: [{ role: "user", content: "hi" }], tools: TOOLS as any, tool_choice: "auto" } as ChatRequest,
    "secllm/gemma",
    false,
  );
  ok("tools present in the upstream body (not dropped)", JSON.stringify(body.tools) === JSON.stringify(TOOLS), JSON.stringify(body.tools));
  ok("tool_choice forwarded unchanged", body.tool_choice === "auto");
  ok("model set to the resolved upstream id (not the client's)", body.model === "secllm/gemma");
  ok("messages forwarded", Array.isArray(body.messages) && (body.messages as unknown[]).length === 1);
  ok("stream=false forwarded", body.stream === false);
  ok("no stream_options on a non-streaming call", body.stream_options === undefined);
}

console.log("\ntool_choice is omitted when there are no tools (meaningless without them):");
{
  const body = buildOpenAIRequestBody({ model: "m", messages: [], tool_choice: "auto" } as ChatRequest, "u", false);
  ok("no tools key", body.tools === undefined);
  ok("no orphan tool_choice key", body.tool_choice === undefined);
}

console.log("\nan empty tools array is treated as no tools:");
{
  const body = buildOpenAIRequestBody({ model: "m", messages: [], tools: [] as any, tool_choice: "auto" } as ChatRequest, "u", false);
  ok("empty tools ⇒ tools omitted", body.tools === undefined);
  ok("empty tools ⇒ tool_choice omitted", body.tool_choice === undefined);
}

console.log("\nsampling/stop params forwarded only when present:");
{
  const full = buildOpenAIRequestBody(
    { model: "m", messages: [], max_tokens: 128, temperature: 0.2, top_p: 0.9, stop: ["</s>"] } as ChatRequest,
    "u",
    false,
  );
  ok("max_tokens forwarded", full.max_tokens === 128);
  ok("temperature forwarded", full.temperature === 0.2);
  ok("top_p forwarded", full.top_p === 0.9);
  ok("stop forwarded", JSON.stringify(full.stop) === JSON.stringify(["</s>"]));
  const bare = buildOpenAIRequestBody({ model: "m", messages: [] } as ChatRequest, "u", false);
  ok(
    "absent optional fields are omitted entirely (no undefined-valued keys)",
    !("max_tokens" in bare) && !("temperature" in bare) && !("top_p" in bare) && !("stop" in bare) && !("tools" in bare),
    JSON.stringify(bare),
  );
}

console.log("\nstreaming adds stream_options so usage accounting isn't silently zero:");
{
  const body = buildOpenAIRequestBody({ model: "m", messages: [] } as ChatRequest, "u", true);
  ok("stream=true forwarded", body.stream === true);
  ok("stream_options.include_usage set", JSON.stringify(body.stream_options) === JSON.stringify({ include_usage: true }));
}

console.log("\nresolveSecllmModel — an explicit secllm/<tag> resolves via the SECROUTER_SECLLM_MODELS remap:");
{
  const aliases = { balanced: "lmstudio-community/gemma-4-26B", fast: "mlx-community/Llama-3.2-3B" };
  ok("secllm + mapped tag → the real backend id", resolveSecllmModel("secllm", "balanced", aliases) === "lmstudio-community/gemma-4-26B");
  ok("secllm + a different mapped tag", resolveSecllmModel("secllm", "fast", aliases) === "mlx-community/Llama-3.2-3B");
  ok("secllm + unmapped tag → unchanged (literal forwarded)", resolveSecllmModel("secllm", "large", aliases) === "large");
  ok("secllm + already-real id → unchanged (tier route carries the id)", resolveSecllmModel("secllm", "lmstudio-community/gemma-4-26B", aliases) === "lmstudio-community/gemma-4-26B");
  ok("non-secllm provider → never remapped", resolveSecllmModel("bedrock", "balanced", aliases) === "balanced");
  ok("no aliases configured → unchanged", resolveSecllmModel("secllm", "balanced", undefined) === "balanced");
}

console.log(`\nOpenAI forward body: ${pass} passed, ${fail} failed`);
if (fail > 0) process.exit(1);
