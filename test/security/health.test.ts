/**
 * Health-aware routing unit tests. Run: npx tsx test/security/health.test.ts
 * Pure functions (src/router/health.ts) — no server, no network, fully deterministic.
 */

import { healthAwareModel, isLoopbackUrl, computeLiveModels, autoProbeProvider } from "../../src/router/health.js";

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

const live = (...ids: string[]) => new Set(ids);

console.log("healthAwareModel — no liveness signal is a no-op (route as configured):");
{
  const r = healthAwareModel("bedrock/gpt-oss-120b", ["bedrock/gpt-oss-120b"], new Set());
  ok("empty live set -> null", r === null);
}

console.log("\nhealthAwareModel — routed model already live is a no-op:");
{
  const r = healthAwareModel("secllm/Llama-3.2-3B-Instruct", ["secllm/Llama-3.2-3B-Instruct", "secllm/gemma-4-26B-A4B-it"], live("secllm/Llama-3.2-3B-Instruct", "secllm/gemma-4-26B-A4B-it"));
  ok("routed model in live set -> null", r === null);
}

console.log("\nhealthAwareModel — sole live model: every non-gated request collapses onto it:");
{
  const r = healthAwareModel("bedrock/gpt-oss-120b", ["bedrock/gpt-oss-120b", "bedrock/gpt-oss-20b"], live("secllm/Llama-3.2-3B-Instruct"));
  ok("routed dead, one model live -> collapse to it", r?.model === "secllm/Llama-3.2-3B-Instruct", JSON.stringify(r));
  ok("reason names the sole live model", !!r && /sole live model/.test(r.reason), r?.reason);
}

console.log("\nhealthAwareModel — prefers a LIVE model from the tier's own chain, in order:");
{
  // primary dead, first fallback live, second fallback also live -> take the FIRST live in chain
  const r = healthAwareModel(
    "bedrock/gpt-oss-120b",
    ["bedrock/gpt-oss-120b", "azure/gpt-4o", "local/llama-3.3-70b"],
    live("azure/gpt-4o", "local/llama-3.3-70b"),
  );
  ok("first live in chain wins (azure/gpt-4o)", r?.model === "azure/gpt-4o", JSON.stringify(r));
  ok("tier-fallback reason, not sole-live", !!r && /tier fallback/.test(r.reason), r?.reason);
}

console.log("\nhealthAwareModel — a chain fallback equal to routedModel is skipped:");
{
  // routedModel appears in its own chain (as primary); it's dead; the live one is the fallback
  const r = healthAwareModel(
    "bedrock/gpt-oss-120b",
    ["bedrock/gpt-oss-120b", "secllm/Llama-3.2-3B-Instruct"],
    live("secllm/Llama-3.2-3B-Instruct", "secllm/gemma-4-26B-A4B-it"), // 2 live -> not sole; must come from the chain
  );
  ok("skips dead routed, returns live chain fallback", r?.model === "secllm/Llama-3.2-3B-Instruct", JSON.stringify(r));
}

console.log("\nhealthAwareModel — several live but none in this tier's chain: don't cross tiers:");
{
  const r = healthAwareModel(
    "bedrock/gpt-oss-120b",
    ["bedrock/gpt-oss-120b"], // chain has only the (dead) primary
    live("secllm/Llama-3.2-3B-Instruct", "secllm/gemma-4-26B-A4B-it"), // 2 live, neither in chain
  );
  ok("multiple live, none in chain -> null (no guess)", r === null, JSON.stringify(r));
}

console.log("\nisLoopbackUrl — local endpoints are safe to auto-probe; remote are not:");
{
  ok("http://127.0.0.1:11400/v1", isLoopbackUrl("http://127.0.0.1:11400/v1"));
  ok("http://localhost:11400/v1", isLoopbackUrl("http://localhost:11400/v1"));
  ok("http://[::1]:11400/v1", isLoopbackUrl("http://[::1]:11400/v1"));
  ok("http://127.5.0.9/v1 (whole 127/8)", isLoopbackUrl("http://127.5.0.9/v1"));
  ok("http://secllm.localhost/v1", isLoopbackUrl("http://secllm.localhost/v1"));
  ok("bedrock gov endpoint is remote", !isLoopbackUrl("https://bedrock-runtime.us-gov-west-1.amazonaws.com/openai/v1"));
  ok("a public host is remote", !isLoopbackUrl("https://llm.internal.example.mil/v1"));
  ok("unparseable -> remote (conservative)", !isLoopbackUrl("not a url"));
}

console.log("\ncomputeLiveModels — folds served-model sets into fully-qualified live ids:");
{
  const served = new Map<string, Set<string>>([
    ["secllm#0", new Set(["Llama-3.2-3B-Instruct", "gemma-4-26B-A4B-it"])],
    ["bedrock#0", new Set(["openai.gpt-oss-20b-1:0"])], // bare id with dots/colon survives intact
  ]);
  const out = computeLiveModels(served, new Set());
  ok("provider/model fan-out", out.has("secllm/Llama-3.2-3B-Instruct") && out.has("secllm/gemma-4-26B-A4B-it"), [...out].join(","));
  ok("provider prefix taken before the LAST '#'; colon id intact", out.has("bedrock/openai.gpt-oss-20b-1:0"), [...out].join(","));
  ok("size is the union count", out.size === 3, String(out.size));
}

console.log("\ncomputeLiveModels — an open endpoint contributes nothing:");
{
  const served = new Map<string, Set<string>>([
    ["secllm#0", new Set(["Llama-3.2-3B-Instruct"])],
    ["secllm#1", new Set(["gemma-4-26B-A4B-it"])],
  ]);
  const out = computeLiveModels(served, new Set(["secllm#1"])); // endpoint 1 circuit open
  ok("open endpoint's model excluded", out.has("secllm/Llama-3.2-3B-Instruct") && !out.has("secllm/gemma-4-26B-A4B-it"), [...out].join(","));
}

console.log("\nautoProbeProvider — what's safe to actively probe in auto mode:");
{
  // Pooled provider (>1 endpoint): probe regardless of locality (LB needs per-replica liveness).
  ok("pooled remote provider -> probe", autoProbeProvider("bedrock", ["https://a.example/v1", "https://b.example/v1"], false));
  // Single remote third-party endpoint: passive by default (no background egress).
  ok("single remote endpoint -> passive", !autoProbeProvider("bedrock", ["https://bedrock.example/v1"], false));
  // Loopback endpoint: always safe to poll (not egress).
  ok("single loopback endpoint -> probe", autoProbeProvider("local", ["http://127.0.0.1:11400/v1"], false));
  // The turnkey SecLLM intake pool addressed by FQDN (SecDeploy single-host): probe because the
  // intake flag says it's our own inference tier — the loopback signal alone would miss it.
  ok("secllm intake, single FQDN endpoint -> probe", autoProbeProvider("secllm", ["http://secllm.suite.mil:11400/v1"], true));
  // Same provider/endpoint but intake NOT active (hand-authored remote 'secllm'): stays passive.
  ok("remote 'secllm' without intake flag -> passive", !autoProbeProvider("secllm", ["http://secllm.suite.mil:11400/v1"], false));
  // The intake flag only privileges the provider actually named 'secllm'.
  ok("intake flag doesn't privilege other providers", !autoProbeProvider("bedrock", ["https://bedrock.example/v1"], true));
}

console.log(`\nHealth-aware: ${pass} passed, ${fail} failed`);
if (fail > 0) process.exit(1);
