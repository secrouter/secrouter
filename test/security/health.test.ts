/**
 * Health-aware routing unit tests. Run: npx tsx test/security/health.test.ts
 * Pure functions (src/router/health.ts) — no server, no network, fully deterministic.
 */

import { healthAwareModel, isLoopbackUrl, computeLiveModels } from "../../src/router/health.js";

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
  const r = healthAwareModel("secllm/fast", ["secllm/fast", "secllm/balanced"], live("secllm/fast", "secllm/balanced"));
  ok("routed model in live set -> null", r === null);
}

console.log("\nhealthAwareModel — sole live model: every non-gated request collapses onto it:");
{
  const r = healthAwareModel("bedrock/gpt-oss-120b", ["bedrock/gpt-oss-120b", "bedrock/gpt-oss-20b"], live("secllm/fast"));
  ok("routed dead, one model live -> collapse to it", r?.model === "secllm/fast", JSON.stringify(r));
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
    ["bedrock/gpt-oss-120b", "secllm/fast"],
    live("secllm/fast", "secllm/balanced"), // 2 live -> not sole; must come from the chain
  );
  ok("skips dead routed, returns live chain fallback", r?.model === "secllm/fast", JSON.stringify(r));
}

console.log("\nhealthAwareModel — several live but none in this tier's chain: don't cross tiers:");
{
  const r = healthAwareModel(
    "bedrock/gpt-oss-120b",
    ["bedrock/gpt-oss-120b"], // chain has only the (dead) primary
    live("secllm/fast", "secllm/balanced"), // 2 live, neither in chain
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
    ["secllm#0", new Set(["fast", "balanced"])],
    ["bedrock#0", new Set(["openai.gpt-oss-20b-1:0"])], // bare id with dots/colon survives intact
  ]);
  const out = computeLiveModels(served, new Set());
  ok("provider/model fan-out", out.has("secllm/fast") && out.has("secllm/balanced"), [...out].join(","));
  ok("provider prefix taken before the LAST '#'; colon id intact", out.has("bedrock/openai.gpt-oss-20b-1:0"), [...out].join(","));
  ok("size is the union count", out.size === 3, String(out.size));
}

console.log("\ncomputeLiveModels — an open endpoint contributes nothing:");
{
  const served = new Map<string, Set<string>>([
    ["secllm#0", new Set(["fast"])],
    ["secllm#1", new Set(["balanced"])],
  ]);
  const out = computeLiveModels(served, new Set(["secllm#1"])); // endpoint 1 circuit open
  ok("open endpoint's model excluded", out.has("secllm/fast") && !out.has("secllm/balanced"), [...out].join(","));
}

console.log(`\nHealth-aware: ${pass} passed, ${fail} failed`);
if (fail > 0) process.exit(1);
