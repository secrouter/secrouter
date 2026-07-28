/**
 * Metrics module tests. Run: npx tsx test/security/metrics.test.ts
 * Proves the hand-rolled Prometheus exposition is well-formed and that labels
 * stay bounded (no principal / request id ever appears in /metrics).
 */

import { metrics, renderMetrics } from "../../src/metrics.js";

let pass = 0;
let fail = 0;
const ok = (n: string, c: boolean, x = "") => {
  if (c) (pass++, console.log(`  ✓ ${n}`));
  else (fail++, console.error(`  ✗ ${n} ${x}`));
};

console.log("Metrics exposition:");

metrics.requestsTotal.inc({ tier: "MEDIUM", provider: "local", model: "local/m", outcome: "ok" });
metrics.requestsTotal.inc({ tier: "MEDIUM", provider: "local", model: "local/m", outcome: "ok" });
metrics.tokensTotal.inc({ direction: "input" }, 100);
metrics.tokensTotal.inc({ direction: "output" }, 40);
metrics.costUsdTotal.inc({}, 0.0025);
metrics.authFailuresTotal.inc();
metrics.egressDeniedTotal.inc();
metrics.upstreamErrorsTotal.inc({ provider: "bedrock" });
metrics.requestDuration.observe({ tier: "MEDIUM" }, 0.3);
metrics.requestDuration.observe({ tier: "MEDIUM" }, 1.5);
metrics.circuitState.set({ provider: "local" }, 1); // open
metrics.circuitTransitionsTotal.inc({ provider: "local", state: "open" });

const out = renderMetrics();

ok("HELP + TYPE headers", /# HELP secrouter_requests_total /.test(out) && /# TYPE secrouter_requests_total counter/.test(out));
ok("labeled counter accumulates", out.includes('secrouter_requests_total{tier="MEDIUM",provider="local",model="local/m",outcome="ok"} 2'));
ok("tokens split by direction", out.includes('secrouter_tokens_total{direction="input"} 100') && out.includes('secrouter_tokens_total{direction="output"} 40'));
ok("float cost counter", /secrouter_cost_usd_total 0\.0025/.test(out));
ok("unlabeled counter renders its value", out.includes("secrouter_auth_failures_total 1"));
ok("un-touched counter still initializes to 0", out.includes("secrouter_quota_denied_total 0"));
ok("labeled upstream errors", out.includes('secrouter_upstream_errors_total{provider="bedrock"} 1'));
ok(
  "histogram: cumulative buckets + le=+Inf",
  out.includes('secrouter_request_duration_seconds_bucket{tier="MEDIUM",le="0.5"} 1') &&
    out.includes('secrouter_request_duration_seconds_bucket{tier="MEDIUM",le="+Inf"} 2'),
);
ok(
  "histogram: _sum and _count",
  /secrouter_request_duration_seconds_sum\{tier="MEDIUM"\} 1\.8/.test(out) &&
    out.includes('secrouter_request_duration_seconds_count{tier="MEDIUM"} 2'),
);
ok("gauges present", /secrouter_up 1/.test(out) && /secrouter_start_time_seconds \d+/.test(out));
ok(
  "circuit-breaker gauge + transitions counter (Phase C)",
  /# TYPE secrouter_circuit_state gauge/.test(out) &&
    out.includes('secrouter_circuit_state{provider="local"} 1') &&
    out.includes('secrouter_circuit_transitions_total{provider="local",state="open"} 1'),
);
ok("NO principal / request-id labels leak", !/principal|request_?id/i.test(out));

console.log(`\nMetrics: ${pass} passed, ${fail} failed`);
if (fail > 0) process.exit(1);
