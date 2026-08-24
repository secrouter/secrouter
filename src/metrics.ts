/**
 * Zero-dependency Prometheus metrics — bounded-cardinality counters, a gauge,
 * and a histogram rendered in the text exposition format (v0.0.4).
 *
 * Cardinality discipline: labels are limited to tier / provider / model /
 * outcome / direction. NEVER a principal id, request id, or free-form value —
 * per-principal detail lives in the usage ledger (GET /admin/usage), not here.
 * Keeping labels bounded is what makes /metrics safe to scrape at scale.
 */

interface Renderable {
  render(): string;
}

const registry: Renderable[] = [];

function esc(v: string): string {
  return v.replace(/\\/g, "\\\\").replace(/\n/g, "\\n").replace(/"/g, '\\"');
}

/** Render a label set (in a fixed name order) as `{k="v",...}` or "". */
function labelStr(names: string[], labels: Record<string, string | number>): string {
  if (names.length === 0) return "";
  return "{" + names.map((n) => `${n}="${esc(String(labels[n] ?? ""))}"`).join(",") + "}";
}

class Counter implements Renderable {
  private readonly values = new Map<string, number>();
  constructor(
    readonly name: string,
    readonly help: string,
    readonly labelNames: string[] = [],
  ) {
    registry.push(this);
  }
  inc(labels: Record<string, string> = {}, by = 1): void {
    const k = labelStr(this.labelNames, labels);
    this.values.set(k, (this.values.get(k) ?? 0) + by);
  }
  render(): string {
    let out = `# HELP ${this.name} ${this.help}\n# TYPE ${this.name} counter\n`;
    if (this.values.size === 0 && this.labelNames.length === 0) out += `${this.name} 0\n`;
    for (const [k, v] of this.values) out += `${this.name}${k} ${v}\n`;
    return out;
  }
}

class Gauge implements Renderable {
  private value: number;
  constructor(
    readonly name: string,
    readonly help: string,
    initial = 0,
  ) {
    this.value = initial;
    registry.push(this);
  }
  set(v: number): void {
    this.value = v;
  }
  render(): string {
    return `# HELP ${this.name} ${this.help}\n# TYPE ${this.name} gauge\n${this.name} ${this.value}\n`;
  }
}

/** A gauge with bounded labels — one settable value per label set. */
class LabeledGauge implements Renderable {
  private readonly values = new Map<string, number>();
  constructor(
    readonly name: string,
    readonly help: string,
    readonly labelNames: string[],
  ) {
    registry.push(this);
  }
  set(labels: Record<string, string>, v: number): void {
    this.values.set(labelStr(this.labelNames, labels), v);
  }
  render(): string {
    let out = `# HELP ${this.name} ${this.help}\n# TYPE ${this.name} gauge\n`;
    for (const [k, v] of this.values) out += `${this.name}${k} ${v}\n`;
    return out;
  }
}

class Histogram implements Renderable {
  private readonly series = new Map<string, { counts: number[]; sum: number; count: number }>();
  constructor(
    readonly name: string,
    readonly help: string,
    readonly labelNames: string[],
    readonly buckets: number[],
  ) {
    registry.push(this);
  }
  observe(labels: Record<string, string>, v: number): void {
    const k = labelStr(this.labelNames, labels);
    let s = this.series.get(k);
    if (!s) {
      s = { counts: new Array(this.buckets.length).fill(0), sum: 0, count: 0 };
      this.series.set(k, s);
    }
    for (let i = 0; i < this.buckets.length; i++) if (v <= this.buckets[i]) s.counts[i]++;
    s.sum += v;
    s.count++;
  }
  render(): string {
    let out = `# HELP ${this.name} ${this.help}\n# TYPE ${this.name} histogram\n`;
    for (const [k, s] of this.series) {
      const base = k === "" ? "" : k.slice(0, -1); // strip trailing "}" to inject le
      const withLe = (le: string) => (base === "" ? `{le="${le}"}` : `${base},le="${le}"}`);
      for (let i = 0; i < this.buckets.length; i++) {
        out += `${this.name}_bucket${withLe(String(this.buckets[i]))} ${s.counts[i]}\n`;
      }
      out += `${this.name}_bucket${withLe("+Inf")} ${s.count}\n`;
      out += `${this.name}_sum${k} ${s.sum}\n`;
      out += `${this.name}_count${k} ${s.count}\n`;
    }
    return out;
  }
}

export const metrics = {
  requestsTotal: new Counter(
    "secrouter_requests_total",
    "Chat requests routed, by outcome.",
    ["tier", "provider", "model", "outcome"],
  ),
  tokensTotal: new Counter("secrouter_tokens_total", "Tokens processed.", ["direction"]),
  costUsdTotal: new Counter("secrouter_cost_usd_total", "Estimated upstream cost in USD."),
  authFailuresTotal: new Counter("secrouter_auth_failures_total", "Rejected authentications."),
  egressDeniedTotal: new Counter("secrouter_egress_denied_total", "Egress denials (deny-by-default gate)."),
  quotaDeniedTotal: new Counter("secrouter_quota_denied_total", "Requests refused for budget / rate limits."),
  upstreamErrorsTotal: new Counter("secrouter_upstream_errors_total", "Upstream forward errors, by provider.", ["provider", "endpoint"]),
  circuitState: new LabeledGauge(
    "secrouter_circuit_state",
    "Provider circuit-breaker state (0 closed, 1 open, 2 half-open).",
    ["provider", "endpoint"],
  ),
  circuitTransitionsTotal: new Counter(
    "secrouter_circuit_transitions_total",
    "Circuit-breaker state transitions, by target state.",
    ["provider", "endpoint", "state"],
  ),
  toolCallsTotal: new Counter(
    "secrouter_tool_calls_total",
    "MCP tool calls proxied through the gateway, by outcome.",
    ["server", "tool", "outcome"],
  ),
  toolDeniedTotal: new Counter(
    "secrouter_tool_denied_total",
    "MCP tool calls refused by policy / classification, by reason.",
    ["reason"],
  ),
  requestDuration: new Histogram(
    "secrouter_request_duration_seconds",
    "Chat request duration over the forward path.",
    ["tier"],
    [0.1, 0.25, 0.5, 1, 2, 5, 10, 30, 60],
  ),
  splitAssignedTotal: new Counter(
    "secrouter_split_assigned_total",
    "Split (A/B) routing variant assignments, by tier and assigned model.",
    ["tier", "model"],
  ),
  splitSteeredTotal: new Counter(
    "secrouter_split_steered_total",
    "Split (A/B) assignments the health-aware steer subsequently moved off of (contaminated sample marker), by tier.",
    ["tier"],
  ),
  escalationsTotal: new Counter(
    "secrouter_escalations_total",
    "Escalation-routing outcomes, by source tier, target tier, and outcome.",
    ["from_tier", "to_tier", "outcome"],
  ),
  escalationJudgeDuration: new Histogram(
    "secrouter_escalation_judge_duration_seconds",
    "Escalation judge call duration, by judge mode.",
    ["mode"],
    [0.01, 0.05, 0.1, 0.25, 0.5, 1, 2, 5, 10],
  ),
  up: new Gauge("secrouter_up", "1 when the router is serving.", 1),
  startTime: new Gauge("secrouter_start_time_seconds", "Process start time (unix seconds)."),
};

metrics.startTime.set(Math.floor(Date.now() / 1000));

/** Full exposition text for GET /metrics. */
export function renderMetrics(): string {
  return registry.map((m) => m.render()).join("\n");
}
