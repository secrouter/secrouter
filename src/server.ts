/**
 * SecRouter Proxy Server
 *
 * OpenAI-compatible HTTP server that classifies incoming requests
 * using the 14-dimension weighted scorer and routes to the best backend.
 *
 * Endpoints:
 *   POST /v1/chat/completions  — OpenAI-compatible chat completions
 *   GET  /v1/models            — list available models
 *   GET  /health               — health check
 *
 * Zero external deps. Uses Node.js built-in http + native fetch.
 */

import { createServer, type IncomingMessage, type ServerResponse } from "node:http";
import { randomUUID } from "node:crypto";
import { route } from "./router/index.js";
import { getRoutingConfig } from "./router/config.js";
import { selectEndpoints, type CursorState } from "./router/balance.js";
import { buildPricingMap, getModelCatalog } from "./models.js";
import { forwardRequest, forwardEmbeddingsRequest, TimeoutError, type ChatRequest } from "./provider.js";
import {
  CircuitBreaker,
  isHealthFailure,
  resolveResilience,
  CIRCUIT_STATE_CODE,
  type Transition,
  type ProviderHealth,
} from "./security/resilience.js";
import { reloadAuth } from "./auth.js";
import {
  loadConfig,
  getConfig,
  reloadConfig,
  getSanitizedConfig,
  getConfigPath,
  getSecurityConfig,
  validateSecurityConfig,
  endpointsOf,
  takePendingEgressFileAudit,
  type FreeRouterConfig,
} from "./config.js";
import {
  initSecurity,
  closeSecurity,
  isEnabled as securityEnabled,
  authenticate,
  AuthError,
  getAuditor,
  getStore,
  getOverrides,
  getEffectivePolicy,
  authorize,
  checkQuota,
  computeCost,
  toUsageRecord,
  classRank,
  EgressDeniedError,
  assertFips,
  isFipsEnabled,
  httpsOptions,
  createHttpsServer,
  audit,
} from "./security/index.js";
import type { Principal, UsageResult, OverrideScope } from "./security/types.js";
import { ADMIN_HTML } from "./admin-ui.js";
import { probeEndpoint, previewEndpoint, applyEndpoint, type ProbeRequest, type EndpointSpec } from "./security/endpoints.js";
import { metrics, renderMetrics } from "./metrics.js";
import { handleMcpRpc, probeMcpTools } from "./security/mcp/gateway.js";
import type { JsonRpcRequest } from "./security/mcp/types.js";
import { logger, setLogLevel } from "./logger.js";

/** Per-request context threaded through handlers. */
type Ctx = { requestId: string; sourceIp: string; principal?: Principal; traceId?: string; traceparent?: string };

/**
 * Attribute token usage to the principal: write the ledger row (cost
 * containment) and emit a CUI-safe usage audit event (AU 3.3.2). No-op when
 * security is disabled or the request was anonymous.
 */
function recordUsageAndAudit(ctx: Ctx, tier: string, usage: UsageResult, outcome: string) {
  const cost = computeCost(usage, modelPricing);
  // Metrics count all forwarded traffic (bounded labels — no principal id).
  metrics.requestsTotal.inc({ tier, provider: usage.provider, model: `${usage.provider}/${usage.model}`, outcome });
  metrics.tokensTotal.inc({ direction: "input" }, usage.inputTokens);
  metrics.tokensTotal.inc({ direction: "output" }, usage.outputTokens);
  metrics.costUsdTotal.inc({}, cost);
  if (!ctx.principal || !securityEnabled()) return; // ledger + audit only when secured
  try {
    getStore().recordUsage(toUsageRecord(ctx.principal, ctx.requestId, tier, usage, cost, outcome));
  } catch (err) {
    logger.error(`[${ctx.requestId}] usage ledger write failed: ${err instanceof Error ? err.message : String(err)}`);
  }
  getAuditor().emit(
    audit.usage(ctx.principal.id, ctx.requestId, `${usage.provider}/${usage.model}`, tier, {
      inputTokens: usage.inputTokens,
      outputTokens: usage.outputTokens,
      cacheReadTokens: usage.cacheReadTokens,
      costUsd: Number(cost.toFixed(6)),
      outcome,
      traceId: ctx.traceId,
    }),
  );

  // Threat-aware monitoring (800-172 3.14.6e): flag anomalously large single
  // requests so they surface in the SIEM even when within budget.
  const total = usage.inputTokens + usage.outputTokens;
  if (total > ANOMALY_TOKEN_THRESHOLD) {
    getAuditor().emit({
      type: "anomaly",
      requestId: ctx.requestId,
      principalId: ctx.principal.id,
      model: `${usage.provider}/${usage.model}`,
      tier,
      outcome: "alert",
      detail: { reason: "large_single_request", totalTokens: total, threshold: ANOMALY_TOKEN_THRESHOLD },
    });
  }
}

/** Single-request token count above which a request is flagged as anomalous. */
const ANOMALY_TOKEN_THRESHOLD = parseInt(process.env.SECROUTER_ANOMALY_TOKENS ?? "300000", 10);

// ── Provider circuit breaker (Tier 1 Phase C / SC 3.13.x availability) ──
// One process-wide breaker, keyed per (provider, endpoint). Configured from
// security.resilience at startup and on reload; the fallback loop skips open
// endpoints so a dead upstream fails fast to the next authorized endpoint/model
// instead of paying its full timeout forever.
const breaker = new CircuitBreaker(resolveResilience());

// ── Load-balancing cursor (multi-endpoint round robin) ──
// One process-wide cursor, `{ [provider]: nextEndpointIndex }`, shared by every
// request via router/balance.ts's selectEndpoints(). A provider with a single
// endpoint never advances past index 0.
const endpointCursor: CursorState = {};

/** Meter + audit a circuit transition (best-effort: never fails a live request). */
function onCircuitTransition(tr: Transition): void {
  const labels = { provider: tr.provider, endpoint: String(tr.endpoint) };
  metrics.circuitState.set(labels, CIRCUIT_STATE_CODE[tr.to]);
  metrics.circuitTransitionsTotal.inc({ ...labels, state: tr.to });
  logger.warn(`circuit ${tr.provider}#${tr.endpoint}: ${tr.from} -> ${tr.to} (consecutiveFailures=${tr.consecutiveFailures})`);
  try {
    getAuditor().emit(audit.providerCircuit(tr.provider, tr.to, tr.from, tr.consecutiveFailures, tr.endpoint));
  } catch (err) {
    logger.error(`circuit audit emit failed: ${err instanceof Error ? err.message : String(err)}`);
  }
}

/**
 * Drain + audit a pending SECROUTER_EGRESS_FILE load (config.ts
 * applyEgressFileIntake), if the (re)load that just ran produced one. Called
 * right after initSecurity() — both at startup and from handleReloadConfig()
 * — so getAuditor() is guaranteed live when security is enabled. PROMINENT by
 * design: always logged at warn level regardless of security.enabled, and
 * additionally written to the tamper-evident audit trail (AU 3.3.1/3.3.2)
 * whenever that trail exists.
 */
function emitPendingEgressFileAudit(): void {
  const pending = takePendingEgressFileAudit();
  if (!pending) return;
  logger.warn(
    `⚠ Loaded ${pending.totalCount} egress rule${pending.totalCount === 1 ? "" : "s"} from ${pending.path} (SECROUTER_EGRESS_FILE) ` +
      `— ${pending.addedCount} new, merged into security.egress.allowlist (audited, AU 3.3.1/3.3.2)`,
  );
  if (!securityEnabled()) return; // no audit store to write into in dev/open mode — the log line above still stands
  try {
    getAuditor().emit(audit.egressFileLoaded(pending.path, pending.addedCount, pending.totalCount));
  } catch (err) {
    logger.error(`egress-file-load audit emit failed: ${err instanceof Error ? err.message : String(err)}`);
  }
}

// ── Active health checks (optional; security.resilience.healthIntervalSec) ──
// Off by default — air-gap friendly, no background egress unless asked for. When
// enabled, periodically probe EVERY endpoint (config.endpointsOf) of each
// OpenAI-compatible provider's model list and feed the result into the
// per-endpoint breaker, so an endpoint can trip or recover without waiting for
// live traffic. Uses model-list reachability as the health signal.
//
// The same probe also powers model-awareness for load balancing: each
// endpoint's returned model-id set is cached here, keyed `${provider}#${idx}`,
// so the chat forward loop's selectEndpoints() call (server.ts, modelLoop) can
// skip an endpoint that doesn't (yet, as far as we know) serve the requested
// model — see the `serves` hook wired in handleChatCompletions. An endpoint
// with no entry (no successful probe yet) is treated as "might serve it" —
// never narrowed away — and router/balance.ts's own never-starve-to-zero
// fallback covers the all-unknown case too.
let healthTimer: ReturnType<typeof setInterval> | undefined;
const servedModels = new Map<string, Set<string>>();
async function runHealthChecks(): Promise<void> {
  const cfg = getConfig();
  for (const [name, p] of Object.entries(cfg.providers ?? {})) {
    if (p.api !== "openai") continue; // model-list probe is only meaningful for OpenAI-compatible
    const authEnvKey = p.auth?.type === "env" ? p.auth.key : undefined;
    let endpoints: string[];
    try {
      endpoints = endpointsOf(p);
    } catch (err) {
      logger.error(`health check: endpoint config error for provider '${name}': ${err instanceof Error ? err.message : String(err)}`);
      continue;
    }
    for (let idx = 0; idx < endpoints.length; idx++) {
      try {
        const r = await probeEndpoint({ baseUrl: endpoints[idx], api: "openai", authEnvKey });
        const tr = r.ok ? breaker.recordSuccess(name, r.latencyMs, idx) : breaker.recordFailure(name, idx);
        if (tr) onCircuitTransition(tr);
        // Only overwrite on a successful, model-list-bearing probe — a
        // transient failure leaves the last-known served set in place rather
        // than flapping this endpoint's model-aware eligibility (its
        // liveness/admission is already governed separately by the breaker).
        if (r.ok && r.models) servedModels.set(`${name}#${idx}`, new Set(r.models));
      } catch (err) {
        const tr = breaker.recordFailure(name, idx);
        if (tr) onCircuitTransition(tr);
        logger.error(`health check: probe threw for '${name}#${idx}': ${err instanceof Error ? err.message : String(err)}`);
      }
    }
  }
}
/** Default active-check interval when auto-enabled for a pooled provider (see startHealthChecks). */
const AUTO_HEALTH_INTERVAL_SEC = 15;
/** True if any configured provider has more than one endpoint (a load-balanced pool). */
function hasPooledProvider(cfg: FreeRouterConfig): boolean {
  for (const p of Object.values(cfg.providers ?? {})) {
    try {
      if (endpointsOf(p).length > 1) return true;
    } catch {
      /* malformed baseUrl — not this function's concern */
    }
  }
  return false;
}
/** (Re)start the health-check timer to match the current resilience config. */
function startHealthChecks(): void {
  if (healthTimer) {
    clearInterval(healthTimer);
    healthTimer = undefined;
  }
  const configuredSec = breaker.config().healthIntervalSec;
  // Explicit config always wins. Otherwise, auto-enable at a conservative
  // default for a pooled deploy: multi-endpoint load balancing needs liveness
  // AND model-list polling per endpoint to work well (breaker isolation,
  // model-aware routing) — waiting for live traffic alone is too slow to
  // discover a dead or freshly-rebalanced replica. A single-endpoint config
  // stays passive-only (today's default) unless explicitly enabled.
  const auto = (!configuredSec || configuredSec <= 0) && hasPooledProvider(getConfig());
  const intervalSec = auto ? AUTO_HEALTH_INTERVAL_SEC : configuredSec;
  if (!intervalSec || intervalSec <= 0) return; // passive-only (default; no pooled provider)
  healthTimer = setInterval(() => void runHealthChecks(), intervalSec * 1000);
  healthTimer.unref?.(); // don't keep the process alive for the timer
  logger.info(
    auto
      ? `Active provider health checks auto-enabled (every ${intervalSec}s) — a pooled provider (>1 endpoint) needs liveness + model-list polling for load balancing`
      : `Active provider health checks enabled (every ${intervalSec}s)`,
  );
}

// Load config at startup. loadConfig() throws if SECROUTER_EGRESS_FILE is set
// but missing/unreadable/malformed (config.ts applyEgressFileIntake — a
// security control fails loud, never silently continues), so this is a
// refuse-to-start FATAL exactly like the security-config/FIPS checks below.
let appConfig: FreeRouterConfig;
try {
  appConfig = loadConfig();
} catch (err) {
  logger.error(`FATAL: ${err instanceof Error ? err.message : String(err)}`);
  process.exit(1);
}

// Validate + initialize the security subsystem (fail-closed: a CUI gateway
// must refuse to start rather than run in an unsafe configuration).
const _secErrors = validateSecurityConfig(appConfig);
if (_secErrors.length > 0) {
  logger.error("FATAL: invalid security configuration — refusing to start:");
  for (const e of _secErrors) logger.error(`  - ${e}`);
  process.exit(1);
}
try {
  // Fail closed if FIPS-validated crypto is required but unavailable (SC 3.13.11).
  assertFips(appConfig.security?.requireFips === true);
} catch (err) {
  logger.error(`FATAL: ${err instanceof Error ? err.message : String(err)}`);
  process.exit(1);
}
initSecurity(appConfig.security);
emitPendingEgressFileAudit(); // audit-evident (not silent) if SECROUTER_EGRESS_FILE loaded rules above
breaker.setConfig(resolveResilience(appConfig.security?.resilience));
startHealthChecks();

const PORT = parseInt(process.env.SECROUTER_PORT ?? String(appConfig.port), 10);
const HOST = process.env.SECROUTER_HOST ?? appConfig.host ?? "127.0.0.1";

// Build pricing map once at startup
const modelPricing = buildPricingMap();

// Stats
const stats = {
  started: new Date().toISOString(),
  requests: 0,
  errors: 0,
  timeouts: 0,
  byTier: { SIMPLE: 0, MEDIUM: 0, COMPLEX: 0, REASONING: 0 } as Record<string, number>,
  byModel: {} as Record<string, number>,
};

/** Max accepted request body. Bounds memory + a trivial DoS vector (SI 3.14.6). */
const MAX_BODY_BYTES = parseInt(process.env.SECROUTER_MAX_BODY_BYTES ?? "10485760", 10); // 10 MiB

class BodyTooLargeError extends Error {
  constructor() {
    super("request body too large");
    this.name = "BodyTooLargeError";
  }
}

/**
 * Read request body as a string, enforcing a hard size cap. Aborts the socket
 * if the client exceeds MAX_BODY_BYTES rather than buffering unboundedly.
 */
function readBody(req: IncomingMessage, maxBytes = MAX_BODY_BYTES): Promise<string> {
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = [];
    let total = 0;
    req.on("data", (chunk: Buffer) => {
      total += chunk.length;
      if (total > maxBytes) {
        reject(new BodyTooLargeError());
        req.destroy();
        return;
      }
      chunks.push(chunk);
    });
    req.on("end", () => resolve(Buffer.concat(chunks).toString("utf-8")));
    req.on("error", reject);
  });
}

/**
 * Structural validation of a chat-completions request body (SI 3.14.1).
 * Returns a generic, non-leaking error string, or null if valid.
 */
function validateChatRequest(body: unknown): string | null {
  if (typeof body !== "object" || body === null) return "request body must be a JSON object";
  const b = body as Record<string, unknown>;
  if (typeof b.model !== "string" || b.model.length === 0 || b.model.length > 256) {
    return "model field is required";
  }
  if (!Array.isArray(b.messages) || b.messages.length === 0 || b.messages.length > 5000) {
    return "messages array is required";
  }
  for (const m of b.messages as unknown[]) {
    if (typeof m !== "object" || m === null) return "each message must be an object";
    const role = (m as Record<string, unknown>).role;
    if (typeof role !== "string") return "each message requires a role";
  }
  return null;
}

/**
 * Send JSON error response.
 */
function sendError(res: ServerResponse, status: number, message: string, type = "server_error") {
  res.writeHead(status, { "Content-Type": "application/json" });
  res.end(JSON.stringify({
    error: { message, type, code: status },
  }));
}

/**
 * Extract the user's prompt text from messages for classification.
 */
function extractPromptForClassification(messages: ChatRequest["messages"]): {
  prompt: string;
  systemPrompt: string | undefined;
} {
  let systemPrompt: string | undefined;
  const contextWindow = 3; // Include last N non-system messages for context-aware classification

  // Separate system messages from conversation
  const conversationMsgs: Array<{ role: string; text: string }> = [];
  for (const msg of messages) {
    const text = typeof msg.content === "string"
      ? msg.content
      : (msg.content ?? []).filter(b => b.type === "text").map(b => b.text ?? "").join("\n");

    if (msg.role === "system" || msg.role === "developer") {
      systemPrompt = (systemPrompt ? systemPrompt + "\n" : "") + text;
    } else {
      conversationMsgs.push({ role: msg.role, text });
    }
  }

  // Take the last N messages for classification context
  const recentMsgs = conversationMsgs.slice(-contextWindow);

  // Build classification prompt: weight the last user message most,
  // but include recent context so quoted/replied content gets scored too
  const lastUserMsg = recentMsgs.filter(m => m.role === "user").pop()?.text ?? "";
  const contextParts: string[] = [];
  for (const msg of recentMsgs) {
    if (msg.text !== lastUserMsg) {
      // Truncate context messages to avoid over-counting long assistant replies
      contextParts.push(msg.text.slice(0, 500));
    }
  }

  // Combine: context (truncated) + full last user message
  const prompt = contextParts.length > 0
    ? contextParts.join("\n") + "\n" + lastUserMsg
    : lastUserMsg;

  return { prompt, systemPrompt };
}


/**
 * Detect user-requested mode override in prompt text.
 * Users can prefix or include mode directives to force a specific tier:
 *   "simple mode: ..."  or  "/simple ..."   → SIMPLE
 *   "medium mode: ..."  or  "/medium ..."   → MEDIUM  
 *   "complex mode: ..." or  "/complex ..."  → COMPLEX
 *   "max mode: ..."     or  "/max ..."      → REASONING
 *   "reasoning mode: ..." or "/reasoning ..." → REASONING
 * 
 * Returns the forced tier and cleaned prompt (directive stripped), or null if no override.
 */
function detectModeOverride(prompt: string): { tier: string; cleanedPrompt: string } | null {
  const modeMap: Record<string, string> = {
    simple: "SIMPLE",
    basic: "SIMPLE",
    cheap: "SIMPLE",
    medium: "MEDIUM",
    balanced: "MEDIUM",
    complex: "COMPLEX",
    advanced: "COMPLEX",
    max: "REASONING",
    reasoning: "REASONING",
    think: "REASONING",
    deep: "REASONING",
  };

  // Pattern 1: "/mode ..." at start of message
  const slashMatch = prompt.match(/^\/([a-z]+)\s+/i);
  if (slashMatch) {
    const mode = slashMatch[1].toLowerCase();
    if (modeMap[mode]) {
      return { tier: modeMap[mode], cleanedPrompt: prompt.slice(slashMatch[0].length).trim() };
    }
  }

  // Pattern 2: "mode mode: ..." or "mode mode, ..." at start  
  const prefixMatch = prompt.match(/^([a-z]+)\s+mode[:\s,]+/i);
  if (prefixMatch) {
    const mode = prefixMatch[1].toLowerCase();
    if (modeMap[mode]) {
      return { tier: modeMap[mode], cleanedPrompt: prompt.slice(prefixMatch[0].length).trim() };
    }
  }

  // Pattern 3: "[mode]" at start
  const bracketMatch = prompt.match(/^\[([a-z]+)\]\s*/i);
  if (bracketMatch) {
    const mode = bracketMatch[1].toLowerCase();
    if (modeMap[mode]) {
      return { tier: modeMap[mode], cleanedPrompt: prompt.slice(bracketMatch[0].length).trim() };
    }
  }

  return null;
}

/**
 * Handle POST /v1/chat/completions
 */
/**
 * POST /v1/embeddings — governed embeddings. Same auth (deny-by-default),
 * per-model policy, classification clearance, egress gate, quota, and usage/cost
 * accounting as chat — but no tier classification (the model is explicit or the
 * configured default). Closes the RAG bypass so embedding traffic is governed too.
 */
async function handleEmbeddings(req: IncomingMessage, res: ServerResponse, ctx: Ctx) {
  res.setHeader("X-Request-Id", ctx.requestId);
  const t0 = Date.now();
  let body: Record<string, unknown>;
  try {
    body = JSON.parse(await readBody(req));
  } catch (err) {
    if (err instanceof BodyTooLargeError) return sendError(res, 413, "Request body too large", "invalid_request_error");
    return sendError(res, 400, "Invalid JSON body", "invalid_request_error");
  }
  if (body.input === undefined || body.input === null || body.input === "") {
    return sendError(res, 400, "Missing 'input'", "invalid_request_error");
  }

  // Resolve the model: explicit, or the configured default for "auto" / none.
  const cfg = getConfig();
  let model = typeof body.model === "string" ? body.model : "";
  if (!model || model === "auto") model = cfg.embeddings?.default ?? "";
  if (!model) {
    return sendError(res, 400, "No embeddings model specified and no embeddings.default configured", "invalid_request_error");
  }

  // Classification for this request (trusted header or default) — feeds the
  // clearance check and the egress data-residency gate.
  const secCfg = getSecurityConfig();
  let requestClassification = secCfg?.classification?.default;
  if (securityEnabled() && secCfg?.classification) {
    const hdr = req.headers["x-data-classification"];
    const asserted = (Array.isArray(hdr) ? hdr[0] : hdr)?.trim();
    if (asserted && secCfg.classification.levels.includes(asserted)) requestClassification = asserted;
  }

  // Per-user authorization + quota (no tier — model-level allow/deny only).
  if (ctx.principal && securityEnabled() && secCfg) {
    const policy = getEffectivePolicy(ctx.principal);
    if (requestClassification && classRank(requestClassification, secCfg) > classRank(policy.maxClassification, secCfg)) {
      getAuditor().emit(audit.authzDeny(ctx.principal.id, ctx.requestId, model, `classification_not_cleared:${requestClassification}`));
      return sendError(res, 403, "Not cleared for the requested data classification", "authorization_error");
    }
    const notAllowed = policy.allowedModels && !policy.allowedModels.includes(model);
    if (notAllowed || policy.deniedModels?.includes(model)) {
      getAuditor().emit(audit.authzDeny(ctx.principal.id, ctx.requestId, model, "embedding_model_not_permitted"));
      return sendError(res, 403, "Requested embeddings model is not permitted for your account", "authorization_error");
    }
    const q = checkQuota(getStore(), ctx.principal.id, policy.budgets);
    if (!q.allowed) {
      metrics.quotaDeniedTotal.inc();
      getAuditor().emit(audit.quotaExceeded(ctx.principal.id, ctx.requestId, { violation: q.violation }));
      res.setHeader("Retry-After", "60");
      return sendError(res, 429, `Usage quota exceeded (${q.violation?.limitType} per ${q.violation?.window})`, "rate_limit_error");
    }
  }

  stats.requests++;
  res.setHeader("X-SecRouter-Model", model);
  const eProvider = model.split("/")[0];
  // Fail fast if this provider's circuit is open — embeddings have no fallback chain.
  const eGate = breaker.admit(eProvider);
  if (eGate.transition) onCircuitTransition(eGate.transition);
  if (!eGate.ok) {
    stats.errors++;
    metrics.requestsTotal.inc({ tier: "EMBEDDING", provider: "", model: "", outcome: "circuit_open" });
    res.setHeader("Retry-After", String(breaker.config().cooldownSec));
    return sendError(res, 503, `Provider '${eProvider}' is temporarily unavailable (circuit open)`, "provider_unavailable");
  }
  const eStarted = Date.now();
  try {
    const usage = await forwardEmbeddingsRequest(model, body, res, requestClassification, ctx.traceparent);
    const tr = breaker.recordSuccess(eProvider, Date.now() - eStarted);
    if (tr) onCircuitTransition(tr);
    recordUsageAndAudit(ctx, "EMBEDDING", usage, "ok"); // ledger + audit + metrics (tier=EMBEDDING)
    metrics.requestDuration.observe({ tier: "EMBEDDING" }, (Date.now() - t0) / 1000);
  } catch (err) {
    stats.errors++;
    const msg = err instanceof Error ? err.message : String(err);
    if (err instanceof EgressDeniedError) {
      metrics.egressDeniedTotal.inc();
      metrics.requestsTotal.inc({ tier: "EMBEDDING", provider: "", model: "", outcome: "egress_denied" });
      if (ctx.principal && securityEnabled()) getAuditor().emit(audit.egressDeny(ctx.principal.id, ctx.requestId, err.provider, msg));
      if (!res.headersSent) sendError(res, 502, "No authorized model is available for this request's data classification", "egress_denied");
      return;
    }
    metrics.upstreamErrorsTotal.inc({ provider: eProvider, endpoint: "0" }); // embeddings: endpoint 0 only, no LB yet
    if (isHealthFailure(err)) {
      const tr = breaker.recordFailure(eProvider);
      if (tr) onCircuitTransition(tr);
    }
    metrics.requestsTotal.inc({ tier: "EMBEDDING", provider: "", model: "", outcome: "error" });
    logger.error(`Embeddings error (${model}): ${msg}`);
    if (!res.headersSent) sendError(res, 502, `Backend error: ${msg}`, "upstream_error");
  }
}

/**
 * POST /mcp — governed MCP / tool-calling gateway (Phase D). Authenticated at the
 * same gate as chat; brokers JSON-RPC tools/list + tools/call to in-boundary
 * upstream servers under the principal's tool allow-list + classification gate.
 */
async function handleMcp(req: IncomingMessage, res: ServerResponse, ctx: Ctx) {
  res.setHeader("X-Request-Id", ctx.requestId);
  if (!ctx.principal) return sendError(res, 401, "Authentication required", "authentication_error");
  const rpcError = (code: number, message: string) => {
    res.writeHead(200, { "Content-Type": "application/json" });
    res.end(JSON.stringify({ jsonrpc: "2.0", id: null, error: { code, message } }));
  };

  let bodyStr: string;
  try {
    bodyStr = await readBody(req);
  } catch (err) {
    if (err instanceof BodyTooLargeError) return sendError(res, 413, "Request body too large", "invalid_request_error");
    return sendError(res, 400, "Could not read request body", "invalid_request_error");
  }
  let payload: unknown;
  try {
    payload = JSON.parse(bodyStr);
  } catch {
    return rpcError(-32700, "parse error");
  }

  // Data classification for this request — same trusted-header resolution as chat.
  const secCfg = getSecurityConfig();
  let classification = secCfg?.classification?.default ?? "UNCLASSIFIED";
  const hdr = req.headers["x-data-classification"];
  const asserted = (Array.isArray(hdr) ? hdr[0] : hdr)?.trim();
  if (asserted && secCfg?.classification?.levels.includes(asserted)) classification = asserted;
  const mctx = { principal: ctx.principal, classification, requestId: ctx.requestId };

  try {
    if (Array.isArray(payload)) {
      const responses = (await Promise.all(payload.map((r) => handleMcpRpc(r as JsonRpcRequest, mctx)))).filter((r) => r !== null);
      res.writeHead(200, { "Content-Type": "application/json" });
      res.end(JSON.stringify(responses));
    } else {
      const response = await handleMcpRpc(payload as JsonRpcRequest, mctx);
      if (!response) {
        res.writeHead(202); // a notification — accepted, no body
        return res.end();
      }
      res.writeHead(200, { "Content-Type": "application/json" });
      res.end(JSON.stringify(response));
    }
  } catch (err) {
    logger.error(`[${ctx.requestId}] MCP gateway error: ${err instanceof Error ? err.message : String(err)}`);
    if (!res.headersSent) rpcError(-32603, "internal error");
  }
}

async function handleChatCompletions(req: IncomingMessage, res: ServerResponse, ctx: Ctx) {
  res.setHeader("X-Request-Id", ctx.requestId);
  const t0 = Date.now();
  let bodyStr: string;
  try {
    bodyStr = await readBody(req);
  } catch (err) {
    if (err instanceof BodyTooLargeError) return sendError(res, 413, "Request body too large", "invalid_request_error");
    return sendError(res, 400, "Could not read request body", "invalid_request_error");
  }

  let chatReq: ChatRequest;
  try {
    chatReq = JSON.parse(bodyStr);
  } catch {
    return sendError(res, 400, "Invalid JSON body", "invalid_request_error");
  }

  // Structural input validation (SI 3.14.1) before any processing.
  const invalid = validateChatRequest(chatReq);
  if (invalid) {
    return sendError(res, 400, invalid, "invalid_request_error");
  }

  const stream = chatReq.stream ?? false;
  const maxTokens = chatReq.max_tokens ?? 4096;

  // Extract prompt for classification
  const { prompt, systemPrompt } = extractPromptForClassification(chatReq.messages);

  if (!prompt) {
    return sendError(res, 400, "No user message found");
  }

  // Route through classifier
  const requestedModel = chatReq.model ?? "auto";
  let routedModel: string;
  let tier: string;
  let reasoning: string;

  if (requestedModel === "auto" || requestedModel === "secrouter/auto") {
    // Check for user mode override (e.g., "max mode: ...", "/complex ...", "[reasoning] ...")
    const modeOverride = detectModeOverride(prompt);
    
    if (modeOverride) {
      // User explicitly requested a tier — honor it
      const routingCfg = getRoutingConfig();
      const tierConfig = routingCfg.tiers[modeOverride.tier as keyof typeof routingCfg.tiers];
      routedModel = tierConfig?.primary ?? "anthropic/claude-opus-4-6";
      tier = modeOverride.tier;
      reasoning = `user-mode: ${modeOverride.tier.toLowerCase()}`;
      logger.info(`[${stats.requests + 1}] Mode override: tier=${tier} model=${routedModel} | ${reasoning}`);
    } else {
      // Run the classifier
      const decision = route(prompt, systemPrompt, maxTokens, {
        config: getRoutingConfig(),
        modelPricing,
      });

      routedModel = decision.model;
      tier = decision.tier;
      reasoning = decision.reasoning;

      logger.info(`[${stats.requests + 1}] Classified: tier=${tier} model=${routedModel} confidence=${decision.confidence.toFixed(2)} | ${reasoning}`);
    }
  } else {
    // Explicit model requested — pass through
    routedModel = requestedModel;
    tier = "EXPLICIT";
    reasoning = `explicit model: ${requestedModel}`;
    logger.info(`[${stats.requests + 1}] Passthrough: model=${routedModel}`);
  }

  // Data classification for this request: a trusted classification header
  // (set by the front-end proxy) or the configured default. Used for the
  // clearance check below and the egress data-residency gate.
  const secCfg = getSecurityConfig();
  let requestClassification = secCfg?.classification?.default;
  if (securityEnabled() && secCfg?.classification) {
    const hdr = req.headers["x-data-classification"];
    const asserted = (Array.isArray(hdr) ? hdr[0] : hdr)?.trim();
    if (asserted && secCfg.classification.levels.includes(asserted)) {
      requestClassification = asserted;
    }
  }

  // ── Per-user authorization + quota (Feature 2 / AC 3.1.2, 3.1.5, 3.1.3) ──
  // Runs before stats/headers/forward so they reflect any downgrade.
  if (ctx.principal && securityEnabled() && secCfg) {
    const policy = getEffectivePolicy(ctx.principal);

    // Clearance: is the principal authorized to submit data at this classification?
    if (
      requestClassification &&
      classRank(requestClassification, secCfg) > classRank(policy.maxClassification, secCfg)
    ) {
      getAuditor().emit(
        audit.authzDeny(ctx.principal.id, ctx.requestId, routedModel, `classification_not_cleared:${requestClassification}`),
      );
      return sendError(res, 403, "Not cleared for the requested data classification", "authorization_error");
    }

    const decision = authorize(policy, routedModel, tier, getRoutingConfig());
    if (decision.effect === "deny") {
      getAuditor().emit(audit.authzDeny(ctx.principal.id, ctx.requestId, routedModel, decision.reason));
      return sendError(res, 403, "Requested model or tier is not permitted for your account", "authorization_error");
    }
    if (decision.effect === "downgrade") {
      getAuditor().emit(
        audit.authzDowngrade(ctx.principal.id, ctx.requestId, routedModel, decision.model, decision.reason),
      );
      routedModel = decision.model;
      tier = decision.tier;
      reasoning = `${reasoning} | ${decision.reason}`;
    }

    // Pre-flight quota / rate limit (cost containment).
    const q = checkQuota(getStore(), ctx.principal.id, policy.budgets);
    if (!q.allowed) {
      metrics.quotaDeniedTotal.inc();
      getAuditor().emit(audit.quotaExceeded(ctx.principal.id, ctx.requestId, { violation: q.violation }));
      res.setHeader("Retry-After", "60");
      return sendError(
        res,
        429,
        `Usage quota exceeded (${q.violation?.limitType} per ${q.violation?.window})`,
        "rate_limit_error",
      );
    }
  }

  // Update stats
  stats.requests++;
  stats.byTier[tier] = (stats.byTier[tier] ?? 0) + 1;
  stats.byModel[routedModel] = (stats.byModel[routedModel] ?? 0) + 1;

  // Add routing info headers
  res.setHeader("X-SecRouter-Model", routedModel);
  res.setHeader("X-SecRouter-Tier", tier);
  res.setHeader("X-SecRouter-Reasoning", reasoning.slice(0, 200));

  // Per-request accountability: tie principal → tier → final model (AU 3.3.2).
  if (ctx.principal && securityEnabled()) {
    getAuditor().emit({
      type: "route.decision",
      requestId: ctx.requestId,
      principalId: ctx.principal.id,
      sourceIp: ctx.sourceIp,
      model: routedModel,
      tier,
      outcome: "routed",
      detail: { reasoning: reasoning.slice(0, 200), stream },
    });
  }

  // Build model list: primary + fallbacks
  const modelsToTry: string[] = [routedModel];
  if (tier !== "EXPLICIT") {
    const routingCfg = getRoutingConfig();
    const tierConfig = routingCfg.tiers[tier as keyof typeof routingCfg.tiers];
    if (tierConfig?.fallback) {
      for (const fb of tierConfig.fallback) {
        if (fb !== routedModel) modelsToTry.push(fb);
      }
    }
  }

  let lastError: string = "";
  let egressBlocked = false;
  let attempted = false; // did we actually forward to any provider?
  let skippedOpen = false; // did we skip a provider/endpoint because its circuit was open?
  modelLoop:
  for (const modelToTry of modelsToTry) {
    const provider = modelToTry.split("/")[0];
    const providerEntry = getConfig().providers[provider];
    let endpointCount = 1;
    try {
      endpointCount = providerEntry ? endpointsOf(providerEntry).length : 1;
    } catch (err) {
      lastError = err instanceof Error ? err.message : String(err);
      logger.error(`Endpoint config error for provider '${provider}': ${lastError}`);
      continue;
    }

    // Pre-selection (Phase C+, multi-endpoint): drop endpoints whose breaker is
    // open, round-robin the survivors (router/balance.ts). Empty means every
    // endpoint for this provider is open -- fail fast to the next authorized
    // model, exactly like the old provider-level circuit_open skip.
    //
    // Model-aware narrowing: `serves` restricts candidates to the endpoints
    // known (via the active /models health-check probe, see runHealthChecks)
    // to actually carry this model — an endpoint with no info yet is kept
    // (`?? true`), and balance.ts never narrows a request down to zero
    // candidates even if every endpoint is of unconfirmed support.
    const bareModel = modelToTry.slice(provider.length + 1);
    const order = selectEndpoints(provider, endpointCount, breaker, endpointCursor, {
      onTransition: onCircuitTransition,
      serves: (idx) => servedModels.get(`${provider}#${idx}`)?.has(bareModel) ?? true,
    });
    if (order.length === 0) {
      skippedOpen = true;
      lastError = `circuit open for provider '${provider}'`;
      logger.warn(`circuit open: skip ${modelToTry} — failing fast to next authorized model`);
      continue;
    }

    for (const endpointIdx of order) {
      // Fresh recheck immediately before use: selectEndpoints's admission pass
      // can be stale by the time we get here (an earlier endpoint in this same
      // list may have awaited a full upstream round-trip in between).
      const gate = breaker.admit(provider, endpointIdx);
      if (gate.transition) onCircuitTransition(gate.transition);
      if (!gate.ok) continue; // raced open since selection -- try the next endpoint

      const baseUrl = providerEntry ? endpointsOf(providerEntry)[endpointIdx] : undefined;
      const started = Date.now();
      try {
        if (modelToTry !== routedModel) {
          logger.info(`[${stats.requests}] Falling back to ${modelToTry}`);
          res.setHeader("X-SecRouter-Model", modelToTry);
        }
        attempted = true;
        const usage = await forwardRequest(chatReq, modelToTry, tier, res, stream, requestClassification, ctx.traceparent, baseUrl);
        const tr = breaker.recordSuccess(provider, Date.now() - started, endpointIdx);
        if (tr) onCircuitTransition(tr); // half-open -> closed (recovery)
        recordUsageAndAudit(ctx, tier, usage, "ok"); // per-user token/cost accounting
        metrics.requestDuration.observe({ tier }, (Date.now() - t0) / 1000);
        return; // success
      } catch (err) {
        lastError = err instanceof Error ? err.message : String(err);
        if (err instanceof EgressDeniedError) {
          // Data-residency violation blocked at the choke point — audit and try
          // the next (possibly authorized) fallback MODEL instead of leaking the
          // reason (not a health signal, and not endpoint-specific today).
          metrics.egressDeniedTotal.inc();
          egressBlocked = true;
          if (ctx.principal && securityEnabled()) {
            getAuditor().emit(audit.egressDeny(ctx.principal.id, ctx.requestId, err.provider, err.message));
          }
          logger.error(`⛔ EGRESS DENIED (${modelToTry}#${endpointIdx}): ${lastError}`);
          continue modelLoop;
        }
        metrics.upstreamErrorsTotal.inc({ provider, endpoint: String(endpointIdx) });
        // Only health failures (timeout / 5xx / connect) count toward the breaker;
        // a 4xx client error says nothing about provider availability.
        if (isHealthFailure(err)) {
          const tr = breaker.recordFailure(provider, endpointIdx);
          if (tr) onCircuitTransition(tr); // closed -> open at threshold, or failed probe -> open
        }
        const isTimeout = err instanceof TimeoutError;
        if (isTimeout) {
          stats.timeouts++;
          logger.error(`\u23f1 TIMEOUT (${modelToTry}#${endpointIdx}): ${lastError} — trying next endpoint...`);
        } else {
          logger.error(`Forward error (${modelToTry}#${endpointIdx}): ${lastError}`);
        }
        if (res.headersSent) break modelLoop; // can't retry if already streaming
        // else: fall through and try the next endpoint for this model
      }
    }
  }

  stats.errors++;
  metrics.requestDuration.observe({ tier }, (Date.now() - t0) / 1000);
  // All authorized providers open (nothing forwarded) is a distinct, fast outcome.
  const circuitOnly = !attempted && skippedOpen;
  const failOutcome = egressBlocked ? "egress_denied" : circuitOnly ? "circuit_open" : "error";
  metrics.requestsTotal.inc({ tier, provider: "", model: "", outcome: failOutcome });
  if (!res.headersSent) {
    if (egressBlocked) {
      sendError(res, 502, "No authorized model is available for this request's data classification", "egress_denied");
    } else if (circuitOnly) {
      res.setHeader("Retry-After", String(breaker.config().cooldownSec));
      sendError(res, 503, "All authorized providers are currently unavailable (circuit open)", "provider_unavailable");
    } else {
      sendError(res, 502, `Backend error: ${lastError}`, "upstream_error");
    }
  } else if (!res.writableEnded) {
    res.write(`data: ${JSON.stringify({ error: { message: lastError } })}\n\n`);
    res.write("data: [DONE]\n\n");
    res.end();
  }
}

/**
 * Handle GET /v1/models — derived from the loaded routing config so the list
 * always reflects the actual (allowed) backends, never a stale hardcode.
 */
function handleListModels(_req: IncomingMessage, res: ServerResponse) {
  const created = Math.floor(Date.now() / 1000);
  const ids = new Set<string>();
  const routing = getRoutingConfig();
  for (const tier of Object.values(routing.tiers)) {
    if (tier?.primary) ids.add(tier.primary);
    for (const fb of tier?.fallback ?? []) ids.add(fb);
  }
  const models = [
    { id: "auto", object: "model", created, owned_by: "secrouter", permission: [] },
    ...[...ids].sort().map((id) => ({
      id,
      object: "model",
      created,
      owned_by: id.split("/")[0],
    })),
  ];

  res.writeHead(200, { "Content-Type": "application/json" });
  res.end(JSON.stringify({ object: "list", data: models }));
}

/**
 * Handle GET /health — unauthenticated liveness probe.
 * Least functionality (CM 3.4.6): exposes no usage stats or config to anonymous
 * callers; detailed stats live behind the admin-gated /stats endpoint.
 */
function handleHealth(_req: IncomingMessage, res: ServerResponse) {
  res.writeHead(200, { "Content-Type": "application/json" });
  res.end(JSON.stringify({
    status: "ok",
    version: "1.1.0",
    uptime: process.uptime(),
    security: securityEnabled() ? "enabled" : "disabled",
  }));
}

/**
 * GET /metrics — Prometheus exposition. Off unless security.metrics.enabled.
 * Scrapers can't do OIDC, so this route sits before the auth gate; protect it
 * with an optional static bearer (security.metrics.bearerEnvKey) and/or network
 * placement. Labels are bounded — no principal id leaks here.
 */
function handleMetrics(req: IncomingMessage, res: ServerResponse) {
  const cfg = getSecurityConfig()?.metrics;
  if (!cfg?.enabled) {
    return sendError(res, 404, "Not found: GET /metrics", "not_found");
  }
  if (cfg.bearerEnvKey) {
    const expected = process.env[cfg.bearerEnvKey];
    const header = req.headers["authorization"];
    const got = typeof header === "string" && header.startsWith("Bearer ") ? header.slice(7) : "";
    if (!expected || got !== expected) {
      res.setHeader("WWW-Authenticate", "Bearer");
      return sendError(res, 401, "Unauthorized", "authentication_error");
    }
  }
  res.writeHead(200, { "Content-Type": "text/plain; version=0.0.4; charset=utf-8" });
  res.end(renderMetrics());
}

/**
 * Handle GET /stats
 */
function handleStats(_req: IncomingMessage, res: ServerResponse) {
  res.writeHead(200, { "Content-Type": "application/json" });
  res.end(JSON.stringify(stats, null, 2));
}


/**
 * Handle GET /config — show sanitized config (no secrets)
 */
function handleConfig(_req: IncomingMessage, res: ServerResponse) {
  res.writeHead(200, { "Content-Type": "application/json" });
  res.end(JSON.stringify({
    configPath: getConfigPath(),
    config: getSanitizedConfig(),
  }, null, 2));
}

/**
 * Handle POST /reload-config — reload config + auth without restart
 */
function handleReloadConfig(_req: IncomingMessage, res: ServerResponse) {
  const newCfg = reloadConfig();
  // Re-validate before applying security changes: never hot-swap into an
  // unsafe configuration (fail-closed). On error, keep the running config.
  const errors = validateSecurityConfig(newCfg);
  if (errors.length > 0) {
    return sendError(res, 422, `Refusing reload — invalid security config: ${errors.join("; ")}`, "config_error");
  }
  reloadAuth();
  initSecurity(newCfg.security);
  emitPendingEgressFileAudit(); // audit-evident (not silent) if SECROUTER_EGRESS_FILE loaded rules above
  breaker.setConfig(resolveResilience(newCfg.security?.resilience));
  startHealthChecks(); // reflect any healthIntervalSec change
  const cfg = getConfig();
  res.writeHead(200, { "Content-Type": "application/json" });
  res.end(JSON.stringify({
    status: "reloaded",
    configPath: getConfigPath(),
    providers: Object.keys(cfg.providers),
    tiers: Object.keys(cfg.tiers),
    security: cfg.security?.enabled === true ? "enabled" : "disabled",
  }));
}

/**
 * Handle POST /reload
 */
function handleReload(_req: IncomingMessage, res: ServerResponse) {
  reloadConfig();
  reloadAuth();
  res.writeHead(200, { "Content-Type": "application/json" });
  res.end(JSON.stringify({ status: "reloaded" }));
}

/**
 * Best-effort client IP for the audit trail. Trusts the first X-Forwarded-For
 * hop only when TLS is terminated by the front-end proxy (the deployment model);
 * otherwise uses the socket peer address (avoids header spoofing).
 */
function getClientIp(req: IncomingMessage): string {
  if (getSecurityConfig()?.tls?.mode === "frontend") {
    const xff = req.headers["x-forwarded-for"];
    const first = Array.isArray(xff) ? xff[0] : xff;
    if (first) return first.split(",")[0].trim();
  }
  return req.socket.remoteAddress ?? "unknown";
}

/**
 * Apply CORS. Deny-by-default when secured: only configured origins are echoed
 * (AC 3.1.3). Dev mode (security disabled) preserves the original `*` behavior.
 */
function applyCors(req: IncomingMessage, res: ServerResponse) {
  res.setHeader("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type, Authorization");
  if (!securityEnabled()) {
    res.setHeader("Access-Control-Allow-Origin", "*");
    return;
  }
  const allowed = getSecurityConfig()?.cors?.allowedOrigins ?? [];
  const origin = req.headers.origin;
  if (origin && allowed.includes(origin)) {
    res.setHeader("Access-Control-Allow-Origin", origin);
    res.setHeader("Vary", "Origin");
  }
  // else: no Access-Control-Allow-Origin header → browsers block the response.
}

/**
 * Admin gate for sensitive endpoints (AC 3.1.2). Returns true if allowed;
 * otherwise writes a 401/403 and audits the denial.
 */
function requireAdmin(ctx: Ctx, res: ServerResponse, action: string): boolean {
  if (!securityEnabled()) return true; // dev mode (warned at startup)
  const p = ctx.principal;
  if (!p) {
    sendError(res, 401, "Unauthorized", "authentication_error");
    return false;
  }
  const pol = getEffectivePolicy(p);
  if (!pol.admin) {
    getAuditor().emit(audit.authzDeny(p.id, ctx.requestId, action, "admin_required"));
    sendError(res, 403, "Forbidden", "authorization_error");
    return false;
  }
  getAuditor().emit(audit.adminAction(p.id, action, { sourceIp: ctx.sourceIp }));
  return true;
}

/**
 * GET /v1/usage — a principal's own token/cost usage and remaining budget.
 * Supports the user-facing side of cost containment (Feature 2).
 */
function handleUsageSelf(ctx: Ctx, res: ServerResponse) {
  if (!securityEnabled() || !ctx.principal) {
    return sendError(res, 401, "Unauthorized", "authentication_error");
  }
  const store = getStore();
  const id = ctx.principal.id;
  const day = new Date(Date.now() - 86_400_000).toISOString();
  const month = new Date(Date.now() - 30 * 86_400_000).toISOString();
  res.writeHead(200, { "Content-Type": "application/json" });
  res.end(
    JSON.stringify(
      {
        principal: id,
        groups: ctx.principal.groups,
        budgets: getEffectivePolicy(ctx.principal).budgets,
        usage: { last24h: store.aggregateUsage(id, day), last30d: store.aggregateUsage(id, month) },
        byModel: store.usageBreakdown({ principalId: id, sinceIso: month, groupBy: "model" }),
      },
      null,
      2,
    ),
  );
}

/**
 * GET /admin/usage — org-wide usage breakdown (admin only).
 * Query: ?groupBy=principal|model|day  &days=N  &principal=<id>
 */
function handleUsageAdmin(url: string, res: ServerResponse) {
  const q = new URL(url, "http://localhost").searchParams;
  const gb = q.get("groupBy");
  const groupBy: "model" | "principal" | "day" =
    gb === "model" || gb === "day" ? gb : "principal";
  const days = Math.min(Math.max(parseInt(q.get("days") ?? "30", 10) || 30, 1), 365);
  const sinceIso = new Date(Date.now() - days * 86_400_000).toISOString();
  const principalId = q.get("principal") ?? undefined;
  res.writeHead(200, { "Content-Type": "application/json" });
  res.end(
    JSON.stringify(
      {
        window: `${days}d`,
        groupBy,
        principal: principalId ?? "all",
        breakdown: getStore().usageBreakdown({ principalId, sinceIso, groupBy }),
      },
      null,
      2,
    ),
  );
}

// ─── Admin console (web UX) ───

/** GET /admin — serve the SPA shell (public; the data APIs below are admin-gated). */
function serveAdminUi(res: ServerResponse) {
  res.writeHead(200, {
    "Content-Type": "text/html; charset=utf-8",
    "Cache-Control": "no-store",
    "X-Content-Type-Options": "nosniff",
    "Content-Security-Policy":
      "default-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'; connect-src 'self' *; img-src 'self' data:",
  });
  res.end(ADMIN_HTML);
}

/** GET /admin/oidc — PUBLIC: the params the SPA needs to begin an OIDC PKCE login. */
function handleAdminOidc(res: ServerResponse) {
  res.writeHead(200, { "Content-Type": "application/json", "Cache-Control": "no-store" });
  if (!securityEnabled()) {
    res.end(JSON.stringify({ enabled: false }));
    return;
  }
  const oidc = getSecurityConfig()?.oidc;
  res.end(
    JSON.stringify({
      enabled: true,
      issuer: oidc?.issuer ?? null,
      clientId: oidc?.clientId ?? null,
      scopes: oidc?.scopes ?? "openid profile email",
    }),
  );
}

/** GET /admin/api/config — effective policy + tiers + model catalog; providers/egress read-only. */
function handleAdminConfig(res: ServerResponse) {
  const cfg = getConfig();
  const sec = cfg.security;
  const providers: Record<string, unknown> = {};
  for (const [name, p] of Object.entries(cfg.providers ?? {})) {
    providers[name] = { baseUrl: p.baseUrl, api: p.api, region: p.region }; // no secrets
  }
  res.writeHead(200, { "Content-Type": "application/json" });
  res.end(
    JSON.stringify(
      {
        securityEnabled: securityEnabled(),
        classification: sec?.classification ?? null,
        policy: sec?.policy ?? { default: {}, groups: {}, users: {} },
        tiers: cfg.tiers,
        providers, // read-only
        egress: sec?.egress?.allowlist ?? [], // read-only (compliance-critical)
        mcp: { enabled: sec?.mcp?.enabled === true, servers: (sec?.mcp?.servers ?? []).map((s) => ({ name: s.name, url: s.url, authorizedClassifications: s.authorizedClassifications })) }, // read-only
        overrides: getOverrides().list(),
        knownModels: getModelCatalog().map((m) => ({ id: m.id, name: m.name, inputPrice: m.inputPrice, outputPrice: m.outputPrice, kind: m.kind ?? "chat" })),
      },
      null,
      2,
    ),
  );
}

/**
 * GET /admin/api/health — per-provider circuit-breaker state (Phase C / SC
 * availability posture). Lists every configured provider, including those with
 * no traffic yet, plus the effective resilience tuning.
 */
function handleProviderHealth(res: ServerResponse) {
  const cfg = getConfig();
  const snap = breaker.snapshot();
  const byKey = new Map(snap.map((h) => [`${h.provider}#${h.endpoint}`, h]));
  // One row per configured endpoint (endpointsOf) — a single-baseUrl provider
  // still yields exactly one row (endpoint 0), matching today's shape plus the
  // new `endpoint` field.
  const providers: ProviderHealth[] = [];
  for (const [name, entry] of Object.entries(cfg.providers ?? {})) {
    const count = endpointsOf(entry).length;
    for (let i = 0; i < count; i++) {
      providers.push(
        byKey.get(`${name}#${i}`) ?? {
          provider: name,
          endpoint: i,
          state: "closed",
          consecutiveFailures: 0,
          totalFailures: 0,
          totalSuccesses: 0,
        },
      );
    }
  }
  // Surface any breaker state for a provider/endpoint no longer in config (renamed/removed).
  const known = new Set(providers.map((p) => `${p.provider}#${p.endpoint}`));
  for (const h of snap) if (!known.has(`${h.provider}#${h.endpoint}`)) providers.push(h);
  res.writeHead(200, { "Content-Type": "application/json" });
  res.end(JSON.stringify({ resilience: breaker.config(), providers, ts: new Date().toISOString() }, null, 2));
}

/** POST /admin/api/mcp/probe — list a registered MCP server's tools (admin, audited). */
async function handleMcpProbe(req: IncomingMessage, res: ServerResponse, ctx: Ctx) {
  let body: { name?: string };
  try {
    body = JSON.parse(await readBody(req)) as { name?: string };
  } catch {
    return sendError(res, 400, "Invalid JSON body", "invalid_request_error");
  }
  const name = String(body?.name ?? "");
  const result = await probeMcpTools(name);
  getAuditor().emit(audit.adminAction(ctx.principal!.id, "mcp.probe", { server: name, ok: result.ok, sourceIp: ctx.sourceIp }));
  res.writeHead(200, { "Content-Type": "application/json" });
  res.end(JSON.stringify(result));
}

/** GET /admin/api/audit — recent audit events for monitoring. */
function handleAdminAudit(url: string, res: ServerResponse) {
  const q = new URL(url, "http://localhost").searchParams;
  const limit = Math.min(Math.max(parseInt(q.get("limit") ?? "100", 10) || 100, 1), 1000);
  const type = q.get("type") ?? undefined;
  res.writeHead(200, { "Content-Type": "application/json" });
  res.end(JSON.stringify(getStore().queryAudit({ limit, type }), null, 2));
}

/** POST /admin/api/endpoint/probe — reach a candidate endpoint and list its models. */
async function handleEndpointProbe(req: IncomingMessage, res: ServerResponse, ctx: Ctx) {
  let body: ProbeRequest;
  try {
    body = JSON.parse(await readBody(req)) as ProbeRequest;
  } catch {
    return sendError(res, 400, "Invalid JSON body", "invalid_request_error");
  }
  getAuditor().emit(audit.adminAction(ctx.principal!.id, "endpoint.probe", { baseUrl: body?.baseUrl, sourceIp: ctx.sourceIp }));
  res.writeHead(200, { "Content-Type": "application/json" });
  res.end(JSON.stringify(await probeEndpoint(body)));
}

/** POST /admin/api/endpoint/preview — validate a proposed endpoint change (no write). */
async function handleEndpointPreview(req: IncomingMessage, res: ServerResponse) {
  let body: EndpointSpec;
  try {
    body = JSON.parse(await readBody(req)) as EndpointSpec;
  } catch {
    return sendError(res, 400, "Invalid JSON body", "invalid_request_error");
  }
  try {
    res.writeHead(200, { "Content-Type": "application/json" });
    res.end(JSON.stringify(previewEndpoint(body)));
  } catch (err) {
    return sendError(res, 400, err instanceof Error ? err.message : "invalid endpoint spec", "invalid_request_error");
  }
}

/** POST /admin/api/endpoint/apply — write the endpoint into the config file (validated, atomic). */
async function handleEndpointApply(req: IncomingMessage, res: ServerResponse, ctx: Ctx) {
  let body: EndpointSpec;
  try {
    body = JSON.parse(await readBody(req)) as EndpointSpec;
  } catch {
    return sendError(res, 400, "Invalid JSON body", "invalid_request_error");
  }
  let out: { path: string };
  try {
    out = applyEndpoint(body);
  } catch (err) {
    return sendError(res, 422, err instanceof Error ? err.message : "apply failed", "config_error");
  }
  getAuditor().emit(audit.adminAction(ctx.principal!.id, "endpoint.apply", { provider: body?.provider?.name, path: out.path, sourceIp: ctx.sourceIp }));
  res.writeHead(200, { "Content-Type": "application/json" });
  res.end(JSON.stringify({ status: "written", ...out, applied: false, hint: "reload or restart to apply" }));
}

/** POST /admin/api/restart — graceful restart so the supervisor reloads the new config. */
function handleAdminRestart(res: ServerResponse, ctx: Ctx) {
  getAuditor().emit(audit.adminAction(ctx.principal!.id, "service.restart", { sourceIp: ctx.sourceIp }));
  logger.warn(`Admin-initiated restart requested by ${ctx.principal!.id} — exiting; supervisor will relaunch.`);
  res.writeHead(202, { "Content-Type": "application/json" });
  res.end(JSON.stringify({ status: "restarting" }));
  setTimeout(() => process.exit(0), 300);
}

/** GET /admin/api/audit/verify — verify the audit hash chain (AU 3.3.8 tamper-evidence). */
function handleAuditVerify(res: ServerResponse) {
  const r = getStore().verifyAuditChain();
  res.writeHead(200, { "Content-Type": "application/json" });
  res.end(JSON.stringify({ ...r, ts: new Date().toISOString() }, null, 2));
}

/** Derive a live, family-level control self-assessment from the running config + state. */
function buildControlSelfAssessment(
  sec: ReturnType<typeof getSecurityConfig>,
  chain: { ok: boolean; brokenAtId?: number; checked: number },
  egressCount: number,
) {
  const oidc = sec?.oidc;
  return {
    "AC-3.1.1/3.1.2 (access control)": {
      evidence: "config.security.oidc + audit auth.success/auth.failure",
      status: securityEnabled() ? "enforced (deny-by-default)" : "DISABLED",
    },
    "AC-3.1.3 / SC-3.13.6 (CUI flow / deny-by-default egress)": {
      evidence: "config.security.egress.allowlist + audit egress.deny",
      allowlistRules: egressCount,
      status: egressCount > 0 ? "enforced" : "NO RULES",
    },
    "AC-3.1.5 (least privilege)": {
      evidence: "config.security.policy + audit authz.deny/authz.downgrade",
      status: sec?.policy ? "per-group/user policy" : "default-only",
    },
    "AC-3.1.3/3.1.5 (governed tool access — MCP)": {
      evidence: "config.security.mcp + policy.allowedTools + audit tool.call/tool.deny",
      servers: sec?.mcp?.servers?.length ?? 0,
      status: sec?.mcp?.enabled ? "enforced (deny-by-default tools)" : "disabled",
    },
    "IA-3.5.1/3.5.2 (identification & authentication)": {
      evidence: "config.security.oidc (issuer/audience/jwks)",
      status: oidc ? "OIDC SSO" : "NONE",
    },
    "IA-3.5.3 (multifactor)": {
      evidence: "config.security.oidc.requireMfa + audit auth.success detail.mfa",
      required: oidc?.requireMfa === true,
      status: oidc?.requireMfa ? "required" : "not required",
    },
    "AU-3.3.1/3.3.2 (audit creation & traceability)": {
      evidence: "auditRecent[] — per-principal, metadata-only (CUI-safe)",
      status: "active",
    },
    "AU-3.3.8 (audit tamper-evidence)": {
      evidence: "auditChain — SHA-256 hash-chain verification",
      verified: chain.ok,
      eventsChecked: chain.checked,
      status: chain.ok ? "intact" : `BROKEN at id ${chain.brokenAtId}`,
    },
    "SC-3.13.8 (encryption in transit)": {
      evidence: "config.security.tls (mode/minVersion/ciphers)",
      status: sec?.tls?.mode === "native" ? "native TLS" : "front-end termination",
    },
    "SC-3.13.11 (FIPS crypto)": {
      evidence: "startup assertFips() + crypto.getFips()",
      required: sec?.requireFips === true,
      active: isFipsEnabled(),
      status: isFipsEnabled() ? "FIPS active" : sec?.requireFips ? "REQUIRED-NOT-ACTIVE" : "not enabled",
    },
    "CM-3.4.1/3.4.2 (baseline config & change control)": {
      evidence: "config (this baseline) + audit admin.action (config writes) + .bak backups",
      configPath: getConfigPath(),
      status: "baseline captured",
    },
  };
}

/** GET /admin/api/evidence — one-shot CMMC evidence bundle (downloaded by the console). */
function handleEvidence(res: ServerResponse, ctx: Ctx) {
  const store = getStore();
  const sec = getSecurityConfig();
  const chain = store.verifyAuditChain();
  const sinceIso = new Date(Date.now() - 30 * 86_400_000).toISOString();
  const today = new Date().toISOString().slice(0, 10);
  const bundle = {
    product: "SecRouter",
    version: "1.1.0",
    generatedAt: new Date().toISOString(),
    generatedBy: ctx.principal!.id,
    configPath: getConfigPath(),
    health: { status: "ok", version: "1.1.0", uptime: process.uptime(), security: securityEnabled() ? "enabled" : "disabled" },
    fips: { required: sec?.requireFips === true, active: isFipsEnabled() },
    config: getSanitizedConfig(), // baseline (AC/SC/CM) — secrets redacted
    auditChain: { ...chain, ts: new Date().toISOString() }, // AU 3.3.8
    auditRecent: store.queryAudit({ limit: 200 }), // AU 3.3.1/3.3.2
    usage: { window: "30d", byPrincipal: store.usageBreakdown({ sinceIso, groupBy: "principal" }) },
    stats,
    controls: buildControlSelfAssessment(sec, chain, sec?.egress?.allowlist?.length ?? 0),
  };
  res.writeHead(200, {
    "Content-Type": "application/json",
    "Content-Disposition": `attachment; filename="secrouter-evidence-${today}.json"`,
  });
  res.end(JSON.stringify(bundle, null, 2));
}

/** Admin data + mutation API (admin-gated). Edits go through the audited overrides layer. */
async function handleAdminApi(method: string, path: string, req: IncomingMessage, res: ServerResponse, ctx: Ctx) {
  if (!securityEnabled()) {
    return sendError(res, 503, "Admin console requires security.enabled (no store in dev mode)", "unavailable");
  }
  const url = req.url ?? path;

  if (method === "GET" && path === "/admin/api/config") return handleAdminConfig(res);
  if (method === "GET" && path === "/admin/api/usage") return handleUsageAdmin(url, res);
  if (method === "GET" && path === "/admin/api/audit") return handleAdminAudit(url, res);

  // Provider availability: circuit-breaker health (Phase C).
  if (method === "GET" && path === "/admin/api/health") return handleProviderHealth(res);

  // MCP gateway: probe a registered server's tools (Phase D).
  if (method === "POST" && path === "/admin/api/mcp/probe") return handleMcpProbe(req, res, ctx);

  // CMMC control validation: verify the audit hash chain + one-shot evidence bundle.
  if (method === "GET" && path === "/admin/api/audit/verify") return handleAuditVerify(res);
  if (method === "GET" && path === "/admin/api/evidence") return handleEvidence(res, ctx);

  // Add-endpoint tooling: probe → preview → apply (write file) → reload/restart.
  if (method === "POST" && path === "/admin/api/endpoint/probe") return handleEndpointProbe(req, res, ctx);
  if (method === "POST" && path === "/admin/api/endpoint/preview") return handleEndpointPreview(req, res);
  if (method === "POST" && path === "/admin/api/endpoint/apply") return handleEndpointApply(req, res, ctx);
  if (method === "POST" && path === "/admin/api/reload") {
    getAuditor().emit(audit.adminAction(ctx.principal!.id, "config.reload", { sourceIp: ctx.sourceIp }));
    return handleReloadConfig(req, res);
  }
  if (method === "POST" && path === "/admin/api/restart") return handleAdminRestart(res, ctx);

  // Mutations: /admin/api/policy/group/<name>, /admin/api/policy/user/<id>, /admin/api/tier/<name>
  const segs = path.split("/").filter(Boolean); // ["admin","api",...]
  let scope: OverrideScope | null = null;
  let name = "";
  if (segs[2] === "policy" && (segs[3] === "group" || segs[3] === "user")) {
    scope = segs[3] === "group" ? "policy.group" : "policy.user";
    name = decodeURIComponent(segs.slice(4).join("/"));
  } else if (segs[2] === "tier") {
    scope = "tier";
    name = decodeURIComponent(segs.slice(3).join("/"));
  }
  if (!scope || !name) return sendError(res, 404, "Unknown admin route", "not_found");

  if (method === "DELETE") {
    getOverrides().remove(scope, name, ctx.principal!.id);
    res.writeHead(200, { "Content-Type": "application/json" });
    return res.end(JSON.stringify({ status: "deleted", scope, name }));
  }
  if (method === "PUT") {
    let body: unknown;
    try {
      body = JSON.parse(await readBody(req));
    } catch {
      return sendError(res, 400, "Invalid JSON body", "invalid_request_error");
    }
    try {
      getOverrides().put(scope, name, body, ctx.principal!.id, new Date().toISOString());
    } catch (err) {
      return sendError(res, 422, err instanceof Error ? err.message : "override rejected", "config_error");
    }
    res.writeHead(200, { "Content-Type": "application/json" });
    return res.end(JSON.stringify({ status: "saved", scope, name }));
  }
  return sendError(res, 405, "Method not allowed", "method_not_allowed");
}

/**
 * Request router. Order: CORS → OPTIONS → unauthenticated /health + admin shell →
 * AuthN gate (deny-by-default) → dispatch (admin-gated where sensitive).
 */
async function handleRequest(req: IncomingMessage, res: ServerResponse) {
  const method = req.method ?? "GET";
  const url = req.url ?? "/";
  const path = url.split("?")[0];
  const requestId = randomUUID();
  const sourceIp = getClientIp(req);
  // W3C trace context: adopt a valid inbound traceparent so audit rows join to
  // the caller's APM trace (AU 3.3.5 correlation); propagated to upstream too.
  const tp = req.headers["traceparent"];
  const traceparent = typeof tp === "string" && /^00-[0-9a-f]{32}-[0-9a-f]{16}-[0-9a-f]{2}$/.test(tp) ? tp : undefined;
  const traceId = traceparent ? traceparent.slice(3, 35) : undefined;
  res.setHeader("X-Request-Id", requestId);

  applyCors(req, res);

  if (method === "OPTIONS") {
    res.writeHead(204);
    res.end();
    return;
  }

  // Health is unauthenticated (liveness probe).
  if (method === "GET" && path === "/health") {
    return handleHealth(req, res);
  }
  // Prometheus scrape (off by default; scrapers can't do OIDC — see security.metrics).
  if (method === "GET" && path === "/metrics") {
    return handleMetrics(req, res);
  }
  // Admin console shell + OIDC params are public: the SPA logs in via OIDC PKCE,
  // then calls the admin-gated /admin/api/* data + mutation endpoints below.
  if (method === "GET" && (path === "/admin" || path === "/admin/")) {
    return serveAdminUi(res);
  }
  if (method === "GET" && path === "/admin/oidc") {
    return handleAdminOidc(res);
  }

  // ── AuthN gate (IA 3.5.1/3.5.2, deny-by-default) ──
  const ctx: Ctx = { requestId, sourceIp, traceId, traceparent };
  if (securityEnabled()) {
    try {
      ctx.principal = await authenticate(req.headers);
      getAuditor().emit(
        audit.authSuccess(ctx.principal.id, sourceIp, {
          requestId,
          mfa: ctx.principal.mfa,
          groups: ctx.principal.groups,
          // Present only for on-behalf-of requests: the trusted service that
          // authenticated and vouched for this end-user (completes the chain).
          ...(ctx.principal.delegatedBy ? { delegatedBy: ctx.principal.delegatedBy } : {}),
          traceId,
        }),
      );
    } catch (err) {
      metrics.authFailuresTotal.inc();
      const code = err instanceof AuthError ? err.code : "auth_error";
      try {
        getAuditor().emit(audit.authFailure(sourceIp, code, { requestId }));
      } catch {
        /* audit is best-effort on the pre-auth path */
      }
      res.setHeader("WWW-Authenticate", "Bearer");
      return sendError(res, 401, "Unauthorized", "authentication_error");
    }
  }

  try {
    if (method === "POST" && (path === "/v1/chat/completions" || path === "/chat/completions")) {
      await handleChatCompletions(req, res, ctx);
    } else if (method === "POST" && (path === "/v1/embeddings" || path === "/embeddings")) {
      await handleEmbeddings(req, res, ctx);
    } else if (method === "POST" && path === "/mcp") {
      if (!getSecurityConfig()?.mcp?.enabled) sendError(res, 404, "Not found", "not_found");
      else await handleMcp(req, res, ctx);
    } else if (method === "GET" && (path === "/v1/models" || path === "/models")) {
      handleListModels(req, res);
    } else if (method === "GET" && path === "/v1/usage") {
      handleUsageSelf(ctx, res);
    } else if (method === "GET" && path === "/admin/usage") {
      if (requireAdmin(ctx, res, "GET /admin/usage")) handleUsageAdmin(url, res);
    } else if (path.startsWith("/admin/api/")) {
      if (requireAdmin(ctx, res, `${method} ${path}`)) await handleAdminApi(method, path, req, res, ctx);
    } else if (method === "GET" && path === "/stats") {
      if (requireAdmin(ctx, res, "GET /stats")) handleStats(req, res);
    } else if (method === "POST" && path === "/reload") {
      if (requireAdmin(ctx, res, "POST /reload")) handleReload(req, res);
    } else if (method === "GET" && path === "/config") {
      if (requireAdmin(ctx, res, "GET /config")) handleConfig(req, res);
    } else if (method === "POST" && path === "/reload-config") {
      if (requireAdmin(ctx, res, "POST /reload-config")) handleReloadConfig(req, res);
    } else {
      sendError(res, 404, `Not found: ${method} ${path}`, "not_found");
    }
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    logger.error(`[${requestId}] Unhandled error: ${msg}`);
    if (!res.headersSent) {
      // Non-leaking error (SI 3.14): generic message to client, detail to logs.
      sendError(res, 500, securityEnabled() ? "Internal error" : msg);
    }
  }
}

// ─── Start server ───

if (process.argv.includes("--debug")) {
  setLogLevel("debug");
}

// Native TLS termination when configured (SC 3.13.8); otherwise plain HTTP for
// a FIPS-validated front-end proxy (tls.mode="frontend") or dev.
const _tls = appConfig.security?.tls;
const server =
  _tls?.mode === "native"
    ? createHttpsServer(httpsOptions(appConfig.security!), handleRequest)
    : createServer(handleRequest);
const _scheme = _tls?.mode === "native" ? "https" : "http";

server.listen(PORT, HOST, () => {
  const sec = securityEnabled() ? "🔒 secured (OIDC auth, deny-by-default)" : "⚠ OPEN (security disabled)";
  logger.info(`🚀 SecRouter proxy listening on ${_scheme}://${HOST}:${PORT} — ${sec} (config: ${getConfigPath() ?? "built-in defaults"})`);
  logger.info(`   POST /v1/chat/completions  — route & forward (authn)`);
  logger.info(`   GET  /v1/models            — list models (authn)`);
  logger.info(`   GET  /health               — liveness (open)`);
  logger.info(`   GET  /stats                — request statistics (admin)`);
  logger.info(`   POST /reload               — reload auth keys (admin)`);
  logger.info(`   GET  /config               — show config, sanitized (admin)`);
  logger.info(`   POST /reload-config        — reload config + auth (admin)`);
});

// Graceful shutdown
function shutdown() {
  logger.info("Shutting down...");
  server.close(() => {
    closeSecurity(); // flush/close the security store (audit + ledger)
    process.exit(0);
  });
}
process.on("SIGINT", shutdown);
process.on("SIGTERM", shutdown);
