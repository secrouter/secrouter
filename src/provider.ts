/**
 * SecRouter Provider — handles forwarding to backend APIs
 * Supports: Anthropic Messages API, OpenAI-compatible (Kimi, OpenAI)
 * Zero external deps â€” uses native fetch + streams.
 */

import { getAuth } from "./auth.js";
import { getConfig, toInternalApiType, supportsAdaptiveThinking as configSupportsAdaptive, getThinkingBudget, getSecurityConfig, isSecurityEnabled, endpointsOf } from "./config.js";
import { logger } from "./logger.js";
import { zeroUsage } from "./security/accounting/usage.js";
import { checkEgress, EgressDeniedError } from "./security/egress/allowlist.js";
import { signRequest } from "./security/transport/sigv4.js";
import { getEntraToken } from "./security/transport/azureEntra.js";
import type { UsageResult } from "./security/types.js";
import type { IncomingMessage, ServerResponse } from "node:http";
// --- Timeout Configuration ---
const TIER_TIMEOUTS: Record<string, number> = {
  SIMPLE: 30_000,
  MEDIUM: 60_000,
  COMPLEX: 120_000,
  REASONING: 120_000,
  EXPLICIT: 120_000,
};
const STREAM_STALL_TIMEOUT = 30_000;

function getTierTimeout(tier: string): number {
  return TIER_TIMEOUTS[tier] ?? 60_000;
}

export class TimeoutError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "TimeoutError";
  }
}

/**
 * A non-OK HTTP response from an upstream provider. Carries the status so the
 * circuit breaker can distinguish a provider health problem (5xx / connect) from
 * a client error (4xx) that says nothing about availability.
 */
export class UpstreamError extends Error {
  constructor(
    message: string,
    readonly status: number,
    readonly provider: string,
  ) {
    super(message);
    this.name = "UpstreamError";
  }
}


// Provider configs loaded from freerouter.config.json
export type ProviderConfig = {
  /** All configured endpoints (config.endpointsOf normalizes to this shape upstream). */
  baseUrl: string | string[];
  api: "anthropic-messages" | "openai-completions" | "bedrock-runtime" | "azure-openai";
  headers?: Record<string, string>;
  region?: string;
  /** Azure OpenAI (api="azure-openai"): REST api-version, auth mode, and Entra config. */
  apiVersion?: string;
  azureAuth?: "api-key" | "entra";
  entra?: { tenantId: string; clientId: string; clientSecretEnv: string; authority?: string; scope?: string };
};

// OpenAI tool types
export type OpenAIFunction = {
  name: string;
  description?: string;
  parameters?: Record<string, unknown>;
};

export type OpenAITool = {
  type: "function";
  function: OpenAIFunction;
};

export type OpenAIToolCall = {
  id: string;
  type: "function";
  function: { name: string; arguments: string };
};

// OpenAI-format message
export type ChatMessage = {
  role: "system" | "user" | "assistant" | "developer" | "tool";
  content: string | null | Array<{ type: string; text?: string; image_url?: { url: string } }>;
  tool_calls?: OpenAIToolCall[];
  tool_call_id?: string;
  name?: string;
};

export type ChatRequest = {
  model: string;
  messages: ChatMessage[];
  max_tokens?: number;
  temperature?: number;
  stream?: boolean;
  top_p?: number;
  stop?: string[];
  tools?: OpenAITool[];
  tool_choice?: unknown;
};

// Provider configs — loaded from freerouter.config.json via getProviderConfig()

/**
 * Get provider config from the loaded config file.
 */
function getProviderConfig(provider: string): ProviderConfig | undefined {
  const cfg = getConfig();
  const entry = cfg.providers[provider];
  if (!entry) return undefined;
  return {
    baseUrl: entry.baseUrl,
    api: toInternalApiType(entry.api),
    headers: entry.headers,
    region: entry.region,
    apiVersion: entry.apiVersion,
    azureAuth: entry.azureAuth,
    entra: entry.entra,
  };
}

/**
 * Parse a routed model ID like "anthropic/claude-opus-4-6" into provider + model parts.
 */
export function parseModelId(modelId: string): { provider: string; model: string } {
  const slash = modelId.indexOf("/");
  if (slash === -1) return { provider: "anthropic", model: modelId };
  return { provider: modelId.slice(0, slash), model: modelId.slice(slash + 1) };
}

/**
 * Check if a model supports adaptive thinking (Opus 4.6+)
 */
function supportsAdaptiveThinking(modelId: string): boolean {
  return modelId.includes("opus-4-6") || modelId.includes("opus-4.6");
}

/**
 * Get thinking config based on tier and model.
 */
function getThinkingConfig(tier: string, modelId: string): { type: string; budget_tokens?: number; effort?: string } | undefined {
  if (supportsAdaptiveThinking(modelId) && (tier === "COMPLEX" || tier === "REASONING")) {
    return { type: "adaptive" };
  }
  if (tier === "MEDIUM") {
    return { type: "enabled", budget_tokens: 4096 };
  }
  return undefined;
}

/** Convert OpenAI tools to Anthropic tools format */
function convertToolsToAnthropic(tools: OpenAITool[]): Array<{ name: string; description?: string; input_schema: Record<string, unknown> }> {
  return tools.map(t => ({
    name: t.function.name,
    ...(t.function.description ? { description: t.function.description } : {}),
    input_schema: t.function.parameters ?? { type: "object", properties: {} },
  }));
}

/** Convert OpenAI tool_choice to Anthropic tool_choice format */
function convertToolChoiceToAnthropic(toolChoice: unknown): { type: string; name?: string } | undefined {
  if (toolChoice === "none") return { type: "none" };
  if (toolChoice === "auto" || toolChoice === undefined) return { type: "auto" };
  if (toolChoice === "required") return { type: "any" };
  if (typeof toolChoice === "object" && toolChoice !== null) {
    const tc = toolChoice as { type?: string; function?: { name: string } };
    if (tc.function?.name) return { type: "tool", name: tc.function.name };
  }
  return { type: "auto" };
}

/**
 * Convert OpenAI messages array to Anthropic messages format.
 * Handles system extraction, tool_calls, tool results, and content merging.
 */
function convertMessagesToAnthropic(
  openaiMessages: ChatMessage[]
): { system: string; messages: Array<{ role: string; content: unknown }> } {
  let systemContent = "";
  const messages: Array<{ role: string; content: unknown }> = [];

  for (let i = 0; i < openaiMessages.length; i++) {
    const msg = openaiMessages[i];

    // Extract system/developer messages
    if (msg.role === "system" || msg.role === "developer") {
      const text = typeof msg.content === "string"
        ? msg.content
        : (msg.content ?? []).filter((b: any) => b.type === "text").map((b: any) => b.text).join("\n");
      systemContent += (systemContent ? "\n" : "") + text;
      continue;
    }

    // Tool role -> tool_result content block (wrapped in user message)
    if (msg.role === "tool") {
      const toolResult = {
        type: "tool_result" as const,
        tool_use_id: msg.tool_call_id ?? "",
        content: typeof msg.content === "string" ? msg.content : JSON.stringify(msg.content ?? ""),
      };
      // Merge with previous user message if it only has tool_results
      const last = messages[messages.length - 1];
      if (last && last.role === "user" && Array.isArray(last.content) &&
          (last.content as any[]).every((b: any) => b.type === "tool_result")) {
        (last.content as any[]).push(toolResult);
      } else {
        messages.push({ role: "user", content: [toolResult] });
      }
      continue;
    }

    // Assistant with tool_calls -> content blocks with tool_use
    if (msg.role === "assistant" && msg.tool_calls && msg.tool_calls.length > 0) {
      const contentBlocks: Array<Record<string, unknown>> = [];
      // Include text content first
      if (msg.content) {
        const text = typeof msg.content === "string" ? msg.content
          : msg.content.filter((b: any) => b.type === "text").map((b: any) => b.text).join("");
        if (text) contentBlocks.push({ type: "text", text });
      }
      // Add tool_use blocks
      for (const tc of msg.tool_calls) {
        let input: unknown = {};
        try { input = JSON.parse(tc.function.arguments); } catch { input = {}; }
        contentBlocks.push({ type: "tool_use", id: tc.id, name: tc.function.name, input });
      }
      messages.push({ role: "assistant", content: contentBlocks });
      continue;
    }

    // Regular user/assistant messages
    const text = typeof msg.content === "string"
      ? msg.content
      : (msg.content ?? []).filter((b: any) => b.type === "text").map((b: any) => b.text).join("\n");
    messages.push({ role: msg.role === "assistant" ? "assistant" : "user", content: text || "" });
  }

  return { system: systemContent, messages };
}


/**
 * Read a stream with stall detection. Aborts if no data for STREAM_STALL_TIMEOUT.
 */
async function readStreamWithStallDetection(
  reader: ReadableStreamDefaultReader<Uint8Array>,
  onChunk: (value: Uint8Array) => void,
  abortController: AbortController,
): Promise<void> {
  while (true) {
    let stallTimerId: ReturnType<typeof setTimeout> | undefined;
    const stallPromise = new Promise<never>((_, reject) => {
      stallTimerId = setTimeout(() => {
        abortController.abort();
        reject(new TimeoutError(`Stream stalled: no data for ${STREAM_STALL_TIMEOUT / 1000}s`));
      }, STREAM_STALL_TIMEOUT);
    });

    try {
      const result = await Promise.race([reader.read(), stallPromise]);
      clearTimeout(stallTimerId);
      const { done, value } = result as ReadableStreamReadResult<Uint8Array>;
      if (done) break;
      if (value) onChunk(value);
    } catch (err) {
      clearTimeout(stallTimerId);
      throw err;
    }
  }
}

/**
 * Forward a chat request to Anthropic Messages API, streaming back as OpenAI SSE.
 */
async function forwardToAnthropic(
  req: ChatRequest,
  modelName: string,
  tier: string,
  res: ServerResponse,
  stream: boolean,
  baseUrl?: string,
): Promise<UsageResult> {
  const auth = getAuth("anthropic");
  if (!auth?.token) throw new Error("No Anthropic auth token");

  const config = getProviderConfig("anthropic");
  if (!config) throw new Error("Anthropic provider not configured");
  const resolvedBaseUrl = baseUrl ?? endpointsOf(config)[0];
  const { system: systemContent, messages } = convertMessagesToAnthropic(req.messages);

  const isOAuth = auth.token!.startsWith("sk-ant-oat");
  const thinkingConfig = getThinkingConfig(tier, modelName);
  const maxTokens = req.max_tokens ?? 4096;

  const body: Record<string, unknown> = {
    model: modelName,
    messages,
    max_tokens: (thinkingConfig?.type === "enabled" && thinkingConfig.budget_tokens) ? maxTokens + thinkingConfig.budget_tokens : maxTokens,
    stream: stream,
  };

  // Add tools if present
  if (req.tools && req.tools.length > 0) {
    body.tools = convertToolsToAnthropic(req.tools);
    if (req.tool_choice !== undefined) {
      body.tool_choice = convertToolChoiceToAnthropic(req.tool_choice);
    }
  }

  // System prompt
  if (isOAuth) {
    const systemBlocks: Array<{ type: string; text: string; cache_control?: { type: string } }> = [
      {
        type: "text",
        text: "You are Claude Code, Anthropic\'s official CLI for Claude.",
        cache_control: { type: "ephemeral" },
      },
    ];
    if (systemContent) {
      systemBlocks.push({ type: "text", text: systemContent, cache_control: { type: "ephemeral" } });
    }
    body.system = systemBlocks;
  } else if (systemContent) {
    body.system = systemContent;
  }

  if (thinkingConfig) {
    if (thinkingConfig.type === "adaptive") {
      body.thinking = { type: "adaptive" };
    } else {
      body.thinking = { type: "enabled", budget_tokens: thinkingConfig.budget_tokens };
    }
  }

  if (req.temperature !== undefined && !thinkingConfig) {
    body.temperature = req.temperature;
  }

  const url = `${resolvedBaseUrl}/v1/messages`;
  const timeoutMs = getTierTimeout(tier);
  logger.info(`-> Anthropic: ${modelName} (tier=${tier}, thinking=${thinkingConfig?.type ?? "off"}, stream=${stream}, tools=${req.tools?.length ?? 0}, timeout=${timeoutMs / 1000}s)`);

  const authHeaders: Record<string, string> = {
    "Content-Type": "application/json",
    "anthropic-version": "2023-06-01",
    "accept": "application/json",
  };

  if (isOAuth) {
    authHeaders["Authorization"] = `Bearer ${auth.token}`;
    authHeaders["anthropic-beta"] = "claude-code-20250219,oauth-2025-04-20,fine-grained-tool-streaming-2025-05-14,interleaved-thinking-2025-05-14";
    authHeaders["user-agent"] = "claude-cli/2.1.2 (external, cli)";
    authHeaders["x-app"] = "cli";
    authHeaders["anthropic-dangerous-direct-browser-access"] = "true";
  } else {
    authHeaders["x-api-key"] = auth.token!;
  }

  // Timeout via AbortController
  const abortController = new AbortController();
  const timeoutId = setTimeout(() => abortController.abort(), timeoutMs);

  let response: Response;
  try {
    response = await fetch(url, {
      method: "POST",
      headers: authHeaders,
      body: JSON.stringify(body),
      signal: abortController.signal,
    });
  } catch (err: any) {
    clearTimeout(timeoutId);
    if (err?.name === "AbortError" || abortController.signal.aborted) {
      logger.error(`\u23f1 TIMEOUT: Anthropic ${modelName} after ${timeoutMs / 1000}s (tier=${tier})`);
      throw new TimeoutError(`Anthropic request timed out after ${timeoutMs / 1000}s (model=${modelName}, tier=${tier})`);
    }
    throw err;
  }

  if (!response.ok) {
    clearTimeout(timeoutId);
    const errText = await response.text();
    logger.error(`Anthropic ${response.status}: ${errText}`);
    throw new UpstreamError(`Anthropic API error ${response.status}: ${errText}`, response.status, "anthropic");
  }

  if (!stream) {
    clearTimeout(timeoutId);
    const data = await response.json() as {
      content: Array<{ type: string; text?: string; thinking?: string; id?: string; name?: string; input?: unknown }>;
      usage?: {
        input_tokens: number;
        output_tokens: number;
        cache_read_input_tokens?: number;
        cache_creation_input_tokens?: number;
      };
      model: string;
      stop_reason?: string;
    };

    const textContent = data.content
      .filter((b) => b.type === "text")
      .map((b) => b.text ?? "")
      .join("");

    // Convert tool_use blocks to OpenAI tool_calls
    const toolUseBlocks = data.content.filter((b) => b.type === "tool_use");
    const toolCalls: OpenAIToolCall[] = toolUseBlocks.map((b, idx) => ({
      id: b.id ?? `call_${Date.now()}_${idx}`,
      type: "function" as const,
      function: { name: b.name ?? "", arguments: JSON.stringify(b.input ?? {}) },
    }));

    const finishReason = data.stop_reason === "tool_use" ? "tool_calls"
      : data.stop_reason === "end_turn" ? "stop"
      : (data.stop_reason ?? "stop");

    const message: Record<string, unknown> = {
      role: "assistant",
      content: textContent || (toolCalls.length > 0 ? null : ""),
    };
    if (toolCalls.length > 0) message.tool_calls = toolCalls;

    const openaiResponse = {
      id: `chatcmpl-${Date.now()}`,
      object: "chat.completion",
      created: Math.floor(Date.now() / 1000),
      model: `secrouter/${modelName}`,
      choices: [{ index: 0, message, finish_reason: finishReason }],
      usage: {
        prompt_tokens: data.usage?.input_tokens ?? 0,
        completion_tokens: data.usage?.output_tokens ?? 0,
        total_tokens: (data.usage?.input_tokens ?? 0) + (data.usage?.output_tokens ?? 0),
      },
    };

    res.writeHead(200, { "Content-Type": "application/json" });
    res.end(JSON.stringify(openaiResponse));
    return {
      provider: "anthropic",
      model: modelName,
      inputTokens: data.usage?.input_tokens ?? 0,
      outputTokens: data.usage?.output_tokens ?? 0,
      cacheReadTokens: data.usage?.cache_read_input_tokens ?? 0,
      cacheWriteTokens: data.usage?.cache_creation_input_tokens ?? 0,
    };
  }

  // Streaming: convert Anthropic SSE to OpenAI SSE format
  res.writeHead(200, {
    "Content-Type": "text/event-stream",
    "Cache-Control": "no-cache",
    "Connection": "keep-alive",
  });

  clearTimeout(timeoutId); // Stall detection takes over for streaming
  const reader = response.body?.getReader();
  if (!reader) throw new Error("No response body");

  const decoder = new TextDecoder();
  let buffer = "";
  let insideThinking = false;
  // Track tool_use streaming state
  let currentBlockType: string | null = null;
  let currentToolIndex = -1;
  let stopReason: string | null = null;
  // Token accounting — Anthropic reports input/cache in message_start and the
  // final cumulative output_tokens in message_delta.
  const usage = zeroUsage("anthropic", modelName);

  const makeChunk = (delta: Record<string, unknown>, finish: string | null = null) => ({
    id: `chatcmpl-${Date.now()}`,
    object: "chat.completion.chunk",
    created: Math.floor(Date.now() / 1000),
    model: `secrouter/${modelName}`,
    choices: [{ index: 0, delta, finish_reason: finish }],
  });

  try {
    await readStreamWithStallDetection(reader, (value) => {
      buffer += decoder.decode(value, { stream: true });
      const lines = buffer.split("\n");
      buffer = lines.pop() ?? "";

      for (const line of lines) {
        if (!line.startsWith("data: ")) continue;
        const jsonStr = line.slice(6).trim();
        if (jsonStr === "[DONE]" || !jsonStr) continue;

        try {
          const event = JSON.parse(jsonStr);

          if (event.type === "message_start") {
            const u = event.message?.usage;
            if (u) {
              usage.inputTokens = u.input_tokens ?? 0;
              usage.cacheReadTokens = u.cache_read_input_tokens ?? 0;
              usage.cacheWriteTokens = u.cache_creation_input_tokens ?? 0;
              usage.outputTokens = u.output_tokens ?? usage.outputTokens;
            }
            continue;
          }

          if (event.type === "content_block_start") {
            const block = event.content_block;
            if (block?.type === "thinking") {
              insideThinking = true;
              currentBlockType = "thinking";
            } else if (block?.type === "tool_use") {
              insideThinking = false;
              currentBlockType = "tool_use";
              currentToolIndex++;
              // Emit first tool_calls chunk with id and function name
              const chunk = makeChunk({
                tool_calls: [{
                  index: currentToolIndex,
                  id: block.id,
                  type: "function",
                  function: { name: block.name, arguments: "" },
                }],
              });
              res.write(`data: ${JSON.stringify(chunk)}\n\n`);
            } else {
              insideThinking = false;
              currentBlockType = block?.type ?? "text";
            }
            continue;
          }

          if (event.type === "content_block_stop") {
            insideThinking = false;
            currentBlockType = null;
            continue;
          }

          if (event.type === "content_block_delta") {
            if (insideThinking) continue;

            // Handle tool_use argument streaming
            if (currentBlockType === "tool_use" && event.delta?.type === "input_json_delta") {
              const chunk = makeChunk({
                tool_calls: [{
                  index: currentToolIndex,
                  function: { arguments: event.delta.partial_json ?? "" },
                }],
              });
              res.write(`data: ${JSON.stringify(chunk)}\n\n`);
              continue;
            }

            // Regular text delta
            const text = event.delta?.text;
            if (text) {
              res.write(`data: ${JSON.stringify(makeChunk({ content: text }))}\n\n`);
            }
          }

          if (event.type === "message_delta") {
            stopReason = event.delta?.stop_reason ?? null;
            if (event.usage?.output_tokens != null) usage.outputTokens = event.usage.output_tokens;
            if (event.usage?.input_tokens != null) usage.inputTokens = event.usage.input_tokens;
          }

          if (event.type === "message_stop") {
            const finish = stopReason === "tool_use" ? "tool_calls" : "stop";
            res.write(`data: ${JSON.stringify(makeChunk({}, finish))}\n\n`);
          }
        } catch {
          // skip unparseable lines
        }
      }
    }, abortController);
  } catch (err) {
    if (err instanceof TimeoutError) {
      logger.error(`\u23f1 STREAM STALL: Anthropic ${modelName} - ${(err as Error).message}`);
    }
    throw err;
  } finally {
    res.write("data: [DONE]\n\n");
    res.end();
  }
  return usage;
}

/**
 * Forward a chat request to OpenAI-compatible API (Kimi), streaming back as-is.
 */
/**
 * Build the OpenAI-compatible upstream request body from a client ChatRequest.
 * Extracted + exported so the forwarded-field allow-list is unit-testable: a
 * field silently dropped here is a capability silently broken for EVERY
 * OpenAI-compatible backend (MLX/vLLM/Ollama/TGI/Bedrock-openai/Azure). In
 * particular `tools`/`tool_choice` must be forwarded verbatim (the upstream is
 * already OpenAI-shaped — no Anthropic-style conversion) or the model can never
 * emit a structured tool_call and an agentic client just sees it ramble about
 * the tool in prose. The Anthropic path forwards tools too (convertToolsToAnthropic);
 * this keeps the two paths symmetric.
 */
export function buildOpenAIRequestBody(req: ChatRequest, modelName: string, stream: boolean): Record<string, unknown> {
  const body: Record<string, unknown> = {
    model: modelName,
    messages: req.messages,
    stream,
  };
  if (req.max_tokens) body.max_tokens = req.max_tokens;
  if (req.temperature !== undefined) body.temperature = req.temperature;
  if (req.top_p !== undefined) body.top_p = req.top_p;
  if (req.stop !== undefined) body.stop = req.stop;
  if (req.tools && req.tools.length > 0) {
    body.tools = req.tools;
    if (req.tool_choice !== undefined) body.tool_choice = req.tool_choice;
  }
  // Ask the upstream to include token usage in the final streaming chunk,
  // otherwise per-user accounting would silently record zero for streamed calls.
  if (stream) body.stream_options = { include_usage: true };
  return body;
}

async function forwardToOpenAI(
  req: ChatRequest,
  provider: string,
  modelName: string,
  tier: string,
  res: ServerResponse,
  stream: boolean,
  traceparent?: string,
  baseUrl?: string,
): Promise<UsageResult> {
  const config = getProviderConfig(provider);
  if (!config) throw new Error(`Unknown provider: ${provider}`);
  const resolvedBaseUrl = baseUrl ?? endpointsOf(config)[0];

  // Auth is optional for OpenAI-compatible endpoints: many self-hosted / on-prem
  // servers (vLLM, Ollama, llama.cpp, TGI) require no API key. Send the Bearer
  // header only when one is configured; otherwise let the upstream decide.
  const auth = getAuth(provider);

  const usage = zeroUsage(provider, modelName);
  const body = buildOpenAIRequestBody(req, modelName, stream);

  // Azure OpenAI puts the deployment in the path + an api-version query; other
  // OpenAI-compatible endpoints (incl. Bedrock's /openai/v1) use a flat path.
  const isAzure = config.api === "azure-openai";
  const url = isAzure
    ? `${resolvedBaseUrl.replace(/\/+$/, "")}/openai/deployments/${encodeURIComponent(modelName)}/chat/completions?api-version=${config.apiVersion ?? "2024-10-21"}`
    : `${resolvedBaseUrl}/chat/completions`;
  logger.info(`-> ${provider}: ${modelName} (tier=${tier}, stream=${stream}${isAzure ? ", azure" : ""})`);

  // Auth: Azure uses the `api-key` header or an Entra bearer token; everything
  // else (OpenAI, vLLM/Ollama, Bedrock's /openai/v1) uses `Authorization: Bearer`.
  let authHeaders: Record<string, string> = {};
  if (isAzure && config.azureAuth === "entra") {
    if (!config.entra) throw new Error(`Azure provider '${provider}' uses azureAuth="entra" but has no entra config`);
    authHeaders = { Authorization: `Bearer ${await getEntraToken(provider, config.entra)}` };
  } else if (isAzure) {
    if (auth?.apiKey) authHeaders = { "api-key": auth.apiKey };
  } else if (auth?.apiKey) {
    authHeaders = { Authorization: `Bearer ${auth.apiKey}` };
  }

  const headers: Record<string, string> = {
    "Content-Type": "application/json",
    ...authHeaders,
    ...(traceparent ? { traceparent } : {}),
    ...config.headers,
  };

  const timeoutMs = getTierTimeout(tier);
  const abortController = new AbortController();
  const timeoutId = setTimeout(() => abortController.abort(), timeoutMs);

  let response: Response;
  try {
    response = await fetch(url, {
      method: "POST",
      headers,
      body: JSON.stringify(body),
      signal: abortController.signal,
    });
  } catch (err: any) {
    clearTimeout(timeoutId);
    if (err?.name === "AbortError" || abortController.signal.aborted) {
      logger.error(`\u23f1 TIMEOUT: ${provider} ${modelName} after ${timeoutMs / 1000}s (tier=${tier})`);
      throw new TimeoutError(`${provider} request timed out after ${timeoutMs / 1000}s (model=${modelName}, tier=${tier})`);
    }
    throw err;
  }

  if (!response.ok) {
    clearTimeout(timeoutId);
    const errText = await response.text();
    logger.error(`${provider} ${response.status}: ${errText}`);
    throw new UpstreamError(`${provider} API error ${response.status}: ${errText}`, response.status, provider);
  }

  clearTimeout(timeoutId);

  if (!stream) {
    const data = await response.json() as Record<string, unknown>;
    const u = data.usage as
      | { prompt_tokens?: number; completion_tokens?: number; prompt_tokens_details?: { cached_tokens?: number } }
      | undefined;
    if (u) {
      usage.inputTokens = u.prompt_tokens ?? 0;
      usage.outputTokens = u.completion_tokens ?? 0;
      usage.cacheReadTokens = u.prompt_tokens_details?.cached_tokens ?? 0;
    }
    if (data.model) data.model = `secrouter/${modelName}`;
    res.writeHead(200, { "Content-Type": "application/json" });
    res.end(JSON.stringify(data));
    return usage;
  }

  // Streaming: pass through SSE with model name rewrite
  res.writeHead(200, {
    "Content-Type": "text/event-stream",
    "Cache-Control": "no-cache",
    "Connection": "keep-alive",
  });

  const reader = response.body?.getReader();
  if (!reader) throw new Error("No response body");

  const decoder = new TextDecoder();
  let buffer = "";

  try {
    await readStreamWithStallDetection(reader, (value) => {
      buffer += decoder.decode(value, { stream: true });
      const lines = buffer.split("\n");
      buffer = lines.pop() ?? "";

      for (const line of lines) {
        if (line.startsWith("data: ")) {
          const jsonStr = line.slice(6).trim();
          if (jsonStr === "[DONE]") {
            res.write("data: [DONE]\n\n");
            continue;
          }
          try {
            const chunk = JSON.parse(jsonStr);
            if (chunk.usage) {
              usage.inputTokens = chunk.usage.prompt_tokens ?? usage.inputTokens;
              usage.outputTokens = chunk.usage.completion_tokens ?? usage.outputTokens;
              usage.cacheReadTokens =
                chunk.usage.prompt_tokens_details?.cached_tokens ?? usage.cacheReadTokens;
            }
            if (chunk.model) chunk.model = `secrouter/${modelName}`;
            res.write(`data: ${JSON.stringify(chunk)}\n\n`);
          } catch {
            res.write(line + "\n");
          }
        } else if (line.trim()) {
          res.write(line + "\n");
        } else {
          res.write("\n");
        }
      }
    }, abortController);
  } catch (err) {
    if (err instanceof TimeoutError) {
      logger.error(`\u23f1 STREAM STALL: ${provider} ${modelName} - ${(err as Error).message}`);
    }
    throw err;
  } finally {
    if (!res.writableEnded) {
      res.write("data: [DONE]\n\n");
      res.end();
    }
  }
  return usage;
}

/** Convert an Anthropic Messages JSON response into an OpenAI chat.completion + usage. */
function buildOpenAIFromAnthropic(
  data: {
    content: Array<{ type: string; text?: string; id?: string; name?: string; input?: unknown }>;
    usage?: {
      input_tokens?: number;
      output_tokens?: number;
      cache_read_input_tokens?: number;
      cache_creation_input_tokens?: number;
    };
    stop_reason?: string;
  },
  modelLabel: string,
  provider: string,
  modelName: string,
): { response: Record<string, unknown>; usage: UsageResult } {
  const textContent = data.content.filter((b) => b.type === "text").map((b) => b.text ?? "").join("");
  const toolCalls: OpenAIToolCall[] = data.content
    .filter((b) => b.type === "tool_use")
    .map((b, idx) => ({
      id: b.id ?? `call_${Date.now()}_${idx}`,
      type: "function" as const,
      function: { name: b.name ?? "", arguments: JSON.stringify(b.input ?? {}) },
    }));
  const finishReason =
    data.stop_reason === "tool_use" ? "tool_calls" : data.stop_reason === "end_turn" ? "stop" : data.stop_reason ?? "stop";
  const message: Record<string, unknown> = { role: "assistant", content: textContent || (toolCalls.length > 0 ? null : "") };
  if (toolCalls.length > 0) message.tool_calls = toolCalls;
  const usage: UsageResult = {
    provider,
    model: modelName,
    inputTokens: data.usage?.input_tokens ?? 0,
    outputTokens: data.usage?.output_tokens ?? 0,
    cacheReadTokens: data.usage?.cache_read_input_tokens ?? 0,
    cacheWriteTokens: data.usage?.cache_creation_input_tokens ?? 0,
  };
  const response = {
    id: `chatcmpl-${Date.now()}`,
    object: "chat.completion",
    created: Math.floor(Date.now() / 1000),
    model: modelLabel,
    choices: [{ index: 0, message, finish_reason: finishReason }],
    usage: {
      prompt_tokens: usage.inputTokens,
      completion_tokens: usage.outputTokens,
      total_tokens: usage.inputTokens + usage.outputTokens,
    },
  };
  return { response, usage };
}

/**
 * Forward to Claude on Amazon Bedrock (AWS GovCloud) — the FedRAMP High / IL4-5
 * authorized path for CUI. Uses SigV4-signed InvokeModel. Bedrock streams via a
 * binary event-stream; to keep token accounting exact and avoid an unverified
 * binary parser, we invoke non-streaming and (when the client asked for stream)
 * re-emit the complete response as SSE. Credentials come from the standard AWS
 * environment (IAM role / instance profile in GovCloud).
 */
async function forwardToBedrock(
  req: ChatRequest,
  provider: string,
  modelName: string,
  tier: string,
  res: ServerResponse,
  stream: boolean,
  baseUrl?: string,
): Promise<UsageResult> {
  const config = getProviderConfig(provider);
  if (!config) throw new Error(`Unknown provider: ${provider}`);
  const region = config.region ?? process.env.AWS_REGION ?? "us-gov-west-1";
  const accessKeyId = process.env.AWS_ACCESS_KEY_ID;
  const secretAccessKey = process.env.AWS_SECRET_ACCESS_KEY;
  const sessionToken = process.env.AWS_SESSION_TOKEN;
  if (!accessKeyId || !secretAccessKey) {
    throw new Error("Bedrock requires AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY in the environment");
  }

  const { system: systemContent, messages } = convertMessagesToAnthropic(req.messages);
  const thinkingConfig = getThinkingConfig(tier, modelName);
  const maxTokens = req.max_tokens ?? 4096;

  const body: Record<string, unknown> = {
    anthropic_version: "bedrock-2023-05-31",
    messages,
    max_tokens:
      thinkingConfig?.type === "enabled" && thinkingConfig.budget_tokens
        ? maxTokens + thinkingConfig.budget_tokens
        : maxTokens,
  };
  if (systemContent) body.system = systemContent;
  if (req.tools && req.tools.length > 0) {
    body.tools = convertToolsToAnthropic(req.tools);
    if (req.tool_choice !== undefined) body.tool_choice = convertToolChoiceToAnthropic(req.tool_choice);
  }
  if (thinkingConfig) {
    body.thinking =
      thinkingConfig.type === "adaptive"
        ? { type: "adaptive" }
        : { type: "enabled", budget_tokens: thinkingConfig.budget_tokens };
  }
  if (req.temperature !== undefined && !thinkingConfig) body.temperature = req.temperature;

  const resolvedBaseUrl = (baseUrl ?? endpointsOf(config)[0]).replace(/\/$/, "");
  const url = `${resolvedBaseUrl}/model/${encodeURIComponent(modelName)}/invoke`;
  const bodyStr = JSON.stringify(body);
  const signedHeaders = signRequest({
    method: "POST",
    url,
    region,
    service: "bedrock",
    accessKeyId,
    secretAccessKey,
    sessionToken,
    headers: { "content-type": "application/json", accept: "application/json" },
    body: bodyStr,
  });

  const timeoutMs = getTierTimeout(tier);
  const abortController = new AbortController();
  const timeoutId = setTimeout(() => abortController.abort(), timeoutMs);
  logger.info(`-> bedrock(${region}): ${modelName} (tier=${tier}, clientStream=${stream}, timeout=${timeoutMs / 1000}s)`);

  let response: Response;
  try {
    response = await fetch(url, {
      method: "POST",
      headers: { ...signedHeaders, "Content-Type": "application/json", accept: "application/json" },
      body: bodyStr,
      signal: abortController.signal,
    });
  } catch (err: any) {
    clearTimeout(timeoutId);
    if (err?.name === "AbortError" || abortController.signal.aborted) {
      throw new TimeoutError(`Bedrock request timed out after ${timeoutMs / 1000}s (model=${modelName})`);
    }
    throw err;
  }
  clearTimeout(timeoutId);
  if (!response.ok) {
    const errText = await response.text();
    logger.error(`Bedrock ${response.status}: ${errText}`);
    throw new UpstreamError(`Bedrock API error ${response.status}: ${errText}`, response.status, provider);
  }

  const data = (await response.json()) as Parameters<typeof buildOpenAIFromAnthropic>[0];
  const { response: openai, usage } = buildOpenAIFromAnthropic(data, `secrouter/${modelName}`, provider, modelName);

  if (!stream) {
    res.writeHead(200, { "Content-Type": "application/json" });
    res.end(JSON.stringify(openai));
    return usage;
  }

  // Buffered → SSE re-emit for streaming clients.
  res.writeHead(200, { "Content-Type": "text/event-stream", "Cache-Control": "no-cache", Connection: "keep-alive" });
  const choice = (openai.choices as Array<{ message: Record<string, unknown>; finish_reason: string }>)[0];
  const msg = choice.message;
  const mk = (delta: Record<string, unknown>, finish: string | null = null) =>
    `data: ${JSON.stringify({
      id: openai.id,
      object: "chat.completion.chunk",
      created: openai.created,
      model: openai.model,
      choices: [{ index: 0, delta, finish_reason: finish }],
    })}\n\n`;
  res.write(mk({ role: "assistant" }));
  if (Array.isArray(msg.tool_calls)) {
    (msg.tool_calls as OpenAIToolCall[]).forEach((tc, i) =>
      res.write(mk({ tool_calls: [{ index: i, id: tc.id, type: "function", function: tc.function }] })),
    );
  } else if (msg.content) {
    res.write(mk({ content: msg.content }));
  }
  res.write(mk({}, choice.finish_reason ?? "stop"));
  res.write("data: [DONE]\n\n");
  res.end();
  return usage;
}

/**
 * Forward a chat completion request to the appropriate backend.
 * Returns the token usage so the caller can attribute it to the principal.
 */
/**
 * Resolve a SecLLM tag alias to its real backend model id. When a request explicitly names
 * `secllm/<tag>` (provider "secllm", model a SecLLM catalog tag like "balanced") and the operator
 * remapped that tag via SECROUTER_SECLLM_MODELS (`aliases`), return the mapped id so the literal
 * tag — which a custom pool's catalog doesn't contain — is never forwarded. No-op for any other
 * provider, an unmapped model, or when no remap is configured. Pure + exported for unit testing.
 */
export function resolveSecllmModel(provider: string, model: string, aliases?: Record<string, string>): string {
  if (provider === "secllm" && aliases && Object.prototype.hasOwnProperty.call(aliases, model)) {
    return aliases[model];
  }
  return model;
}

export async function forwardRequest(
  chatReq: ChatRequest,
  routedModel: string,
  tier: string,
  res: ServerResponse,
  stream: boolean,
  classification?: string,
  traceparent?: string,
  /** Which of the provider's endpoints (config.endpointsOf) to use. Defaults to endpoint 0. */
  baseUrl?: string,
): Promise<UsageResult> {
  const { provider, model: requestedModel } = parseModelId(routedModel);
  // Resolve an explicit `secllm/<tag>` request to the real backend id when the operator remapped
  // that tag via SECROUTER_SECLLM_MODELS — so requesting the tag by name (e.g. `secllm/balanced`,
  // as an agentic client pins its model) yields the mapped model. A tier-routed request already
  // carries the real id, so this is a no-op for it.
  const model = resolveSecllmModel(provider, requestedModel, getConfig().secllmModelAliases);

  const providerConfig = getProviderConfig(provider);
  if (!providerConfig) {
    throw new Error(`Unsupported provider: ${provider}`);
  }
  const effectiveBaseUrl = baseUrl ?? endpointsOf(providerConfig)[0];

  // ── Egress deny-by-default + data-residency gate (the network choke point) ──
  // No code path reaches the network without passing this when security is on.
  // Checked against the ACTUAL endpoint this attempt will use, so a
  // multi-endpoint provider's replicas are each subject to their own host rule.
  if (isSecurityEnabled()) {
    const sec = getSecurityConfig()!;
    const host = (() => {
      try {
        return new URL(effectiveBaseUrl).host;
      } catch {
        return effectiveBaseUrl;
      }
    })();
    const dataClass = classification ?? sec.classification?.default ?? "UNCLASSIFIED";
    const decision = checkEgress(provider, host, dataClass, sec);
    if (!decision.allowed) {
      logger.error(`⛔ EGRESS DENIED: ${provider} (${host}) — ${decision.reason}`);
      throw new EgressDeniedError(decision.reason, provider);
    }
  }

  if (providerConfig.api === "anthropic-messages") {
    return forwardToAnthropic(chatReq, model, tier, res, stream, effectiveBaseUrl);
  }
  if (providerConfig.api === "bedrock-runtime") {
    return forwardToBedrock(chatReq, provider, model, tier, res, stream, effectiveBaseUrl);
  }
  return forwardToOpenAI(chatReq, provider, model, tier, res, stream, traceparent, effectiveBaseUrl);
}

/**
 * Forward an embeddings request. Runs the same egress deny-by-default +
 * data-residency gate as chat (embedding an input still sends content out), then
 * forwards to an OpenAI-compatible upstream (Bedrock Titan/Cohere embed is a
 * later phase). Returns usage so the caller attributes cost.
 */
export async function forwardEmbeddingsRequest(
  routedModel: string,
  body: Record<string, unknown>,
  res: ServerResponse,
  classification?: string,
  traceparent?: string,
): Promise<UsageResult> {
  const { provider, model } = parseModelId(routedModel);
  const providerConfig = getProviderConfig(provider);
  if (!providerConfig) throw new Error(`Unsupported provider: ${provider}`);
  // Embeddings don't load-balance across endpoints (yet) — always endpoint 0.
  const embeddingsBaseUrl = endpointsOf(providerConfig)[0];

  if (isSecurityEnabled()) {
    const sec = getSecurityConfig()!;
    const host = (() => {
      try {
        return new URL(embeddingsBaseUrl).host;
      } catch {
        return embeddingsBaseUrl;
      }
    })();
    const dataClass = classification ?? sec.classification?.default ?? "UNCLASSIFIED";
    const decision = checkEgress(provider, host, dataClass, sec);
    if (!decision.allowed) {
      logger.error(`⛔ EGRESS DENIED (embeddings): ${provider} (${host}) — ${decision.reason}`);
      throw new EgressDeniedError(decision.reason, provider);
    }
  }

  const isAzure = providerConfig.api === "azure-openai";
  if (providerConfig.api !== "openai-completions" && !isAzure) {
    throw new Error(`Embeddings are only supported on OpenAI-compatible providers for now (got '${providerConfig.api}')`);
  }

  const auth = getAuth(provider);
  const url = isAzure
    ? `${embeddingsBaseUrl.replace(/\/+$/, "")}/openai/deployments/${encodeURIComponent(model)}/embeddings?api-version=${providerConfig.apiVersion ?? "2024-10-21"}`
    : `${embeddingsBaseUrl}/embeddings`;
  let authHeaders: Record<string, string> = {};
  if (isAzure && providerConfig.azureAuth === "entra") {
    if (!providerConfig.entra) throw new Error(`Azure provider '${provider}' uses azureAuth="entra" but has no entra config`);
    authHeaders = { Authorization: `Bearer ${await getEntraToken(provider, providerConfig.entra)}` };
  } else if (isAzure) {
    if (auth?.apiKey) authHeaders = { "api-key": auth.apiKey };
  } else if (auth?.apiKey) {
    authHeaders = { Authorization: `Bearer ${auth.apiKey}` };
  }
  const headers: Record<string, string> = {
    "Content-Type": "application/json",
    ...authHeaders,
    ...(traceparent ? { traceparent } : {}),
    ...providerConfig.headers,
  };
  const payload = { ...body, model }; // send the upstream model name (provider prefix stripped)

  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), 30_000);
  let response: Response;
  try {
    response = await fetch(url, { method: "POST", headers, body: JSON.stringify(payload), signal: controller.signal });
  } catch (err) {
    clearTimeout(timeoutId);
    if (err instanceof Error && err.name === "AbortError") throw new TimeoutError(`Embeddings request to ${provider} timed out`);
    throw err;
  }
  clearTimeout(timeoutId);

  if (!response.ok) {
    const text = await response.text().catch(() => "");
    throw new UpstreamError(`Embeddings upstream ${response.status}: ${text.slice(0, 200)}`, response.status, provider);
  }
  const json = (await response.json()) as { usage?: { prompt_tokens?: number } };
  res.writeHead(200, { "Content-Type": "application/json" });
  res.end(JSON.stringify(json));

  const usage = zeroUsage(provider, model);
  usage.inputTokens = json.usage?.prompt_tokens ?? 0;
  return usage;
}