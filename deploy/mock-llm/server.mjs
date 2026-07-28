/**
 * Mock OpenAI-compatible model for the SecRouter TEST stack — echoes the prompt
 * and returns realistic token usage so per-user accounting works. Zero deps.
 *   POST /v1/chat/completions   (stream + non-stream; honors stream_options.include_usage)
 *   GET  /v1/models             (OpenAI-style list — used by the admin add-endpoint probe)
 * Env: PORT (8080).
 */
import { createServer } from "node:http";

const PORT = parseInt(process.env.PORT ?? "8080", 10);
const toks = (s) => Math.max(1, Math.ceil((s || "").length / 4));

function readBody(req) {
  return new Promise((r) => { let d = ""; req.on("data", (c) => (d += c)); req.on("end", () => r(d)); });
}

const server = createServer(async (req, res) => {
  // Model discovery for the admin "add endpoint" wizard (OpenAI /v1/models shape).
  if (req.method === "GET" && req.url.endsWith("/models")) {
    res.writeHead(200, { "Content-Type": "application/json" });
    return res.end(JSON.stringify({
      object: "list",
      data: [
        { id: "mock-model", object: "model", owned_by: "mock" },
        { id: "mock-model-mini", object: "model", owned_by: "mock" },
      ],
    }));
  }
  // Embeddings (deterministic vectors + token usage) for the governed /v1/embeddings path.
  if (req.method === "POST" && req.url.endsWith("/embeddings")) {
    const b = JSON.parse((await readBody(req)) || "{}");
    const inputs = Array.isArray(b.input) ? b.input : [b.input];
    const prompt_tokens = inputs.reduce((n, s) => n + toks(typeof s === "string" ? s : JSON.stringify(s)), 0);
    const data = inputs.map((s, i) => {
      const str = typeof s === "string" ? s : JSON.stringify(s || "");
      const embedding = Array.from({ length: 8 }, (_, d) => Number((((str.charCodeAt(d % Math.max(str.length, 1)) || 0) % 100) / 100).toFixed(4)));
      return { object: "embedding", index: i, embedding };
    });
    res.writeHead(200, { "Content-Type": "application/json" });
    return res.end(JSON.stringify({ object: "list", data, model: b.model || "mock-embed", usage: { prompt_tokens, total_tokens: prompt_tokens } }));
  }
  if (!req.url.endsWith("/chat/completions") || req.method !== "POST") {
    res.writeHead(404, { "Content-Type": "application/json" });
    return res.end(JSON.stringify({ error: "not_found" }));
  }
  const body = JSON.parse((await readBody(req)) || "{}");
  const model = body.model || "mock-model";
  const lastUser = [...(body.messages || [])].reverse().find((m) => m.role === "user");
  const prompt = typeof lastUser?.content === "string" ? lastUser.content : JSON.stringify(lastUser?.content ?? "");
  const reply = `[mock-llm] received ${prompt.length} chars. This is a canned test response from SecRouter's mock model.`;
  const promptTokens = (body.messages || []).reduce((n, m) => n + toks(typeof m.content === "string" ? m.content : JSON.stringify(m.content)), 0);
  const completionTokens = toks(reply);
  const id = "chatcmpl-mock-" + Math.floor(Math.random() * 1e9).toString(36);
  const created = Math.floor(Date.now() / 1000);

  if (!body.stream) {
    res.writeHead(200, { "Content-Type": "application/json" });
    return res.end(JSON.stringify({
      id, object: "chat.completion", created, model,
      choices: [{ index: 0, message: { role: "assistant", content: reply }, finish_reason: "stop" }],
      usage: { prompt_tokens: promptTokens, completion_tokens: completionTokens, total_tokens: promptTokens + completionTokens },
    }));
  }

  res.writeHead(200, { "Content-Type": "text/event-stream", "Cache-Control": "no-cache", Connection: "keep-alive" });
  const chunk = (delta, finish = null, extra = {}) =>
    res.write(`data: ${JSON.stringify({ id, object: "chat.completion.chunk", created, model, choices: finish !== undefined && delta === null ? [] : [{ index: 0, delta, finish_reason: finish }], ...extra })}\n\n`);
  chunk({ role: "assistant" });
  for (const word of reply.split(" ")) chunk({ content: word + " " });
  chunk({}, "stop");
  // Final usage chunk (requested via stream_options.include_usage).
  res.write(`data: ${JSON.stringify({ id, object: "chat.completion.chunk", created, model, choices: [], usage: { prompt_tokens: promptTokens, completion_tokens: completionTokens, total_tokens: promptTokens + completionTokens } })}\n\n`);
  res.write("data: [DONE]\n\n");
  res.end();
});

server.listen(PORT, () => console.log(`[mock-llm] listening on :${PORT}`));
