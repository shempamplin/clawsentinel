/**
 * ClawSentinel — Memory HTTP API Routes
 * New file: src/memory/sentinel-memory-routes.ts
 *
 * Mounts under /api/clawsentinel/memory/
 *
 * Routes:
 *   POST   /recall          — retrieve relevant memories for a query
 *   POST   /write           — store a new memory
 *   POST   /bulk-write      — store multiple memories (used by flush hook)
 *   DELETE /:id             — delete a specific memory
 *   GET    /stats           — memory statistics for an agent
 *   POST   /flush-prompt    — generate the pre-compaction flush prompt
 *   DELETE /agent/:agentId  — clear all memories for an agent
 */

import type { IncomingMessage, ServerResponse } from "node:http";
import { createSubsystemLogger } from "../logging/subsystem.js";
import { getSentinelMemory } from "./sentinel-memory.js";
import type { MemoryType, WriteMemoryParams, TrustSource } from "./sentinel-memory.js";
import { redactLogMessage } from "../security/sentinel-hardening.js";

const log = createSubsystemLogger("sentinel-memory-routes");

function readJson(req: IncomingMessage): Promise<unknown> {
  return new Promise((resolve, reject) => {
    let body = "";
    req.on("data", (chunk) => { body += chunk; });
    req.on("end", () => {
      try { resolve(JSON.parse(body)); }
      catch (e) { reject(new Error("Invalid JSON")); }
    });
    req.on("error", reject);
  });
}

function json(res: ServerResponse, status: number, data: unknown): void {
  const body = JSON.stringify(data);
  res.writeHead(status, {
    "Content-Type": "application/json",
    "Content-Length": Buffer.byteLength(body),
    "Cache-Control": "no-store",
  });
  res.end(body);
}

function err(res: ServerResponse, status: number, message: string): void {
  json(res, status, { error: message });
}

// ─── Route handler ────────────────────────────────────────────────────────────

export function handleMemoryRoute(
  req: IncomingMessage,
  res: ServerResponse,
  subpath: string,
): boolean {
  const method = req.method ?? "GET";
  const memory = getSentinelMemory();

  // POST /recall
  if (method === "POST" && subpath === "/recall") {
    readJson(req).then((body) => {
      const b = body as Record<string, unknown>;
      if (!b.agentId || !b.query) return err(res, 400, "agentId and query required");

      const result = memory.recall({
        agentId: String(b.agentId),
        userId: b.userId ? String(b.userId) : undefined,
        query: String(b.query),
        limit: b.limit ? Number(b.limit) : undefined,
        tokenBudget: b.tokenBudget ? Number(b.tokenBudget) : undefined,
        includeTypes: b.includeTypes as MemoryType[] | undefined,
        minImportance: b.minImportance ? Number(b.minImportance) : undefined,
      });

      json(res, 200, { ok: true, ...result });
    }).catch((e) => err(res, 400, String(e)));
    return true;
  }

  // POST /write
  if (method === "POST" && subpath === "/write") {
    readJson(req).then((body) => {
      const b = body as Record<string, unknown>;
      if (!b.agentId || !b.type || !b.content || !b.sessionId) {
        return err(res, 400, "agentId, type, content, sessionId required");
      }

      const VALID_TYPES: MemoryType[] = ["fact", "decision", "preference", "entity", "procedure", "event"];
      if (!VALID_TYPES.includes(b.type as MemoryType)) {
        return err(res, 400, `type must be one of: ${VALID_TYPES.join(", ")}`);
      }

      // OPEN-016: Map route context to validated TrustSource (Gemini 20260308-006-GEMINI)
      // Callers pass an optional `source` field. We map known values to trusted sources;
      // everything else (including skills calling this API) defaults to "skill-api".
      // The write() method enforces a ceiling — only INTERNAL_SOURCES can claim high trust —
      // so even if a skill passes "manual-ui" here, it will be demoted at the write layer.
      const SOURCE_MAP: Record<string, TrustSource> = {
        "manual-ui":         "manual",           // Shem writing via Memory UI tab
        "compaction-flush":  "flush-unverified", // Pre-compaction flush (single pass)
        "flush-verified":    "flush-verified",   // Pre-compaction flush (agent confirmed)
        "agent-auto":        "agent-auto",        // Agent writing during normal conversation
        "diagnostic-system": "system",           // ClawSentinel internal diagnostics
      };
      const trustSource: TrustSource = SOURCE_MAP[String(b.source ?? "")] ?? "skill-api";

      const written = memory.write({
        agentId: String(b.agentId),
        userId: b.userId ? String(b.userId) : undefined,
        type: b.type as MemoryType,
        content: String(b.content),
        tags: Array.isArray(b.tags) ? b.tags.map(String) : undefined,
        importance: b.importance ? Number(b.importance) : undefined,
        sessionId: String(b.sessionId),
        expiresAt: b.expiresAt ? Number(b.expiresAt) : undefined,
        sensitive: b.sensitive === true,
        trustSource,
      });

      log.info(`route:write agent=${b.agentId} type=${b.type} trust=${trustSource}`);
      json(res, 201, { ok: true, memory: written });
    }).catch((e) => err(res, 400, String(e)));
    return true;
  }

  // POST /bulk-write
  if (method === "POST" && subpath === "/bulk-write") {
    readJson(req).then((body) => {
      const b = body as Record<string, unknown>;
      if (!Array.isArray(b.memories)) return err(res, 400, "memories array required");

      // Bulk writes from compaction flush pass trustSource on each entry.
      // If not provided, write() defaults to "flush-unverified" for bulk operations.
      const result = memory.bulkWrite(b.memories as WriteMemoryParams[]);
      log.info(`route:bulk-write written=${result.written} skipped=${result.skipped}`);
      json(res, 200, { ok: true, ...result });
    }).catch((e) => err(res, 400, String(e)));
    return true;
  }

  // POST /flush-prompt
  if (method === "POST" && subpath === "/flush-prompt") {
    readJson(req).then((body) => {
      const b = body as Record<string, unknown>;
      if (!b.agentId || !b.sessionId) return err(res, 400, "agentId and sessionId required");

      const prompt = memory.buildFlushPrompt(String(b.agentId), String(b.sessionId));
      json(res, 200, { ok: true, prompt });
    }).catch((e) => err(res, 400, String(e)));
    return true;
  }

  // GET /stats?agentId=...
  if (method === "GET" && subpath === "/stats") {
    const url = new URL(req.url ?? "/", "http://localhost");
    const agentId = url.searchParams.get("agentId");
    if (!agentId) return (err(res, 400, "agentId required"), true);

    const stats = memory.stats(agentId);
    json(res, 200, { ok: true, stats });
    return true;
  }

  // DELETE /agent/:agentId
  const agentClearMatch = subpath.match(/^\/agent\/([^/]+)$/);
  if (method === "DELETE" && agentClearMatch) {
    const agentId = decodeURIComponent(agentClearMatch[1]!);
    const deleted = memory.clearAgent(agentId);
    log.info(`route:clear-agent agent=${agentId} deleted=${deleted}`);
    json(res, 200, { ok: true, deleted });
    return true;
  }

  // DELETE /:id?agentId=...
  const deleteMatch = subpath.match(/^\/([a-f0-9\-]{36})$/);
  if (method === "DELETE" && deleteMatch) {
    const url = new URL(req.url ?? "/", "http://localhost");
    const agentId = url.searchParams.get("agentId");
    if (!agentId) return (err(res, 400, "agentId required"), true);

    const deleted = memory.delete(deleteMatch[1]!, agentId);
    json(res, deleted ? 200 : 404, { ok: deleted });
    return true;
  }

  return false; // route not matched
}