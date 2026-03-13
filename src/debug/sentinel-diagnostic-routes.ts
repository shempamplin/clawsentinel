/**
 * ClawSentinel — Diagnostics Gateway Routes
 * New file: src/debug/sentinel-diagnostic-routes.ts
 *
 * Registers HTTP routes for the diagnostics system:
 *
 *   GET  /api/clawsentinel/diagnostics/events     — recent error log
 *   GET  /api/clawsentinel/diagnostics/profile    — last scan performance profile
 *   POST /api/clawsentinel/diagnostics/test-rule  — test a rule against a snippet
 *   POST /api/clawsentinel/diagnostics/self-test  — run the full self-test suite
 *   GET  /api/clawsentinel/diagnostics/bug-report — build + download bug report JSON
 *   POST /api/clawsentinel/diagnostics/clear-log  — clear the event log
 */

import type { Express, Request, Response } from "express";
import {
  getRecentEvents,
  getLastScanProfile,
  getActiveScanProfile,
  testRule,
  runSelfTests,
  buildBugReport,
  clearEventLog,
  logDiagnosticEvent,
  getAllRuleMetadata,
  SELF_TEST_CASES,
  type DiagnosticLevel,
} from "./sentinel-diagnostics.js";

export function registerDiagnosticRoutes(app: Express): void {
  // ── GET /api/clawsentinel/diagnostics/events ─────────────────────────────
  app.get("/api/clawsentinel/diagnostics/events", (req: Request, res: Response) => {
    const level = (req.query["level"] as DiagnosticLevel | undefined) ?? "info";
    const subsystem = req.query["subsystem"] as string | undefined;
    const limit = Math.min(parseInt((req.query["limit"] as string) ?? "100", 10), 500);

    try {
      const events = getRecentEvents({ level, subsystem, limit });
      res.json({ events, total: events.length });
    } catch (err) {
      res.status(500).json({ error: String(err) });
    }
  });

  // ── GET /api/clawsentinel/diagnostics/profile ────────────────────────────
  app.get("/api/clawsentinel/diagnostics/profile", (_req: Request, res: Response) => {
    try {
      const active = getActiveScanProfile();
      const last = getLastScanProfile();
      res.json({
        active: active
          ? { ...active, status: "running" }
          : null,
        last: last
          ? { ...last, status: "completed" }
          : null,
      });
    } catch (err) {
      res.status(500).json({ error: String(err) });
    }
  });

  // ── POST /api/clawsentinel/diagnostics/test-rule ─────────────────────────
  app.post("/api/clawsentinel/diagnostics/test-rule", async (req: Request, res: Response) => {
    const { ruleId, input, context } = req.body as {
      ruleId: string;
      input: string;
      context?: string;
    };

    if (!ruleId || typeof input !== "string") {
      res.status(400).json({ error: "ruleId and input are required" });
      return;
    }

    const knownRuleIds = getAllRuleMetadata().map((r) => r.ruleId);
    if (!knownRuleIds.includes(ruleId)) {
      res.status(400).json({
        error: `Unknown ruleId: ${ruleId}`,
        availableRules: knownRuleIds,
      });
      return;
    }

    if (input.length > 50_000) {
      res.status(400).json({ error: "Input too large (max 50KB)" });
      return;
    }

    try {
      const result = await testRule(ruleId, input, context);
      res.json(result);
    } catch (err) {
      logDiagnosticEvent("error", "clawsentinel/routes", "test-rule failed", { ruleId }, err);
      res.status(500).json({ error: String(err) });
    }
  });

  // ── POST /api/clawsentinel/diagnostics/self-test ──────────────────────────
  app.post("/api/clawsentinel/diagnostics/self-test", async (_req: Request, res: Response) => {
    try {
      logDiagnosticEvent("info", "clawsentinel/routes", "Self-test initiated via API");
      const report = await runSelfTests(SELF_TEST_CASES);
      res.json(report);
    } catch (err) {
      logDiagnosticEvent("error", "clawsentinel/routes", "Self-test failed", {}, err);
      res.status(500).json({ error: String(err) });
    }
  });

  // ── GET /api/clawsentinel/diagnostics/bug-report ──────────────────────────
  app.get("/api/clawsentinel/diagnostics/bug-report", async (req: Request, res: Response) => {
    const includeRawLogs = req.query["logs"] === "true";
    const includeSelfTest = req.query["selftest"] === "true";
    const logServerUrl = (req.query["logserver"] as string) ?? "";

    try {
      const report = await buildBugReport({
        logServerUrl,
        includeRawLogs,
        includeSelfTest,
      });

      const filename = `clawsentinel-bug-report-${report.id}.json`;
      res.setHeader("Content-Disposition", `attachment; filename="${filename}"`);
      res.setHeader("Content-Type", "application/json");
      res.json(report);
    } catch (err) {
      logDiagnosticEvent("error", "clawsentinel/routes", "Bug report generation failed", {}, err);
      res.status(500).json({ error: String(err) });
    }
  });

  // ── POST /api/clawsentinel/diagnostics/clear-log ──────────────────────────
  app.post("/api/clawsentinel/diagnostics/clear-log", (_req: Request, res: Response) => {
    clearEventLog();
    logDiagnosticEvent("info", "clawsentinel/routes", "Event log cleared via API");
    res.json({ ok: true });
  });

  // ── GET /api/clawsentinel/diagnostics/rules ──────────────────────────────
  app.get("/api/clawsentinel/diagnostics/rules", (_req: Request, res: Response) => {
    try {
      const rules = getAllRuleMetadata();
      res.json({
        rules,
        testCases: SELF_TEST_CASES.map((tc) => ({
          id: tc.id,
          ruleId: tc.ruleId,
          description: tc.description,
          expectMatch: tc.expectMatch,
        })),
      });
    } catch (err) {
      res.status(500).json({ error: String(err) });
    }
  });
}