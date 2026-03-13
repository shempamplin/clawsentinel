/**
 * ClawSentinel — Gateway HTTP Route Handler
 * New file: src/security/sentinel-routes.ts
 *
 * Registers /api/clawsentinel/scan and /api/clawsentinel/remediate
 * as HTTP routes on OpenClaw's gateway server.
 *
 * To wire this in, add to your plugin's register() function:
 *
 *   import { registerSentinelRoutes } from "../../src/security/sentinel-routes.js";
 *   registerSentinelRoutes(api);
 *
 * Or call directly from the gateway server setup.
 */

import path from "node:path";
import fs from "node:fs/promises";
import type { Express, Request, Response } from "express";
import {
  scanDirectoryWithSummary,
  remediateSource,
  getAllRuleMetadata,
  type SkillScanOptions,
  type SkillScanFinding,
} from "./skill-scanner.js";
import { resolveUserPath } from "../utils.js";

export function registerSentinelRoutes(app: Express): void {
  // GET /api/clawsentinel/rules — return all rule metadata for the UI
  app.get("/api/clawsentinel/rules", (_req: Request, res: Response) => {
    try {
      const rules = getAllRuleMetadata();
      res.json({ rules });
    } catch (err) {
      res.status(500).json({ error: String(err) });
    }
  });

  // POST /api/clawsentinel/scan — run a security scan
  app.post("/api/clawsentinel/scan", async (req: Request, res: Response) => {
    const {
      path: scanPath,
      disabledRules,
      streamTo,
      autoRemediate,
    } = req.body as {
      path: string;
      disabledRules?: ThreatCategory[];
      streamTo?: { url: string; enabled: boolean; categories?: ThreatCategory[] };
      autoRemediate?: boolean;
    };

    if (!scanPath || typeof scanPath !== "string") {
      res.status(400).json({ error: "path is required" });
      return;
    }

    const resolvedPath = resolveUserPath(scanPath);

    // Safety: only allow scanning inside user's home or openclaw config dirs
    const homeDir = process.env.HOME ?? process.env.USERPROFILE ?? "/";
    if (
      !resolvedPath.startsWith(homeDir) &&
      !resolvedPath.startsWith("/tmp/")
    ) {
      res.status(403).json({ error: "scan path must be within home directory" });
      return;
    }

    try {
      const opts: SkillScanOptions = {
        disabledRules: disabledRules ?? [],
        streamTo: streamTo ?? { url: "", enabled: false },
      };

      const summary = await scanDirectoryWithSummary(resolvedPath, opts);

      let remediatedCount = 0;
      if (autoRemediate && summary.findings.length > 0) {
        // Remediate each unique file that has remediable findings
        const fileFindings = new Map<string, SkillScanFinding[]>();
        for (const finding of summary.findings) {
          if (!finding.remediable) continue;
          if (!fileFindings.has(finding.file)) {
            fileFindings.set(finding.file, []);
          }
          fileFindings.get(finding.file)!.push(finding);
        }

        for (const [filePath, findings] of fileFindings) {
          try {
            const source = await fs.readFile(filePath, "utf-8");
            const { source: patched, remediatedCount: count } = remediateSource(source, findings);
            if (count > 0) {
              await fs.writeFile(filePath, patched, "utf-8");
              remediatedCount += count;
            }
          } catch {
            // Don't fail the whole scan if one file can't be remediated
          }
        }
      }

      res.json({
        ...summary,
        remediatedCount,
      });
    } catch (err) {
      res.status(500).json({ error: String(err) });
    }
  });

  // POST /api/clawsentinel/remediate — apply remediations to specific files
  app.post("/api/clawsentinel/remediate", async (req: Request, res: Response) => {
    const { path: targetPath, findings } = req.body as {
      path: string;
      findings: SkillScanFinding[];
    };

    if (!targetPath || !Array.isArray(findings)) {
      res.status(400).json({ error: "path and findings are required" });
      return;
    }

    const resolvedPath = resolveUserPath(targetPath);
    const remediableFindings = findings.filter((f) => f.remediable);

    if (remediableFindings.length === 0) {
      res.json({ remediatedCount: 0, preview: "No remediable findings." });
      return;
    }

    // Group by file
    const fileFindings = new Map<string, SkillScanFinding[]>();
    for (const finding of remediableFindings) {
      const filePath = path.isAbsolute(finding.file)
        ? finding.file
        : path.join(resolvedPath, finding.file);
      if (!fileFindings.has(filePath)) fileFindings.set(filePath, []);
      fileFindings.get(filePath)!.push(finding);
    }

    let totalRemediated = 0;
    const previewLines: ThreatCategory[] = [];

    for (const [filePath, fileSpecificFindings] of fileFindings) {
      try {
        const source = await fs.readFile(filePath, "utf-8");
        const { source: patched, remediatedCount } = remediateSource(source, fileSpecificFindings);
        if (remediatedCount > 0) {
          await fs.writeFile(filePath, patched, "utf-8");
          totalRemediated += remediatedCount;
          previewLines.push(`// === ${path.basename(filePath)} — ${remediatedCount} fix(es) applied ===`);
          previewLines.push(patched.slice(0, 500) + (patched.length > 500 ? "\n// ... (truncated)" : ""));
          previewLines.push("");
        }
      } catch (err) {
        previewLines.push(`// Error remediating ${path.basename(filePath)}: ${String(err)}`);
      }
    }

    res.json({
      remediatedCount: totalRemediated,
      preview: previewLines.join("\n"),
    });
  });

  // GET /api/clawsentinel/health — log server health check proxy
  app.get("/api/clawsentinel/health", async (req: Request, res: Response) => {
    const targetUrl = req.query["url"] as string;
    if (!targetUrl) {
      res.status(400).json({ error: "url query param required" });
      return;
    }
    try {
      const resp = await fetch(targetUrl, { method: "HEAD", signal: AbortSignal.timeout(3000) });
      res.json({ ok: resp.ok, status: resp.status });
    } catch {
      res.json({ ok: false, status: 0 });
    }
  });
}