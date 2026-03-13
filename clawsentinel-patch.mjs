#!/usr/bin/env node
// clawsentinel-patch.mjs
// ClawSentinel patch/upgrade script — applies incremental updates to the installed package.
// Run: node clawsentinel-patch.mjs [--dry-run]
//
// OPEN-017 hardening (20260312-057-GEMINI):
//   - Rollback on partial failure (Finding A)
//   - Version precondition check against package.json (Finding B)
//   - fs.access() W_OK check before each write (Finding C)

import fs from "node:fs/promises";
import path from "node:path";
import { execSync } from "node:child_process";

const TARGET_VERSION = "1.0.0-beta14";
const INSTALL_ROOT = path.resolve(process.cwd(), "node_modules/@openclaw/clawsentinel");

const PATCH_FILES = [
  { src: "./patches/skill-scanner.js",       dest: `${INSTALL_ROOT}/dist/security/skill-scanner.js` },
  { src: "./patches/sentinel-memory.js",     dest: `${INSTALL_ROOT}/dist/memory/sentinel-memory.js` },
  { src: "./patches/skill-sandbox.js",       dest: `${INSTALL_ROOT}/dist/sandbox/skill-sandbox.js` },
  { src: "./patches/skill-runner.js",        dest: `${INSTALL_ROOT}/dist/sandbox/skill-runner.js` },
];

const isDryRun = process.argv.includes("--dry-run");

// OPEN-017 Finding B: Verify installed version matches TARGET_VERSION before patching.
async function verifyInstalledVersion() {
  const pkgPath = path.join(INSTALL_ROOT, "package.json");
  let pkg;
  try {
    pkg = JSON.parse(await fs.readFile(pkgPath, "utf8"));
  } catch (err) {
    throw new Error(
      `[clawsentinel-patch] Cannot read installed package.json at ${pkgPath}: ${err.message}`
    );
  }
  if (pkg.version !== TARGET_VERSION) {
    throw new Error(
      `[clawsentinel-patch] Version mismatch: installed=${pkg.version}, expected=${TARGET_VERSION}. Aborting.`
    );
  }
  console.log(`[clawsentinel-patch] Version check passed: ${pkg.version}`);
}

// OPEN-017 Finding A: Create backups before patching to allow rollback on partial failure.
async function createBackups() {
  const backups = [];
  for (const { dest } of PATCH_FILES) {
    const backup = `${dest}.pre-patch-backup`;
    try {
      await fs.copyFile(dest, backup);
      backups.push({ dest, backup });
      console.log(`[clawsentinel-patch] Backed up: ${path.basename(dest)}`);
    } catch (err) {
      // Destination may not exist yet (fresh install) — skip backup for missing files
      if (err.code !== "ENOENT") throw err;
    }
  }
  return backups;
}

// OPEN-017 Finding A: Restore backups if any patch fails mid-run.
async function rollback(backups) {
  console.error("[clawsentinel-patch] Rolling back all applied patches...");
  for (const { dest, backup } of backups) {
    try {
      await fs.copyFile(backup, dest);
      await fs.unlink(backup);
      console.error(`[clawsentinel-patch] Rolled back: ${path.basename(dest)}`);
    } catch (rbErr) {
      console.error(`[clawsentinel-patch] Rollback FAILED for ${dest}: ${rbErr.message}`);
    }
  }
}

async function applyPatches() {
  console.log(`[clawsentinel-patch] Target: ${TARGET_VERSION}`);
  console.log(`[clawsentinel-patch] Install root: ${INSTALL_ROOT}`);
  if (isDryRun) console.log("[clawsentinel-patch] DRY RUN — no files will be written");

  // OPEN-017 Finding B: Version precondition
  await verifyInstalledVersion();

  // OPEN-017 Finding A: Back up before touching anything
  const backups = isDryRun ? [] : await createBackups();

  try {
    for (const { src, dest } of PATCH_FILES) {
      console.log(`[clawsentinel-patch] Patching: ${dest}`);
      const content = await fs.readFile(src, "utf8");

      if (!isDryRun) {
        // OPEN-017 Finding C: Check write permission before attempting write
        try {
          await fs.access(dest, fs.constants.W_OK);
        } catch {
          throw new Error(
            `[clawsentinel-patch] No write permission for ${dest}. Aborting.`
          );
        }
        await fs.writeFile(dest, content, "utf8");
      }

      console.log(`[clawsentinel-patch] Done: ${path.basename(dest)}`);
    }
  } catch (err) {
    // OPEN-017 Finding A: Rollback on any failure after backups were created
    if (backups.length > 0) await rollback(backups);
    throw err;
  }

  // Clean up backups on success
  if (!isDryRun) {
    for (const { backup } of backups) {
      try { await fs.unlink(backup); } catch { /* ignore */ }
    }
  }

  console.log("[clawsentinel-patch] All patches applied successfully.");
}

applyPatches().catch((err) => {
  console.error("[clawsentinel-patch] FATAL:", err.message);
  process.exit(1);
});