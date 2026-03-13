/**
 * ClawSentinel — Credential Store Tests
 * OPEN-005 implementation — Test Coverage Lead: Grok (xAI)
 * Implementation: Claude Sonnet 4.6
 *
 * Tests the synchronous encrypt/decrypt layer (ADR-001):
 *   - AES-256-GCM round-trips
 *   - Wrong passphrase rejection
 *   - Tampered ciphertext rejection
 *   - IV uniqueness (no IV reuse)
 *   - Normalized error messages (no side-channel)
 *
 * Run: npx vitest run tests/sentinel-secrets-store.test.ts
 */

import { describe, it, expect } from "vitest";
import {
  encryptSecret,
  decryptSecret,
  redactSecrets,
  KNOWN_SECRET_PREFIXES,
} from "../src/security/sentinel-secrets-store";

// ── Round-trip ────────────────────────────────────────────────────────────────

describe("encryptSecret / decryptSecret round-trip", () => {
  it("decrypts to original plaintext with correct passphrase", () => {
    const plaintext   = "my-api-key-value";
    const passphrase  = "correct-horse-battery-staple";
    const { ciphertext, salt } = encryptSecret(plaintext, passphrase);
    const result = decryptSecret(ciphertext, salt, passphrase);
    expect(result.ok).toBe(true);
    if (result.ok) expect(result.value).toBe(plaintext);
  });

  it("round-trips an empty string", () => {
    const { ciphertext, salt } = encryptSecret("", "passphrase");
    const result = decryptSecret(ciphertext, salt, "passphrase");
    expect(result.ok).toBe(true);
    if (result.ok) expect(result.value).toBe("");
  });

  it("round-trips a unicode string", () => {
    const plaintext = "密码: 🔐 café résumé";
    const { ciphertext, salt } = encryptSecret(plaintext, "pass");
    const result = decryptSecret(ciphertext, salt, "pass");
    expect(result.ok).toBe(true);
    if (result.ok) expect(result.value).toBe(plaintext);
  });

  it("round-trips a large secret (1 MB)", () => {
    const plaintext = "x".repeat(1024 * 1024);
    const { ciphertext, salt } = encryptSecret(plaintext, "pass");
    const result = decryptSecret(ciphertext, salt, "pass");
    expect(result.ok).toBe(true);
    if (result.ok) expect(result.value).toBe(plaintext);
  });
});

// ── Wrong passphrase ──────────────────────────────────────────────────────────

describe("decryptSecret with wrong passphrase", () => {
  it("returns ok:false on wrong passphrase", () => {
    const { ciphertext, salt } = encryptSecret("secret", "correct");
    const result = decryptSecret(ciphertext, salt, "wrong");
    expect(result.ok).toBe(false);
  });

  it("returns normalized error — no key or passphrase detail", () => {
    const { ciphertext, salt } = encryptSecret("secret", "correct");
    const result = decryptSecret(ciphertext, salt, "wrong");
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.error).toBe("invalid credential file");
      // Must not leak which part failed
      expect(result.error).not.toMatch(/passphrase|key|auth|tag|gcm/i);
    }
  });
});

// ── Tamper detection ──────────────────────────────────────────────────────────

describe("decryptSecret tamper detection (GCM auth tag)", () => {
  it("rejects ciphertext with a flipped bit", () => {
    const { ciphertext, salt } = encryptSecret("sensitive", "pass");
    // Flip last hex char to corrupt the ciphertext
    const tampered = ciphertext.slice(0, -1) + (ciphertext.slice(-1) === "0" ? "1" : "0");
    const result = decryptSecret(tampered, salt, "pass");
    expect(result.ok).toBe(false);
  });

  it("rejects truncated ciphertext", () => {
    const { ciphertext, salt } = encryptSecret("sensitive", "pass");
    const result = decryptSecret(ciphertext.slice(0, 10), salt, "pass");
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.error).toBe("invalid credential file");
  });

  it("rejects empty ciphertext", () => {
    const { salt } = encryptSecret("sensitive", "pass");
    const result = decryptSecret("", salt, "pass");
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.error).toBe("invalid credential file");
  });
});

// ── IV uniqueness ─────────────────────────────────────────────────────────────

describe("IV uniqueness (ADR-001: no IV reuse)", () => {
  it("produces distinct ciphertexts for the same input", () => {
    const ciphertexts = new Set<string>();
    for (let i = 0; i < 20; i++) {
      const { ciphertext } = encryptSecret("same-plaintext", "same-passphrase");
      ciphertexts.add(ciphertext);
    }
    // Every encryption must produce a unique ciphertext (unique IV)
    expect(ciphertexts.size).toBe(20);
  });
});

// ── Output format ─────────────────────────────────────────────────────────────

describe("encryptSecret output format", () => {
  it("returns hex-encoded ciphertext", () => {
    const { ciphertext } = encryptSecret("test", "pass");
    expect(ciphertext).toMatch(/^[0-9a-f]+$/i);
  });

  it("returns hex-encoded salt", () => {
    const { salt } = encryptSecret("test", "pass");
    expect(salt).toMatch(/^[0-9a-f]+$/i);
  });

  it("produces different salts for each encryption", () => {
    const salts = new Set<string>();
    for (let i = 0; i < 10; i++) {
      const { salt } = encryptSecret("test", "pass");
      salts.add(salt);
    }
    expect(salts.size).toBe(10);
  });
});

// ── redactSecrets ─────────────────────────────────────────────────────────────

describe("redactSecrets", () => {
  it("redacts known secret prefixes from strings", () => {
    const text = "Using key sk-proj-abcdefghijklmnopqrstuvwxyz in request";
    const redacted = redactSecrets(text);
    expect(redacted).not.toContain("sk-proj-abcdefghijklmnopqrstuvwxyz");
  });

  it("passes through strings with no secrets", () => {
    const text = "Nothing sensitive here, just a normal log message";
    expect(redactSecrets(text)).toBe(text);
  });

  it("KNOWN_SECRET_PREFIXES is a non-empty array", () => {
    expect(Array.isArray(KNOWN_SECRET_PREFIXES)).toBe(true);
    expect(KNOWN_SECRET_PREFIXES.length).toBeGreaterThan(0);
  });
});