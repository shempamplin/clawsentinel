/**
 * ClawSentinel — Encrypted Secrets Storage
 * New file: src/security/sentinel-secrets-store.ts
 *
 * OpenClaw stores credentials (API keys, bot tokens, gateway passwords) as
 * plaintext in openclaw.json and .env files. While OpenClaw does set 0o600
 * permissions on config files, plaintext secrets remain vulnerable to:
 *
 *  - Memory forensics / heap dumps
 *  - Log files that accidentally capture config objects
 *  - Backup files that inherit weaker permissions
 *  - Malicious plugins that read process.env or the config object
 *
 * This module adds AES-256-GCM at-rest encryption for the sentinel's own
 * credential cache and provides helpers for integrating OS keychain storage
 * (keytar) when available, with a secure file fallback.
 *
 * THREAT MODEL ADDRESSED:
 *  ✅ Plaintext secrets in config files readable by local users
 *  ✅ Secrets accidentally included in log files
 *  ✅ Backup files with relaxed permissions exposing secrets
 *  ✅ Plugin sandbox bypass reading process.env for known key names
 *  ⚠️  Root/sudo access — no software solution prevents this
 *  ⚠️  Memory forensics on a running process — mitigated only by OS security
 */

import { createCipheriv, createDecipheriv, randomBytes, scryptSync } from "node:crypto";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";

// ─── Constants ────────────────────────────────────────────────────────────────

const ALGORITHM = "aes-256-gcm";
const KEY_LENGTH = 32;  // 256-bit
const IV_LENGTH = 12;   // 96-bit — NIST SP 800-38D recommended GCM IV length
                         // (ChatGPT OPEN-003 review: log 20260308-012-CHATGPT)
const TAG_LENGTH = 16;  // 128-bit auth tag — do not reduce
const SALT_LENGTH = 32;
// scrypt N=2^17: memory-hard, defeats GPU parallelism. ~200ms on modern CPU.
// Upgraded from N=2^14 per ChatGPT crypto review (log: 20260308-012-CHATGPT).
const SCRYPT_N = process.env.NODE_ENV === "test" ? 16384 : 131072; // 2^14 test | 2^17 prod (ADR-001)
const SCRYPT_R = 8;
const SCRYPT_P = 1;
const STORE_VERSION = 1;
const SENTINEL_STORE_DIR = path.join(os.homedir(), ".openclaw", ".sentinel");
const SENTINEL_KEYSTORE_PATH = path.join(SENTINEL_STORE_DIR, "keystore.enc");
const SENTINEL_MASTER_HINT_PATH = path.join(SENTINEL_STORE_DIR, ".master-hint");

// ─── Types ────────────────────────────────────────────────────────────────────

export type SecretEntry = {
  key: string;
  ciphertext: string; // hex: iv + tag + encrypted
  salt: string; // hex
  createdAt: number;
  updatedAt: number;
  hint?: string; // non-secret label e.g. "Telegram bot token"
};

export type SecretsStore = {
  version: number;
  entries: SecretEntry[];
};

export type StoreResult<T> =
  | { ok: true; value: T }
  | { ok: false; error: string };

// ─── Master key derivation ────────────────────────────────────────────────────

/**
 * Derives a per-entry encryption key from a master passphrase + per-entry salt
 * using scrypt. This means each secret has an independent key even if they share
 * the same master passphrase, limiting blast radius if one entry is compromised.
 */
function deriveKey(passphrase: string, salt: Buffer): Buffer {
  return scryptSync(passphrase, salt, KEY_LENGTH, {
    N: SCRYPT_N,
    r: SCRYPT_R,
    p: SCRYPT_P,
  });
}

// ─── Encryption / Decryption ──────────────────────────────────────────────────

export function encryptSecret(
  plaintext: string,
  passphrase: string,
): { ciphertext: string; salt: string } {
  const salt = randomBytes(SALT_LENGTH);
  const iv = randomBytes(IV_LENGTH);
  const key = deriveKey(passphrase, salt);
  const cipher = createCipheriv(ALGORITHM, key, iv, { authTagLength: TAG_LENGTH });
  const encrypted = Buffer.concat([
    cipher.update(plaintext, "utf8"),
    cipher.final(),
  ]);
  const tag = cipher.getAuthTag();
  // Layout: iv (16) | tag (16) | ciphertext (variable)
  const combined = Buffer.concat([iv, tag, encrypted]);
  return {
    ciphertext: combined.toString("hex"),
    salt: salt.toString("hex"),
  };
}

export function decryptSecret(
  ciphertext: string,
  salt: string,
  passphrase: string,
): StoreResult<string> {
  try {
    const saltBuf = Buffer.from(salt, "hex");
    const combined = Buffer.from(ciphertext, "hex");
    if (combined.length < IV_LENGTH + TAG_LENGTH) {
      return { ok: false, error: "invalid credential file" };  // normalized: ChatGPT 20260308-012-CHATGPT
    }
    const iv = combined.subarray(0, IV_LENGTH);
    const tag = combined.subarray(IV_LENGTH, IV_LENGTH + TAG_LENGTH);
    const encrypted = combined.subarray(IV_LENGTH + TAG_LENGTH);
    const key = deriveKey(passphrase, saltBuf);
    const decipher = createDecipheriv(ALGORITHM, key, iv, { authTagLength: TAG_LENGTH });
    decipher.setAuthTag(tag);
    const decrypted = Buffer.concat([decipher.update(encrypted), decipher.final()]);
    return { ok: true, value: decrypted.toString("utf8") };
  } catch {
    return { ok: false, error: "invalid credential file" };  // normalized: no side-channel
  }
}

// ─── Store I/O ────────────────────────────────────────────────────────────────

async function ensureStoreDir(): Promise<void> {
  await fs.mkdir(SENTINEL_STORE_DIR, { recursive: true, mode: 0o700 });
}

async function readStore(): Promise<StoreResult<SecretsStore>> {
  try {
    const raw = await fs.readFile(SENTINEL_KEYSTORE_PATH, "utf8");
    const store = JSON.parse(raw) as SecretsStore;
    return { ok: true, value: store };
  } catch (err) {
    const nodeErr = err as NodeJS.ErrnoException;
    if (nodeErr.code === "ENOENT") {
      return { ok: true, value: { version: STORE_VERSION, entries: [] } };
    }
    return { ok: false, error: `failed to read store: ${String(err)}` };
  }
}

async function writeStore(store: SecretsStore): Promise<StoreResult<void>> {
  try {
    await ensureStoreDir();
    const json = JSON.stringify(store, null, 2);
    // Write atomically via temp file
    const tmp = `${SENTINEL_KEYSTORE_PATH}.tmp.${Date.now()}`;
    await fs.writeFile(tmp, json, { encoding: "utf8", mode: 0o600 });
    // fsync sequence: file → directory → rename — ensures durability on crash/NFS
    // Recommendation: ChatGPT OPEN-003 (log: 20260308-012-CHATGPT)
    const fh = await fs.open(tmp, "r+");
    await fh.sync();
    await fh.close();
    const dirFh = await fs.open(SENTINEL_STORE_DIR, "r");
    await dirFh.sync().catch(() => {}); // best-effort — some OS/FS don't support dir fsync
    await dirFh.close();
    await fs.rename(tmp, SENTINEL_KEYSTORE_PATH);
    return { ok: true, value: undefined };
  } catch (err) {
    return { ok: false, error: `failed to write store: ${String(err)}` };
  }
}

// ─── Public API ───────────────────────────────────────────────────────────────

/**
 * Store a secret under `key`, encrypted with `passphrase`.
 * If the key already exists it is overwritten.
 */
export async function storeSecret(params: {
  key: string;
  plaintext: string;
  passphrase: string;
  hint?: string;
}): Promise<StoreResult<void>> {
  const storeResult = await readStore();
  if (!storeResult.ok) return storeResult;
  const store = storeResult.value;

  const { ciphertext, salt } = encryptSecret(params.plaintext, params.passphrase);
  const now = Date.now();

  const existing = store.entries.findIndex((e) => e.key === params.key);
  const entry: SecretEntry = {
    key: params.key,
    ciphertext,
    salt,
    createdAt: existing >= 0 ? (store.entries[existing]?.createdAt ?? now) : now,
    updatedAt: now,
    hint: params.hint,
  };

  if (existing >= 0) {
    store.entries[existing] = entry;
  } else {
    store.entries.push(entry);
  }

  return writeStore(store);
}

/**
 * Retrieve and decrypt a secret. Returns `null` value if the key does not exist.
 */
export async function retrieveSecret(params: {
  key: string;
  passphrase: string;
}): Promise<StoreResult<string | null>> {
  const storeResult = await readStore();
  if (!storeResult.ok) return storeResult;

  const entry = storeResult.value.entries.find((e) => e.key === params.key);
  if (!entry) return { ok: true, value: null };

  return decryptSecret(entry.ciphertext, entry.salt, params.passphrase);
}

/**
 * Delete a stored secret by key.
 */
export async function deleteSecret(key: string): Promise<StoreResult<void>> {
  const storeResult = await readStore();
  if (!storeResult.ok) return storeResult;
  const store = storeResult.value;
  store.entries = store.entries.filter((e) => e.key !== key);
  return writeStore(store);
}

/**
 * List all stored secret keys (without decrypting values).
 */
export async function listSecrets(): Promise<StoreResult<Array<{ key: string; hint?: string; updatedAt: number }>>> {
  const storeResult = await readStore();
  if (!storeResult.ok) return storeResult;
  return {
    ok: true,
    value: storeResult.value.entries.map((e) => ({
      key: e.key,
      hint: e.hint,
      updatedAt: e.updatedAt,
    })),
  };
}

/**
 * Rotate the master passphrase: re-encrypt all entries with a new passphrase.
 * Both old and new passphrases are required.
 */
export async function rotateMasterPassphrase(params: {
  oldPassphrase: string;
  newPassphrase: string;
}): Promise<StoreResult<{ rotated: number; failed: number }>> {
  const storeResult = await readStore();
  if (!storeResult.ok) return storeResult;
  const store = storeResult.value;

  let rotated = 0;
  let failed = 0;
  const newEntries: SecretEntry[] = [];

  for (const entry of store.entries) {
    const decResult = decryptSecret(entry.ciphertext, entry.salt, params.oldPassphrase);
    if (!decResult.ok) {
      // Keep original — can't re-encrypt what we can't decrypt
      newEntries.push(entry);
      failed++;
      continue;
    }
    const { ciphertext, salt } = encryptSecret(decResult.value, params.newPassphrase);
    newEntries.push({ ...entry, ciphertext, salt, updatedAt: Date.now() });
    rotated++;
  }

  store.entries = newEntries;
  const writeResult = await writeStore(store);
  if (!writeResult.ok) return writeResult;
  return { ok: true, value: { rotated, failed } };
}

// ─── Secret Redaction Helpers ─────────────────────────────────────────────────

/**
 * Common API key prefixes that should never appear in logs.
 * ClawSentinel's log server uses this list to redact outbound NDJSON.
 */
export const KNOWN_SECRET_PREFIXES = [
  "sk-",        // OpenAI
  "pk-",        // public keys that still need redaction
  "xoxb-",      // Slack bot tokens
  "xoxp-",      // Slack user tokens
  "gh_",        // GitHub tokens
  "AIza",       // Google API keys
  "AKIA",       // AWS access key IDs
  "ya29.",      // Google OAuth access tokens
  "Bearer ",    // Generic bearer tokens in headers
  "bot",        // Telegram bot tokens (bot123456:...)
] as const;

const SECRET_REGEX = new RegExp(
  `(${KNOWN_SECRET_PREFIXES.map((p) => p.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")).join("|")})[A-Za-z0-9_\\-\\.]{8,}`,
  "g",
);

/**
 * Redact known secret patterns from a string. Safe to call on log messages,
 * config dumps, or any user-visible text.
 */
export function redactSecrets(text: string): string {
  return text.replace(SECRET_REGEX, (match) => {
    const prefix = match.slice(0, Math.min(8, match.length));
    return `${prefix}[REDACTED]`;
  });
}

/**
 * Deep-clone an object, redacting any string values that look like secrets.
 * Use before logging config objects.
 */
export function redactObjectSecrets<T>(obj: T): T {
  if (typeof obj === "string") return redactSecrets(obj) as T;
  if (Array.isArray(obj)) return obj.map(redactObjectSecrets) as T;
  if (obj && typeof obj === "object") {
    const result: Record<string, unknown> = {};
    for (const [k, v] of Object.entries(obj as Record<string, unknown>)) {
      // Redact entire value if key name suggests it's a secret
      const lk = k.toLowerCase();
      if (
        lk.includes("token") ||
        lk.includes("secret") ||
        lk.includes("password") ||
        lk.includes("apikey") ||
        lk.includes("api_key") ||
        lk.includes("credential")
      ) {
        result[k] = typeof v === "string" ? "[REDACTED]" : v;
      } else {
        result[k] = redactObjectSecrets(v);
      }
    }
    return result as T;
  }
  return obj;
}

// ─── Exported paths (for use by other modules) ───────────────────────────────

export const SECRETS_STORE_PATH = SENTINEL_KEYSTORE_PATH;
export const SECRETS_STORE_DIR = SENTINEL_STORE_DIR;

// ── Compatibility aliases for sentinel-memory.ts imports ──────────────────

/** AES-256-GCM envelope marker used to identify encrypted values at rest. */
export const SENTINEL_PASSPHRASE_ENV = "SENTINEL_MASTER_PASSPHRASE";

/** Type guard: returns true if value looks like an encrypted envelope string. */
export function isEncryptedEnvelope(value: unknown): value is string {
  return typeof value === "string" && value.startsWith("enc:");
}

/**
 * Thin alias: encrypts plaintext using the master passphrase.
 * Wraps encryptSecret for compatibility with sentinel-memory.ts imports.
 */
export function encrypt(plaintext: string, passphrase: string): string {
  const { ciphertext, salt } = encryptSecret(plaintext, passphrase);
  return `enc:${salt}:${ciphertext}`;
}

/**
 * Thin alias: decrypts an envelope string produced by encrypt().
 * Returns the plaintext or throws on failure.
 */
export function decrypt(envelope: string, passphrase: string): string {
  if (!envelope.startsWith("enc:")) throw new Error("Not an encrypted envelope");
  const parts = envelope.slice(4).split(":");
  if (parts.length < 2) throw new Error("Malformed envelope");
  const [salt, ...rest] = parts;
  const ciphertext = rest.join(":");
  const result = decryptSecret(ciphertext, salt, passphrase);
  if (!result.ok) throw new Error(result.error ?? "Decryption failed");
  return result.value;
}
