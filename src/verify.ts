import type { MemberDigest, Seal, VerifyResult } from "./types.ts";
import { buildMerkle } from "./merkle.ts";
import {
  SEAL_ALGORITHM,
  SEAL_MERKLE,
  SEAL_VERSION,
  canonicalPayload,
} from "./seal.ts";
import { publicKeyEquals, publicKeyFingerprint, verifyData } from "./keys.ts";
import { memberDigests, sha256Hex } from "./wacz.ts";

export interface VerifyOptions {
  expectedRoot?: string;
  expectedPublicKey?: string;
  previous?: MemberDigest[];
  strictBytes?: boolean;
}

interface MemberDiff {
  added: string[];
  removed: string[];
  modified: string[];
}

const HEX64 = /^[0-9a-f]{64}$/;

function failure(reasons: string[]): VerifyResult {
  return {
    ok: false,
    reasons,
    added: [],
    removed: [],
    modified: [],
    signatureOk: false,
    expectedRootOk: false,
    expectedPublicKeyOk: false,
    trusted: false,
  };
}

function diffMembers(
  previous: MemberDigest[],
  current: MemberDigest[],
): MemberDiff {
  const before = new Map(previous.map((d) => [d.path, d.sha256]));
  const after = new Map(current.map((d) => [d.path, d.sha256]));

  const added: string[] = [];
  const removed: string[] = [];
  const modified: string[] = [];

  for (const [path, sha256] of after) {
    const prior = before.get(path);
    if (prior === undefined) added.push(path);
    else if (prior !== sha256) modified.push(path);
  }
  for (const path of before.keys()) {
    if (!after.has(path)) removed.push(path);
  }

  added.sort();
  removed.sort();
  modified.sort();
  return { added, removed, modified };
}

export interface SealValidation {
  ok: boolean;
  seal?: Seal;
  reason?: string;
}

/**
 * Structural and format validation. Rejects unknown `version`, `algorithm`,
 * or `merkle` values before any of them are trusted.
 */
export function validateSeal(value: unknown): SealValidation {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    return { ok: false, reason: "seal must be a JSON object" };
  }
  const seal = value as Record<string, unknown>;

  if (seal.version !== SEAL_VERSION) {
    return {
      ok: false,
      reason: `unsupported seal version: ${String(seal.version)} (expected ${SEAL_VERSION})`,
    };
  }
  if (seal.algorithm !== SEAL_ALGORITHM) {
    return {
      ok: false,
      reason: `unsupported seal algorithm: ${String(seal.algorithm)} (expected ${SEAL_ALGORITHM})`,
    };
  }
  if (seal.merkle !== SEAL_MERKLE) {
    return {
      ok: false,
      reason: `unsupported merkle construction: ${String(seal.merkle)} (expected ${SEAL_MERKLE})`,
    };
  }
  if (typeof seal.root !== "string" || !HEX64.test(seal.root)) {
    return { ok: false, reason: "seal root must be a 64-character hex string" };
  }
  if (
    typeof seal.memberCount !== "number" ||
    !Number.isInteger(seal.memberCount) ||
    seal.memberCount < 0
  ) {
    return { ok: false, reason: "seal memberCount must be a non-negative integer" };
  }
  if (typeof seal.createdAt !== "string" || seal.createdAt.length === 0) {
    return { ok: false, reason: "seal createdAt must be a non-empty string" };
  }
  if (
    seal.archiveSha256 !== undefined &&
    (typeof seal.archiveSha256 !== "string" || !HEX64.test(seal.archiveSha256))
  ) {
    return {
      ok: false,
      reason: "seal archiveSha256 must be a 64-character hex string",
    };
  }
  if (typeof seal.publicKey !== "string" || seal.publicKey.length === 0) {
    return { ok: false, reason: "seal publicKey must be a non-empty string" };
  }
  if (typeof seal.signature !== "string" || seal.signature.length === 0) {
    return { ok: false, reason: "seal signature must be a non-empty string" };
  }

  return { ok: true, seal: seal as unknown as Seal };
}

export function verifySealSignature(seal: Seal): boolean {
  return verifyData(
    canonicalPayload(seal),
    seal.signature,
    seal.publicKey,
  );
}

export function verifySeal(
  seal: Seal,
  data: Uint8Array,
  options: VerifyOptions = {},
): VerifyResult {
  const format = validateSeal(seal);
  if (!format.ok) {
    return failure([format.reason ?? "invalid seal"]);
  }

  const reasons: string[] = [];

  let current: MemberDigest[];
  try {
    current = memberDigests(data);
  } catch (error) {
    return failure([
      `failed to read archive: ${error instanceof Error ? error.message : String(error)}`,
    ]);
  }
  const root = buildMerkle(current).root;

  const signatureOk = verifySealSignature(seal);
  if (!signatureOk) reasons.push("signature verification failed");

  let fingerprint: string | undefined;
  try {
    fingerprint = publicKeyFingerprint(seal.publicKey);
  } catch {
    fingerprint = undefined;
  }

  const rootOk = root === seal.root;
  if (!rootOk) {
    reasons.push(`merkle root mismatch: computed ${root}, seal ${seal.root}`);
  }

  let expectedRootOk = true;
  if (options.expectedRoot !== undefined) {
    expectedRootOk = root === options.expectedRoot;
    if (!expectedRootOk) {
      reasons.push(
        `root does not match expectedRoot: computed ${root}, expected ${options.expectedRoot}`,
      );
    }
  }

  let expectedPublicKeyOk = true;
  if (options.expectedPublicKey !== undefined) {
    try {
      expectedPublicKeyOk = publicKeyEquals(seal.publicKey, options.expectedPublicKey);
    } catch {
      expectedPublicKeyOk = false;
    }
    if (!expectedPublicKeyOk) {
      reasons.push("public key does not match expectedPublicKey");
    }
  }

  let bytesOk = true;
  if (options.strictBytes) {
    if (!seal.archiveSha256) {
      bytesOk = false;
      reasons.push(
        "strict byte check requested but the seal carries no archiveSha256",
      );
    } else {
      const actual = sha256Hex(data);
      bytesOk = actual === seal.archiveSha256;
      if (!bytesOk) {
        reasons.push(
          `archive bytes mismatch: computed ${actual}, seal ${seal.archiveSha256}`,
        );
      }
    }
  }

  const { added, removed, modified } = options.previous
    ? diffMembers(options.previous, current)
    : { added: [], removed: [], modified: [] };

  if (added.length > 0) reasons.push(`members added: ${added.join(", ")}`);
  if (removed.length > 0) {
    reasons.push(`members removed: ${removed.join(", ")}`);
  }
  if (modified.length > 0) {
    reasons.push(`members modified: ${modified.join(", ")}`);
  }

  const trusted =
    options.expectedRoot !== undefined || options.expectedPublicKey !== undefined;

  const ok =
    signatureOk &&
    rootOk &&
    expectedRootOk &&
    expectedPublicKeyOk &&
    bytesOk &&
    added.length === 0 &&
    removed.length === 0 &&
    modified.length === 0;

  return {
    ok,
    root,
    reasons,
    added,
    removed,
    modified,
    signatureOk,
    expectedRootOk,
    expectedPublicKeyOk,
    trusted,
    fingerprint,
  };
}

export function verifySealJson(
  sealJson: string,
  data: Uint8Array,
  options: VerifyOptions = {},
): VerifyResult {
  let parsed: unknown;
  try {
    parsed = JSON.parse(sealJson);
  } catch (error) {
    return failure([
      `invalid seal JSON: ${error instanceof Error ? error.message : String(error)}`,
    ]);
  }

  const validation = validateSeal(parsed);
  if (!validation.ok || !validation.seal) {
    return failure([validation.reason ?? "invalid seal"]);
  }

  return verifySeal(validation.seal, data, options);
}
