import type { MemberDigest, Seal, VerifyResult } from "./types.ts";
import { buildMerkle } from "./merkle.ts";
import { canonicalPayload } from "./seal.ts";
import { verifyData } from "./keys.ts";
import { memberDigests, sha256Hex } from "./wacz.ts";

export interface VerifyOptions {
  expectedRoot?: string;
  previous?: MemberDigest[];
  strictBytes?: boolean;
}

interface MemberDiff {
  added: string[];
  removed: string[];
  modified: string[];
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

export function verifySeal(
  seal: Seal,
  data: Uint8Array,
  options: VerifyOptions = {},
): VerifyResult {
  const reasons: string[] = [];
  const current = memberDigests(data);
  const root = buildMerkle(current).root;

  const signatureOk = verifyData(
    canonicalPayload(seal),
    seal.signature,
    seal.publicKey,
  );
  if (!signatureOk) reasons.push("signature verification failed");

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

  let bytesOk = true;
  if (options.strictBytes && seal.archiveSha256) {
    const actual = sha256Hex(data);
    bytesOk = actual === seal.archiveSha256;
    if (!bytesOk) {
      reasons.push(
        `archive bytes mismatch: computed ${actual}, seal ${seal.archiveSha256}`,
      );
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

  const ok =
    signatureOk &&
    rootOk &&
    expectedRootOk &&
    bytesOk &&
    added.length === 0 &&
    removed.length === 0 &&
    modified.length === 0;

  return { ok, root, reasons, added, removed, modified, signatureOk };
}

export function verifySealJson(
  sealJson: string,
  data: Uint8Array,
  options: VerifyOptions = {},
): VerifyResult {
  return verifySeal(JSON.parse(sealJson) as Seal, data, options);
}
