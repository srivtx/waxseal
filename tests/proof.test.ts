/// <reference types="bun" />
import { describe, expect, test } from "bun:test";

import { defaultWacz } from "../src/fixtures.ts";
import { buildMerkle, rootOf, verifyInclusion } from "../src/merkle.ts";
import { createInclusionProofs } from "../src/seal.ts";
import type { ProofStep } from "../src/types.ts";
import { memberDigests, sha256Hex } from "../src/wacz.ts";

function parseProof(steps: string[]): ProofStep[] {
  return steps.map((step) => JSON.parse(step) as ProofStep);
}

describe("inclusion proofs over a WACZ", () => {
  test("every member's proof verifies against the rebuilt root", () => {
    const archive = defaultWacz();
    const digests = memberDigests(archive);
    const proofs = createInclusionProofs(archive);

    const tree = buildMerkle(digests);
    const root = rootOf(digests);
    expect(root).toBe(tree.root);

    expect(Object.keys(proofs).sort()).toEqual(
      digests.map((digest) => digest.path).sort(),
    );

    for (const digest of digests) {
      const proof = parseProof(proofs[digest.path] ?? []);
      expect(verifyInclusion(digest.path, digest.sha256, proof, root)).toBe(
        true,
      );
    }
  });

  test("a proof for a modified digest fails", () => {
    const archive = defaultWacz();
    const digests = memberDigests(archive);
    const root = rootOf(digests);
    const proofs = createInclusionProofs(archive);

    const target = digests[0]!;
    const proof = parseProof(proofs[target.path] ?? []);
    const modified = sha256Hex(new TextEncoder().encode("tampered"));

    expect(verifyInclusion(target.path, modified, proof, root)).toBe(false);
  });
});
