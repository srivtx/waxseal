/// <reference types="bun" />
import { describe, expect, test } from "bun:test";

import { defaultWacz } from "../src/fixtures.ts";
import { buildMerkle, rootOf, verifyInclusion } from "../src/merkle.ts";
import { createInclusionProofs, createProofDocument } from "../src/seal.ts";
import { memberDigests, sha256Hex } from "../src/wacz.ts";

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
      const proof = proofs[digest.path] ?? [];
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
    const proof = proofs[target.path] ?? [];
    const modified = sha256Hex(new TextEncoder().encode("tampered"));

    expect(verifyInclusion(target.path, modified, proof, root)).toBe(false);
  });

  test("createProofDocument records the root and each member content hash", () => {
    const archive = defaultWacz();
    const digests = memberDigests(archive);
    const document = createProofDocument(archive);

    expect(document.version).toBe(1);
    expect(document.root).toBe(rootOf(digests));
    expect(Object.keys(document.proofs).sort()).toEqual(
      digests.map((digest) => digest.path).sort(),
    );

    for (const digest of digests) {
      const entry = document.proofs[digest.path]!;
      expect(entry.sha256).toBe(digest.sha256);
      expect(verifyInclusion(digest.path, entry.sha256, entry.steps, document.root)).toBe(
        true,
      );
    }
  });
});
