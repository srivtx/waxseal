import { describe, expect, test } from "bun:test";
import {
  buildMerkle,
  proveInclusion,
  rootOf,
  verifyInclusion,
} from "../src/merkle.ts";
import type { MemberDigest } from "../src/types.ts";
import { sha256Hex } from "../src/wacz.ts";

const encoder = new TextEncoder();

function digest(path: string, content: string): MemberDigest {
  const bytes = encoder.encode(content);
  return { path, sha256: sha256Hex(bytes), size: bytes.length };
}

const a = digest("a.txt", "alpha");
const b = digest("b.txt", "bravo");
const c = digest("c.txt", "charlie");
const d = digest("d.txt", "delta");

describe("buildMerkle", () => {
  test("is deterministic regardless of input order", () => {
    const t1 = buildMerkle([a, b, c]);
    const t2 = buildMerkle([c, a, b]);
    expect(t1.root).toBe(t2.root);
    expect(t1.levels).toEqual(t2.levels);
    expect(t1.leafOrder).toEqual(["a.txt", "b.txt", "c.txt"]);
    expect(rootOf([b, c, a])).toBe(t1.root);
  });

  test("a single leaf root equals that leaf hash", () => {
    const tree = buildMerkle([a]);
    const expected = sha256Hex(encoder.encode(`waxseal:leaf:a.txt:${a.sha256}`));
    expect(tree.root).toBe(expected);
    expect(tree.levels[0]).toEqual([expected]);
  });

  test("inclusion proofs verify for every leaf (odd and even counts)", () => {
    for (const digests of [
      [a],
      [a, b],
      [a, b, c],
      [a, b, c, d],
    ]) {
      const tree = buildMerkle(digests);
      for (const entry of digests) {
        const proof = proveInclusion(tree, entry.path);
        expect(proof).toBeDefined();
        expect(verifyInclusion(entry.path, entry.sha256, proof!, tree.root)).toBe(
          true,
        );
      }
    }
  });

  test("a wrong sibling fails verification", () => {
    const tree = buildMerkle([a, b, c]);
    const proof = proveInclusion(tree, "a.txt")!;
    expect(proof.length).toBeGreaterThan(0);
    const tampered = proof.map((step, i) =>
      i === 0 ? { ...step, hash: "00".repeat(32) } : step,
    );
    expect(verifyInclusion("a.txt", a.sha256, tampered, tree.root)).toBe(false);
  });

  test("root changes when a digest changes", () => {
    const changed = digest("b.txt", "bravo-changed");
    expect(buildMerkle([a, b]).root).not.toBe(buildMerkle([a, changed]).root);
  });

  test("matches a hard-coded known root for a fixed three-member vector", () => {
    const vector: MemberDigest[] = [
      {
        path: "a.txt",
        sha256: "24d5a8c909c5a2efb7d0d5e0c8bd1c1d0e2d6c1d1f5a5e3a7b6c9d0e1f2a3b4c",
        size: 5,
      },
      {
        path: "b.txt",
        sha256: "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
        size: 5,
      },
      {
        path: "c.txt",
        sha256: "c3ab8ff13720e8ad9047dd39466b3c8974e592c2fa383d4a3960714caef0c4f2",
        size: 7,
      },
    ];
    expect(buildMerkle(vector).root).toBe(
      "9d2b9f800326e650919e1754fe67585851462bc19ea640dd48f6ccf8042456c8",
    );
  });
});
