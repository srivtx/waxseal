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
    const expected = sha256Hex(encoder.encode(`wacz-seal:leaf:a.txt:${a.sha256}`));
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
});
