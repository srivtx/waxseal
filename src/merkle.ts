import type { MemberDigest, MerkleTree, ProofStep } from "./types.ts";
import { sha256Hex } from "./wacz.ts";

const encoder = new TextEncoder();

function utf8(text: string): Uint8Array {
  return encoder.encode(text);
}

function comparePaths(a: string, b: string): number {
  return a < b ? -1 : a > b ? 1 : 0;
}

function leafHash(path: string, sha256: string): string {
  return sha256Hex(utf8(`waxseal:leaf:${path}:${sha256}`));
}

function nodeHash(left: string, right: string): string {
  return sha256Hex(utf8(`waxseal:node:${left}:${right}`));
}

export function buildMerkle(digests: MemberDigest[]): MerkleTree {
  const sorted = [...digests].sort((a, b) => comparePaths(a.path, b.path));
  const leafOrder = sorted.map((d) => d.path);

  if (sorted.length === 0) {
    return {
      root: sha256Hex(utf8("waxseal:empty")),
      levels: [[]],
      leafOrder,
    };
  }

  const leaves = sorted.map((d) => leafHash(d.path, d.sha256));
  const levels: string[][] = [leaves];

  let current = leaves;
  while (current.length > 1) {
    const next: string[] = [];
    for (let i = 0; i < current.length; i += 2) {
      const left = current[i]!;
      const right = current[i + 1];
      next.push(right === undefined ? left : nodeHash(left, right));
    }
    levels.push(next);
    current = next;
  }

  const root = levels[levels.length - 1]![0]!;
  return { root, levels, leafOrder };
}

export function proveInclusion(
  tree: MerkleTree,
  path: string,
): ProofStep[] | undefined {
  const index = tree.leafOrder.indexOf(path);
  if (index === -1) return undefined;

  const proof: ProofStep[] = [];
  let idx = index;

  for (let level = 0; level < tree.levels.length - 1; level++) {
    const nodes = tree.levels[level]!;
    const leftSide = idx % 2 === 0;
    const sibling = leftSide ? idx + 1 : idx - 1;
    const siblingHash = nodes[sibling];
    if (siblingHash !== undefined) {
      proof.push({
        hash: siblingHash,
        position: leftSide ? "right" : "left",
      });
    }
    idx = Math.floor(idx / 2);
  }

  return proof;
}

export function verifyInclusion(
  path: string,
  sha256: string,
  proof: ProofStep[],
  root: string,
): boolean {
  let hash = leafHash(path, sha256);
  for (const step of proof) {
    hash =
      step.position === "left"
        ? nodeHash(step.hash, hash)
        : nodeHash(hash, step.hash);
  }
  return hash === root;
}

export function rootOf(digests: MemberDigest[]): string {
  return buildMerkle(digests).root;
}
