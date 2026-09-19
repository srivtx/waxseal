import type {
  MemberDigest,
  MerkleTree,
  ProofDocument,
  ProofStep,
  Seal,
} from "./types.ts";
import { buildMerkle, proveInclusion } from "./merkle.ts";
import { publicKeyBase64, signData } from "./keys.ts";
import { memberDigests, sha256Hex } from "./wacz.ts";

export const PROOF_VERSION = 1 as const;

export const SEAL_VERSION = 1 as const;
export const SEAL_ALGORITHM = "ed25519" as const;
export const SEAL_MERKLE = "sha256-domain-separated-sorted" as const;

export interface SealPayloadFields {
  version: number;
  algorithm: string;
  root: string;
  memberCount: number;
  merkle: string;
  createdAt: string;
  archiveSha256?: string;
}

export function canonicalPayload(sealFields: SealPayloadFields): Uint8Array {
  const ordered: Record<string, unknown> = {
    version: sealFields.version,
    algorithm: sealFields.algorithm,
    root: sealFields.root,
    memberCount: sealFields.memberCount,
    merkle: sealFields.merkle,
    createdAt: sealFields.createdAt,
  };
  if (sealFields.archiveSha256) ordered.archiveSha256 = sealFields.archiveSha256;
  return new TextEncoder().encode(JSON.stringify(ordered));
}

function sealRoot(digests: MemberDigest[]): string {
  const tree: MerkleTree = buildMerkle(digests);
  return tree.root;
}

export function createSeal(
  data: Uint8Array,
  privateKeyPem: string,
  publicKeyPem: string,
  createdAt: string = new Date().toISOString(),
): Seal {
  const digests = memberDigests(data);
  const root = sealRoot(digests);
  const archiveSha256 = sha256Hex(data);
  const payload = canonicalPayload({
    version: SEAL_VERSION,
    algorithm: SEAL_ALGORITHM,
    root,
    memberCount: digests.length,
    merkle: SEAL_MERKLE,
    createdAt,
    archiveSha256,
  });

  return {
    version: SEAL_VERSION,
    algorithm: SEAL_ALGORITHM,
    root,
    memberCount: digests.length,
    merkle: SEAL_MERKLE,
    createdAt,
    archiveSha256,
    publicKey: publicKeyBase64(publicKeyPem),
    signature: signData(payload, privateKeyPem),
  };
}

export function sealToJson(seal: Seal): string {
  return JSON.stringify(seal, null, 2);
}

export function sealFromJson(text: string): Seal {
  return JSON.parse(text) as Seal;
}

export function createInclusionProofs(
  data: Uint8Array,
): Record<string, ProofStep[]> {
  const digests = memberDigests(data);
  const tree = buildMerkle(digests);
  const proofs: Record<string, ProofStep[]> = {};

  for (const digest of digests) {
    proofs[digest.path] = proveInclusion(tree, digest.path) ?? [];
  }

  return proofs;
}

export function createProofDocument(data: Uint8Array): ProofDocument {
  const digests = memberDigests(data);
  const tree = buildMerkle(digests);
  const proofs: ProofDocument["proofs"] = {};

  for (const digest of digests) {
    proofs[digest.path] = {
      sha256: digest.sha256,
      steps: proveInclusion(tree, digest.path) ?? [],
    };
  }

  return { version: PROOF_VERSION, root: tree.root, proofs };
}
