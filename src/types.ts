export interface MemberDigest {
  path: string;
  sha256: string;
  size: number;
}

export interface DatapackageResource {
  path: string;
  hash?: string;
  bytes?: number;
}

export interface WaczInspection {
  members: MemberDigest[];
  datapackagePath?: string;
  resources: DatapackageResource[];
  digestOk: boolean;
  issues: string[];
}

export interface MerkleTree {
  root: string;
  levels: string[][];
  leafOrder: string[];
}

export interface ProofStep {
  hash: string;
  position: "left" | "right";
}

export interface Seal {
  version: 1;
  algorithm: "ed25519";
  root: string;
  memberCount: number;
  merkle: "sha256-domain-separated-sorted";
  createdAt: string;
  archiveSha256?: string;
  publicKey: string;
  signature: string;
}

export interface VerifyResult {
  ok: boolean;
  root?: string;
  reasons: string[];
  added: string[];
  removed: string[];
  modified: string[];
  signatureOk: boolean;
}
