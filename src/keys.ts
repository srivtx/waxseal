import {
  createHash,
  createPrivateKey,
  createPublicKey,
  generateKeyPairSync,
  sign,
  verify,
} from "node:crypto";

export interface KeyPairPem {
  publicKeyPem: string;
  privateKeyPem: string;
}

export function generateKeyPair(): KeyPairPem {
  const { publicKey, privateKey } = generateKeyPairSync("ed25519");
  return {
    publicKeyPem: publicKey.export({ type: "spki", format: "pem" }).toString(),
    privateKeyPem: privateKey
      .export({ type: "pkcs8", format: "pem" })
      .toString(),
  };
}

export function publicKeyBase64(pem: string): string {
  const key = createPublicKey(pem);
  const der = key.export({ type: "spki", format: "der" });
  return Buffer.from(der).toString("base64");
}

/**
 * Accepts either a PEM SPKI public key or a base64-encoded DER SPKI public key
 * (the form stored in a seal) and returns its raw DER bytes.
 */
export function publicKeyDer(publicKey: string): Buffer {
  const trimmed = publicKey.trim();
  const key = trimmed.includes("-----BEGIN")
    ? createPublicKey(trimmed)
    : createPublicKey({
        key: Buffer.from(trimmed, "base64"),
        format: "der",
        type: "spki",
      });
  return Buffer.from(key.export({ type: "spki", format: "der" }));
}

/**
 * SHA-256 of the SPKI DER encoding, hex encoded. This is the value a user can
 * pin out of band to identify a signing key independently of any seal.
 */
export function publicKeyFingerprint(publicKey: string): string {
  return createHash("sha256").update(publicKeyDer(publicKey)).digest("hex");
}

export function publicKeyEquals(left: string, right: string): boolean {
  return publicKeyDer(left).equals(publicKeyDer(right));
}

export function signData(data: Uint8Array, privateKeyPem: string): string {
  const key = createPrivateKey(privateKeyPem);
  const signature = sign(null, data, key);
  return Buffer.from(signature).toString("base64");
}

export function verifyData(
  data: Uint8Array,
  signatureBase64: string,
  publicKeyBase64: string,
): boolean {
  try {
    const key = createPublicKey({
      key: Buffer.from(publicKeyBase64, "base64"),
      format: "der",
      type: "spki",
    });
    const signature = Buffer.from(signatureBase64, "base64");
    return verify(null, data, key, signature);
  } catch {
    return false;
  }
}
