import {
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
