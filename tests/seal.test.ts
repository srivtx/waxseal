import { describe, expect, test } from "bun:test";
import { strToU8, zipSync } from "fflate";
import type { Seal } from "../src/types.ts";
import {
  buildWacz,
  defaultWacz,
  type WaczMember,
} from "../src/fixtures.ts";
import { memberDigests } from "../src/wacz.ts";
import { rootOf, verifyInclusion } from "../src/merkle.ts";
import {
  canonicalPayload,
  createInclusionProofs,
  createSeal,
  sealFromJson,
  sealToJson,
} from "../src/seal.ts";
import {
  validateSeal,
  verifySeal,
  verifySealJson,
  verifySealSignature,
} from "../src/verify.ts";
import {
  generateKeyPair,
  publicKeyBase64,
  publicKeyFingerprint,
} from "../src/keys.ts";

const CREATED_AT = "2024-01-01T00:00:00.000Z";

const BASE_MEMBERS: WaczMember[] = [
  { path: "archive/data.warc.gz", data: "warc-gzip-placeholder-bytes" },
  { path: "pages/pages.jsonl", data: `{"url":"https://example.com"}\n` },
  {
    path: "indexes/index.cdx",
    data: `com,example)/ 20240101000000 {"url":"https://example.com"}\n`,
  },
];

function zipInOrder(entries: Array<[string, string]>): Uint8Array {
  const files: Record<string, Uint8Array> = {};
  for (const [path, text] of entries) files[path] = strToU8(text);
  return zipSync(files);
}

describe("canonicalPayload", () => {
  test("serializes fixed keys in fixed order without spaces", () => {
    const payload = new TextDecoder().decode(
      canonicalPayload({
        version: 1,
        algorithm: "ed25519",
        root: "abc",
        memberCount: 2,
        merkle: "sha256-domain-separated-sorted",
        createdAt: CREATED_AT,
      }),
    );
    expect(payload).toBe(
      `{"version":1,"algorithm":"ed25519","root":"abc","memberCount":2,"merkle":"sha256-domain-separated-sorted","createdAt":"${CREATED_AT}"}`,
    );
  });
});

describe("createSeal / verifySeal", () => {
  test("round trip verifies and survives JSON", () => {
    const keys = generateKeyPair();
    const data = defaultWacz();
    const seal = createSeal(
      data,
      keys.privateKeyPem,
      keys.publicKeyPem,
      CREATED_AT,
    );

    expect(seal.version).toBe(1);
    expect(seal.algorithm).toBe("ed25519");
    expect(seal.merkle).toBe("sha256-domain-separated-sorted");
    expect(seal.createdAt).toBe(CREATED_AT);
    expect(seal.memberCount).toBe(memberDigests(data).length);

    const result = verifySeal(seal, data);
    expect(result.ok).toBe(true);
    expect(result.signatureOk).toBe(true);
    expect(result.root).toBe(seal.root);
    expect(result.added).toEqual([]);
    expect(result.removed).toEqual([]);
    expect(result.modified).toEqual([]);

    const json = sealToJson(seal);
    expect(sealFromJson(json).signature).toBe(seal.signature);
    expect(verifySealJson(json, data).ok).toBe(true);
    expect(verifySeal(seal, data, { expectedRoot: seal.root }).ok).toBe(true);
  });

  test("tampered archive fails and reports modified member", () => {
    const keys = generateKeyPair();
    const original = defaultWacz();
    const previous = memberDigests(original);
    const seal = createSeal(
      original,
      keys.privateKeyPem,
      keys.publicKeyPem,
      CREATED_AT,
    );

    const tampered = buildWacz(
      BASE_MEMBERS.map((member) =>
        member.path === "pages/pages.jsonl"
          ? { ...member, data: member.data.replace("example.com", "evil.test") }
          : { ...member },
      ),
    );

    const result = verifySeal(seal, tampered, { previous });
    expect(result.signatureOk).toBe(true);
    expect(result.ok).toBe(false);
    expect(result.root).not.toBe(seal.root);
    expect(result.modified).toContain("pages/pages.jsonl");
    expect(result.reasons.length).toBeGreaterThan(0);
  });

  test("wrong public key makes signatureOk false", () => {
    const keys = generateKeyPair();
    const other = generateKeyPair();
    const data = defaultWacz();
    const seal = createSeal(
      data,
      keys.privateKeyPem,
      keys.publicKeyPem,
      CREATED_AT,
    );

    const swapped: Seal = {
      ...seal,
      publicKey: publicKeyBase64(other.publicKeyPem),
    };

    const result = verifySeal(swapped, data);
    expect(result.signatureOk).toBe(false);
    expect(result.ok).toBe(false);
  });

  test("re-zipping the same members in another order yields the same root", () => {
    const keys = generateKeyPair();
    const entries: Array<[string, string]> = [
      ["a.txt", "alpha"],
      ["b.txt", "beta"],
      ["c.txt", "gamma"],
    ];
    const forward = zipInOrder(entries);
    const reversed = zipInOrder([...entries].reverse());

    const sealForward = createSeal(
      forward,
      keys.privateKeyPem,
      keys.publicKeyPem,
      CREATED_AT,
    );
    const sealReversed = createSeal(
      reversed,
      keys.privateKeyPem,
      keys.publicKeyPem,
      CREATED_AT,
    );

    expect(sealForward.root).toBe(sealReversed.root);
    expect(rootOf(memberDigests(forward))).toBe(
      rootOf(memberDigests(reversed)),
    );
    expect(verifySeal(sealForward, reversed).ok).toBe(true);
    expect(verifySeal(sealReversed, forward).ok).toBe(true);
  });
  test("strictBytes catches a trailing-byte change that member-only allows", () => {
    const keys = generateKeyPair();
    const data = defaultWacz();
    const seal = createSeal(
      data,
      keys.privateKeyPem,
      keys.publicKeyPem,
      CREATED_AT,
    );

    const appended = new Uint8Array(data.length + 1);
    appended.set(data);
    appended[data.length] = 0x78;

    expect(seal.archiveSha256).toBeDefined();
    expect(verifySeal(seal, appended).ok).toBe(true);
    const strict = verifySeal(seal, appended, { strictBytes: true });
    expect(strict.ok).toBe(false);
    expect(
      strict.reasons.some((reason) => reason.includes("archive bytes mismatch")),
    ).toBe(true);
  });

  test("archiveSha256 is covered by the signature", () => {
    const keys = generateKeyPair();
    const data = defaultWacz();
    const seal = createSeal(
      data,
      keys.privateKeyPem,
      keys.publicKeyPem,
      CREATED_AT,
    );

    const edited: Seal = { ...seal, archiveSha256: "0".repeat(64) };
    expect(verifySeal(edited, data).signatureOk).toBe(false);
  });

  test("a malformed archive yields a structured failure, not a throw", () => {
    const keys = generateKeyPair();
    const seal = createSeal(
      defaultWacz(),
      keys.privateKeyPem,
      keys.publicKeyPem,
      CREATED_AT,
    );

    const result = verifySeal(
      seal,
      new TextEncoder().encode("this is not a zip"),
    );
    expect(result.ok).toBe(false);
    expect(result.reasons[0]).toContain("failed to read archive");
  });

  test("strictBytes fails when the seal carries no archiveSha256", () => {
    const keys = generateKeyPair();
    const data = defaultWacz();
    const seal = createSeal(
      data,
      keys.privateKeyPem,
      keys.publicKeyPem,
      CREATED_AT,
    );
    const withoutBytes: Seal = { ...seal };
    delete withoutBytes.archiveSha256;

    const result = verifySeal(withoutBytes, data, { strictBytes: true });
    expect(result.ok).toBe(false);
    expect(
      result.reasons.some((reason) => reason.includes("no archiveSha256")),
    ).toBe(true);
  });

  test("expectedPublicKey must match the embedded key", () => {
    const keys = generateKeyPair();
    const other = generateKeyPair();
    const data = defaultWacz();
    const seal = createSeal(
      data,
      keys.privateKeyPem,
      keys.publicKeyPem,
      CREATED_AT,
    );

    const good = verifySeal(seal, data, {
      expectedPublicKey: keys.publicKeyPem,
    });
    expect(good.ok).toBe(true);
    expect(good.expectedPublicKeyOk).toBe(true);
    expect(good.trusted).toBe(true);

    const bad = verifySeal(seal, data, {
      expectedPublicKey: other.publicKeyPem,
    });
    expect(bad.ok).toBe(false);
    expect(bad.expectedPublicKeyOk).toBe(false);
    expect(bad.trusted).toBe(false);
  });

  test("expectedRoot must match the computed root", () => {
    const keys = generateKeyPair();
    const data = defaultWacz();
    const seal = createSeal(
      data,
      keys.privateKeyPem,
      keys.publicKeyPem,
      CREATED_AT,
    );

    const good = verifySeal(seal, data, { expectedRoot: seal.root });
    expect(good.ok).toBe(true);
    expect(good.trusted).toBe(true);
    const bad = verifySeal(seal, data, { expectedRoot: "0".repeat(64) });
    expect(bad.ok).toBe(false);
    expect(bad.expectedRootOk).toBe(false);
    expect(bad.trusted).toBe(false);
  });

  test("verify reports a fingerprint of the SPKI key", () => {
    const keys = generateKeyPair();
    const data = defaultWacz();
    const seal = createSeal(
      data,
      keys.privateKeyPem,
      keys.publicKeyPem,
      CREATED_AT,
    );

    const result = verifySeal(seal, data);
    expect(result.fingerprint).toBe(publicKeyFingerprint(keys.publicKeyPem));
  });

  test("a tampered member fails even when trusted against the same key", () => {
    const keys = generateKeyPair();
    const original = defaultWacz();
    const seal = createSeal(
      original,
      keys.privateKeyPem,
      keys.publicKeyPem,
      CREATED_AT,
    );

    const tampered = buildWacz(
      BASE_MEMBERS.map((member) =>
        member.path === "indexes/index.cdx"
          ? { ...member, data: "tampered index\n" }
          : { ...member },
      ),
    );
    expect(
      verifySeal(seal, tampered, { expectedPublicKey: keys.publicKeyPem }).ok,
    ).toBe(false);
  });
});

describe("validateSeal", () => {
  test("accepts a well-formed seal", () => {
    const keys = generateKeyPair();
    const seal = createSeal(
      defaultWacz(),
      keys.privateKeyPem,
      keys.publicKeyPem,
      CREATED_AT,
    );
    expect(validateSeal(JSON.parse(sealToJson(seal))).ok).toBe(true);
    expect(verifySealSignature(seal)).toBe(true);
  });

  test("rejects null, arrays, and wrong-typed fields", () => {
    expect(validateSeal(null).ok).toBe(false);
    expect(validateSeal([]).ok).toBe(false);
    expect(validateSeal({ version: 1 }).ok).toBe(false);
    expect(validateSeal("seal").ok).toBe(false);
  });

  test("rejects unknown version, algorithm, and merkle constructions", () => {
    const keys = generateKeyPair();
    const seal = createSeal(
      defaultWacz(),
      keys.privateKeyPem,
      keys.publicKeyPem,
      CREATED_AT,
    );
    expect(validateSeal({ ...seal, version: 2 }).ok).toBe(false);
    expect(validateSeal({ ...seal, algorithm: "rsa" }).ok).toBe(false);
    expect(validateSeal({ ...seal, merkle: "sha256-flat" }).ok).toBe(false);
  });

  test("verifySealJson returns a structured failure for a null seal", () => {
    const result = verifySealJson("null", defaultWacz());
    expect(result.ok).toBe(false);
    expect(result.reasons[0]).toContain("seal");
  });

  test("verifySealJson returns a structured failure for invalid JSON", () => {
    const result = verifySealJson("{not json", defaultWacz());
    expect(result.ok).toBe(false);
    expect(result.reasons[0]).toContain("invalid seal JSON");
  });
});

describe("createInclusionProofs", () => {
  test("every member proof verifies against the root", () => {
    const data = defaultWacz();
    const digests = memberDigests(data);
    const root = rootOf(digests);
    const proofs = createInclusionProofs(data);

    expect(Object.keys(proofs).sort()).toEqual(
      digests.map((d) => d.path).sort(),
    );

    for (const digest of digests) {
      const proof = proofs[digest.path];
      expect(proof).toBeDefined();
      expect(
        verifyInclusion(digest.path, digest.sha256, proof ?? [], root),
      ).toBe(true);
    }
  });
});
