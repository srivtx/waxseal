import { describe, expect, test } from "bun:test";
import { strToU8, zipSync } from "fflate";
import type { ProofStep, Seal } from "../src/types.ts";
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
import { verifySeal, verifySealJson } from "../src/verify.ts";
import { generateKeyPair, publicKeyBase64 } from "../src/keys.ts";

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
      const raw = proofs[digest.path];
      expect(raw).toBeDefined();
      const proof = (raw ?? []).map(
        (step) => JSON.parse(step) as ProofStep,
      );
      expect(
        verifyInclusion(digest.path, digest.sha256, proof, root),
      ).toBe(true);
    }
  });
});
