/// <reference types="bun" />
import { describe, expect, test } from "bun:test";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { strToU8, zipSync } from "fflate";
import { buildWacz, defaultWacz } from "../src/fixtures.ts";
import { createSeal, createProofDocument } from "../src/seal.ts";
import { verifySeal } from "../src/verify.ts";
import { generateKeyPair, publicKeyBase64 } from "../src/keys.ts";

const CLI = join(import.meta.dir, "..", "src", "cli.ts");

interface CliResult {
  stdout: string;
  stderr: string;
  exitCode: number;
}

async function runCli(args: string[], cwd: string): Promise<CliResult> {
  const proc = Bun.spawn(["bun", CLI, ...args], {
    cwd,
    stdout: "pipe",
    stderr: "pipe",
  });
  const [stdout, stderr, exitCode] = await Promise.all([
    new Response(proc.stdout).text(),
    new Response(proc.stderr).text(),
    proc.exited,
  ]);
  return { stdout, stderr, exitCode };
}

describe("library round trip", () => {
  test("seal then verify is ok", () => {
    const archive = defaultWacz();
    const { privateKeyPem, publicKeyPem } = generateKeyPair();

    const seal = createSeal(archive, privateKeyPem, publicKeyPem);
    const result = verifySeal(seal, archive);

    expect(result.ok).toBe(true);
    expect(result.signatureOk).toBe(true);
    expect(result.root).toBe(seal.root);
    expect(result.modified).toHaveLength(0);
  });

  test("a tampered wacz fails", () => {
    const archive = defaultWacz();
    const { privateKeyPem, publicKeyPem } = generateKeyPair();
    const seal = createSeal(archive, privateKeyPem, publicKeyPem);

    const tampered = buildWacz([
      { path: "pages/pages.jsonl", data: `{"url":"https://evil.example"}\n` },
      { path: "archive/data.warc.gz", data: "warc-gzip-placeholder-bytes" },
      { path: "indexes/index.cdx", data: "tampered index\n" },
    ]);

    const result = verifySeal(seal, tampered);
    expect(result.ok).toBe(false);
  });

  test("keygen shape: seal public key equals base64 of generated pem", () => {
    const { privateKeyPem, publicKeyPem } = generateKeyPair();
    const expected = publicKeyBase64(publicKeyPem);
    expect(expected).toMatch(/^[A-Za-z0-9+/]+=*$/);

    const seal = createSeal(defaultWacz(), privateKeyPem, publicKeyPem);
    expect(seal.publicKey).toBe(expected);
  });
});

describe("cli round trip", () => {
  test("keygen + seal + verify succeeds", async () => {
    const dir = await mkdtemp(join(tmpdir(), "waxseal-cli-"));
    try {
      const archivePath = join(dir, "archive.wacz");
      const keyBase = join(dir, "key");
      const sealPath = join(dir, "seal.json");
      await Bun.write(archivePath, defaultWacz());

      const keygen = await runCli(["keygen", "--out", keyBase], dir);
      expect(keygen.exitCode).toBe(0);
      expect(keygen.stdout.trim().length).toBeGreaterThan(0);
      expect(await Bun.file(`${keyBase}.pem`).exists()).toBe(true);
      expect(await Bun.file(`${keyBase}.pub.pem`).exists()).toBe(true);

      const seal = await runCli(
        ["seal", archivePath, "--key", `${keyBase}.pem`, "--out", sealPath],
        dir,
      );
      expect(seal.exitCode).toBe(0);
      expect(seal.stdout).toContain("root:");

      const verify = await runCli(
        ["verify", archivePath, "-s", sealPath],
        dir,
      );
      expect(verify.exitCode).toBe(0);
      expect(verify.stdout).toContain("OK");
      expect(verify.stdout).toContain("signature: valid");
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  });

  test("verify exits 1 for a tampered archive", async () => {
    const dir = await mkdtemp(join(tmpdir(), "waxseal-cli-"));
    try {
      const archivePath = join(dir, "archive.wacz");
      const tamperedPath = join(dir, "tampered.wacz");
      const keyBase = join(dir, "key");
      const sealPath = join(dir, "seal.json");
      await Bun.write(archivePath, defaultWacz());
      await Bun.write(
        tamperedPath,
        buildWacz([{ path: "only.txt", data: "different" }]),
      );

      await runCli(["keygen", "--out", keyBase], dir);
      await runCli(
        ["seal", archivePath, "--key", `${keyBase}.pem`, "--out", sealPath],
        dir,
      );

      const verify = await runCli(
        ["verify", tamperedPath, "-s", sealPath],
        dir,
      );
      expect(verify.exitCode).toBe(1);
      expect(verify.stdout).toContain("FAILED");
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  });

  test("no arguments prints usage and exits 2", async () => {
    const result = await runCli([], process.cwd());
    expect(result.exitCode).toBe(2);
    expect(result.stderr).toContain("Usage:");
  });
});

describe("cli metadata", () => {
  test("--version prints the package version and exits 0", async () => {
    const result = await runCli(["--version"], process.cwd());
    expect(result.exitCode).toBe(0);
    expect(result.stdout.trim()).toMatch(/^waxseal \d+\.\d+\.\d+/);
  });

  test("--help lists the commands and exits 0", async () => {
    const result = await runCli(["--help"], process.cwd());
    expect(result.exitCode).toBe(0);
    expect(result.stdout).toContain("Usage:");
    expect(result.stdout).toContain("proof-verify");
  });
});

describe("cli proof verification", () => {
  test("seal --json writes the file and prints the seal JSON", async () => {
    const dir = await mkdtemp(join(tmpdir(), "waxseal-cli-"));
    try {
      const archivePath = join(dir, "archive.wacz");
      const keyBase = join(dir, "key");
      const sealPath = join(dir, "seal.json");
      await Bun.write(archivePath, defaultWacz());

      await runCli(["keygen", "--out", keyBase], dir);

      const seal = await runCli(
        [
          "seal",
          archivePath,
          "--key",
          `${keyBase}.pem`,
          "--out",
          sealPath,
          "--json",
        ],
        dir,
      );
      expect(seal.exitCode).toBe(0);

      const parsed = JSON.parse(seal.stdout) as {
        root?: string;
        signature?: string;
      };
      expect(parsed.root).toBeDefined();
      expect(parsed.signature).toBeDefined();
      expect(await Bun.file(sealPath).exists()).toBe(true);
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  });

  test("proof-verify checks every proof and honors --path", async () => {
    const dir = await mkdtemp(join(tmpdir(), "waxseal-cli-"));
    try {
      const archivePath = join(dir, "archive.wacz");
      const proofsPath = join(dir, "proofs.json");
      await Bun.write(archivePath, defaultWacz());

      const seal = await runCli(
        ["seal", archivePath, "--proofs", proofsPath],
        dir,
      );
      expect(seal.exitCode).toBe(0);
      expect(await Bun.file(proofsPath).exists()).toBe(true);

      const all = await runCli(
        ["proof-verify", archivePath, "--proofs", proofsPath],
        dir,
      );
      expect(all.exitCode).toBe(0);
      expect(all.stdout).toContain("OK");

      const single = await runCli(
        [
          "proof-verify",
          archivePath,
          "--proofs",
          proofsPath,
          "--path",
          "archive/data.warc.gz",
        ],
        dir,
      );
      expect(single.exitCode).toBe(0);
      expect(single.stdout).toContain("archive/data.warc.gz");

      const json = await runCli(
        ["proof-verify", archivePath, "--proofs", proofsPath, "--json"],
        dir,
      );
      expect(json.exitCode).toBe(0);
      const parsed = JSON.parse(json.stdout) as {
        ok?: boolean;
        results?: unknown[];
      };
      expect(parsed.ok).toBe(true);
      expect(parsed.results?.length).toBeGreaterThan(0);

      const missing = await runCli(
        [
          "proof-verify",
          archivePath,
          "--proofs",
          proofsPath,
          "--path",
          "not-a-member.txt",
        ],
        dir,
      );
      expect(missing.exitCode).toBe(1);
      expect(missing.stderr).toContain("no proof for path");
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  });
});

describe("cli trust boundary", () => {
  test("a seal verified with the wrong pinned key fails; the right one passes", async () => {
    const dir = await mkdtemp(join(tmpdir(), "waxseal-cli-"));
    try {
      const archivePath = join(dir, "archive.wacz");
      const keyA = join(dir, "a");
      const keyB = join(dir, "b");
      const sealPath = join(dir, "seal.json");
      await Bun.write(archivePath, defaultWacz());
      await runCli(["keygen", "--out", keyA], dir);
      await runCli(["keygen", "--out", keyB], dir);
      await runCli(
        ["seal", archivePath, "--key", `${keyA}.pem`, "--out", sealPath],
        dir,
      );

      const wrong = await runCli(
        ["verify", archivePath, "-s", sealPath, "--public-key", `${keyB}.pub.pem`],
        dir,
      );
      expect(wrong.exitCode).toBe(1);
      expect(wrong.stdout).toContain("FAILED");
      expect(wrong.stdout).toContain("fingerprint: sha256:");
      expect(wrong.stdout).toContain("expectedPublicKey");
      expect(wrong.stdout).toContain("trusted:     no");

      const right = await runCli(
        ["verify", archivePath, "-s", sealPath, "--public-key", `${keyA}.pub.pem`],
        dir,
      );
      expect(right.exitCode).toBe(0);
      expect(right.stdout).toContain("trusted:     yes");
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  });

  test("a seal verified with the wrong pinned root fails", async () => {
    const dir = await mkdtemp(join(tmpdir(), "waxseal-cli-"));
    try {
      const archivePath = join(dir, "archive.wacz");
      const keyBase = join(dir, "key");
      const sealPath = join(dir, "seal.json");
      await Bun.write(archivePath, defaultWacz());
      await runCli(["keygen", "--out", keyBase], dir);
      await runCli(
        ["seal", archivePath, "--key", `${keyBase}.pem`, "--out", sealPath],
        dir,
      );

      const bad = await runCli(
        ["verify", archivePath, "-s", sealPath, "--root", "0".repeat(64)],
        dir,
      );
      expect(bad.exitCode).toBe(1);
      expect(bad.stdout).toContain("expectedRoot");
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  });

  test("an unpinned self-signed seal is labelled untrusted, and pinning rejects it", async () => {
    const dir = await mkdtemp(join(tmpdir(), "waxseal-cli-"));
    try {
      const forgedPath = join(dir, "forged.wacz");
      const sealPath = join(dir, "forged.seal.json");
      const trustedKey = join(dir, "trusted");
      await Bun.write(
        forgedPath,
        buildWacz([{ path: "only.txt", data: "attacker archive" }]),
      );
      await runCli(["keygen", "--out", trustedKey], dir);

      const seal = await runCli(["seal", forgedPath, "--out", sealPath], dir);
      expect(seal.exitCode).toBe(0);

      const unpinned = await runCli(["verify", forgedPath, "-s", sealPath], dir);
      expect(unpinned.exitCode).toBe(0);
      expect(unpinned.stdout).toContain("OK");
      expect(unpinned.stdout).toContain("trusted:     no");
      expect(unpinned.stdout).toContain("fingerprint: sha256:");

      const pinned = await runCli(
        ["verify", forgedPath, "-s", sealPath, "--public-key", `${trustedKey}.pub.pem`],
        dir,
      );
      expect(pinned.exitCode).toBe(1);
      expect(pinned.stdout).toContain("FAILED");
      expect(pinned.stdout).toContain("trusted:     no");
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  });

  test("a seal with an unknown format is rejected", async () => {
    const dir = await mkdtemp(join(tmpdir(), "waxseal-cli-"));
    try {
      const archivePath = join(dir, "archive.wacz");
      const keyBase = join(dir, "key");
      const sealPath = join(dir, "seal.json");
      await Bun.write(archivePath, defaultWacz());
      await runCli(["keygen", "--out", keyBase], dir);
      await runCli(
        ["seal", archivePath, "--key", `${keyBase}.pem`, "--out", sealPath],
        dir,
      );

      const seal = JSON.parse(await Bun.file(sealPath).text()) as Record<
        string,
        unknown
      >;
      seal.version = 2;
      await Bun.write(sealPath, JSON.stringify(seal));

      const verify = await runCli(
        ["verify", archivePath, "-s", sealPath, "--json"],
        dir,
      );
      expect(verify.exitCode).toBe(1);
      const parsed = JSON.parse(verify.stdout) as { ok: boolean; reasons: string[] };
      expect(parsed.ok).toBe(false);
      expect(parsed.reasons[0]).toContain("version");
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  });
});

describe("cli proof-verify anchored to a seal", () => {
  test("proofs verify against seal.root, offline, and fail on tamper or wrong root", async () => {
    const dir = await mkdtemp(join(tmpdir(), "waxseal-cli-"));
    try {
      const archivePath = join(dir, "archive.wacz");
      const keyBase = join(dir, "key");
      const sealPath = join(dir, "seal.json");
      const proofsPath = join(dir, "proofs.json");
      await Bun.write(archivePath, defaultWacz());
      await runCli(["keygen", "--out", keyBase], dir);
      await runCli(
        ["seal", archivePath, "--key", `${keyBase}.pem`, "--out", sealPath],
        dir,
      );
      await runCli(
        ["seal", archivePath, "--key", `${keyBase}.pem`, "--proofs", proofsPath],
        dir,
      );

      const document = JSON.parse(await Bun.file(proofsPath).text()) as {
        root: string;
        proofs: Record<string, { sha256: string; steps: unknown[] }>;
      };
      const member = "archive/data.warc.gz";
      expect(document.root).toMatch(/^[0-9a-f]{64}$/);
      expect(document.proofs[member]?.sha256).toMatch(/^[0-9a-f]{64}$/);

      const anchored = await runCli(
        ["proof-verify", archivePath, "--proofs", proofsPath, "--seal", sealPath],
        dir,
      );
      expect(anchored.exitCode).toBe(0);

      const offline = await runCli(
        [
          "proof-verify",
          "--proofs",
          proofsPath,
          "--path",
          member,
          "--root",
          document.root,
          "--sha256",
          document.proofs[member]!.sha256,
        ],
        dir,
      );
      expect(offline.exitCode).toBe(0);
      expect(offline.stdout).toContain(member);

      const wrongRoot = await runCli(
        [
          "proof-verify",
          archivePath,
          "--proofs",
          proofsPath,
          "--root",
          "0".repeat(64),
        ],
        dir,
      );
      expect(wrongRoot.exitCode).toBe(1);

      const tamperedProofs = join(dir, "tampered-proofs.json");
      const tampered = structuredClone(document) as typeof document;
      const steps = tampered.proofs[member]!.steps as Array<{
        hash: string;
        position: string;
      }>;
      if (steps.length > 0) {
        steps[0]!.hash = "00".repeat(32);
      }
      await Bun.write(tamperedProofs, JSON.stringify(tampered));
      const tamperedResult = await runCli(
        ["proof-verify", archivePath, "--proofs", tamperedProofs],
        dir,
      );
      if (steps.length > 0) {
        expect(tamperedResult.exitCode).toBe(1);
      }
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  });

  test("an empty requested proof set is vacuously OK", async () => {
    const dir = await mkdtemp(join(tmpdir(), "waxseal-cli-"));
    try {
      const emptyPath = join(dir, "empty.wacz");
      const proofsPath = join(dir, "empty-proofs.json");
      await Bun.write(emptyPath, zipSync({}));

      const seal = await runCli(
        ["seal", emptyPath, "--proofs", proofsPath, "--json"],
        dir,
      );
      expect(seal.exitCode).toBe(0);

      const verify = await runCli(
        ["proof-verify", emptyPath, "--proofs", proofsPath, "--json"],
        dir,
      );
      expect(verify.exitCode).toBe(0);
      const parsed = JSON.parse(verify.stdout) as { ok: boolean; results: unknown[] };
      expect(parsed.ok).toBe(true);
      expect(parsed.results).toEqual([]);
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  });

  test("malformed archives produce JSON failures, not raw crashes", async () => {
    const dir = await mkdtemp(join(tmpdir(), "waxseal-cli-"));
    try {
      const archivePath = join(dir, "archive.wacz");
      const malformedPath = join(dir, "malformed.wacz");
      const keyBase = join(dir, "key");
      const sealPath = join(dir, "seal.json");
      const proofsPath = join(dir, "proofs.json");
      await Bun.write(archivePath, defaultWacz());
      await Bun.write(malformedPath, strToU8("this is not a zip"));
      await runCli(["keygen", "--out", keyBase], dir);
      await runCli(
        ["seal", archivePath, "--key", `${keyBase}.pem`, "--out", sealPath],
        dir,
      );
      await runCli(
        ["seal", archivePath, "--key", `${keyBase}.pem`, "--proofs", proofsPath],
        dir,
      );

      const verify = await runCli(
        ["verify", malformedPath, "-s", sealPath, "--json"],
        dir,
      );
      expect(verify.exitCode).toBe(1);
      const parsed = JSON.parse(verify.stdout) as { ok: boolean; reasons: string[] };
      expect(parsed.ok).toBe(false);
      expect(parsed.reasons.length).toBeGreaterThan(0);

      const proof = await runCli(
        ["proof-verify", malformedPath, "--proofs", proofsPath, "--json"],
        dir,
      );
      expect(proof.exitCode).toBe(1);
      const proofParsed = JSON.parse(proof.stdout) as { ok: boolean };
      expect(proofParsed.ok).toBe(false);
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  });
});

describe("cli robustness", () => {
  test("keygen refuses to overwrite an existing key without --force", async () => {
    const dir = await mkdtemp(join(tmpdir(), "waxseal-cli-"));
    try {
      const keyBase = join(dir, "key");
      const first = await runCli(["keygen", "--out", keyBase], dir);
      expect(first.exitCode).toBe(0);
      const original = await Bun.file(`${keyBase}.pem`).text();

      const again = await runCli(["keygen", "--out", keyBase], dir);
      expect(again.exitCode).toBe(1);
      expect(again.stderr).toContain("refusing to overwrite");
      expect(await Bun.file(`${keyBase}.pem`).text()).toBe(original);

      const forced = await runCli(["keygen", "--out", keyBase, "--force"], dir);
      expect(forced.exitCode).toBe(0);
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  });

  test("an empty --out value is an error", async () => {
    const dir = await mkdtemp(join(tmpdir(), "waxseal-cli-"));
    try {
      const result = await runCli(["keygen", "--out"], dir);
      expect(result.exitCode).toBe(2);
      expect(result.stderr).toContain("--out requires a value");
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  });

  test("--member-only=false does not relax strict byte checking", async () => {
    const dir = await mkdtemp(join(tmpdir(), "waxseal-cli-"));
    try {
      const archivePath = join(dir, "archive.wacz");
      const appendedPath = join(dir, "appended.wacz");
      const keyBase = join(dir, "key");
      const sealPath = join(dir, "seal.json");
      const archive = defaultWacz();
      await Bun.write(archivePath, archive);
      const appended = new Uint8Array(archive.length + 1);
      appended.set(archive);
      appended[archive.length] = 0x78;
      await Bun.write(appendedPath, appended);
      await runCli(["keygen", "--out", keyBase], dir);
      await runCli(
        ["seal", archivePath, "--key", `${keyBase}.pem`, "--out", sealPath],
        dir,
      );

      const strictFalse = await runCli(
        ["verify", appendedPath, "-s", sealPath, "--member-only=false"],
        dir,
      );
      expect(strictFalse.exitCode).toBe(1);

      const memberOnly = await runCli(
        ["verify", appendedPath, "-s", sealPath, "--member-only"],
        dir,
      );
      expect(memberOnly.exitCode).toBe(0);
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  });
});

describe("cli proof-verify tamper detection", () => {
  test("a tampered single-member archive with its original proofs fails", async () => {
    const dir = await mkdtemp(join(tmpdir(), "waxseal-cli-"));
    try {
      const archivePath = join(dir, "one.wacz");
      const tamperedPath = join(dir, "one.tampered.wacz");
      const proofsPath = join(dir, "one.proofs.json");
      const member = "datapackage.json";

      await Bun.write(
        archivePath,
        zipSync({ [member]: strToU8(JSON.stringify({ resources: [] })) }),
      );
      const seal = await runCli(
        ["seal", archivePath, "--proofs", proofsPath],
        dir,
      );
      expect(seal.exitCode).toBe(0);

      await Bun.write(
        tamperedPath,
        zipSync({
          [member]: strToU8(JSON.stringify({ resources: [{ path: "evil" }] })),
        }),
      );

      const result = await runCli(
        ["proof-verify", tamperedPath, "--proofs", proofsPath],
        dir,
      );
      expect(result.exitCode).toBe(1);
      expect(result.stdout).toContain("FAIL");
      expect(result.stdout).toContain("does not match");

      const json = await runCli(
        ["proof-verify", tamperedPath, "--proofs", proofsPath, "--json"],
        dir,
      );
      expect(json.exitCode).toBe(1);
      const parsed = JSON.parse(json.stdout) as {
        ok: boolean;
        reasons: string[];
      };
      expect(parsed.ok).toBe(false);
      expect(parsed.reasons.some((r) => r.includes("does not match"))).toBe(true);
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  });

  test("a proofs document whose declared root does not match the archive fails", async () => {
    const dir = await mkdtemp(join(tmpdir(), "waxseal-cli-"));
    try {
      const archivePath = join(dir, "archive.wacz");
      const proofsPath = join(dir, "proofs.json");
      const mismatchPath = join(dir, "mismatch-proofs.json");
      await Bun.write(archivePath, defaultWacz());

      const seal = await runCli(
        ["seal", archivePath, "--proofs", proofsPath],
        dir,
      );
      expect(seal.exitCode).toBe(0);

      const document = JSON.parse(await Bun.file(proofsPath).text()) as {
        root: string;
        proofs: unknown;
      };
      document.root = "f".repeat(64);
      await Bun.write(mismatchPath, JSON.stringify(document));

      const result = await runCli(
        ["proof-verify", archivePath, "--proofs", mismatchPath],
        dir,
      );
      expect(result.exitCode).toBe(1);
      expect(result.stdout).toContain("does not match");
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  });

  test("a legacy proofs document without a root fails closed unless pinned", async () => {
    const dir = await mkdtemp(join(tmpdir(), "waxseal-cli-"));
    try {
      const archivePath = join(dir, "archive.wacz");
      const barePath = join(dir, "bare-proofs.json");
      const archive = defaultWacz();
      await Bun.write(archivePath, archive);

      const document = createProofDocument(archive);
      const bare: Record<string, unknown> = {};
      for (const [path, entry] of Object.entries(document.proofs)) {
        bare[path] = entry.steps;
      }
      await Bun.write(barePath, JSON.stringify(bare));

      const unpinned = await runCli(
        ["proof-verify", archivePath, "--proofs", barePath],
        dir,
      );
      expect(unpinned.exitCode).toBe(1);
      expect(unpinned.stderr).toContain("no root");

      const anchored = await runCli(
        ["proof-verify", archivePath, "--proofs", barePath, "--root", document.root],
        dir,
      );
      expect(anchored.exitCode).toBe(0);
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  });
});

