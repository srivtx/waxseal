/// <reference types="bun" />
import { describe, expect, test } from "bun:test";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { buildWacz, defaultWacz } from "../src/fixtures.ts";
import { createSeal } from "../src/seal.ts";
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
