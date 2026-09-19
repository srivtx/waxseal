#!/usr/bin/env bun
/// <reference types="bun" />

import { createPublicKey } from "node:crypto";
import { generateKeyPair, publicKeyBase64 } from "./keys.ts";
import {
  createInclusionProofs,
  createSeal,
  sealToJson,
} from "./seal.ts";
import { verifySealJson } from "./verify.ts";
import { inspectWacz, memberDigests } from "./wacz.ts";
import { buildMerkle, verifyInclusion } from "./merkle.ts";
import type { ProofStep } from "./types.ts";

const USAGE = `waxseal — detached Ed25519 seals for WACZ web archives

Usage:
  waxseal <command> [options]

Commands:
  keygen [--out <base>]                 Generate an Ed25519 key pair
                                        (default base: waxseal-key)
  seal <archive.wacz> [--key <pem>] [--out <seal.json>] [--proofs <proofs.json>] [--json]
                                        Create a detached seal for an archive
  verify <archive.wacz> -s <seal.json> [--json] [--member-only]
                                        Verify an archive against a seal
                                        (default: strict byte-level check;
                                        --member-only allows a re-zip)
  proof-verify <archive.wacz> --proofs <proofs.json> [--path <member>] [--json]
                                        Verify Merkle inclusion proofs against
                                        the archive's rebuilt root
                                        (default: every proof in the file)
  inspect <archive.wacz> [--json]       Inspect members, digest status, root

Options:
  -s, --seal <file>                     Seal file for the verify command
  --proofs <file>                       Proofs file (seal, proof-verify)
  --path <member>                       Only verify this proof (proof-verify)
  --json                                Machine-readable output (seal, verify,
                                        proof-verify, inspect)
  -h, --help                            Show this help
  -v, --version                         Show the version
`;

interface ParsedArgs {
  positionals: string[];
  options: Map<string, string>;
}

function parseArgs(argv: string[]): ParsedArgs {
  const positionals: string[] = [];
  const options = new Map<string, string>();

  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i]!;
    if (!arg.startsWith("-") || arg === "-") {
      positionals.push(arg);
      continue;
    }

    const eq = arg.indexOf("=");
    if (eq !== -1) {
      options.set(arg.slice(0, eq), arg.slice(eq + 1));
      continue;
    }

    const next = argv[i + 1];
    if (next !== undefined && !next.startsWith("-")) {
      options.set(arg, next);
      i++;
    } else {
      options.set(arg, "");
    }
  }

  return { positionals, options };
}

function getOption(
  options: Map<string, string>,
  ...names: string[]
): string | undefined {
  for (const name of names) {
    if (options.has(name)) return options.get(name);
  }
  return undefined;
}

function hasFlag(options: Map<string, string>, ...names: string[]): boolean {
  return names.some((name) => options.has(name));
}

function fail(message: string): number {
  process.stderr.write(`${message}\n`);
  return 1;
}

function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}

async function packageVersion(): Promise<string> {
  try {
    const pkg = (await Bun.file(
      new URL("../package.json", import.meta.url),
    ).json()) as { version?: string };
    return pkg.version ?? "0.0.0";
  } catch {
    return "0.0.0";
  }
}

async function readBytes(path: string): Promise<Uint8Array> {
  return new Uint8Array(await Bun.file(path).arrayBuffer());
}

function parseProof(value: unknown): ProofStep[] {
  if (!Array.isArray(value)) {
    throw new Error("proof is not an array");
  }
  return value.map((item) => {
    if (typeof item !== "string") {
      throw new Error("proof step is not a string");
    }
    const step = JSON.parse(item) as Partial<ProofStep> | null;
    if (
      !step ||
      typeof step.hash !== "string" ||
      (step.position !== "left" && step.position !== "right")
    ) {
      throw new Error("invalid proof step");
    }
    return { hash: step.hash, position: step.position };
  });
}

function publicPemFromPrivate(privateKeyPem: string): string {
  return createPublicKey(privateKeyPem)
    .export({ type: "spki", format: "pem" })
    .toString();
}

async function cmdKeygen(args: ParsedArgs): Promise<number> {
  const out = getOption(args.options, "--out") ?? "waxseal-key";
  const { publicKeyPem, privateKeyPem } = generateKeyPair();

  await Bun.write(`${out}.pem`, privateKeyPem);
  await Bun.write(`${out}.pub.pem`, publicKeyPem);

  console.log(publicKeyBase64(publicKeyPem));
  return 0;
}

async function cmdSeal(args: ParsedArgs): Promise<number> {
  const archive = args.positionals[0];
  if (!archive) return fail("seal: missing <archive.wacz>");

  const out = getOption(args.options, "--out") ?? `${archive}.seal.json`;
  const proofsPath = getOption(args.options, "--proofs");
  const keyPath = getOption(args.options, "--key");

  const data = await readBytes(archive);

  let privateKeyPem: string;
  let publicKeyPem: string;
  let generated = false;

  if (keyPath) {
    privateKeyPem = await Bun.file(keyPath).text();
    publicKeyPem = publicPemFromPrivate(privateKeyPem);
  } else {
    const pair = generateKeyPair();
    privateKeyPem = pair.privateKeyPem;
    publicKeyPem = pair.publicKeyPem;
    generated = true;
  }

  const seal = createSeal(data, privateKeyPem, publicKeyPem);
  await Bun.write(out, sealToJson(seal));

  if (generated) {
    const keyOut = `${archive}.key.pem`;
    await Bun.write(keyOut, privateKeyPem);
    await Bun.write(`${archive}.key.pub.pem`, publicKeyPem);

    console.warn("WARNING: no --key was provided; a NEW key pair was generated.");
    console.warn(`  private key: ${keyOut}`);
    console.warn(`  public key:  ${archive}.key.pub.pem`);
    console.warn("  Keep the private key safe; it is required to sign again.");
  }

  if (proofsPath) {
    const proofs = createInclusionProofs(data);
    await Bun.write(proofsPath, JSON.stringify(proofs, null, 2));
  }

  if (hasFlag(args.options, "--json")) {
    console.log(sealToJson(seal));
    return 0;
  }

  console.log(`archive:     ${archive}`);
  console.log(`seal:        ${out}`);
  console.log(`root:        ${seal.root}`);
  console.log(`memberCount: ${seal.memberCount}`);
  console.log(`algorithm:   ${seal.algorithm}`);
  console.log(`signature:   ${seal.signature.slice(0, 24)}...`);
  return 0;
}

async function cmdVerify(args: ParsedArgs): Promise<number> {
  const archive = args.positionals[0];
  if (!archive) return fail("verify: missing <archive.wacz>");

  const sealPath = getOption(args.options, "-s", "--seal");
  if (!sealPath) return fail("verify: missing -s <seal.json>");

  const data = await readBytes(archive);
  const sealJson = await Bun.file(sealPath).text();
  const result = verifySealJson(sealJson, data, {
    strictBytes: !hasFlag(args.options, "--member-only"),
  });

  if (hasFlag(args.options, "--json")) {
    console.log(JSON.stringify(result, null, 2));
    return result.ok ? 0 : 1;
  }

  console.log(result.ok ? "OK" : "FAILED");
  console.log(`root:      ${result.root ?? "(unknown)"}`);
  console.log(`signature: ${result.signatureOk ? "valid" : "invalid"}`);

  if (result.added.length > 0) {
    console.log(`added:     ${result.added.join(", ")}`);
  }
  if (result.removed.length > 0) {
    console.log(`removed:   ${result.removed.join(", ")}`);
  }
  if (result.modified.length > 0) {
    console.log(`modified:  ${result.modified.join(", ")}`);
  }
  for (const reason of result.reasons) {
    console.log(`reason:    ${reason}`);
  }

  return result.ok ? 0 : 1;
}

interface ProofVerifyEntry {
  path: string;
  ok: boolean;
  reason?: string;
}

async function cmdProofVerify(args: ParsedArgs): Promise<number> {
  const archive = args.positionals[0];
  if (!archive) return fail("proof-verify: missing <archive.wacz>");

  const proofsPath = getOption(args.options, "--proofs");
  if (!proofsPath) return fail("proof-verify: missing --proofs <proofs.json>");

  const pathFilter = getOption(args.options, "--path");

  const data = await readBytes(archive);
  const digests = memberDigests(data);
  const root = buildMerkle(digests).root;
  const digestByPath = new Map(digests.map((d) => [d.path, d.sha256]));

  let raw: unknown;
  try {
    raw = JSON.parse(await Bun.file(proofsPath).text());
  } catch (error) {
    return fail(
      `proof-verify: failed to read ${proofsPath}: ${errorMessage(error)}`,
    );
  }

  if (!raw || typeof raw !== "object" || Array.isArray(raw)) {
    return fail(
      "proof-verify: proofs JSON must be an object mapping path to ProofStep[]",
    );
  }
  const proofs = raw as Record<string, unknown>;

  if (pathFilter && !Object.hasOwn(proofs, pathFilter)) {
    return fail(
      `proof-verify: no proof for path "${pathFilter}" in ${proofsPath}`,
    );
  }

  const requested = pathFilter ? [pathFilter] : Object.keys(proofs).sort();
  const results: ProofVerifyEntry[] = [];

  for (const path of requested) {
    const sha256 = digestByPath.get(path);
    if (sha256 === undefined) {
      results.push({ path, ok: false, reason: "member not present in archive" });
      continue;
    }

    let proof: ProofStep[];
    try {
      proof = parseProof(proofs[path]);
    } catch (error) {
      results.push({ path, ok: false, reason: errorMessage(error) });
      continue;
    }

    results.push(
      verifyInclusion(path, sha256, proof, root)
        ? { path, ok: true }
        : { path, ok: false, reason: "inclusion proof did not match root" },
    );
  }

  const ok = results.length > 0 && results.every((entry) => entry.ok);

  if (hasFlag(args.options, "--json")) {
    console.log(JSON.stringify({ archive, root, ok, results }, null, 2));
    return ok ? 0 : 1;
  }

  console.log(`archive: ${archive}`);
  console.log(`root:    ${root}`);
  for (const entry of results) {
    const suffix = entry.reason ? ` — ${entry.reason}` : "";
    console.log(`${entry.ok ? "OK  " : "FAIL"} ${entry.path}${suffix}`);
  }

  return ok ? 0 : 1;
}

async function cmdInspect(args: ParsedArgs): Promise<number> {
  const archive = args.positionals[0];
  if (!archive) return fail("inspect: missing <archive.wacz>");

  const data = await readBytes(archive);
  const inspection = inspectWacz(data);
  const root = buildMerkle(inspection.members).root;
  const resources = inspection.resources.length;

  if (hasFlag(args.options, "--json")) {
    console.log(
      JSON.stringify({ ...inspection, root, resourceCount: resources }, null, 2),
    );
    return inspection.issues.length === 0 ? 0 : 1;
  }

  console.log(`archive:            ${archive}`);
  console.log(`datapackage digest: ${inspection.digestOk ? "OK" : "FAILED"}`);
  console.log(`member count:       ${inspection.members.length}`);
  console.log(`resource count:     ${resources}`);
  console.log(`merkle root:        ${root}`);
  if (inspection.datapackagePath) {
    console.log(`datapackage:        ${inspection.datapackagePath}`);
  }
  for (const issue of inspection.issues) {
    console.log(`issue:              ${issue}`);
  }

  return inspection.issues.length === 0 ? 0 : 1;
}

async function main(): Promise<number> {
  const argv = process.argv.slice(2);

  if (argv.length === 0) {
    process.stderr.write(USAGE);
    return 2;
  }

  const parsed = parseArgs(argv);
  if (hasFlag(parsed.options, "-v", "--version")) {
    process.stdout.write(`waxseal ${await packageVersion()}\n`);
    return 0;
  }
  if (hasFlag(parsed.options, "-h", "--help")) {
    process.stdout.write(USAGE);
    return 0;
  }

  const command = parsed.positionals.shift();

  switch (command) {
    case "keygen":
      return cmdKeygen(parsed);
    case "seal":
      return cmdSeal(parsed);
    case "verify":
      return cmdVerify(parsed);
    case "proof-verify":
      return cmdProofVerify(parsed);
    case "inspect":
      return cmdInspect(parsed);
    default:
      process.stderr.write(`unknown command: ${String(command)}\n\n${USAGE}`);
      return 2;
  }
}

if (import.meta.main) {
  main()
    .then((code) => process.exit(code))
    .catch((error: unknown) => {
      process.stderr.write(
        `${error instanceof Error ? error.message : String(error)}\n`,
      );
      process.exit(1);
    });
}
