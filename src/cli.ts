#!/usr/bin/env bun
/// <reference types="bun" />

import { createPublicKey } from "node:crypto";
import { generateKeyPair, publicKeyBase64 } from "./keys.ts";
import {
  PROOF_VERSION,
  createProofDocument,
  createSeal,
  sealToJson,
} from "./seal.ts";
import { validateSeal, verifySealJson, verifySealSignature } from "./verify.ts";
import { inspectWacz, memberDigests } from "./wacz.ts";
import { buildMerkle, verifyInclusion } from "./merkle.ts";
import type { ProofStep, VerifyResult } from "./types.ts";

const USAGE = `waxseal — detached Ed25519 seals for WACZ web archives

Usage:
  waxseal <command> [options]

Commands:
  keygen [--out <base>] [--force]       Generate an Ed25519 key pair
                                        (default base: waxseal-key; refuses to
                                        overwrite unless --force/--yes)
  seal <archive.wacz> [--key <pem>] [--out <seal.json>] [--proofs <proofs.json>] [--json]
                                        Create a detached seal for an archive
  verify <archive.wacz> -s <seal.json> [--public-key <pem|base64>] [--root <hex>] [--json] [--member-only]
                                        Verify an archive against a seal.
                                        Pass --public-key or --root to pin a
                                        trusted key or root; without one the
                                        seal is only self-consistent. The SPKI
                                        key fingerprint is always printed.
                                        (default: strict byte-level check;
                                        --member-only allows a re-zip)
  proof-verify [<archive.wacz>] --proofs <proofs.json> [--seal <seal.json>] [--path <member>] [--root <hex>] [--sha256 <hex>] [--json]
                                        Verify Merkle inclusion proofs.
                                        With an archive, proofs are checked
                                        against its rebuilt root (or --seal /
                                        --root); without one, pass --root or
                                        --seal and the member's content hash
                                        (or use a proof file that records it)
  inspect <archive.wacz> [--json]       Inspect members, digest status, root

Options:
  -s, --seal <file>                     Seal file (verify, proof-verify)
  --proofs <file>                       Proofs file (seal, proof-verify)
  --path <member>                       Only verify this proof (proof-verify)
  --public-key <pem|base64>             Pin the expected SPKI public key (verify)
  --root <hex>                          Pin the expected Merkle root (verify, proof-verify)
  --sha256 <hex>                        Member content hash for offline proof-verify
  --force, --yes                        Overwrite existing key files (keygen)
  --json                                Machine-readable output (seal, verify,
                                        proof-verify, inspect)
  -h, --help                            Show this help
  -v, --version                         Show the version
`;

const VALUE_OPTIONS = [
  "--out",
  "--key",
  "-s",
  "--seal",
  "--proofs",
  "--path",
  "--public-key",
  "--root",
  "--sha256",
];

const HEX64 = /^[0-9a-f]{64}$/;

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

function flagEnabled(options: Map<string, string>, ...names: string[]): boolean {
  for (const name of names) {
    if (!options.has(name)) continue;
    const value = (options.get(name) ?? "").trim().toLowerCase();
    return !(value === "false" || value === "0" || value === "no");
  }
  return false;
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

function failureResult(reasons: string[]): VerifyResult {
  return {
    ok: false,
    reasons,
    added: [],
    removed: [],
    modified: [],
    signatureOk: false,
    expectedRootOk: false,
    expectedPublicKeyOk: false,
    trusted: false,
  };
}

function publicPemFromPrivate(privateKeyPem: string): string {
  return createPublicKey(privateKeyPem)
    .export({ type: "spki", format: "pem" })
    .toString();
}

async function resolvePublicKey(value: string): Promise<string> {
  const trimmed = value.trim();
  if (trimmed.includes("-----BEGIN")) return trimmed;
  try {
    const file = Bun.file(value);
    if (await file.exists()) return (await file.text()).trim();
  } catch {
    // fall through and treat the value as a literal key
  }
  return trimmed;
}

async function cmdKeygen(args: ParsedArgs): Promise<number> {
  const out = getOption(args.options, "--out") ?? "waxseal-key";
  const privatePath = `${out}.pem`;
  const publicPath = `${out}.pub.pem`;

  const overwrite = flagEnabled(args.options, "--force", "--yes");
  const existing = [];
  if (await Bun.file(privatePath).exists()) existing.push(privatePath);
  if (await Bun.file(publicPath).exists()) existing.push(publicPath);

  if (existing.length > 0 && !overwrite) {
    return fail(
      `keygen: refusing to overwrite ${existing.join(", ")}; pass --force to replace`,
    );
  }

  const { publicKeyPem, privateKeyPem } = generateKeyPair();
  await Bun.write(privatePath, privateKeyPem);
  await Bun.write(publicPath, publicKeyPem);

  console.log(publicKeyBase64(publicKeyPem));
  return 0;
}

async function cmdSeal(args: ParsedArgs): Promise<number> {
  const archive = args.positionals[0];
  if (!archive) return fail("seal: missing <archive.wacz>");

  const out = getOption(args.options, "--out") ?? `${archive}.seal.json`;
  const proofsPath = getOption(args.options, "--proofs");
  const keyPath = getOption(args.options, "--key");

  let data: Uint8Array;
  try {
    data = await readBytes(archive);
  } catch (error) {
    return fail(`seal: failed to read ${archive}: ${errorMessage(error)}`);
  }

  let privateKeyPem: string;
  let publicKeyPem: string;
  let generated = false;

  if (keyPath) {
    try {
      privateKeyPem = await Bun.file(keyPath).text();
      publicKeyPem = publicPemFromPrivate(privateKeyPem);
    } catch (error) {
      return fail(`seal: failed to read key ${keyPath}: ${errorMessage(error)}`);
    }
  } else {
    const pair = generateKeyPair();
    privateKeyPem = pair.privateKeyPem;
    publicKeyPem = pair.publicKeyPem;
    generated = true;
  }

  let seal;
  let proofs;
  try {
    seal = createSeal(data, privateKeyPem, publicKeyPem);
    if (proofsPath) proofs = createProofDocument(data);
  } catch (error) {
    return fail(`seal: failed to seal ${archive}: ${errorMessage(error)}`);
  }

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

  if (proofsPath && proofs) {
    await Bun.write(proofsPath, JSON.stringify(proofs, null, 2));
  }

  if (flagEnabled(args.options, "--json")) {
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

  const publicKey = getOption(args.options, "--public-key");
  const expectedRoot = getOption(args.options, "--root");
  if (expectedRoot !== undefined && !HEX64.test(expectedRoot)) {
    return fail("verify: --root must be a 64-character hex string");
  }

  let result: VerifyResult;
  try {
    const data = await readBytes(archive);
    const sealJson = await Bun.file(sealPath).text();
    const expectedPublicKey =
      publicKey === undefined ? undefined : await resolvePublicKey(publicKey);
    result = verifySealJson(sealJson, data, {
      strictBytes: !flagEnabled(args.options, "--member-only"),
      expectedRoot,
      expectedPublicKey,
    });
  } catch (error) {
    result = failureResult([errorMessage(error)]);
  }

  if (flagEnabled(args.options, "--json")) {
    console.log(JSON.stringify(result, null, 2));
    return result.ok ? 0 : 1;
  }

  console.log(result.ok ? "OK" : "FAILED");
  console.log(`root:        ${result.root ?? "(unknown)"}`);
  console.log(`signature: ${result.signatureOk ? "valid" : "invalid"}`);
  console.log(
    `fingerprint: sha256:${result.fingerprint ?? "(unavailable)"}`,
  );
  if (result.trusted) {
    console.log("trusted:     yes (pinned by --public-key/--root)");
  } else {
    console.log(
      "trusted:     no — self-signed seal; pin it with --public-key or --root",
    );
  }
  for (const reason of result.reasons) {
    console.log(`reason:      ${reason}`);
  }

  return result.ok ? 0 : 1;
}

interface ProofVerifyEntry {
  path: string;
  ok: boolean;
  sha256?: string;
  reason?: string;
}

interface NormalizedProof {
  sha256?: string;
  steps: ProofStep[];
}

function parseSteps(value: unknown, path: string): ProofStep[] {
  if (!Array.isArray(value)) {
    throw new Error(`proof for ${path} is not an array`);
  }
  return value.map((item) => {
    let step: unknown = item;
    if (typeof item === "string") {
      try {
        step = JSON.parse(item);
      } catch {
        throw new Error(`invalid proof step for ${path}`);
      }
    }
    if (!step || typeof step !== "object" || Array.isArray(step)) {
      throw new Error(`invalid proof step for ${path}`);
    }
    const candidate = step as Record<string, unknown>;
    if (
      typeof candidate.hash !== "string" ||
      (candidate.position !== "left" && candidate.position !== "right")
    ) {
      throw new Error(`invalid proof step for ${path}`);
    }
    return { hash: candidate.hash, position: candidate.position };
  });
}

function normalizeProofs(raw: unknown): {
  root?: string;
  proofs: Record<string, NormalizedProof>;
} {
  if (!raw || typeof raw !== "object" || Array.isArray(raw)) {
    throw new Error("proofs JSON must be an object");
  }
  const obj = raw as Record<string, unknown>;

  const looksLikeDocument =
    obj.version !== undefined || obj.proofs !== undefined || obj.root !== undefined;

  if (looksLikeDocument) {
    if (obj.version !== PROOF_VERSION) {
      throw new Error(
        `unsupported proofs version: ${String(obj.version)} (expected ${PROOF_VERSION})`,
      );
    }
    if (typeof obj.root !== "string" || !HEX64.test(obj.root)) {
      throw new Error("proofs root must be a 64-character hex string");
    }
    if (!obj.proofs || typeof obj.proofs !== "object" || Array.isArray(obj.proofs)) {
      throw new Error("proofs document is missing a proofs object");
    }
    const proofs: Record<string, NormalizedProof> = {};
    for (const [path, entry] of Object.entries(
      obj.proofs as Record<string, unknown>,
    )) {
      if (!entry || typeof entry !== "object" || Array.isArray(entry)) {
        throw new Error(`proof for ${path} is not an object`);
      }
      const candidate = entry as Record<string, unknown>;
      if (typeof candidate.sha256 !== "string" || !HEX64.test(candidate.sha256)) {
        throw new Error(`proof for ${path} is missing a valid sha256`);
      }
      proofs[path] = {
        sha256: candidate.sha256,
        steps: parseSteps(candidate.steps, path),
      };
    }
    return { root: obj.root, proofs };
  }

  const proofs: Record<string, NormalizedProof> = {};
  for (const [path, entry] of Object.entries(obj)) {
    proofs[path] = { steps: parseSteps(entry, path) };
  }
  return { proofs };
}

async function cmdProofVerify(args: ParsedArgs): Promise<number> {
  const archive = args.positionals[0];
  const sealPath = getOption(args.options, "-s", "--seal");
  const rootOption = getOption(args.options, "--root");
  const proofsPath = getOption(args.options, "--proofs");
  const pathFilter = getOption(args.options, "--path");
  const shaOption = getOption(args.options, "--sha256");

  if (!proofsPath) return fail("proof-verify: missing --proofs <proofs.json>");
  if (!archive && !sealPath && !rootOption) {
    return fail(
      "proof-verify: provide <archive.wacz>, --seal <seal.json>, or --root <hex>",
    );
  }
  if (rootOption !== undefined && !HEX64.test(rootOption)) {
    return fail("proof-verify: --root must be a 64-character hex string");
  }
  if (shaOption !== undefined && !HEX64.test(shaOption)) {
    return fail("proof-verify: --sha256 must be a 64-character hex string");
  }

  const failure = (reason: string): number => {
    if (flagEnabled(args.options, "--json")) {
      console.log(
        JSON.stringify({ ok: false, reasons: [reason], results: [] }, null, 2),
      );
      return 1;
    }
    return fail(reason);
  };

  let raw: unknown;
  try {
    raw = JSON.parse(await Bun.file(proofsPath).text());
  } catch (error) {
    return failure(
      `proof-verify: failed to read ${proofsPath}: ${errorMessage(error)}`,
    );
  }

  let document: { root?: string; proofs: Record<string, NormalizedProof> };
  try {
    document = normalizeProofs(raw);
  } catch (error) {
    return failure(`proof-verify: ${errorMessage(error)}`);
  }
  const proofs = document.proofs;

  if (pathFilter && !Object.hasOwn(proofs, pathFilter)) {
    return fail(
      `proof-verify: no proof for path "${pathFilter}" in ${proofsPath}`,
    );
  }

  let digestByPath: Map<string, string> | undefined;
  let root: string | undefined;
  const reasons: string[] = [];

  if (archive) {
    try {
      const digests = memberDigests(await readBytes(archive));
      digestByPath = new Map(digests.map((d) => [d.path, d.sha256]));
      root = buildMerkle(digests).root;
    } catch (error) {
      return failure(`proof-verify: ${errorMessage(error)}`);
    }
  }

  if (sealPath) {
    try {
      const parsed = JSON.parse(await Bun.file(sealPath).text()) as unknown;
      const validation = validateSeal(parsed);
      if (!validation.ok || !validation.seal) {
        return failure(`proof-verify: ${validation.reason ?? "invalid seal"}`);
      }
      if (!verifySealSignature(validation.seal)) {
        return failure("proof-verify: seal signature verification failed");
      }
      if (root !== undefined && root !== validation.seal.root) {
        reasons.push(
          `archive merkle root ${root} does not match seal root ${validation.seal.root}`,
        );
      }
      root = validation.seal.root;
    } catch (error) {
      return failure(`proof-verify: failed to read ${sealPath}: ${errorMessage(error)}`);
    }
  } else if (rootOption !== undefined) {
    if (root !== undefined && root !== rootOption) {
      reasons.push(
        `archive merkle root ${root} does not match expected root ${rootOption}`,
      );
    }
    root = rootOption;
  }

  if (root === undefined) {
    return failure("proof-verify: could not determine a root to verify against");
  }

  const requested = pathFilter ? [pathFilter] : Object.keys(proofs).sort();
  const results: ProofVerifyEntry[] = [];

  for (const path of requested) {
    const entry = proofs[path];
    if (!entry) {
      results.push({ path, ok: false, reason: "no proof for path" });
      continue;
    }

    let sha256: string | undefined;
    if (digestByPath) {
      sha256 = digestByPath.get(path);
    } else if (pathFilter && shaOption !== undefined && path === pathFilter) {
      sha256 = shaOption;
    }
    if (sha256 === undefined) sha256 = entry.sha256;
    if (sha256 === undefined) {
      results.push({
        path,
        ok: false,
        reason: "no content sha256 available for this member",
      });
      continue;
    }

    results.push(
      verifyInclusion(path, sha256, entry.steps, root)
        ? { path, ok: true, sha256 }
        : { path, ok: false, sha256, reason: "inclusion proof did not match root" },
    );
  }

  const ok = reasons.length === 0 && results.every((entry) => entry.ok);

  if (flagEnabled(args.options, "--json")) {
    console.log(
      JSON.stringify({ archive, root, ok, reasons, results }, null, 2),
    );
    return ok ? 0 : 1;
  }

  console.log(`archive: ${archive ?? "(offline)"}`);
  console.log(`root:    ${root}`);
  for (const reason of reasons) {
    console.log(`reason:  ${reason}`);
  }
  for (const entry of results) {
    const suffix = entry.reason ? ` — ${entry.reason}` : "";
    console.log(`${entry.ok ? "OK  " : "FAIL"} ${entry.path}${suffix}`);
  }

  return ok ? 0 : 1;
}

async function cmdInspect(args: ParsedArgs): Promise<number> {
  const archive = args.positionals[0];
  if (!archive) return fail("inspect: missing <archive.wacz>");

  const json = flagEnabled(args.options, "--json");
  let inspection;
  try {
    inspection = inspectWacz(await readBytes(archive));
  } catch (error) {
    if (json) {
      console.log(
        JSON.stringify(
          { ok: false, issues: [errorMessage(error)], members: [], resources: [] },
          null,
          2,
        ),
      );
    } else {
      process.stderr.write(`${errorMessage(error)}\n`);
    }
    return 1;
  }

  const root = buildMerkle(inspection.members).root;
  const resources = inspection.resources.length;

  if (json) {
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
  for (const name of VALUE_OPTIONS) {
    if (parsed.options.has(name) && parsed.options.get(name) === "") {
      process.stderr.write(`error: ${name} requires a value\n`);
      return 2;
    }
  }

  if (flagEnabled(parsed.options, "-v", "--version")) {
    process.stdout.write(`waxseal ${await packageVersion()}\n`);
    return 0;
  }
  if (flagEnabled(parsed.options, "-h", "--help")) {
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
