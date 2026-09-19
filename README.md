# wacz-seal

[![CI](https://github.com/wacz-seal/wacz-seal/actions/workflows/ci.yml/badge.svg)](https://github.com/wacz-seal/wacz-seal/actions/workflows/ci.yml)
[![Bun](https://img.shields.io/badge/bun-%3E%3D1.1-black)](https://bun.sh)
[![tests](https://img.shields.io/badge/tests-bun%20test-brightgreen)](https://bun.sh/docs/cli/test)
[![license: MIT](https://img.shields.io/badge/license-MIT-blue)](./LICENSE)
[![offline](https://img.shields.io/badge/verification-100%25%20offline-success)](#)

Offline, detached Ed25519 seals and Merkle inclusion proofs for [WACZ](https://specs.webrecorder.net/wacz/1.1.1/) web archives.

## Why another WACZ integrity tool?

A WACZ is a ZIP of web-archive files. Each archived resource is hashed in `datapackage.json`, and the hash of `datapackage.json` itself is stored in `datapackage-digest.json`. Existing tooling — notably [py-wacz](https://github.com/webrecorder/py-wacz) — already verifies those hashes, and **wacz-seal intentionally overlaps with that check**. If all you need is "does this archive match its own datapackage?", use py-wacz.

py-wacz alone leaves four gaps that wacz-seal closes:

1. **The signature is inside the archive.** The signed `datapackage-digest.json` travels with the bytes it protects, so the proof cannot be detached or shared on its own.
2. **Signatures are ECDSA/X.509 only.** There is no Ed25519 option.
3. **There is no Merkle root.** You can verify an entire archive, but you cannot prove that a single member belongs to it, and you cannot compare two builds on one short commitment.
4. **There is no TypeScript implementation** and no detached, portable proof format.

`wacz-seal` adds a detached **`seal.json`**: a canonical Merkle root over every archive member plus an Ed25519 signature. It verifies fully offline, and it can emit **inclusion proofs** so any single file's membership can be shown without shipping the archive.

## Install

```sh
bun install
```

## CLI

```
wacz-seal <command> [options]

Commands:
  keygen [--out <base>]                 Generate an Ed25519 key pair (default base: wacz-seal-key)
  seal <archive.wacz> [--key <pem>] [--out <seal.json>] [--proofs <proofs.json>]
  verify <archive.wacz> -s <seal.json> [--json]
  inspect <archive.wacz> [--json]
```

### Generate a key pair

```sh
bun src/cli.ts keygen --out my-key
# writes my-key.pem (private) and my-key.pub.pem (public)
# prints the public key (SPKI, base64) to stdout
```

### Seal an archive

```sh
bun src/cli.ts seal archive.wacz --key my-key.pem --out archive.seal.json --proofs archive.proofs.json
```

If `--key` is omitted, a **fresh** key pair is generated, written next to the archive as `<archive>.key.pem` and `<archive>.key.pub.pem`, and a warning is printed. Use this for quick, self-contained signing; supply `--key` when you need a stable identity.

The command prints the Merkle `root`, `memberCount`, `algorithm` and a short signature prefix.

### Verify

```sh
bun src/cli.ts verify archive.wacz -s archive.seal.json        # human output
bun src/cli.ts verify archive.wacz -s archive.seal.json --json # machine output
```

Human output prints `OK`/`FAILED`, the computed root, signature status, and any added/removed/modified members. Exit code is `0` when valid and `1` otherwise.

### Inspect

```sh
bun src/cli.ts inspect archive.wacz --json
```

Shows the `datapackage-digest.json` status, member and resource counts, issues, and the canonical Merkle root.

## Library

```ts
import { defaultWacz, generateKeyPair, createSeal, verifySeal } from "wacz-seal";

const archive = defaultWacz();
const { privateKeyPem, publicKeyPem } = generateKeyPair();

const seal = createSeal(archive, privateKeyPem, publicKeyPem);
const result = verifySeal(seal, archive);

console.log(result.ok); // true
```

`src/index.ts` re-exports `./types`, `./wacz`, `./merkle`, `./seal`, `./verify` and `./keys`.

## Canonicalization

The Merkle root is deterministic and independent of how the ZIP was produced.

- **Members are path-sorted.** Every ZIP member becomes a leaf, ordered by its normalized path using byte-wise ascending comparison.
- **Domain-separated leaves.** `leaf = SHA-256("wacz-seal:leaf:" + path + ":" + sha256hex(content))`.
- **Domain-separated nodes.** `node = SHA-256("wacz-seal:node:" + left + ":" + right)`.
- **Odd-node promotion.** When a level has an odd number of nodes, the last node is carried up unchanged (it is not duplicated).
- **Empty tree.** An archive with no members commits to `SHA-256("wacz-seal:empty")`.
- **Signed payload.** The Ed25519 signature covers a canonical JSON object containing `version`, `algorithm`, `root`, `memberCount`, `merkle`, `createdAt`, and `archiveSha256` (the raw SHA-256 of the archive bytes). The public key (SPKI, base64) and the signature (base64) are stored in `seal.json`.

Because membership is defined as `(normalized path, content SHA-256)` pairs, re-zipping the same logical content — even with different compression or member order — yields the same root.

### Byte-level vs member-level verification

`archiveSha256` lets a verifier pin the exact bytes. `verifySeal(seal, data, { strictBytes: true })` fails if the archive bytes differ in any way — including appended trailing data that leaves every member unchanged. The CLI `verify` command defaults to `strictBytes` and accepts `--member-only` when a legitimate re-zip should still pass. The library default is member-level so reproducible re-packaging keeps verifying.

## Limitations

- **ZIP member order and metadata are not part of the sealed bytes.** The seal covers normalized `path` + content-hash pairs, not raw ZIP bytes, timestamps, permissions, or compression method. Re-zipping the same content yields the same root; this is a feature for reproducibility. When you need byte-for-byte attestation, use `strictBytes` / `--strict-bytes`, which checks the signed `archiveSha256` against the raw file.
- **The seal proves integrity, membership, and key possession — not a trusted timestamp.** `createdAt` is self-asserted by the signer.
- **No identity/trust model.** Verification proves that whoever holds the private key signed this root. Mapping the public key to a real-world identity is out of scope.
- **Ed25519 only.** There is no X.509 or ECDSA support.
- **The datapackage digest re-check overlaps py-wacz.** wacz-seal is not a replacement for py-wacz's WACZ validation; it adds a detached, portable proof on top.

## License

MIT — see [LICENSE](./LICENSE).
