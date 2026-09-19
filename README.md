<div align="center">

# waxseal

> Seal the archive. Prove any file.

**Detached Ed25519 Merkle seals for WACZ web archives.**

[![CI](https://github.com/srivtx/waxseal/actions/workflows/ci.yml/badge.svg)](https://github.com/srivtx/waxseal/actions/workflows/ci.yml)
[![release](https://img.shields.io/github/v/release/srivtx/waxseal?sort=semver&color=4f46e5)](https://github.com/srivtx/waxseal/releases)
[![license](https://img.shields.io/badge/license-MIT-0f766e)](LICENSE)
[![runtime](https://img.shields.io/badge/runtime-Bun-14151A?logo=bun&logoColor=white)](https://bun.sh)
[![types](https://img.shields.io/badge/TypeScript-strict-3178C6?logo=typescript&logoColor=white)](tsconfig.json)
[![tests](https://img.shields.io/badge/tests-63-0f766e)](#testing)
[![network](https://img.shields.io/badge/network-none-0f766e)](#privacy)

</div>

---

**Live site:** [waxseal](https://waxseal-srivtx.vercel.app)  ·  **Demo:** [https://waxseal-srivtx.vercel.app/#demo](https://waxseal-srivtx.vercel.app/#demo)  ·  **Source:** [github.com/srivtx/waxseal](https://github.com/srivtx/waxseal)  ·  **Changelog:** [CHANGELOG.md](CHANGELOG.md)

## What a WACZ is, and what is missing

A **WACZ** is a ZIP of web-archive files. It carries its own integrity chain:
`datapackage.json` lists every resource with a SHA-256 and a byte count, and
`datapackage-digest.json` holds the hash of `datapackage.json`.

[`py-wacz`](https://github.com/webrecorder/py-wacz) already validates that chain.
What the ecosystem does **not** have:

- **A detached proof.** The WACZ signature lives *inside* the ZIP it attests to,
  so it cannot be pinned, notarized, or distributed out of band.
- **A Merkle root.** Everything is a flat one-level hash chain. There are no
  inclusion or consistency proofs.
- **Ed25519.** The spec and implementations use anonymous ECDSA or X.509 ECDSA.
- **A TypeScript implementation.** `py-wacz` is Python; `wabac.js` and
  ReplayWeb.page are read/replay-only; `waczerciser` has no crypto.

`waxseal` adds a detached `seal.json`: a canonical Merkle root over every
archive member plus an Ed25519 signature, verifiable with no network and no
server, with an inclusion proof so any single file's membership can be shown
without shipping the archive.

## Install

```bash
# One-line install (installs the `waxseal` binary)
curl -fsSL https://raw.githubusercontent.com/srivtx/waxseal/main/install.sh | sh

# Or run once, without installing
bunx github:srivtx/waxseal seal archive.wacz

# Install globally
bun add -g github:srivtx/waxseal
waxseal seal archive.wacz

# Add to a project as a dev dependency
bun add -d github:srivtx/waxseal
```

`waxseal` is not published to npm: the one-line script installs the binary
(requires [Bun](https://bun.sh)), and `bunx` runs it without installing.

> The package `exports` map points at raw TypeScript (`src/index.ts`), not a
> compiled bundle. It is intended for Bun, which runs `.ts` directly; a Node
> project would need its own TypeScript loader (for example `tsx`).

## Usage

```bash
# 1. Create a key pair
waxseal keygen --out archive-key
#    -> archive-key.pem (private), archive-key.pub.pem (public)

# 2. Seal an archive
waxseal seal capture.wacz --key archive-key.pem --out capture.seal.json
waxseal seal capture.wacz --key archive-key.pem --proofs capture.proofs.json

# 3. Verify it later, offline, against a pinned key or root
waxseal verify capture.wacz -s capture.seal.json --public-key archive-key.pub.pem
waxseal verify capture.wacz -s capture.seal.json --root <hex-root>

# 4. Inspect the archive's own datapackage chain
waxseal inspect capture.wacz --json
```

`verify` defaults to a **strict byte-level** check. Pass `--member-only` to
allow a legitimate re-zip.

A seal carries its own `publicKey`, so on its own it only proves internal
consistency: `verify` prints `trusted: no` and the signature is checked against
the embedded key. Pass `--public-key <pem|base64>` or `--root <hex>` to pin what
you trust; `verify` then reports `trusted: yes` only when the pin actually
matches, and fails (exit 1) otherwise. The SHA-256 fingerprint of the SPKI key is
always printed so you can pin it out of band.

> **Root-only pinning attests content, not provenance.** Pinning `--root` proves
> the archive hashes to that root, but it does not prove who signed it: an
> attacker can re-sign the *same* archive with their own key and still satisfy
> `--root`. When only `--root` is supplied the CLI prints
> `provenance:  not checked (root-only pin attests content, not an author)`. Pin
> `--public-key` when you need a provenance verdict.

### Prove a single file

`seal` can also emit one inclusion proof per member. Hand someone a single proof
and they can confirm that file is part of the sealed archive without the archive
itself. The proof file records the Merkle root and each member's content
SHA-256.

```bash
# Prove a member against the archive, anchored to the seal's signed root
waxseal proof-verify capture.wacz --proofs capture.proofs.json \
  --path archive/data.warc.gz --seal capture.seal.json

# Fully offline: no archive, just the proof, root, and content hash
waxseal proof-verify --proofs capture.proofs.json \
  --path archive/data.warc.gz --root <hex-root> --sha256 <hex-content-hash>
```

`proof-verify` checks each requested proof against the root declared by the
proof document, and against the seal root (or `--root`) when supplied. With an
archive it rebuilds the Merkle root from the archive and fails if that root does
not match the declared/proofs root or the pin, so a tampered member is rejected
even when no pin is given. If a proofs document carries no root, pass `--seal` or
`--root` to anchor the verdict; otherwise the command fails closed. Omit `--path`
to check every proof in the file, or add `--json` for machine-readable output. It
exits `0` only when all requested proofs verify, and `1` when a proof fails, a
root does not match, or a `--path` is missing. An empty requested set is
vacuously valid.

Run `waxseal --help` (or `-h`) for the full command list and `waxseal --version`
for the installed version.

### Library

```ts
import {
  createSeal,
  verifySeal,
  buildMerkle,
  proveInclusion,
  verifyInclusion,
  createInclusionProofs,
  generateKeyPair,
} from "waxseal";

const { privateKeyPem, publicKeyPem } = generateKeyPair();
const seal = createSeal(archive, privateKeyPem, publicKeyPem);

const result = verifySeal(seal, archive, { strictBytes: true });
// { ok, root, signatureOk, reasons, added, removed, modified }
```

## Website

A self-contained product site lives in [`site/`](site/) and ships with the
repo. The live site is at
**[https://waxseal-srivtx.vercel.app](https://waxseal-srivtx.vercel.app)**.

The page embeds an interactive demo that runs the real Merkle and
inclusion-proof code in the browser. In the browser it hashes with a vendored
JavaScript SHA-256 shim, not `node:crypto`; Ed25519 key operations still
require the CLI. The site is static, makes no external requests, and needs no
build at deploy time: `site/assets/demo.js` is committed.

## Development

Clone the repository and install its dependencies with Bun:

```bash
git clone https://github.com/srivtx/waxseal
cd waxseal
bun install
```

Run the tests and the type check:

```bash
bun test
bunx tsc --noEmit
```

Rebuild the bundled browser demo and preview the site locally:

```bash
bun run build:site   # bundle src/index.ts -> site/assets/demo.js
bunx serve site      # or: python3 -m http.server --directory site
```

Then open `http://localhost:3000` (or the port your static server prints). Run
`bun run check:site` to verify links, classes, and page structure.

## Canonicalization

The Merkle root is deterministic and independent of how the ZIP was produced.

- **Path-sorted leaves.** Every member is a leaf, ordered by normalized path.
  Normalization is Unicode NFC, forward-slash relative paths with any leading
  `./` removed; directory entries are skipped, and absolute or `..` paths are
  rejected.
- **Domain-separated leaves.** `leaf = SHA-256("waxseal:leaf:" + path + ":" + sha256(content))`
- **Domain-separated nodes.** `node = SHA-256("waxseal:node:" + left + ":" + right)`
- **Odd-node promotion.** The last node of an odd level is carried up unchanged
  (never duplicated).
- **Empty tree.** An archive with no members commits to `SHA-256("waxseal:empty")`.
- **Signed payload.** The Ed25519 signature covers a canonical JSON object with
  `version`, `algorithm`, `root`, `memberCount`, `merkle`, `createdAt`, and
  `archiveSha256`.

Because membership is `(normalized path, content SHA-256)` pairs, re-zipping the
same logical content yields the same root.

### Member-level vs byte-level

`archiveSha256` pins the exact bytes. `verifySeal(seal, data, { strictBytes: true })`
fails if the archive differs in any way — including appended trailing bytes that
leave every member unchanged. The CLI defaults to strict and `--member-only`
relaxes it for reproducible re-packaging. The library default is member-level.

## What verification proves

- The archive contains exactly the members the signer committed to
  (no additions, removals, or modifications).
- The signer held the private key for the embedded public key.
- With `strictBytes`, the file is byte-for-byte the one that was sealed.

It does **not** prove identity or provide a trusted timestamp: `createdAt` is
self-asserted by the signer. Pair the root with a timestamping authority if you
need a proven "existed before" time.

## Testing

| Gate | Result |
|---|---|
| `bun test` | 63 tests |
| `bunx tsc --noEmit` | clean (strict) |
| round trip | `keygen` → `seal` → `verify` succeeds; a tampered archive exits 1 |

Tests cover determinism (re-zipped archives share a root), tamper detection with
a previous-digest diff, wrong-key rejection, strict byte-level detection of
appended bytes, signature coverage of `archiveSha256`, and inclusion proofs for
every member.

## Privacy

No network code. Signing and verification use `node:crypto` locally.

## Limitations

- ZIP member order and metadata are not part of the sealed bytes; use
  `strictBytes` when you need byte-for-byte attestation.
- Ed25519 only — no X.509 or ECDSA.
- The datapackage digest re-check overlaps `py-wacz`; `waxseal` is not a
  replacement for it, it is a portable proof layer on top.
- No identity or trust model for the public key beyond pinning
  `--public-key`/`--root`; a seal on its own is `trusted: no`, and a `--root`
  pin attests content only, not provenance (pin `--public-key` for that).
- Decompression is bounded (65,535 members, 1 GiB uncompressed) and member
  paths are normalized; absolute or `..` paths are rejected.

## The suite

- **booklens** — EPUB accessibility audit and fix
- **officelens** — DOCX/PPTX accessibility audit
- **odflens** — ODT/ODS/ODP accessibility audit
- **iconlens** — standalone SVG accessibility lint
- **waxseal** — detached Ed25519 seal for WACZ web archives *(this repo)*

## License

[MIT](LICENSE).
