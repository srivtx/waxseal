<div align="center">

# waxseal

**Detached Ed25519 Merkle seal for WACZ web archives — sign once, verify offline anywhere.**

[![CI](https://github.com/srivtx/waxseal/actions/workflows/ci.yml/badge.svg)](https://github.com/srivtx/waxseal/actions/workflows/ci.yml)
[![release](https://img.shields.io/github/v/release/srivtx/waxseal?sort=semver&color=4f46e5)](https://github.com/srivtx/waxseal/releases)
[![license](https://img.shields.io/badge/license-MIT-0f766e)](LICENSE)
[![runtime](https://img.shields.io/badge/runtime-Bun-14151A?logo=bun&logoColor=white)](https://bun.sh)
[![types](https://img.shields.io/badge/TypeScript-strict-3178C6?logo=typescript&logoColor=white)](tsconfig.json)
[![tests](https://img.shields.io/badge/tests-23-0f766e)](#testing)
[![network](https://img.shields.io/badge/network-none-0f766e)](#privacy)

</div>

---

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
bun install
```

## Usage

```bash
# 1. Create a key pair
waxseal keygen --out archive-key
#    -> archive-key.pem (private), archive-key.pub.pem (public)

# 2. Seal an archive
waxseal seal capture.wacz --key archive-key.pem --out capture.seal.json
waxseal seal capture.wacz --key archive-key.pem --proofs capture.proofs.json

# 3. Verify it later, offline
waxseal verify capture.wacz -s capture.seal.json

# 4. Inspect the archive's own datapackage chain
waxseal inspect capture.wacz --json
```

`verify` defaults to a **strict byte-level** check. Pass `--member-only` to
allow a legitimate re-zip.

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

## Canonicalization

The Merkle root is deterministic and independent of how the ZIP was produced.

- **Path-sorted leaves.** Every member is a leaf, ordered by normalized path.
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
| `bun test` | 23 tests |
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
- No identity/trust model for the public key.

## The suite

- **booklens** — EPUB accessibility audit and fix
- **officelens** — DOCX/PPTX accessibility audit
- **odflens** — ODT/ODS/ODP accessibility audit
- **iconlens** — standalone SVG accessibility lint
- **waxseal** — detached Ed25519 seal for WACZ web archives *(this repo)*

## License

[MIT](LICENSE).
