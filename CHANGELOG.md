# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.2.0] - 2026-09-20

### Security

- `verify` accepts `--public-key <pem|base64>` and `--root <hex>` to pin a
  trusted key or root, always prints the SPKI key fingerprint, and labels a
  self-signed seal `trusted: no` when neither is supplied.
- `proof-verify` accepts `-s/--seal` to check proofs against `seal.root`, plus
  an offline mode (`--root`, `--sha256`) that needs no archive.
- Seal JSON is validated (required fields and types), and unknown `version`,
  `algorithm`, or `merkle` values are rejected before the seal is trusted.
- ZIP extraction is guarded by member-count and uncompressed-size limits and
  fails with structured output instead of crashing.
- Member paths are normalized (leading `./`, Unicode NFC); absolute and `..`
  paths are rejected.

### Fixed

- `keygen` refuses to overwrite an existing key pair unless `--force`/`--yes`.
- `strictBytes` fails when the seal has no `archiveSha256`.
- Empty option values (`--out`, `--seal`, …) are errors, and
  `--member-only=false` no longer enables member-only mode.
- `inspect` reports datapackage resources missing from the ZIP.
- An empty proof-set is treated as vacuously valid.

### Added

- One-line `install.sh` installer.
- Hard-coded known-root test vector for a fixed multi-member archive.

### Changed

- Inclusion proofs are stored as typed `ProofStep[]`; the emitted proof file
  records the root and each member's content SHA-256.
- The CLI no longer prints add/remove/modify lines it could never populate (the
  library diff via `verifySeal(..., { previous })` remains).

## [0.1.0] - 2026-09-19

### Added

- Detached `seal.json` format: canonical Merkle root over all WACZ members plus an Ed25519 signature.
- Domain-separated, path-sorted Merkle tree with odd-node promotion (`waxseal:leaf:`, `waxseal:node:`, `waxseal:empty`).
- Ed25519 key generation and signing/verification (SPKI base64 public keys).
- Merkle inclusion proofs so a single member's membership can be verified without the archive.
- `waxseal` CLI: `keygen`, `seal`, `verify`, `proof-verify`, `inspect`.
- Offline verification of a WACZ against a detached seal.
- Library entry point re-exporting types, WACZ, Merkle, seal, verify and key modules.

[0.2.0]: https://github.com/srivtx/waxseal/releases/tag/v0.2.0
[0.1.0]: https://github.com/srivtx/waxseal/releases/tag/v0.1.0
