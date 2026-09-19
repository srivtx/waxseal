# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - 2026-09-19

### Added

- Detached `seal.json` format: canonical Merkle root over all WACZ members plus an Ed25519 signature.
- Domain-separated, path-sorted Merkle tree with odd-node promotion (`wacz-seal:leaf:`, `wacz-seal:node:`, `wacz-seal:empty`).
- Ed25519 key generation and signing/verification (SPKI base64 public keys).
- Merkle inclusion proofs so a single member's membership can be verified without the archive.
- `wacz-seal` CLI: `keygen`, `seal`, `verify`, `inspect`.
- Offline verification of a WACZ against a detached seal, with added/removed/modified reporting.
- Library entry point re-exporting types, WACZ, Merkle, seal, verify and key modules.

[0.1.0]: https://github.com/wacz-seal/wacz-seal/releases/tag/v0.1.0
