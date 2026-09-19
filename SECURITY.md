# Security Policy

## waxseal

waxseal computes a detached Ed25519 Merkle seal for WACZ web archives. It reads
an untrusted archive, hashes its members into a canonical Merkle tree, signs
the root, and can verify the seal offline with per-file inclusion proofs.

## Supported versions

The latest commit on `main` is the only supported version. Security fixes land
on `main` and ship in the next tagged release. Older tags do not receive
backports.

| Version | Supported |
| --- | --- |
| Latest on `main` | Yes |
| Older tags | No |

## Threat model

- **Offline by design.** waxseal contains no network code. It never opens a
  socket, contacts a timestamp or key server, or checks for updates.
- **No telemetry.** Nothing about your archives, your keys, your usage, or your
  machine is collected or transmitted.
- **Archives and keys never leave the machine.** Hashing, tree construction,
  signing, and verification all run in-process and locally. A private key passed
  with `--key` is read from the path you give and is never copied elsewhere.
- **Generated keys are explicit.** When `seal` runs without `--key` it
  generates a key pair in memory. By default the private key is ephemeral and is
  **not** written to disk; only the signature (verifiable with the embedded
  public key) is persisted. To keep the pair, pass `--write-key`, which writes
  `<archive>.key.pem` next to the archive with file mode `0600` and
  `<archive>.key.pub.pem` with mode `0644`. Writing the private key is opt-in
  and reported on stderr.
- **Untrusted input.** A WACZ is treated as hostile: ZIP members and
  `datapackage.json` are parsed defensively, and a malformed, deeply nested, or
  oversized archive must fail safely rather than escape the working directory or
  exhaust the process. Members are hashed in memory and archives are **never
  extracted to disk**, so symlink or special-file entries cannot be followed or
  materialized. Member paths are normalized before hashing: absolute paths,
  `..` segments, Windows backslashes, drive letters (`C:`), and percent-encoded
  separators or dots (`%2e`, `%2f`, `%5c`, `%00`) are rejected, not silently
  rewritten.
- **Canonical hashing matters.** A seal is only meaningful if the Merkle root is
  computed over a deterministic, documented serialization; changes to member
  ordering or normalization are security-relevant and reviewed as such.
- **Verify, do not trust.** `waxseal verify` must reject a mismatched root, a
  bad signature, a missing member, and a proof that does not reproduce the
  root. A seal is only *self-consistent* until you pin a trusted
  `--public-key` or `--root`; without one the CLI reports `trusted: no`. The CLI
  reports `trusted: yes` only when the supplied pin actually matches, not merely
  because a pin was passed. `waxseal proof-verify` rejects an archive whose
  rebuilt Merkle root does not match the root declared in the proofs document
  (or the `--seal`/`--root` pin), and fails closed when a proofs document
  declares no root and no pin is supplied. The Ed25519 signature is checked by
  `node:crypto`; root and digest comparisons are ordinary string equality over
  public, non-secret values, so they are not constant-time and are not required
  to be.
- **`--root` pinning is content attestation, not provenance.** A root pin proves
  the archive hashes to a known value, but not who signed it: an attacker can
  re-sign the same archive under their own key and still satisfy `--root`. For a
  provenance verdict, pin `--public-key`. When only `--root` is given the CLI
  prints `provenance:  not checked (root-only pin ...)`. Prefer `--public-key`
  whenever the signer's identity matters.

## Reporting a vulnerability

Report privately through GitHub Security Advisories on the repository:

https://github.com/srivtx/waxseal/security/advisories/new

Do not open a public issue for a suspected vulnerability. This is especially
important for anything affecting signature verification, Merkle-root
canonicalization, or inclusion proofs. Include a description, the affected
revision, a minimal reproducer (a fixture archive or seal where possible), and
any suggested fix. Expect an acknowledgement within a few days.

## Verifying a build

```bash
bun install
bunx tsc --noEmit
bun test
```

This installs the locked dependency set, typechecks in strict mode, and runs
the test suite against the generated fixtures. In CI the same gate runs on
every push and pull request.
