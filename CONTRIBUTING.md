# Contributing to waxseal

Thanks for helping improve WACZ archive sealing. This document covers what you
need to build, test, and submit a change.

## Development setup

waxseal targets [Bun](https://bun.sh) and TypeScript in strict mode.

```bash
git clone https://github.com/srivtx/waxseal.git
cd waxseal
bun install
```

Run the CLI from source while you work (generate an archive with
`bun run make-fixtures` first, or use one of your own):

```bash
bun run make-fixtures
bun run src/cli.ts keygen --out /tmp/archive-key
bun run src/cli.ts seal fixtures/default.wacz --key /tmp/archive-key.pem --out /tmp/capture.seal.json
bun run src/cli.ts verify fixtures/default.wacz -s /tmp/capture.seal.json
```

## The gate

Every pull request must pass the same gate CI runs:

```bash
bunx tsc --noEmit && bun test
```

Do not open a PR with a red typecheck or a failing test. Fix the cause rather
than disabling a rule or test.

## Fixtures

The tests build their archives in memory from `src/fixtures.ts`; no checked-in
fixture archive is required. `bun run make-fixtures` writes
`fixtures/default.wacz` for manual CLI use and creates the directory on demand.

When you add behavior, extend `tests/merkle.test.ts` for tree and proof logic,
`tests/seal.test.ts` for signing and verification, `tests/wacz.test.ts` for
archive parsing, and `tests/cli.test.ts` for end-to-end command behavior. Any
change to root canonicalization needs a test that pins the expected root for a
known input.

## Code style

- Strict TypeScript. No `any` to silence a type error, no non-null assertions
  to dodge null checks.
- No new runtime dependencies without discussion in an issue first. The offline
  and dependency-light posture is a feature, and cryptographic primitives should
  come from the platform rather than an added package.
- No network access, ever. Hashing, signing, and verifying are local
  operations.
- Keep Merkle construction, canonical serialization, and signature handling in
  separate, individually tested modules.
- Never log or write private key material.
- Match the surrounding style; keep modules small and focused.
- No comments unless they explain something non-obvious.

## Commit messages

Use [Conventional Commits](https://www.conventionalcommits.org/):

```
<type>(<scope>): <summary>

fix(merkle): include empty leaves in the root computation
feat(verify): reject inclusion proofs with a bad sibling path
test(seal): cover tampered archive members
docs: explain the seal.json schema
```

Common types: `feat`, `fix`, `test`, `docs`, `refactor`, `chore`. Useful scopes:
`merkle`, `seal`, `verify`, `wacz`, `cli`.

## Pull request checklist

- [ ] Tests added or updated for the change.
- [ ] `bunx tsc --noEmit` is clean.
- [ ] `bun test` passes.
- [ ] Docs (`README.md`) updated when behavior or flags change.
- [ ] Commit messages follow Conventional Commits.
