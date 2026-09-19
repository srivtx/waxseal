import { mkdir } from "node:fs/promises";
import { existsSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import * as esbuild from "esbuild";

const repoRoot = dirname(dirname(fileURLToPath(import.meta.url)));
const entry = join(repoRoot, "src", "index.ts");
const shim = join(repoRoot, "site", "assets", "shims", "node-crypto.mjs");
const outfile = join(repoRoot, "site", "assets", "demo.js");

async function main() {
  if (!existsSync(entry)) {
    process.stdout.write(
      `build-site: skipping; ${entry} not found (no src/ to bundle)\n`,
    );
    return;
  }

  await mkdir(dirname(outfile), { recursive: true });

  await esbuild.build({
    entryPoints: [entry],
    outfile,
    bundle: true,
    format: "iife",
    platform: "browser",
    target: "es2020",
    minify: true,
    globalName: "WaxSeal",
    alias: { "node:crypto": shim },
    logLevel: "info",
  });

  process.stdout.write("build-site: built site/assets/demo.js\n");
}

main().catch((error) => {
  process.stderr.write(`${error?.stack ?? error}\n`);
  process.exit(1);
});
