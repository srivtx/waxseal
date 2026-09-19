import { strToU8, zipSync } from "fflate";
import { sha256Hex } from "./wacz.ts";

export interface WaczMember {
  path: string;
  data: string;
}

function isDatapackageFile(path: string): boolean {
  return path === "datapackage.json" || path === "datapackage-digest.json";
}

function defaultMembers(): WaczMember[] {
  return [
    { path: "archive/data.warc.gz", data: "warc-gzip-placeholder-bytes" },
    { path: "pages/pages.jsonl", data: `{"url":"https://example.com"}\n` },
    {
      path: "indexes/index.cdx",
      data: `com,example)/ 20240101000000 {"url":"https://example.com"}\n`,
    },
  ];
}

export function buildWacz(
  members: WaczMember[],
  opts: { withDigest?: boolean } = {},
): Uint8Array {
  const list = members.length > 0 ? members : defaultMembers();
  const files: Record<string, Uint8Array> = {};
  for (const member of list) {
    files[member.path] = strToU8(member.data);
  }

  const resources = list
    .filter((member) => !isDatapackageFile(member.path))
    .map((member) => {
      const bytes = strToU8(member.data);
      return {
        path: member.path,
        hash: `sha256:${sha256Hex(bytes)}`,
        bytes: bytes.length,
      };
    });

  const datapackage = JSON.stringify({ resources });
  const datapackageBytes = strToU8(datapackage);
  files["datapackage.json"] = datapackageBytes;

  if (opts.withDigest !== false) {
    const digest = JSON.stringify({
      path: "datapackage.json",
      hash: `sha256:${sha256Hex(datapackageBytes)}`,
    });
    files["datapackage-digest.json"] = strToU8(digest);
  }

  return zipSync(files);
}

export function defaultWacz(): Uint8Array {
  return buildWacz([]);
}
