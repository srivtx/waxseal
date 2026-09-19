/// <reference types="bun" />
import { createHash } from "node:crypto";
import { unzipSync, type UnzipFileInfo } from "fflate";
import type {
  DatapackageResource,
  MemberDigest,
  WaczInspection,
} from "./types.ts";

const decoder = new TextDecoder();

export interface UnzipLimits {
  maxMembers: number;
  maxUncompressedBytes: number;
}

export const DEFAULT_UNZIP_LIMITS: UnzipLimits = {
  maxMembers: 65535,
  maxUncompressedBytes: 1024 * 1024 * 1024,
};

export function sha256Hex(bytes: Uint8Array): string {
  return createHash("sha256").update(bytes).digest("hex");
}

function comparePaths(a: string, b: string): number {
  return a < b ? -1 : a > b ? 1 : 0;
}

function digestOf(path: string, bytes: Uint8Array): MemberDigest {
  return { path, sha256: sha256Hex(bytes), size: bytes.length };
}

function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}

function isDirectoryEntry(name: string): boolean {
  return name.endsWith("/");
}

/**
 * Canonical member path: Unicode NFC, forward slashes, no leading `./`, no
 * absolute paths, and no `..` or empty segments. Also rejects Windows-style
 * backslashes, drive-letter prefixes, and percent-encoded `/`, `\`, `.`, or
 * NUL bytes (e.g. `%2e%2e/x`), which ZIP tools and URL layers may decode into
 * traversals. Throws for anything that cannot be a safe relative member path.
 */
export function normalizeMemberPath(raw: string): string {
  let path = raw.normalize("NFC");
  while (path.startsWith("./")) path = path.slice(2);

  if (path === "") throw new Error(`empty member path: ${JSON.stringify(raw)}`);
  if (path.includes("\\")) {
    throw new Error(`backslash in member path: ${JSON.stringify(raw)}`);
  }
  if (/^[A-Za-z]:/.test(path)) {
    throw new Error(`absolute member path: ${JSON.stringify(raw)}`);
  }
  if (path.startsWith("/")) {
    throw new Error(`absolute member path: ${JSON.stringify(raw)}`);
  }
  if (/%2e|%2f|%5c|%00/i.test(path)) {
    throw new Error(
      `percent-encoded path segment in member path: ${JSON.stringify(raw)}`,
    );
  }

  const segments = path.split("/");
  for (const segment of segments) {
    if (segment === "") {
      throw new Error(`empty path segment in member path: ${JSON.stringify(raw)}`);
    }
    if (segment === "." || segment === "..") {
      throw new Error(`unsafe path segment in member path: ${JSON.stringify(raw)}`);
    }
  }

  return path;
}

function extractZip(
  data: Uint8Array,
  limits: UnzipLimits = DEFAULT_UNZIP_LIMITS,
): Record<string, Uint8Array> {
  let memberCount = 0;
  let totalUncompressed = 0;

  const files = unzipSync(data, {
    filter: (file: UnzipFileInfo): boolean => {
      if (isDirectoryEntry(file.name)) return false;
      memberCount += 1;
      if (memberCount > limits.maxMembers) {
        throw new Error(
          `archive has more than ${limits.maxMembers} members`,
        );
      }
      totalUncompressed += file.originalSize;
      if (totalUncompressed > limits.maxUncompressedBytes) {
        throw new Error(
          `archive expands beyond ${limits.maxUncompressedBytes} bytes`,
        );
      }
      return true;
    },
  });

  let bytes = 0;
  for (const content of Object.values(files)) bytes += content.length;
  if (bytes > limits.maxUncompressedBytes) {
    throw new Error(
      `archive expands beyond ${limits.maxUncompressedBytes} bytes`,
    );
  }

  return files;
}

interface ArchiveContents {
  files: Record<string, Uint8Array>;
  members: MemberDigest[];
  issues: string[];
}

function readArchive(
  data: Uint8Array,
  limits: UnzipLimits = DEFAULT_UNZIP_LIMITS,
): ArchiveContents {
  const rawFiles = extractZip(data, limits);
  const files: Record<string, Uint8Array> = {};
  const members: MemberDigest[] = [];
  const issues: string[] = [];

  for (const rawPath of Object.keys(rawFiles)) {
    let path: string;
    try {
      path = normalizeMemberPath(rawPath);
    } catch (error) {
      issues.push(errorMessage(error));
      continue;
    }
    if (Object.hasOwn(files, path)) {
      issues.push(`duplicate member path after normalization: ${path}`);
      continue;
    }
    const bytes = rawFiles[rawPath]!;
    files[path] = bytes;
    members.push(digestOf(path, bytes));
  }

  members.sort((a, b) => comparePaths(a.path, b.path));
  return { files, members, issues };
}

export function memberDigests(
  data: Uint8Array,
  limits: UnzipLimits = DEFAULT_UNZIP_LIMITS,
): MemberDigest[] {
  const { members, issues } = readArchive(data, limits);
  if (issues.length > 0) {
    throw new Error(`unsafe or malformed archive: ${issues.join("; ")}`);
  }
  return members;
}

export function inspectWacz(
  data: Uint8Array,
  limits: UnzipLimits = DEFAULT_UNZIP_LIMITS,
): WaczInspection {
  let contents: ArchiveContents;
  try {
    contents = readArchive(data, limits);
  } catch (error) {
    return {
      members: [],
      resources: [],
      digestOk: false,
      issues: [`failed to read zip: ${errorMessage(error)}`],
    };
  }

  const issues = [...contents.issues];
  const files = contents.files;
  const members = contents.members;

  const datapackageBytes = files["datapackage.json"];
  if (!datapackageBytes) {
    issues.push("missing datapackage.json");
    return { members, resources: [], digestOk: false, issues };
  }

  const resources: DatapackageResource[] = [];
  let pkg: unknown;
  try {
    pkg = JSON.parse(decoder.decode(datapackageBytes));
  } catch (error) {
    issues.push(`invalid datapackage.json: ${errorMessage(error)}`);
    return {
      members,
      datapackagePath: "datapackage.json",
      resources: [],
      digestOk: false,
      issues,
    };
  }

  const rawResources = (pkg as { resources?: unknown } | null)?.resources;
  if (!Array.isArray(rawResources)) {
    issues.push("datapackage.json has no resources array");
  } else {
    for (const entry of rawResources) {
      if (!entry || typeof entry !== "object") {
        issues.push("resource entry is not an object");
        continue;
      }
      const raw = entry as Record<string, unknown>;
      const resource: DatapackageResource = {
        path: typeof raw.path === "string" ? raw.path : "",
      };
      if (typeof raw.hash === "string") resource.hash = raw.hash;
      if (typeof raw.bytes === "number") resource.bytes = raw.bytes;
      resources.push(resource);

      if (!resource.path) {
        issues.push("resource missing path");
        continue;
      }
      let normalizedPath: string;
      try {
        normalizedPath = normalizeMemberPath(resource.path);
      } catch (error) {
        issues.push(`resource ${resource.path}: ${errorMessage(error)}`);
        continue;
      }
      const member = files[normalizedPath];
      if (!member) {
        issues.push(`resource ${resource.path}: missing from archive`);
        continue;
      }

      const actualHash = `sha256:${sha256Hex(member)}`;
      if (resource.hash !== undefined && resource.hash !== actualHash) {
        issues.push(
          `resource ${resource.path}: hash mismatch (expected ${resource.hash}, got ${actualHash})`,
        );
      }
      if (resource.bytes !== undefined && resource.bytes !== member.length) {
        issues.push(
          `resource ${resource.path}: byte length mismatch (expected ${resource.bytes}, got ${member.length})`,
        );
      }
    }
  }

  let digestOk = false;
  const digestBytes = files["datapackage-digest.json"];
  if (!digestBytes) {
    issues.push("missing datapackage-digest.json");
  } else {
    try {
      const digest = JSON.parse(decoder.decode(digestBytes)) as {
        hash?: unknown;
      } | null;
      const expected = `sha256:${sha256Hex(datapackageBytes)}`;
      if (digest?.hash === expected) {
        digestOk = true;
      } else {
        issues.push(
          `datapackage-digest.json hash mismatch (expected ${expected}, got ${String(digest?.hash)})`,
        );
      }
    } catch (error) {
      issues.push(`invalid datapackage-digest.json: ${errorMessage(error)}`);
    }
  }

  return {
    members,
    datapackagePath: "datapackage.json",
    resources,
    digestOk,
    issues,
  };
}
