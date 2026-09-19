/// <reference types="bun" />
import { createHash } from "node:crypto";
import { unzipSync } from "fflate";
import type {
  DatapackageResource,
  MemberDigest,
  WaczInspection,
} from "./types.ts";

const decoder = new TextDecoder();

export function sha256Hex(bytes: Uint8Array): string {
  return createHash("sha256").update(bytes).digest("hex");
}

function comparePaths(a: string, b: string): number {
  return a < b ? -1 : a > b ? 1 : 0;
}

function digestOf(path: string, bytes: Uint8Array): MemberDigest {
  return { path, sha256: sha256Hex(bytes), size: bytes.length };
}

function digestsOf(files: Record<string, Uint8Array>): MemberDigest[] {
  return Object.keys(files)
    .map((path) => digestOf(path, files[path]!))
    .sort((a, b) => comparePaths(a.path, b.path));
}

function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}

export function memberDigests(data: Uint8Array): MemberDigest[] {
  return digestsOf(unzipSync(data));
}

export function inspectWacz(data: Uint8Array): WaczInspection {
  const issues: string[] = [];
  let files: Record<string, Uint8Array>;
  try {
    files = unzipSync(data);
  } catch (error) {
    return {
      members: [],
      resources: [],
      digestOk: false,
      issues: [`failed to read zip: ${errorMessage(error)}`],
    };
  }

  const members = digestsOf(files);
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
      const member = files[resource.path];
      if (!member) continue;

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
