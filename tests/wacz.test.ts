import { describe, expect, test } from "bun:test";
import { unzipSync, zipSync } from "fflate";
import { defaultWacz } from "../src/fixtures.ts";
import { inspectWacz, memberDigests, sha256Hex } from "../src/wacz.ts";

describe("memberDigests", () => {
  test("returns sorted paths including datapackage files", () => {
    const members = memberDigests(defaultWacz());
    const paths = members.map((m) => m.path);
    expect(paths).toEqual([...paths].sort());
    expect(paths).toContain("datapackage.json");
    expect(paths).toContain("datapackage-digest.json");
  });
});

describe("inspectWacz", () => {
  test("defaultWacz has digestOk true and no issues", () => {
    const inspection = inspectWacz(defaultWacz());
    expect(inspection.digestOk).toBe(true);
    expect(inspection.issues).toEqual([]);
    expect(inspection.datapackagePath).toBe("datapackage.json");
    expect(inspection.resources.length).toBeGreaterThan(0);
  });

  test("reports an issue when a resource byte is mutated", () => {
    const original = unzipSync(defaultWacz());
    const mutated: Record<string, Uint8Array> = {};
    for (const [path, bytes] of Object.entries(original)) {
      mutated[path] = bytes;
    }
    const warc = mutated["archive/data.warc.gz"]!;
    mutated["archive/data.warc.gz"] = Uint8Array.from([...warc, 0x20]);

    const inspection = inspectWacz(zipSync(mutated));
    expect(inspection.issues.length).toBeGreaterThan(0);
    expect(inspection.issues.some((issue) => issue.includes("archive/data.warc.gz"))).toBe(
      true,
    );
  });
});

describe("sha256Hex", () => {
  test("empty input matches the known empty-string hash", () => {
    expect(sha256Hex(new Uint8Array(0))).toBe(
      "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    );
  });
});
