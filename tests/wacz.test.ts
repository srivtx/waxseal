import { describe, expect, test } from "bun:test";
import { strToU8, unzipSync, zipSync } from "fflate";
import { buildWacz, defaultWacz } from "../src/fixtures.ts";
import {
  inspectWacz,
  memberDigests,
  normalizeMemberPath,
  sha256Hex,
} from "../src/wacz.ts";

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

describe("member path normalization", () => {
  test("strips leading ./ and applies Unicode NFC", () => {
    expect(normalizeMemberPath("./a.txt")).toBe("a.txt");
    expect(normalizeMemberPath("././a.txt")).toBe("a.txt");
    expect(normalizeMemberPath("caf\u00e9.txt")).toBe("caf\u00e9.txt");
    expect(normalizeMemberPath("cafe\u0301.txt")).toBe("caf\u00e9.txt");
  });

  test("rejects absolute and traversal paths", () => {
    expect(() => normalizeMemberPath("/etc/passwd")).toThrow();
    expect(() => normalizeMemberPath("../secret")).toThrow();
    expect(() => normalizeMemberPath("a/../../b")).toThrow();
    expect(() => normalizeMemberPath("a//b")).toThrow();
    expect(() => normalizeMemberPath("")).toThrow();
  });

  test("memberDigests rejects a traversal entry instead of hashing it raw", () => {
    const archive = zipSync({
      "../evil.txt": strToU8("escape"),
      "good.txt": strToU8("ok"),
    });
    expect(() => memberDigests(archive)).toThrow();
  });

  test("rejects backslash and drive-letter paths", () => {
    expect(() => normalizeMemberPath("C:\\evil")).toThrow();
    expect(() => normalizeMemberPath("a\\..\\b")).toThrow();
    expect(() => normalizeMemberPath("dir\\file.txt")).toThrow();
    expect(() => normalizeMemberPath("C:/evil")).toThrow();
  });

  test("rejects percent-encoded traversal and separators", () => {
    expect(() => normalizeMemberPath("%2e%2e/x")).toThrow();
    expect(() => normalizeMemberPath("%2E%2E/x")).toThrow();
    expect(() => normalizeMemberPath("a/%2f/b")).toThrow();
    expect(() => normalizeMemberPath("a%5c..%5cb")).toThrow();
    expect(() => normalizeMemberPath("%00")).toThrow();
  });

  test("memberDigests rejects Windows and encoded traversal entries", () => {
    expect(() =>
      memberDigests(zipSync({ "C:\\evil": strToU8("x") })),
    ).toThrow();
    expect(() =>
      memberDigests(zipSync({ "%2e%2e/x": strToU8("x") })),
    ).toThrow();
  });

  test("directory entries are skipped and normalization is canonical", () => {
    const archive = zipSync({
      "dir/": new Uint8Array(0),
      "./dir/file.txt": strToU8("hello"),
    });
    const members = memberDigests(archive);
    expect(members.map((m) => m.path)).toEqual(["dir/file.txt"]);
  });
});

describe("member and size limits", () => {
  test("rejects an archive with too many members", () => {
    const archive = buildWacz([
      { path: "a.txt", data: "a" },
      { path: "b.txt", data: "b" },
      { path: "c.txt", data: "c" },
    ]);
    expect(() =>
      memberDigests(archive, { maxMembers: 2, maxUncompressedBytes: 1024 }),
    ).toThrow(/more than 2 members/);
  });

  test("rejects an archive that expands beyond the byte cap", () => {
    const archive = buildWacz([{ path: "a.txt", data: "hello world" }]);
    expect(() =>
      memberDigests(archive, { maxMembers: 100, maxUncompressedBytes: 4 }),
    ).toThrow(/expands beyond 4 bytes/);
  });

  test("inspector reports malformed archives instead of throwing", () => {
    const inspection = inspectWacz(strToU8("not a zip at all"));
    expect(inspection.members).toEqual([]);
    expect(inspection.digestOk).toBe(false);
    expect(inspection.issues[0]).toContain("failed to read zip");
  });

  test("inspector reports resources missing from the ZIP", () => {
    const archive = zipSync({
      "datapackage.json": strToU8(
        JSON.stringify({
          resources: [
            { path: "present.txt", hash: "sha256:x", bytes: 1 },
            { path: "absent.txt" },
          ],
        }),
      ),
    });
    const inspection = inspectWacz(archive);
    expect(
      inspection.issues.some((issue) => issue.includes("absent.txt")),
    ).toBe(true);
  });
});

describe("sha256Hex", () => {
  test("empty input matches the known empty-string hash", () => {
    expect(sha256Hex(new Uint8Array(0))).toBe(
      "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    );
  });
});
