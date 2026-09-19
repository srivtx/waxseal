import { existsSync, readFileSync, readdirSync, statSync } from "node:fs";
import { dirname, join, relative, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const repoRoot = dirname(dirname(fileURLToPath(import.meta.url)));
const siteRoot = join(repoRoot, "site");
const stylesPath = join(siteRoot, "assets", "styles.css");
const problems = [];

function rel(path) {
  return relative(repoRoot, path) || path;
}

function report(where, message) {
  problems.push(`${where}: ${message}`);
}

if (!existsSync(stylesPath)) {
  report("site/assets/styles.css", "stylesheet is missing");
}

const css = existsSync(stylesPath) ? readFileSync(stylesPath, "utf8") : "";
const definedClasses = new Set(
  [...css.matchAll(/\.([A-Za-z_][A-Za-z0-9_-]*)/g)].map((match) => match[1]),
);

const htmlFiles = existsSync(siteRoot)
  ? readdirSync(siteRoot)
      .filter((name) => name.endsWith(".html"))
      .sort()
  : [];

function parseTags(html) {
  const tags = [];
  const tagRe = /<([a-zA-Z][a-zA-Z0-9-]*)\b([^>]*)>/g;
  let tag;
  while ((tag = tagRe.exec(html)) !== null) {
    const attrs = {};
    const attrRe = /([a-zA-Z_:][-a-zA-Z0-9_:.]*)\s*=\s*"([^"]*)"/g;
    let attr;
    while ((attr = attrRe.exec(tag[2])) !== null) {
      attrs[attr[1].toLowerCase()] = attr[2];
    }
    tags.push({ name: tag[1].toLowerCase(), attrs });
  }
  return tags;
}

for (const file of htmlFiles) {
  const filePath = join(siteRoot, file);
  const html = readFileSync(filePath, "utf8");
  const tags = parseTags(html);

  const hasLang = tags.some(
    (tag) => tag.name === "html" && (tag.attrs.lang || "").trim().length > 0,
  );
  if (!hasLang) report(file, "missing a lang attribute on <html>");

  const h1Count = tags.filter((tag) => tag.name === "h1").length;
  if (h1Count === 0) {
    report(file, "missing an <h1>");
  } else if (h1Count > 1) {
    report(file, `has ${h1Count} <h1> elements; pages must have exactly one`);
  }

  const hasSkipLink = tags.some((tag) => {
    if (tag.name !== "a") return false;
    const classes = (tag.attrs.class || "").split(/\s+/);
    return classes.includes("skip-link") && (tag.attrs.href || "").startsWith("#");
  });
  if (!hasSkipLink) {
    report(file, "missing a skip link (a.skip-link with a #fragment href)");
  }

  for (const tag of tags) {
    if (typeof tag.attrs.class === "string") {
      for (const token of tag.attrs.class.split(/\s+/)) {
        if (token && !definedClasses.has(token)) {
          report(file, `class "${token}" is not defined in assets/styles.css`);
        }
      }
    }

    for (const key of ["href", "src"]) {
      if (typeof tag.attrs[key] !== "string") continue;
      const raw = tag.attrs[key].trim();
      if (raw.length === 0) continue;

      const isAbsolute = /^[a-z][a-z0-9+.-]*:/i.test(raw) || raw.startsWith("//");
      if (isAbsolute) {
        const isNetwork = /^(https?:)?\/\//i.test(raw);
        if (
          isNetwork &&
          (key === "src" || (key === "href" && tag.name === "link"))
        ) {
          report(file, `external ${key} is not allowed: ${raw}`);
        }
        continue;
      }

      if (raw.startsWith("#")) continue;

      const clean = raw.split("#")[0].split("?")[0];
      if (clean.length === 0) continue;

      const target = clean.startsWith("/")
        ? join(siteRoot, clean)
        : resolve(dirname(filePath), clean);

      if (!existsSync(target) || !statSync(target).isFile()) {
        report(file, `${key}="${raw}" does not resolve to a file (${rel(target)})`);
      }
    }
  }
}

if (htmlFiles.length === 0) {
  report(".", "no HTML pages found under site/");
}

console.log(
  `check-site: checked ${htmlFiles.length} page(s) against ${definedClasses.size} CSS classes`,
);

if (problems.length > 0) {
  for (const problem of problems) {
    console.error(`  - ${problem}`);
  }
  console.error(`check-site: ${problems.length} problem(s) found`);
  process.exit(1);
}

console.log("check-site: all internal links, classes, and page structure are OK");
