import { existsSync, readFileSync, readdirSync, statSync } from "node:fs";
import { dirname, join, relative, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const siteRoot = dirname(dirname(fileURLToPath(import.meta.url)));
const siteDir = join(siteRoot, "site");
const stylesheets = [
  join(siteDir, "assets", "lens.css"),
  join(siteDir, "assets", "theme.css"),
];
const problems = [];

function rel(path) {
  return relative(siteRoot, path) || path;
}

function report(where, message) {
  problems.push(`${where}: ${message}`);
}

/*
 * Collect every class defined in lens.css and theme.css. The design system is
 * shared, so the page may only use classes those two files already define.
 */
const definedClasses = new Set();
const loadedStylesheets = [];

for (const stylesheet of stylesheets) {
  const name = rel(stylesheet);
  if (!existsSync(stylesheet)) {
    report(name, "stylesheet is missing");
    continue;
  }
  loadedStylesheets.push(name);
  const css = readFileSync(stylesheet, "utf8");
  for (const match of css.matchAll(/\.([A-Za-z_][A-Za-z0-9_-]*)/g)) {
    definedClasses.add(match[1]);
  }
}

const htmlFiles = readdirSync(siteDir)
  .filter((name) => name.endsWith(".html"))
  .sort();

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
  const filePath = join(siteDir, file);
  const html = readFileSync(filePath, "utf8");
  const tags = parseTags(html);

  const hasLang = tags.some(
    (tag) => tag.name === "html" && (tag.attrs.lang || "").trim().length > 0,
  );
  if (!hasLang) report(file, "missing a lang attribute on <html>");

  const h1Count = tags.filter((tag) => tag.name === "h1").length;
  if (h1Count === 0) report(file, "missing an <h1>");
  if (h1Count > 1) report(file, `has ${h1Count} <h1> elements, expected exactly one`);

  const ids = new Set(
    tags
      .map((tag) => tag.attrs.id)
      .filter((id) => typeof id === "string" && id.trim().length > 0),
  );

  const skipLink = tags.find((tag) => {
    if (tag.name !== "a") return false;
    const classes = (tag.attrs.class || "").split(/\s+/);
    return classes.includes("skip-link") && (tag.attrs.href || "").startsWith("#");
  });
  if (!skipLink) {
    report(file, "missing a skip link (a.skip-link with a #fragment href)");
  } else {
    const fragment = (skipLink.attrs.href || "").slice(1);
    if (fragment.length === 0 || !ids.has(fragment)) {
      report(file, `skip link href="${skipLink.attrs.href}" does not match an element id`);
    }
  }

  const mainCount = tags.filter((tag) => tag.name === "main").length;
  if (mainCount === 0) report(file, "missing a <main> landmark");
  if (mainCount > 1) {
    report(file, `has ${mainCount} <main> landmarks, expected exactly one`);
  }

  for (const tag of tags) {
    if (typeof tag.attrs.class === "string") {
      for (const token of tag.attrs.class.split(/\s+/)) {
        if (token && !definedClasses.has(token)) {
          report(
            file,
            `class "${token}" is not defined in ${loadedStylesheets.join(" or ")}`,
          );
        }
      }
    }

    const isScript = tag.name === "script";
    const isStylesheet =
      tag.name === "link" && /(^|\s)stylesheet(\s|$)/i.test(tag.attrs.rel || "");

    for (const key of ["href", "src"]) {
      const raw = tag.attrs[key];
      if (typeof raw !== "string") continue;
      const value = raw.trim();
      if (value.length === 0) continue;

      const isNetwork = /^https?:\/\//i.test(value) || value.startsWith("//");
      if (isNetwork) {
        if (isScript && key === "src") {
          report(file, `external script is not allowed: ${value}`);
        } else if (isStylesheet && key === "href") {
          report(file, `external stylesheet is not allowed: ${value}`);
        } else if (key === "src") {
          report(file, `src points at the network: ${value}`);
        }
        continue;
      }

      if (/^[a-z][a-z0-9+.-]*:/i.test(value)) continue;
      if (value.startsWith("#")) continue;

      const clean = value.split("#")[0].split("?")[0];
      if (clean.length === 0) continue;

      const target = clean.startsWith("/")
        ? join(siteDir, clean)
        : resolve(dirname(filePath), clean);

      if (!existsSync(target) || !statSync(target).isFile()) {
        report(file, `${key}="${value}" does not resolve to a file (${rel(target)})`);
      }
    }
  }
}

if (htmlFiles.length === 0) {
  report("site", "no HTML pages found");
}

console.log(
  `check-site: checked ${htmlFiles.length} page(s) against ${loadedStylesheets.join(" + ")} (${definedClasses.size} classes)`,
);

if (problems.length > 0) {
  for (const problem of problems) {
    console.error(`  - ${problem}`);
  }
  console.error(`check-site: ${problems.length} problem(s) found`);
  process.exit(1);
}

console.log("check-site: all internal links, classes, and page structure are OK");
