/* waxseal — progressive enhancement only.
   The page is fully readable with JavaScript disabled: the theme toggle,
   copy buttons, nav shadow, scroll reveal, and mobile nav are additive.
   No network calls anywhere in this file. */
(function () {
  "use strict";

  var THEME_KEY = "waxseal-theme";
  var root = document.documentElement;

  /* ------------------------------------------------------------------ */
  /* Theme — persisted, respects prefers-color-scheme, dark by default. */
  /* ------------------------------------------------------------------ */

  function readStoredTheme() {
    try {
      return window.localStorage.getItem(THEME_KEY);
    } catch (error) {
      return null;
    }
  }

  function prefersDark() {
    return (
      typeof window.matchMedia === "function" &&
      window.matchMedia("(prefers-color-scheme: dark)").matches
    );
  }

  function applyTheme(theme, button) {
    root.setAttribute("data-theme", theme);
    if (!button) return;
    var dark = theme === "dark";
    button.textContent = dark ? "Light mode" : "Dark mode";
    button.setAttribute("aria-pressed", dark ? "true" : "false");
    button.setAttribute(
      "aria-label",
      dark ? "Switch to light theme" : "Switch to dark theme"
    );
  }

  function initTheme() {
    var button = document.getElementById("theme-toggle");
    var stored = readStoredTheme();
    var initial =
      stored === "light" || stored === "dark"
        ? stored
        : prefersDark()
          ? "dark"
          : "light";

    applyTheme(initial, button);
    if (!button) return;

    button.addEventListener("click", function () {
      var current = root.getAttribute("data-theme");
      var next = current === "dark" ? "light" : "dark";
      applyTheme(next, button);
      try {
        window.localStorage.setItem(THEME_KEY, next);
      } catch (error) {
        /* storage may be unavailable; the in-page theme still applies */
      }
    });
  }

  /* ------------------------------------------------------------------ */
  /* Clipboard                                                          */
  /* ------------------------------------------------------------------ */

  function copyText(text) {
    if (navigator.clipboard && window.isSecureContext) {
      return navigator.clipboard.writeText(text);
    }

    return new Promise(function (resolve, reject) {
      var area = document.createElement("textarea");
      area.value = text;
      area.setAttribute("readonly", "");
      area.style.position = "fixed";
      area.style.top = "-1000px";
      document.body.appendChild(area);
      area.select();

      try {
        var ok = document.execCommand("copy");
        document.body.removeChild(area);
        ok ? resolve() : reject(new Error("copy failed"));
      } catch (err) {
        document.body.removeChild(area);
        reject(err);
      }
    });
  }

  function canCopy() {
    if (navigator.clipboard && window.isSecureContext) {
      return true;
    }
    return (
      typeof document.queryCommandSupported === "function" &&
      document.queryCommandSupported("copy")
    );
  }

  function setCopied(button, ok) {
    if (button.dataset.label === undefined) {
      button.dataset.label = button.textContent.trim() || "Copy";
    }
    button.textContent = ok ? "Copied" : "Copy failed";
    button.setAttribute("data-copied", ok ? "true" : "false");

    window.clearTimeout(button._resetTimer);
    button._resetTimer = window.setTimeout(function () {
      button.textContent = button.dataset.label;
      button.removeAttribute("data-copied");
    }, 1600);
  }

  function resolveCopyText(button) {
    if (button.dataset.copy !== undefined) {
      return button.dataset.copy;
    }
    var target = button.dataset.copyTarget;
    if (target) {
      var node = document.querySelector(target);
      if (!node) return "";
      return node.textContent.trim();
    }
    return "";
  }

  function bindCopyButton(button) {
    if (button.dataset.copyBound === "true") return;
    button.dataset.copyBound = "true";
    button.addEventListener("click", function () {
      var text = resolveCopyText(button);
      copyText(text).then(
        function () {
          setCopied(button, true);
        },
        function () {
          setCopied(button, false);
        }
      );
    });
  }

  function enhanceCopyButtons() {
    if (!canCopy()) return;

    Array.prototype.forEach.call(
      document.querySelectorAll("[data-copy], [data-copy-target]"),
      bindCopyButton
    );

    /* Code blocks get an auto-injected copy button. */
    Array.prototype.forEach.call(document.querySelectorAll("pre.code"), function (pre) {
      if (pre.querySelector(".copy-btn")) return;
      var code = pre.querySelector("code") || pre;
      var button = document.createElement("button");
      button.type = "button";
      button.className = "copy-btn";
      button.textContent = "Copy";
      button.setAttribute("aria-label", "Copy code to clipboard");
      button.dataset.copy = code.textContent.trim();
      bindCopyButton(button);
      pre.appendChild(button);
    });
  }

  /* ------------------------------------------------------------------ */
  /* Hash chips — middle truncation + copy for the demo member table.   */
  /* ------------------------------------------------------------------ */

  function middleTruncate(value) {
    if (value.length <= 20) return value;
    return value.slice(0, 8) + "…" + value.slice(-8);
  }

  function enhanceHashCell(cell) {
    if (cell.dataset.enhanced === "true") return;
    var value = cell.textContent.trim();
    if (!/^[0-9a-f]{64}$/.test(value)) return;
    cell.dataset.enhanced = "true";
    cell.textContent = "";

    var chip = document.createElement("span");
    chip.className = "hash-chip";

    var text = document.createElement("span");
    text.className = "hash-text";
    text.textContent = middleTruncate(value);
    text.title = value;

    var button = document.createElement("button");
    button.type = "button";
    button.className = "copy-btn";
    button.textContent = "Copy";
    button.setAttribute("aria-label", "Copy full SHA-256");
    button.dataset.copy = value;
    bindCopyButton(button);

    chip.appendChild(text);
    chip.appendChild(button);
    cell.appendChild(chip);
  }

  function enhanceHashes(scope) {
    if (!canCopy()) return;
    Array.prototype.forEach.call(
      scope.querySelectorAll("#demo-members td:nth-child(2)"),
      enhanceHashCell
    );
  }

  function watchHashes() {
    var body = document.getElementById("demo-members");
    if (!body || typeof MutationObserver !== "function") return;
    var observer = new MutationObserver(function () {
      enhanceHashes(body);
    });
    observer.observe(body, { childList: true, subtree: true });
  }

  /* ------------------------------------------------------------------ */
  /* Sticky nav shadow                                                  */
  /* ------------------------------------------------------------------ */

  function initNavShadow() {
    var header = document.getElementById("site-header");
    if (!header) return;

    var ticking = false;
    function update() {
      header.classList.toggle("is-scrolled", window.scrollY > 8);
      ticking = false;
    }

    window.addEventListener(
      "scroll",
      function () {
        if (ticking) return;
        ticking = true;
        window.requestAnimationFrame(update);
      },
      { passive: true }
    );
    update();
  }

  /* ------------------------------------------------------------------ */
  /* Mobile nav                                                         */
  /* ------------------------------------------------------------------ */

  function initMobileNav() {
    var toggle = document.getElementById("nav-toggle");
    var nav = document.getElementById("primary-nav");
    if (!toggle || !nav) return;

    function setOpen(open) {
      nav.classList.toggle("is-open", open);
      toggle.setAttribute("aria-expanded", open ? "true" : "false");
    }

    toggle.addEventListener("click", function () {
      setOpen(toggle.getAttribute("aria-expanded") !== "true");
    });

    Array.prototype.forEach.call(nav.querySelectorAll("a"), function (link) {
      link.addEventListener("click", function () {
        setOpen(false);
      });
    });

    document.addEventListener("keydown", function (event) {
      if (event.key === "Escape") setOpen(false);
    });
  }

  /* ------------------------------------------------------------------ */
  /* Scroll reveal — safe with JS off; content stays visible.           */
  /* ------------------------------------------------------------------ */

  function initReveal() {
    var elements = document.querySelectorAll(".reveal");
    if (elements.length === 0) return;
    if (typeof IntersectionObserver !== "function") return;

    var reduceMotion =
      typeof window.matchMedia === "function" &&
      window.matchMedia("(prefers-reduced-motion: reduce)").matches;
    if (reduceMotion) return;

    var observer = new IntersectionObserver(
      function (entries) {
        entries.forEach(function (entry) {
          if (!entry.isIntersecting) return;
          entry.target.classList.remove("is-hidden");
          observer.unobserve(entry.target);
        });
      },
      { rootMargin: "0px 0px -8% 0px", threshold: 0.08 }
    );

    Array.prototype.forEach.call(elements, function (element) {
      var rect = element.getBoundingClientRect();
      if (rect.top < window.innerHeight * 0.85) return;
      element.classList.add("is-hidden");
      observer.observe(element);
    });
  }

  /* ------------------------------------------------------------------ */

  function init() {
    initTheme();
    enhanceCopyButtons();
    enhanceHashes(document);
    watchHashes();
    initNavShadow();
    initMobileNav();
    initReveal();
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", init);
  } else {
    init();
  }
})();
