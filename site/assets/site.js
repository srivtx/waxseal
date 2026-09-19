/* waxseal — progressive enhancement only.
   The page is fully readable with JavaScript disabled. Nothing here makes a
   network request. */
(function () {
  "use strict";

  var root = document.documentElement;

  function each(list, fn) {
    Array.prototype.forEach.call(list, fn);
  }

  /* ----- Theme toggle ---------------------------------------------------
     An explicit data-theme is stored when the visitor picks a theme;
     otherwise the stylesheet follows prefers-color-scheme. */
  var STORAGE_KEY = "waxseal-theme";
  var toggle = document.getElementById("theme-toggle");
  var toggleText = document.getElementById("theme-toggle-text");

  function storedTheme() {
    try {
      return window.localStorage.getItem(STORAGE_KEY);
    } catch (err) {
      return null;
    }
  }

  function prefersDark() {
    return (
      typeof window.matchMedia === "function" &&
      window.matchMedia("(prefers-color-scheme: dark)").matches
    );
  }

  function applyTheme(theme) {
    if (theme === "dark" || theme === "light") {
      root.setAttribute("data-theme", theme);
    } else {
      root.removeAttribute("data-theme");
    }

    if (!toggle) return;
    var isDark = theme === "dark" || (theme == null && prefersDark());
    toggle.setAttribute("aria-pressed", isDark ? "true" : "false");
    toggle.setAttribute(
      "aria-label",
      isDark ? "Switch to light theme" : "Switch to dark theme"
    );
    if (toggleText) toggleText.textContent = isDark ? "Dark" : "Light";
  }

  function currentTheme() {
    var explicit = root.getAttribute("data-theme");
    return explicit === "dark" || explicit === "light" ? explicit : storedTheme();
  }

  if (toggle) {
    toggle.addEventListener("click", function () {
      var isDark = toggle.getAttribute("aria-pressed") === "true";
      var next = isDark ? "light" : "dark";
      try {
        window.localStorage.setItem(STORAGE_KEY, next);
      } catch (err) {
        void 0;
      }
      applyTheme(next);
    });
  }

  applyTheme(currentTheme());

  /* ----- Mobile navigation ---------------------------------------------- */
  var navToggle = document.getElementById("nav-toggle");
  var nav = document.getElementById("site-nav");

  function closeNav() {
    if (nav) nav.setAttribute("data-open", "false");
    if (navToggle) navToggle.setAttribute("aria-expanded", "false");
  }

  if (navToggle && nav) {
    navToggle.addEventListener("click", function () {
      var open = nav.getAttribute("data-open") === "true";
      nav.setAttribute("data-open", open ? "false" : "true");
      navToggle.setAttribute("aria-expanded", open ? "false" : "true");
    });

    nav.addEventListener("click", function (event) {
      var target = event.target;
      if (target && target.closest && target.closest("a")) closeNav();
    });

    document.addEventListener("keydown", function (event) {
      if (event.key === "Escape") closeNav();
    });
  }

  /* ----- Copy to clipboard ---------------------------------------------- */
  function canCopy() {
    if (navigator.clipboard && window.isSecureContext) return true;
    return (
      typeof document.queryCommandSupported === "function" &&
      document.queryCommandSupported("copy")
    );
  }

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

  function flashLabel(button, ok, idle) {
    button.textContent = ok ? "Copied" : "Copy failed";
    button.setAttribute("data-copied", ok ? "true" : "false");
    window.clearTimeout(button._resetTimer);
    button._resetTimer = window.setTimeout(function () {
      button.textContent = idle;
      button.removeAttribute("data-copied");
    }, 1600);
  }

  function enhanceCopyButtons() {
    each(document.querySelectorAll("[data-copy]"), function (button) {
      var idle = button.textContent || "Copy";
      button.addEventListener("click", function () {
        var value = button.getAttribute("data-copy") || "";
        copyText(value).then(
          function () {
            flashLabel(button, true, idle);
          },
          function () {
            flashLabel(button, false, idle);
          }
        );
      });
    });
  }

  function enhanceCodeBlocks() {
    each(document.querySelectorAll("pre.code"), function (pre) {
      if (pre.querySelector(".code__copy")) return;
      var code = pre.querySelector("code") || pre;
      var text = code.textContent;

      var button = document.createElement("button");
      button.type = "button";
      button.className = "copy code__copy";
      button.textContent = "Copy";
      button.setAttribute("aria-label", "Copy code to clipboard");

      button.addEventListener("click", function () {
        copyText(text).then(
          function () {
            button.textContent = "Copied";
            button.setAttribute("data-copied", "true");
            window.clearTimeout(button._resetTimer);
            button._resetTimer = window.setTimeout(function () {
              button.textContent = "Copy";
              button.removeAttribute("data-copied");
            }, 1600);
          },
          function () {
            button.textContent = "Copy failed";
            button.setAttribute("data-copied", "false");
          }
        );
      });

      if (getComputedStyle(pre).position === "static") {
        pre.style.position = "relative";
      }
      pre.appendChild(button);
    });
  }

  /* ----- Scroll reveal (opacity + rise, once per element) ---------------
     The .js class is set in <head> only when IntersectionObserver exists and
     reduced motion is off, so content can never be stranded hidden. */
  function initReveal() {
    var items = document.querySelectorAll(".reveal");
    if (items.length === 0) return;

    if (!("IntersectionObserver" in window)) {
      each(items, function (el) {
        el.classList.add("is-visible");
      });
      return;
    }

    var observer = new IntersectionObserver(
      function (entries) {
        entries.forEach(function (entry) {
          if (!entry.isIntersecting) return;
          entry.target.classList.add("is-visible");
          observer.unobserve(entry.target);
        });
      },
      { threshold: 0.08, rootMargin: "0px 0px -40px 0px" }
    );

    each(items, function (el) {
      observer.observe(el);
    });
  }

  function init() {
    if (canCopy()) {
      enhanceCopyButtons();
      enhanceCodeBlocks();
    }
    initReveal();
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", init);
  } else {
    init();
  }
})();
