
/*
 * Single-file application packager
 * Location: public/single-file.js
 *
 * Packages all configured pages into one downloadable HTML document.
 * Each page remains in its own iframe to isolate its scripts and styles.
 */

(() => {
  "use strict";

  const CONFIG = {
    outputName: "Donor-Trust-Quota-Application.html",
    requestTimeoutMs: 25000,
    maxPageBytes: 4 * 1024 * 1024,

    pages: [
      { title: "Application Home", url: "/index.html" },
      { title: "Applicant Instructions", url: "/applicant-instructions.html" },
      { title: "Cover Letter", url: "/cover-letter.html" },
      { title: "Applicant Details", url: "/page-1-applicant.html" },
      { title: "Contact Details", url: "/page-2-contact.html" },
      { title: "Eligibility", url: "/page-3-eligibility.html" },
      { title: "Photo and Signature", url: "/page-4-photo.html" },
      { title: "Supporting Documents", url: "/page-5-documents.html" },
      { title: "Consent", url: "/page-6-consent.html" },
      { title: "Review Application", url: "/page-7-review.html" },
      { title: "Privacy Notice", url: "/privacy-notice.html" }
    ]
  };

  let building = false;

  const statusNode = () =>
    document.querySelector("[data-build-status]");

  const buildButtons = () =>
    [...document.querySelectorAll("[data-build-single-file]")];

  function setStatus(message, error = false) {
    const node = statusNode();
    if (!node) return;

    node.textContent = message;
    node.setAttribute("role", error ? "alert" : "status");
    node.style.color = error ? "#b42318" : "#333";
  }

  function absolutePageUrl(path) {
    return new URL(path, window.location.origin).href;
  }

  async function fetchPage(page) {
    const url = absolutePageUrl(page.url);
    const controller = new AbortController();

    const timeout = window.setTimeout(
      () => controller.abort(),
      CONFIG.requestTimeoutMs
    );

    try {
      const response = await fetch(url, {
        method: "GET",
        credentials: "same-origin",
        cache: "no-store",
        signal: controller.signal
      });

      if (!response.ok) {
        throw new Error(
          `Could not load ${page.url} (HTTP ${response.status}).`
        );
      }

      const html = await response.text();

      if (
        new TextEncoder().encode(html).byteLength >
        CONFIG.maxPageBytes
      ) {
        throw new Error(
          `${page.url} exceeds the packaging size limit.`
        );
      }

      return {
        title: page.title,
        url,
        html: normalizePage(html, url)
      };
    } finally {
      clearTimeout(timeout);
    }
  }

  function normalizePage(html, pageUrl) {
    const doc = new DOMParser().parseFromString(
      html,
      "text/html"
    );

    if (!doc.documentElement || !doc.body) {
      throw new Error(`Invalid HTML in ${pageUrl}.`);
    }

    // Keep relative assets resolvable from the live website.
    let base = doc.head.querySelector("base");

    if (!base) {
      base = doc.createElement("base");
      doc.head.prepend(base);
    }

    base.href = new URL(".", pageUrl).href;

    return "<!doctype html>\n" +
      doc.documentElement.outerHTML;
  }

  function utf8ToBase64(value) {
    const bytes = new TextEncoder().encode(value);
    let binary = "";
    const step = 0x8000;

    for (let i = 0; i < bytes.length; i += step) {
      binary += String.fromCharCode(
        ...bytes.subarray(i, i + step)
      );
    }

    return btoa(binary);
  }

  async function collectPages() {
    const pages = [];

    for (let i = 0; i < CONFIG.pages.length; i++) {
      const page = CONFIG.pages[i];

      setStatus(
        `Loading page ${i + 1} of ${CONFIG.pages.length}: ${page.title}`
      );

      pages.push(await fetchPage(page));
    }

    return pages;
  }

  function makeStandaloneDocument(pages) {
    const payload = pages.map(page => ({
      title: page.title,
      url: page.url,
      htmlBase64: utf8ToBase64(page.html)
    }));

    const encodedPayload = JSON.stringify(payload)
      .replace(/</g, "\\u003c")
      .replace(/>/g, "\\u003e")
      .replace(/&/g, "\\u0026")
      .replace(/\u2028/g, "\\u2028")
      .replace(/\u2029/g, "\\u2029");

    const closeScript = "</" + "script>";

    return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="color-scheme" content="light">
<title>Donor / Trust Quota Application</title>
<style>
:root {
  font-family: Arial, Helvetica, sans-serif;
  color: #111;
  background: #fff;
}
* { box-sizing: border-box; }
body { margin: 0; background: #fff; color: #111; }
.package-header {
  position: sticky;
  top: 0;
  z-index: 999;
  background: #fff;
  border-bottom: 1px solid #ccc;
  padding: 12px;
}
.package-title { font-size: 18px; margin: 0 0 10px; }
.package-controls { display: flex; gap: 8px; flex-wrap: wrap; }
.package-controls button {
  min-height: 42px;
  padding: 10px 13px;
  border: 1px solid #222;
  border-radius: 6px;
  background: #fff;
  color: #111;
  font-size: 14px;
  font-weight: 700;
}
.package-controls button:disabled { opacity: .4; }
.package-progress { font-size: 13px; color: #444; margin-top: 9px; }
.package-pages { width: 100%; min-height: 70vh; }
.package-frame {
  display: none;
  width: 100%;
  height: calc(100vh - 140px);
  min-height: 520px;
  border: 0;
  background: #fff;
}
.package-frame.active { display: block; }
.package-footer {
  padding: 12px;
  border-top: 1px solid #ddd;
  color: #555;
  font-size: 12px;
  line-height: 1.5;
}
@media(max-width:600px) {
  .package-frame {
    height: calc(100vh - 180px);
    min-height: 480px;
  }
  .package-controls button { flex: 1 1 auto; }
}
@media print {
  .package-header, .package-footer { display: none !important; }
  .package-frame { display: none !important; }
  .package-frame.active {
    display: block !important;
    height: auto;
    min-height: 100vh;
  }
}
</style>
</head>
<body>
<header class="package-header">
  <h1 class="package-title">Donor / Trust Quota Application</h1>
  <nav class="package-controls" aria-label="Application pages">
    <button type="button" id="packagePrevious">Previous</button>
    <button type="button" id="packageNext">Next</button>
    <button type="button" id="packageOpenOriginal">Open original page</button>
    <button type="button" id="packagePrint">Print / Save PDF</button>
  </nav>
  <div id="packageProgress" class="package-progress" aria-live="polite">
    Opening application…
  </div>
</header>

<main id="packagePages" class="package-pages"></main>

<footer class="package-footer">
  This file contains the configured pages in a page-by-page viewer.
  External assets and server APIs may require internet access.
  Keep applicant information and attachments private.
  Downloading this file does not submit an application.
</footer>

<script id="packagePayload" type="application/json">${encodedPayload}${closeScript}

<script>
(function() {
  "use strict";

  const payloadNode = document.getElementById("packagePayload");
  const pages = JSON.parse(payloadNode.textContent);
  const container = document.getElementById("packagePages");
  const progress = document.getElementById("packageProgress");
  const previous = document.getElementById("packagePrevious");
  const next = document.getElementById("packageNext");
  const openOriginal = document.getElementById("packageOpenOriginal");
  const printButton = document.getElementById("packagePrint");

  let activeIndex = 0;
  const frames = [];

  function decodeBase64Utf8(value) {
    const binary = atob(value);
    const bytes = new Uint8Array(binary.length);

    for (let i = 0; i < binary.length; i++) {
      bytes[i] = binary.charCodeAt(i);
    }

    return new TextDecoder().decode(bytes);
  }

  function update() {
    pages.forEach((page, index) => {
      frames[index].classList.toggle(
        "active",
        index === activeIndex
      );

      frames[index].setAttribute(
        "aria-hidden",
        index === activeIndex ? "false" : "true"
      );
    });

    previous.disabled = activeIndex === 0;
    next.disabled = activeIndex === pages.length - 1;

    progress.textContent =
      (activeIndex + 1) + " of " + pages.length +
      " -- " + pages[activeIndex].title;
  }

  function show(index) {
    if (
      !Number.isInteger(index) ||
      index < 0 ||
      index >= pages.length
    ) {
      return;
    }

    activeIndex = index;
    update();
    window.scrollTo({ top: 0, behavior: "auto" });
  }

  function installLinkRouting(frame, index) {
    frame.addEventListener("load", function() {
      try {
        const doc = frame.contentDocument;

        if (
          !doc ||
          doc.documentElement.dataset.packageRoutingInstalled === "yes"
        ) {
          return;
        }

        doc.documentElement.dataset.packageRoutingInstalled = "yes";

        doc.addEventListener("click", function(event) {
          const link = event.target.closest &&
            event.target.closest("a[href]");

          if (!link) return;

          const href = link.getAttribute("href");

          if (
            !href ||
            href.startsWith("#") ||
            /^(mailto:|tel:|javascript:|data:)/i.test(href) ||
            link.hasAttribute("download")
          ) {
            return;
          }

          let target;

          try {
            target = new URL(href, pages[index].url);
          } catch (_) {
            return;
          }

          const found = pages.findIndex(page =>
            new URL(page.url).pathname === target.pathname
          );

          if (found !== -1) {
            event.preventDefault();
            show(found);
          }
        }, true);
      } catch (_) {
        // Browser restrictions leave normal page navigation available.
      }
    });
  }

  pages.forEach((page, index) => {
    const frame = document.createElement("iframe");

    frame.className = "package-frame";
    frame.title = page.title;
    frame.loading = index === 0 ? "eager" : "lazy";
    frame.referrerPolicy = "strict-origin-when-cross-origin";

    container.appendChild(frame);
    frames.push(frame);

    installLinkRouting(frame, index);

    // Each page retains a separate document and script scope.
    frame.srcdoc = decodeBase64Utf8(page.htmlBase64);
  });

  previous.addEventListener("click", () => show(activeIndex - 1));
  next.addEventListener("click", () => show(activeIndex + 1));

  openOriginal.addEventListener("click", () => {
    window.open(
      pages[activeIndex].url,
      "_blank",
      "noopener,noreferrer"
    );
  });

  printButton.addEventListener("click", () => {
    try {
      frames[activeIndex].contentWindow.focus();
      frames[activeIndex].contentWindow.print();
    } catch (_) {
      progress.textContent =
        "Printing was blocked. Try opening the original page first.";
    }
  });

  if (pages.length) {
    show(0);
  } else {
    progress.textContent = "No pages were packaged.";
    previous.disabled = true;
    next.disabled = true;
    openOriginal.disabled = true;
    printButton.disabled = true;
  }
})();
${closeScript}
</body>
</html>`;
  }

  async function buildSingleFile() {
    if (building) return;

    if (
      window.location.protocol !== "https:" &&
      window.location.hostname !== "localhost" &&
      window.location.hostname !== "127.0.0.1"
    ) {
      setStatus(
        "Open this builder from your deployed HTTPS website.",
        true
      );
      return;
    }

    building = true;
    buildButtons().forEach(button => button.disabled = true);

    try {
      const pages = await collectPages();

      setStatus("Combining all pages into one HTML file…");

      const output = makeStandaloneDocument(pages);
      const blob = new Blob(
        [output],
        { type: "text/html;charset=utf-8" }
      );

      const objectUrl = URL.createObjectURL(blob);
      const anchor = document.createElement("a");

      anchor.href = objectUrl;
      anchor.download = CONFIG.outputName;
      anchor.style.display = "none";

      document.body.appendChild(anchor);
      anchor.click();
      anchor.remove();

      window.setTimeout(
        () => URL.revokeObjectURL(objectUrl),
        60000
      );

      setStatus(
        `Created ${CONFIG.outputName}. Check your browser downloads.`
      );
    } catch (error) {
      console.error("Single-file build failed:", error);

      setStatus(
        error instanceof Error
          ? error.message
          : "Could not create the single HTML file.",
        true
      );
    } finally {
      building = false;
      buildButtons().forEach(button => button.disabled = false);
    }
  }

  function initialise() {
    buildButtons().forEach(button => {
      if (button.dataset.singleFileBound === "yes") return;

      button.dataset.singleFileBound = "yes";
      button.addEventListener("click", buildSingleFile);
    });
  }

  if (document.readyState === "loading") {
    document.addEventListener(
      "DOMContentLoaded",
      initialise,
      { once: true }
    );
  } else {
    initialise();
  }
})();
</script>
