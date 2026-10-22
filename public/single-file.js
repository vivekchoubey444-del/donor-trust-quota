
/*
 * MedOrbits -- Advanced Single-File Application Packager
 * File: public/single-file.js
 *
 * Purpose:
 *   Fetch configured HTML pages and package them into one downloadable
 *   HTML document with an iframe-based page viewer.
 *
 * Important:
 *   - This is a page packager, not a server/database packager.
 *   - External assets and backend APIs may still require the original site.
 *   - Never include real administrator secrets or private applicant records
 *     in the pages being packaged.
 */

(() => {
  "use strict";

  // ============================================================
  // 1. CONFIGURATION
  // ============================================================

  const CONFIG = Object.freeze({
    outputName: "Donor-Trust-Quota-Application.html",

    requestTimeoutMs: 25000,
    maxPageBytes: 4 * 1024 * 1024,
    maxTotalBytes: 24 * 1024 * 1024,
    maxPages: 40,
    concurrency: 3,

    // A failed page stops the build. This prevents silently
    // producing an incomplete application pack.
    failOnPageError: true,

    // Include a page selector and navigation in the generated viewer.
    includePageSelector: true,

    // Page routes must be same-origin paths.
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
  });

  let building = false;
  let buildController = null;
  let currentProgress = { completed: 0, total: 0 };
  let totalDownloadedBytes = 0;

  const statusNode = () =>
    document.querySelector("[data-build-status]");

  const buildButtons = () =>
    [...document.querySelectorAll("[data-build-single-file]")];

  const cancelButtons = () =>
    [...document.querySelectorAll("[data-cancel-single-file]")];

  // ============================================================
  // 2. STATUS AND UI
  // ============================================================

  function setStatus(message, error = false) {
    const node = statusNode();
    if (!node) return;

    node.textContent = String(message);
    node.setAttribute("role", error ? "alert" : "status");
    node.setAttribute("aria-live", error ? "assertive" : "polite");
    node.style.color = error ? "#b42318" : "#333";
  }

  function setBuildBusy(busy) {
    buildButtons().forEach(button => {
      button.disabled = busy;
      button.setAttribute("aria-busy", busy ? "true" : "false");
    });

    cancelButtons().forEach(button => {
      button.disabled = !busy;
      button.classList.toggle("hidden", !busy);
    });
  }

  function reportProgress(title) {
    currentProgress.completed++;

    setStatus(
      "Loaded " + currentProgress.completed +
      " of " + currentProgress.total + " pages · " + title
    );
  }

  function cancelBuild() {
    if (!building || !buildController) return;

    buildController.abort();
    setStatus("Cancellation requested. Stopping the current build…");
  }

  // ============================================================
  // 3. URL VALIDATION
  // ============================================================

  function resolveConfiguredPage(path) {
    if (typeof path !== "string" || !path.trim()) {
      throw new Error("A configured page has no URL.");
    }

    // Only accept root-relative paths. Avoid external URLs,
    // protocol-relative URLs, and JavaScript/data URL schemes.
    if (
      !path.startsWith("/") ||
      path.startsWith("//") ||
      path.includes("\\") ||
      /[\u0000-\u001f]/.test(path)
    ) {
      throw new Error("Only root-relative page paths are allowed: " + path);
    }

    const url = new URL(path, window.location.origin);

    if (url.origin !== window.location.origin) {
      throw new Error("External page URL rejected: " + path);
    }

    if (!["http:", "https:"].includes(url.protocol)) {
      throw new Error("Unsupported page URL protocol: " + path);
    }

    // Fragments identify locations inside a page; they should not
    // create separate packaged page entries.
    url.hash = "";

    return url;
  }

  function validateConfiguration() {
    if (!Array.isArray(CONFIG.pages) || CONFIG.pages.length === 0) {
      throw new Error("No pages are configured for packaging.");
    }

    if (CONFIG.pages.length > CONFIG.maxPages) {
      throw new Error(
        "Too many configured pages. Maximum: " + CONFIG.maxPages + "."
      );
    }

    if (
      !Number.isInteger(CONFIG.concurrency) ||
      CONFIG.concurrency < 1 ||
      CONFIG.concurrency > 6
    ) {
      throw new Error("Concurrency must be between 1 and 6.");
    }

    const seenPaths = new Set();

    for (const page of CONFIG.pages) {
      if (!page || typeof page.title !== "string" || !page.title.trim()) {
        throw new Error("Every configured page needs a title.");
      }

      const url = resolveConfiguredPage(page.url);
      const key = url.pathname;

      if (seenPaths.has(key)) {
        throw new Error("Duplicate configured page path: " + key);
      }

      seenPaths.add(key);
    }
  }

  // ============================================================
  // 4. FETCH AND NORMALIZE HTML
  // ============================================================

  function getUtf8ByteLength(value) {
    return new TextEncoder().encode(value).byteLength;
  }

  function normalizePage(html, pageUrl) {
    const parser = new DOMParser();
    const doc = parser.parseFromString(html, "text/html");

    if (!doc.documentElement || !doc.head || !doc.body) {
      throw new Error("Invalid HTML returned for " + pageUrl.pathname + ".");
    }

    // Ensure relative URLs resolve against the original website.
    // This does not embed external images, stylesheets, fonts, or scripts.
    let base = doc.head.querySelector("base");

    if (!base) {
      base = doc.createElement("base");
      doc.head.prepend(base);
    }

    base.href = new URL(".", pageUrl).href;

    // Prevent duplicate base elements from overriding the intended base.
    const allBases = [...doc.head.querySelectorAll("base")];

    for (const extraBase of allBases.slice(1)) {
      extraBase.remove();
    }

    // Remove meta refresh redirects from the packaged page.
    // This prevents a packaged page from immediately redirecting the viewer.
    doc.head.querySelectorAll('meta[http-equiv]').forEach(meta => {
      const value = (meta.getAttribute("http-equiv") || "").trim().toLowerCase();

      if (value === "refresh") {
        meta.remove();
      }
    });

    return "<!doctype html>\n" + doc.documentElement.outerHTML;
  }

  async function fetchPage(page, signal) {
    const url = resolveConfiguredPage(page.url);
    const controller = new AbortController();

    let timeoutId;

    const abortFromParent = () => controller.abort();

    if (signal.aborted) {
      controller.abort();
    } else {
      signal.addEventListener("abort", abortFromParent, { once: true });
    }

    timeoutId = window.setTimeout(
      () => controller.abort(),
      CONFIG.requestTimeoutMs
    );

    try {
      const response = await fetch(url.href, {
        method: "GET",
        credentials: "same-origin",
        cache: "no-store",
        redirect: "error",
        referrerPolicy: "no-referrer",
        headers: {
          "Accept": "text/html,application/xhtml+xml"
        },
        signal: controller.signal
      });

      if (!response.ok) {
        throw new Error(
          "Could not load " + page.url +
          " (HTTP " + response.status + ")."
        );
      }

      const contentType = (
        response.headers.get("content-type") || ""
      ).toLowerCase();

      if (
        contentType &&
        !contentType.includes("text/html") &&
        !contentType.includes("application/xhtml+xml")
      ) {
        throw new Error(
          page.url + " did not return an HTML document."
        );
      }

      const html = await response.text();
      const pageBytes = getUtf8ByteLength(html);

      if (pageBytes > CONFIG.maxPageBytes) {
        throw new Error(
          page.url + " exceeds the " +
          Math.round(CONFIG.maxPageBytes / 1024 / 1024) +
          " MB per-page limit."
        );
      }

      totalDownloadedBytes += pageBytes;

      if (totalDownloadedBytes > CONFIG.maxTotalBytes) {
        throw new Error(
          "The combined HTML exceeds the " +
          Math.round(CONFIG.maxTotalBytes / 1024 / 1024) +
          " MB total packaging limit."
        );
      }

      const normalizedHtml = normalizePage(html, url);

      reportProgress(page.title);

      return {
        title: page.title.trim(),
        url: url.href,
        pathname: url.pathname,
        bytes: pageBytes,
        html: normalizedHtml
      };
    } catch (error) {
      if (signal.aborted || error?.name === "AbortError") {
        throw new Error("Build cancelled or request timed out: " + page.url);
      }

      throw error;
    } finally {
      window.clearTimeout(timeoutId);
      signal.removeEventListener("abort", abortFromParent);
    }
  }

  // ============================================================
  // 5. FETCH PAGES WITH BOUNDED CONCURRENCY
  // ============================================================

  async function collectPages(signal) {
    const results = new Array(CONFIG.pages.length);
    let nextIndex = 0;
    let firstError = null;

    currentProgress = {
      completed: 0,
      total: CONFIG.pages.length
    };

    totalDownloadedBytes = 0;

    async function worker() {
      while (!signal.aborted && !firstError) {
        const index = nextIndex++;

        if (index >= CONFIG.pages.length) return;

        const page = CONFIG.pages[index];

        try {
          results[index] = await fetchPage(page, signal);
        } catch (error) {
          firstError = error;

          // Stop other workers as soon as one page fails.
          buildController?.abort();
          return;
        }
      }
    }

    const workers = Array.from(
      { length: Math.min(CONFIG.concurrency, CONFIG.pages.length) },
      () => worker()
    );

    await Promise.all(workers);

    if (firstError) throw firstError;

    if (signal.aborted) {
      throw new Error("The build was cancelled.");
    }

    if (results.some(result => !result)) {
      throw new Error("One or more pages could not be packaged.");
    }

    return results;
  }

  // ============================================================
  // 6. ENCODING
  // ============================================================

  function utf8ToBase64(value) {
    const bytes = new TextEncoder().encode(value);
    const step = 0x8000;
    const chunks = [];

    for (let i = 0; i < bytes.length; i += step) {
      let binary = "";

      for (const byte of bytes.subarray(i, i + step)) {
        binary += String.fromCharCode(byte);
      }

      chunks.push(binary);
    }

    return btoa(chunks.join(""));
  }

  function safeJsonForHtmlScript(value) {
    return JSON.stringify(value)
      .replace(/</g, "\\u003c")
      .replace(/>/g, "\\u003e")
      .replace(/&/g, "\\u0026")
      .replace(/\u2028/g, "\\u2028")
      .replace(/\u2029/g, "\\u2029");
  }

  // ============================================================
  // 7. BUILD THE STANDALONE HTML VIEWER
  // ============================================================

  function makeStandaloneDocument(pages) {
    const payload = pages.map(page => ({
      title: page.title,
      url: page.url,
      pathname: page.pathname,
      bytes: page.bytes,
      htmlBase64: utf8ToBase64(page.html)
    }));

    const encodedPayload = safeJsonForHtmlScript(payload);
    const closeScript = "</" + "script>";

    const selectorMarkup = CONFIG.includePageSelector
      ? '<label class="package-select-label" for="packagePageSelect">Go to page</label>' +
        '<select id="packagePageSelect" aria-label="Select application page"></select>'
      : "";

    return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="color-scheme" content="light">
<meta name="referrer" content="no-referrer">
<title>Donor / Trust Quota Application</title>
<style>
:root {
  color-scheme: light;
  font-family: Arial, Helvetica, sans-serif;
  color: #161616;
  background: #f3f4f6;
}
* { box-sizing: border-box; }
body { margin: 0; background: #f3f4f6; color: #161616; }
button, select { font: inherit; }
button:focus-visible, select:focus-visible {
  outline: 3px solid #9a772c;
  outline-offset: 3px;
}
.package-header {
  position: sticky;
  top: 0;
  z-index: 999;
  background: #fff;
  border-bottom: 1px solid #d5d5d5;
  box-shadow: 0 2px 8px rgba(0,0,0,.05);
  padding: 12px 16px;
}
.package-top {
  max-width: 1300px;
  margin: 0 auto;
}
.package-title {
  margin: 0 0 10px;
  font-size: 19px;
  line-height: 1.3;
}
.package-subtitle {
  margin: 0 0 12px;
  color: #555;
  font-size: 12px;
  line-height: 1.5;
}
.package-controls {
  display: flex;
  align-items: center;
  flex-wrap: wrap;
  gap: 8px;
}
.package-controls button,
.package-controls select {
  min-height: 42px;
  padding: 9px 12px;
  border: 1px solid #bdbdbd;
  border-radius: 7px;
  background: #fff;
  color: #171717;
  font-size: 13px;
  font-weight: 700;
}
.package-controls button:hover:not(:disabled) {
  background: #f3f0e8;
}
.package-controls button:disabled {
  opacity: .45;
  cursor: not-allowed;
}
.package-select-label {
  font-size: 12px;
  font-weight: 700;
}
.package-progress {
  margin-top: 10px;
  color: #454545;
  font-size: 12px;
  line-height: 1.5;
  overflow-wrap: anywhere;
}
.package-pages {
  width: 100%;
  min-height: 70vh;
}
.package-frame {
  display: none;
  width: 100%;
  height: calc(100vh - 190px);
  min-height: 520px;
  border: 0;
  background: #fff;
}
.package-frame.active {
  display: block;
}
.package-footer {
  padding: 13px 16px;
  border-top: 1px solid #d5d5d5;
  background: #fff;
  color: #555;
  font-size: 12px;
  line-height: 1.6;
}
.package-footer-inner {
  max-width: 1300px;
  margin: 0 auto;
}
.package-footer strong { color: #222; }
.package-print-status {
  margin-top: 8px;
  color: #555;
  font-size: 12px;
}
@media(max-width: 650px) {
  .package-header { padding: 10px; }
  .package-title { font-size: 17px; }
  .package-controls button { flex: 1 1 auto; }
  .package-controls select { max-width: 100%; width: 100%; }
  .package-frame {
    height: calc(100vh - 240px);
    min-height: 480px;
  }
}
@media print {
  .package-header,
  .package-footer { display: none !important; }
  .package-frame { display: none !important; }
  .package-frame.active {
    display: block !important;
    width: 100%;
    height: auto;
    min-height: 100vh;
    break-after: page;
  }
}
</style>
</head>
<body>
<header class="package-header">
  <div class="package-top">
    <h1 class="package-title">Donor / Trust Quota Application</h1>
    <p class="package-subtitle">
      Single-file page viewer · ${pages.length} packaged HTML pages
    </p>
    <nav class="package-controls" aria-label="Application pages">
      <button type="button" id="packagePrevious">← Previous</button>
      <button type="button" id="packageNext">Next →</button>
      ${selectorMarkup}
      <button type="button" id="packageReload">Reload page</button>
      <button type="button" id="packageOpenOriginal">Open original</button>
      <button type="button" id="packagePrint">Print current page</button>
      <button type="button" id="packagePrintAll">Print all pages</button>
    </nav>
    <div id="packageProgress" class="package-progress" aria-live="polite">
      Preparing application pages…
    </div>
  </div>
</header>

<main id="packagePages" class="package-pages"></main>

<footer class="package-footer">
  <div class="package-footer-inner">
    <strong>Important:</strong>
    This file contains the configured HTML documents. External assets,
    authentication, uploads, database operations and server APIs may still
    require the original website and network access. Downloading this file
    does not submit an application or establish official admission status.
    Keep applicant data and documents private.
    <div id="packagePrintStatus" class="package-print-status" aria-live="polite"></div>
  </div>
</footer>

<script id="packagePayload" type="application/json">${encodedPayload}${closeScript}
<script>
(function () {
  "use strict";

  const payloadNode = document.getElementById("packagePayload");
  const pages = JSON.parse(payloadNode.textContent);
  const container = document.getElementById("packagePages");
  const progress = document.getElementById("packageProgress");
  const printStatus = document.getElementById("packagePrintStatus");
  const previous = document.getElementById("packagePrevious");
  const next = document.getElementById("packageNext");
  const pageSelect = document.getElementById("packagePageSelect");
  const reloadButton = document.getElementById("packageReload");
  const openOriginal = document.getElementById("packageOpenOriginal");
  const printButton = document.getElementById("packagePrint");
  const printAllButton = document.getElementById("packagePrintAll");

  let activeIndex = 0;
  let printAllMode = false;
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
      const active = index === activeIndex;

      frames[index].classList.toggle("active", active);
      frames[index].setAttribute("aria-hidden", active ? "false" : "true");

      // Do not make inactive frames inert: their documents retain form
      // state and can continue their own page scripts.
    });

    previous.disabled = activeIndex === 0;
    next.disabled = activeIndex === pages.length - 1;

    progress.textContent =
      (activeIndex + 1) + " of " + pages.length +
      " -- " + pages[activeIndex].title;

    if (pageSelect) pageSelect.value = String(activeIndex);
  }

  function show(index) {
    if (!Number.isInteger(index) || index < 0 || index >= pages.length) {
      return;
    }

    activeIndex = index;
    update();

    window.scrollTo({ top: 0, behavior: "auto" });
  }

  function buildPageSelector() {
    if (!pageSelect) return;

    const fragment = document.createDocumentFragment();

    pages.forEach((page, index) => {
      const option = document.createElement("option");
      option.value = String(index);
      option.textContent = (index + 1) + ". " + page.title;
      fragment.append(option);
    });

    pageSelect.replaceChildren(fragment);
    pageSelect.addEventListener("change", () => {
      show(Number(pageSelect.value));
    });
  }

  function findPackagedPage(targetUrl) {
    return pages.findIndex(page => {
      try {
        return new URL(page.url).pathname === targetUrl.pathname;
      } catch (_) {
        return false;
      }
    });
  }

  function installLinkRouting(frame, pageIndex) {
    frame.addEventListener("load", function () {
      try {
        const doc = frame.contentDocument;

        if (!doc || !doc.documentElement) return;

        if (doc.documentElement.dataset.packageRoutingInstalled === "yes") {
          return;
        }

        doc.documentElement.dataset.packageRoutingInstalled = "yes";

        doc.addEventListener("click", function (event) {
          const target = event.target;

          if (!target || typeof target.closest !== "function") return;

          const link = target.closest("a[href]");
          if (!link) return;

          const href = link.getAttribute("href");

          if (
            !href ||
            href.startsWith("#") ||
            /^(mailto:|tel:|javascript:|data:|blob:)/i.test(href) ||
            link.hasAttribute("download") ||
            link.target === "_blank"
          ) {
            return;
          }

          let targetUrl;

          try {
            targetUrl = new URL(href, pages[pageIndex].url);
          } catch (_) {
            return;
          }

          if (!["http:", "https:"].includes(targetUrl.protocol)) return;

          const destinationIndex = findPackagedPage(targetUrl);

          if (destinationIndex !== -1) {
            event.preventDefault();
            show(destinationIndex);
          }
        }, true);
      } catch (_) {
        // Some browser security configurations restrict frame access.
        // In that case, ordinary link behavior remains available.
      }
    });
  }

  function createFrames() {
    const fragment = document.createDocumentFragment();

    pages.forEach((page, index) => {
      const frame = document.createElement("iframe");

      frame.className = "package-frame";
      frame.title = page.title;
      frame.loading = index === 0 ? "eager" : "lazy";
      frame.referrerPolicy = "no-referrer";

      // These pages are authored by the website owner and may contain
      // scripts and form controls. Do not package untrusted HTML here.
      // Sandboxing requires a deliberate review of script and origin needs.

      fragment.append(frame);
      frames.push(frame);
      installLinkRouting(frame, index);
    });

    container.append(fragment);

    // Populate srcdoc only after all frame references are established.
    pages.forEach((page, index) => {
      frames[index].srcdoc = decodeBase64Utf8(page.htmlBase64);
    });
  }

  function openCurrentOriginal() {
    const url = pages[activeIndex].url;

    // Only configured same-origin HTTPS pages are permitted by the builder.
    const parsed = new URL(url);

    if (
      parsed.origin !== window.location.origin ||
      !["https:", "http:"].includes(parsed.protocol)
    ) {
      progress.textContent = "The original page URL failed validation.";
      return;
    }

    window.open(parsed.href, "_blank", "noopener,noreferrer");
  }

  function reloadCurrentPage() {
    const frame = frames[activeIndex];

    try {
      const currentHtml = frame.srcdoc;
      frame.srcdoc = "";
      window.setTimeout(() => {
        frame.srcdoc = currentHtml;
        progress.textContent = "Reloaded " + pages[activeIndex].title;
      }, 0);
    } catch (_) {
      progress.textContent = "Unable to reload this page.";
    }
  }

  function printCurrentPage() {
    try {
      frames[activeIndex].contentWindow.focus();
      frames[activeIndex].contentWindow.print();
    } catch (_) {
      printStatus.textContent =
        "Printing was blocked. Open the original page and print it there.";
    }
  }

  function printAllPages() {
    // Browsers do not consistently support printing every iframe document
    // from one parent print command. A reliable all-pages PDF is better
    // generated from the original application or a dedicated PDF renderer.
    printStatus.textContent =
      "For a complete PDF, print each page individually or use a server-side PDF generator. This viewer cannot guarantee a combined all-pages PDF.";
    printCurrentPage();
  }

  previous.addEventListener("click", () => show(activeIndex - 1));
  next.addEventListener("click", () => show(activeIndex + 1));
  reloadButton.addEventListener("click", reloadCurrentPage);
  openOriginal.addEventListener("click", openCurrentOriginal);
  printButton.addEventListener("click", printCurrentPage);
  printAllButton.addEventListener("click", printAllPages);

  document.addEventListener("keydown", event => {
    const target = event.target;
    const tag = target && target.tagName
      ? target.tagName.toLowerCase()
      : "";

    if (
      event.altKey ||
      event.ctrlKey ||
      event.metaKey ||
      ["input", "textarea", "select", "button"].includes(tag) ||
      target?.isContentEditable
    ) {
      return;
    }

    if (event.key === "ArrowLeft" && activeIndex > 0) {
      show(activeIndex - 1);
    } else if (
      event.key === "ArrowRight" &&
      activeIndex < pages.length - 1
    ) {
      show(activeIndex + 1);
    }
  });

  buildPageSelector();
  createFrames();
  show(0);

})();
${closeScript}
</body>
</html>`;
  }

  // ============================================================
  // 8. DOWNLOAD OUTPUT
  // ============================================================

  function downloadHtml(html) {
    const blob = new Blob([html], {
      type: "text/html;charset=utf-8"
    });

    const objectUrl = URL.createObjectURL(blob);
    const anchor = document.createElement("a");

    anchor.href = objectUrl;
    anchor.download = CONFIG.outputName;
    anchor.style.display = "none";

    document.body.appendChild(anchor);
    anchor.click();
    anchor.remove();

    // Give the browser time to begin the download before releasing it.
    window.setTimeout(() => URL.revokeObjectURL(objectUrl), 60000);
  }

  // ============================================================
  // 9. MAIN BUILD FLOW
  // ============================================================

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

    try {
      validateConfiguration();
    } catch (error) {
      setStatus(
        error instanceof Error ? error.message : "Invalid configuration.",
        true
      );
      return;
    }

    building = true;
    buildController = new AbortController();
    setBuildBusy(true);

    try {
      setStatus("Preparing to package " + CONFIG.pages.length + " pages…");

      const pages = await collectPages(buildController.signal);

      setStatus("Encoding pages and assembling the downloadable HTML…");

      const output = makeStandaloneDocument(pages);
      const outputBytes = getUtf8ByteLength(output);

      if (outputBytes > CONFIG.maxTotalBytes * 2) {
        throw new Error(
          "The generated HTML is too large for the configured output limit."
        );
      }

      downloadHtml(output);

      const megabytes = (outputBytes / 1024 / 1024).toFixed(2);

      setStatus(
        "Created " + CONFIG.outputName +
        " (" + pages.length + " pages, " + megabytes +
        " MB). Check your browser downloads."
      );
    } catch (error) {
      console.error("Single-file build failed:", error);

      const message = buildController?.signal.aborted
        ? "Build cancelled. No new download was created."
        : error instanceof Error
          ? error.message
          : "Could not create the single HTML file.";

      setStatus(message, true);
    } finally {
      building = false;
      buildController = null;
      setBuildBusy(false);
    }
  }

  // ============================================================
  // 10. INITIALIZATION
  // ============================================================

  function initialise() {
    buildButtons().forEach(button => {
      if (button.dataset.singleFileBound === "yes") return;

      button.dataset.singleFileBound = "yes";
      button.addEventListener("click", buildSingleFile);
    });

    cancelButtons().forEach(button => {
      if (button.dataset.cancelSingleFileBound === "yes") return;

      button.dataset.cancelSingleFileBound = "yes";
      button.addEventListener("click", cancelBuild);
      button.disabled = true;
      button.classList.add("hidden");
    });

    if (!buildButtons().length) {
      console.warn(
        "Single-file packager loaded, but no [data-build-single-file] button was found."
      );
    }
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", initialise, {
      once: true
    });
  } else {
    initialise();
  }
})();
