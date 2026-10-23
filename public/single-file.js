
/*
 * MedOrbits -- Donor Trust Quota Single-File Packager
 * File: public/single-file.js
 *
 * Packages configured HTML pages into one downloadable HTML file.
 * This does not package a database, backend, or private uploaded files.
 */

(() => {
  "use strict";

  // ============================================================
  // 1. CONFIGURATION
  // ============================================================

  const CONFIG = {
    outputName: "Donor-Trust-Quota-Application.html",
    timeoutMs: 25000,
    maxPageBytes: 4 * 1024 * 1024,
    maxTotalBytes: 24 * 1024 * 1024,
    maxPages: 40,
    concurrency: 3,

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
  let buildController = null;
  let completed = 0;
  let totalBytes = 0;

  const $ = selector => document.querySelector(selector);

  const buildButtons = () =>
    [...document.querySelectorAll("[data-build-single-file]")];

  const cancelButtons = () =>
    [...document.querySelectorAll("[data-cancel-single-file]")];

  // ============================================================
  // 2. STATUS AND BUTTONS
  // ============================================================

  function setStatus(message, isError = false) {
    const node = $("[data-build-status]");
    if (!node) return;

    node.textContent = message;
    node.setAttribute("role", isError ? "alert" : "status");
    node.setAttribute("aria-live", isError ? "assertive" : "polite");
    node.style.color = isError ? "#b42318" : "#333";
  }

  function setBusy(busy) {
    buildButtons().forEach(button => {
      button.disabled = busy;
      button.setAttribute("aria-busy", String(busy));
    });

    cancelButtons().forEach(button => {
      button.disabled = !busy;
      button.classList.toggle("hidden", !busy);
    });
  }

  function cancelBuild() {
    if (building && buildController) {
      buildController.abort();
      setStatus("Cancellation requested…");
    }
  }

  // ============================================================
  // 3. VALIDATE PAGE CONFIGURATION
  // ============================================================

  function resolvePage(path) {
    if (
      typeof path !== "string" ||
      !path.startsWith("/") ||
      path.startsWith("//") ||
      path.includes("\\") ||
      /[\u0000-\u001f]/.test(path)
    ) {
      throw new Error("Invalid page path: " + path);
    }

    const url = new URL(path, window.location.origin);

    if (
      url.origin !== window.location.origin ||
      !["http:", "https:"].includes(url.protocol)
    ) {
      throw new Error("Only same-origin HTTP(S) pages are allowed.");
    }

    url.hash = "";
    return url;
  }

  function validatePages() {
    if (!Array.isArray(CONFIG.pages) ||
        CONFIG.pages.length === 0 ||
        CONFIG.pages.length > CONFIG.maxPages) {
      throw new Error("Invalid number of configured pages.");
    }

    const paths = new Set();

    CONFIG.pages.forEach(page => {
      if (!page.title || typeof page.title !== "string") {
        throw new Error("Every page needs a title.");
      }

      const url = resolvePage(page.url);

      if (paths.has(url.pathname)) {
        throw new Error("Duplicate page: " + url.pathname);
      }

      paths.add(url.pathname);
    });
  }

  // ============================================================
  // 4. FETCH AND NORMALIZE HTML
  // ============================================================

  function byteLength(text) {
    return new TextEncoder().encode(text).byteLength;
  }

  function normalizeHtml(html, url) {
    const doc = new DOMParser().parseFromString(html, "text/html");

    if (!doc.head || !doc.body) {
      throw new Error("Invalid HTML: " + url.pathname);
    }

    // Preserve original relative asset URLs.
    let base = doc.head.querySelector("base");

    if (!base) {
      base = doc.createElement("base");
      doc.head.prepend(base);
    }

    base.href = new URL(".", url).href;

    doc.head.querySelectorAll("base").forEach((item, index) => {
      if (index > 0) item.remove();
    });

    // Avoid automatic page redirects inside the packaged viewer.
    doc.head.querySelectorAll('meta[http-equiv="refresh" i]')
      .forEach(item => item.remove());

    return "<!doctype html>\n" + doc.documentElement.outerHTML;
  }

  async function fetchPage(page, signal) {
    const url = resolvePage(page.url);
    const controller = new AbortController();

    let timedOut = false;

    const abortParent = () => controller.abort();
    signal.addEventListener("abort", abortParent, { once: true });

    const timer = setTimeout(() => {
      timedOut = true;
      controller.abort();
    }, CONFIG.timeoutMs);

    try {
      const response = await fetch(url.href, {
        method: "GET",
        credentials: "same-origin",
        cache: "no-store",
        redirect: "error",
        referrerPolicy: "no-referrer",
        headers: { Accept: "text/html,application/xhtml+xml" },
        signal: controller.signal
      });

      if (!response.ok) {
        throw new Error(
          page.url + " returned HTTP " + response.status
        );
      }

      const type = (response.headers.get("content-type") || "")
        .toLowerCase();

      if (type &&
          !type.includes("text/html") &&
          !type.includes("application/xhtml+xml")) {
        throw new Error(page.url + " did not return HTML.");
      }

      const html = await response.text();
      const bytes = byteLength(html);

      if (bytes > CONFIG.maxPageBytes) {
        throw new Error(page.url + " exceeds the page size limit.");
      }

      return {
        title: page.title,
        url: url.href,
        pathname: url.pathname,
        bytes,
        html: normalizeHtml(html, url)
      };
    } catch (error) {
      if (signal.aborted) {
        throw new Error("Build cancelled.");
      }

      if (timedOut) {
        throw new Error("Request timed out: " + page.url);
      }

      throw error;
    } finally {
      clearTimeout(timer);
      signal.removeEventListener("abort", abortParent);
    }
  }

  // ============================================================
  // 5. FETCH ALL PAGES IN CONFIGURED ORDER
  // ============================================================

  async function collectPages(signal) {
    const results = new Array(CONFIG.pages.length);
    let nextIndex = 0;
    let firstError = null;

    completed = 0;
    totalBytes = 0;

    async function worker() {
      while (!signal.aborted && !firstError) {
        const index = nextIndex++;

        if (index >= CONFIG.pages.length) return;

        try {
          const result = await fetchPage(CONFIG.pages[index], signal);

          // JavaScript executes this block synchronously, so the
          // combined-size check cannot be interleaved with another worker.
          if (totalBytes + result.bytes > CONFIG.maxTotalBytes) {
            throw new Error("Combined HTML exceeds the size limit.");
          }

          totalBytes += result.bytes;
          results[index] = result;
          completed++;

          setStatus(
            "Loaded " + completed + " of " +
            CONFIG.pages.length + ": " + result.title
          );
        } catch (error) {
          firstError = error;
          buildController?.abort();
          return;
        }
      }
    }

    await Promise.all(
      Array.from(
        { length: Math.min(CONFIG.concurrency, CONFIG.pages.length) },
        () => worker()
      )
    );

    if (firstError) throw firstError;
    if (signal.aborted) throw new Error("Build cancelled.");

    if (results.some(page => !page)) {
      throw new Error("One or more pages could not be loaded.");
    }

    return results;
  }

  // ============================================================
  // 6. ENCODING
  // ============================================================

  function toBase64Utf8(value) {
    const bytes = new TextEncoder().encode(value);
    const parts = [];
    const chunkSize = 8192;

    for (let i = 0; i < bytes.length; i += chunkSize) {
      const chunk = bytes.subarray(i, i + chunkSize);
      let binary = "";

      for (const byte of chunk) {
        binary += String.fromCharCode(byte);
      }

      parts.push(binary);
    }

    return btoa(parts.join(""));
  }

  function safeJson(value) {
    return JSON.stringify(value)
      .replace(/</g, "\\u003c")
      .replace(/>/g, "\\u003e")
      .replace(/&/g, "\\u0026");
  }

  // ============================================================
  // 7. CREATE STANDALONE HTML VIEWER
  // ============================================================

  function createStandaloneHtml(pages) {
    const payload = pages.map(page => ({
      title: page.title,
      url: page.url,
      pathname: page.pathname,
      html: toBase64Utf8(page.html)
    }));

    const json = safeJson(payload);

    return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="referrer" content="no-referrer">
<title>Donor / Trust Quota Application</title>
<style>
*{box-sizing:border-box}
body{margin:0;font-family:Arial,sans-serif;color:#171717;background:#f3f4f6}
header{position:sticky;top:0;z-index:10;padding:12px;background:#fff;border-bottom:1px solid #ddd}
h1{font-size:19px;margin:0 0 10px}
nav{display:flex;flex-wrap:wrap;gap:8px;align-items:center}
button,select{padding:10px;border:1px solid #bbb;border-radius:6px;background:#fff;font:inherit}
button:disabled{opacity:.45}
#status{font-size:12px;margin-top:10px;overflow-wrap:anywhere}
iframe{display:none;width:100%;height:calc(100vh - 150px);min-height:480px;border:0;background:#fff}
iframe.active{display:block}
footer{padding:12px;background:#fff;border-top:1px solid #ddd;font-size:12px;line-height:1.5}
@media(max-width:600px){button,select{max-width:100%}iframe{height:calc(100vh - 210px)}}
</style>
</head>
<body>
<header>
<h1>Donor / Trust Quota Application</h1>
<nav aria-label="Page navigation">
<button id="prev" type="button">← Previous</button>
<button id="next" type="button">Next →</button>
<label for="pageSelect">Go to page</label>
<select id="pageSelect"></select>
<button id="reload" type="button">Reload page</button>
<button id="open" type="button">Open original</button>
<button id="print" type="button">Print current page</button>
</nav>
<div id="status" role="status" aria-live="polite"></div>
</header>
<main id="viewer"></main>
<footer>
This package contains HTML pages only. External assets, APIs,
authentication, database operations and uploads may still require
the original website. It does not submit an application or establish
official admission status. Keep applicant data and documents private.
</footer>
<script id="payload" type="application/json">${json}<\/script>
<script>
(function(){
"use strict";
const pages=JSON.parse(document.getElementById("payload").textContent);
const viewer=document.getElementById("viewer");
const status=document.getElementById("status");
const select=document.getElementById("pageSelect");
const prev=document.getElementById("prev");
const next=document.getElementById("next");
const frames=[];
let current=0;

function decode(value){
 const binary=atob(value);
 const bytes=Uint8Array.from(binary,c=>c.charCodeAt(0));
 return new TextDecoder().decode(bytes);
}

function show(index){
 if(index<0||index>=pages.length)return;
 current=index;
 frames.forEach((frame,i)=>{
   frame.classList.toggle("active",i===index);
   frame.setAttribute("aria-hidden",String(i!==index));
 });
 select.value=String(index);
 prev.disabled=index===0;
 next.disabled=index===pages.length-1;
 status.textContent=(index+1)+" of "+pages.length+" -- "+pages[index].title;
 window.scrollTo(0,0);
}

pages.forEach((page,index)=>{
 const option=document.createElement("option");
 option.value=String(index);
 option.textContent=(index+1)+". "+page.title;
 select.append(option);

 const frame=document.createElement("iframe");
 frame.title=page.title;
 frame.referrerPolicy="no-referrer";
 frame.srcdoc=decode(page.html);
 frames.push(frame);
 viewer.append(frame);

 frame.addEventListener("load",()=>{
   try{
     const doc=frame.contentDocument;
     if(!doc||doc.documentElement.dataset.routingInstalled)return;
     doc.documentElement.dataset.routingInstalled="yes";

     doc.addEventListener("click",event=>{
       const link=event.target.closest?.("a[href]");
       if(!link||link.hasAttribute("download")||link.target==="_blank")return;

       const href=link.getAttribute("href");
       if(!href||href.startsWith("#")||
          /^(mailto:|tel:|javascript:|data:|blob:)/i.test(href))return;

       let destination;
       try{destination=new URL(href,page.url)}catch(_){return}
       if(!["https:","http:"].includes(destination.protocol))return;

       const target=pages.findIndex(item=>
         new URL(item.url).pathname===destination.pathname
       );

       if(target!==-1){
         event.preventDefault();
         show(target);
       }
     },true);
   }catch(error){
     console.warn("Internal link routing could not be installed.",error);
   }
 });
});

prev.addEventListener("click",()=>show(current-1));
next.addEventListener("click",()=>show(current+1));
select.addEventListener("change",()=>show(Number(select.value)));

document.getElementById("reload").addEventListener("click",()=>{
 const frame=frames[current];
 const source=frame.srcdoc;
 frame.srcdoc="";
 requestAnimationFrame(()=>{frame.srcdoc=source});
});

document.getElementById("open").addEventListener("click",()=>{
 const url=new URL(pages[current].url);
 if(url.origin===location.origin){
   window.open(url.href,"_blank","noopener,noreferrer");
 }
});

document.getElementById("print").addEventListener("click",()=>{
 try{
   frames[current].contentWindow.focus();
   frames[current].contentWindow.print();
 }catch(error){
   status.textContent="Printing failed. Open the original page to print.";
 }
});

document.addEventListener("keydown",event=>{
 if(event.altKey||event.ctrlKey||event.metaKey)return;
 if(["INPUT","TEXTAREA","SELECT","BUTTON"].includes(event.target.tagName))return;
 if(event.key==="ArrowLeft")show(current-1);
 if(event.key==="ArrowRight")show(current+1);
});

show(0);
})();
<\/script>
</body>
</html>`;
  }

  // ============================================================
  // 8. DOWNLOAD HTML FILE
  // ============================================================

  function downloadHtml(html) {
    const blob = new Blob([html], {
      type: "text/html;charset=utf-8"
    });

    const url = URL.createObjectURL(blob);
    const anchor = document.createElement("a");

    anchor.href = url;
    anchor.download = CONFIG.outputName;
    anchor.hidden = true;

    document.body.appendChild(anchor);
    anchor.click();
    anchor.remove();

    setTimeout(() => URL.revokeObjectURL(url), 60000);
  }

  // ============================================================
  // 9. BUILD
  // ============================================================

  async function buildSingleFile() {
    if (building) return;

    if (
      location.protocol !== "https:" &&
      location.hostname !== "localhost" &&
      location.hostname !== "127.0.0.1"
    ) {
      setStatus("Open this builder on your deployed HTTPS website.", true);
      return;
    }

    try {
      validatePages();
    } catch (error) {
      setStatus(error.message || "Invalid configuration.", true);
      return;
    }

    building = true;
    buildController = new AbortController();
    setBusy(true);

    try {
      setStatus("Loading application pages…");

      const pages = await collectPages(buildController.signal);

      setStatus("Creating standalone HTML…");

      const output = createStandaloneHtml(pages);
      const outputBytes = byteLength(output);

      // Base64 encoding expands the source, so allow for that overhead.
      if (outputBytes > CONFIG.maxTotalBytes * 2) {
        throw new Error("Generated HTML exceeds the output size limit.");
      }

      downloadHtml(output);

      setStatus(
        "Created " + CONFIG.outputName + " (" +
        pages.length + " pages, " +
        (outputBytes / 1024 / 1024).toFixed(2) +
        " MB). Check your Downloads."
      );
    } catch (error) {
      console.error("Single-file packaging failed:", error);

      setStatus(
        error.message || "Unable to create the HTML package.",
        true
      );
    } finally {
      building = false;
      buildController = null;
      setBusy(false);
    }
  }

  // ============================================================
  // 10. INITIALIZE BUTTONS
  // ============================================================

  function initialize() {
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
        "No [data-build-single-file] button was found."
      );
    }
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", initialize, { once: true });
  } else {
    initialize();
  }
})();
