
/*
 *  -- Private Owner Workspace
 * File: public/private/single-file.js
 *
 * Independent application-preparation workspace.
 * All access control and reference verification must be enforced server-side.
 */

(() => {
  "use strict";

  // =========================================================
  // 1. CONFIGURATION
  // =========================================================

  const CONFIG = Object.freeze({
    // Existing Express backend uses /api/v1.
    // Change this only if your deployed backend uses another prefix.
    apiBase: "/api/v1",

    endpoints: Object.freeze({
      applications: "/admin/applications",
      registry: "/admin/registry",
      verifyPage: "/admin/registry/verify"
    }),

    requestTimeoutMs: 15000,
    maxSecretLength: 512,
    maxPageReferenceLength: 200,
    maxDisplayedValueLength: 500,
    maxApplicationReferenceLength: 120,

    // This must remain true unless you deliberately support a
    // different same-origin deployment arrangement.
    sameOriginOnly: true
  });

  const $ = id => document.getElementById(id);

  const state = {
    secret: "",
    records: [],
    registryRows: [],
    authenticated: false,
    loadingApplications: false,
    loadingRegistry: false,
    activeController: null,
    registryRequestVersion: 0,
    applicationsRequestVersion: 0,
    currentRegistryType: "forms"
  };

  const elements = {
    authForm: $("authForm"),
    adminSecret: $("adminSecret"),
    authMessage: $("authMessage"),
    dataMessage: $("dataMessage"),
    loginBtn: $("loginBtn"),
    clearBtn: $("clearBtn"),
    refreshBtn: $("refreshBtn"),
    refreshBtnTop: $("refreshBtnTop"),

    dashboard: $("dashboard"),
    identityDashboard: $("identityDashboard"),

    connectionTag: $("connectionTag"),
    connectionText: $("connectionText"),

    searchInput: $("searchInput"),
    statusFilter: $("statusFilter"),
    recordsBody: $("recordsBody"),
    shownCount: $("shownCount"),
    updatedAt: $("updatedAt"),

    registrySearch: $("registrySearch"),
    registryType: $("registryType"),
    registryRefresh: $("registryRefresh"),
    registryHead: $("registryHead"),
    registryBody: $("registryBody"),
    registryShown: $("registryShown"),
    registryMessage: $("registryMessage"),

    verifyPageForm: $("verifyPageForm"),
    pageReference: $("pageReference"),
    verifyPageBtn: $("verifyPageBtn"),
    verifyResult: $("verifyResult"),

    qrBox: $("qrBox"),
    qrDescription: $("qrDescription"),
    clearQrBtn: $("clearQrBtn")
  };

  const REGISTRY_COLUMNS = Object.freeze({
    forms: [
      ["form_id", "Form ID"],
      ["form_code", "Form code"],
      ["form_name", "Form name"],
      ["form_version", "Version"],
      ["form_status", "Status"],
      ["route_path", "Route"]
    ],

    pages: [
      ["page_id", "Page ID"],
      ["page_code", "Page code"],
      ["page_name", "Page name"],
      ["form_id", "Parent form"],
      ["page_number", "Page no."],
      ["page_version", "Version"],
      ["page_status", "Status"],
      ["page_ref", "Page reference"],
      ["barcode_value", "Barcode value"]
    ],

    locations: [
      ["location_id", "Location ID"],
      ["location_name", "Location"],
      ["location_type", "Type"],
      ["form_id", "Form ID"],
      ["page_id", "Page ID"],
      ["route_path", "Route"],
      ["location_status", "Status"]
    ],

    activity: [
      ["event_id", "Event ID"],
      ["event_code", "Event code"],
      ["actor_role", "Actor role"],
      ["action", "Action"],
      ["form_id", "Form ID"],
      ["page_id", "Page ID"],
      ["application_ref", "Application"],
      ["page_ref", "Page reference"],
      ["outcome", "Outcome"],
      ["created_at", "Timestamp"]
    ]
  });

  const REGISTRY_PAYLOAD_KEYS = Object.freeze({
    forms: ["forms", "records", "results", "items"],
    pages: ["pages", "records", "results", "items"],
    locations: ["locations", "records", "results", "items"],
    activity: ["events", "activity", "records", "results", "items"]
  });

  // =========================================================
  // 2. GENERAL UTILITIES
  // =========================================================

  function setMessage(element, message, type = "") {
    if (!element) return;

    element.textContent = String(message ?? "");
    element.className = "message" + (type ? " " + type : "");
    element.classList.remove("hidden");
  }

  function hideMessage(element) {
    element?.classList.add("hidden");
  }

  function setConnection(label, secure = false) {
    if (!elements.connectionTag || !elements.connectionText) return;

    elements.connectionText.textContent = label;
    elements.connectionTag.className =
      "connection" + (secure ? " secure" : "");
  }

  function setBusy(button, busy, busyLabel) {
    if (!button) return;

    if (busy) {
      if (!button.dataset.originalLabel) {
        button.dataset.originalLabel = button.textContent;
      }

      button.disabled = true;

      if (busyLabel) {
        button.textContent = busyLabel;
      }
    } else {
      button.disabled = false;

      if (button.dataset.originalLabel) {
        button.textContent = button.dataset.originalLabel;
        delete button.dataset.originalLabel;
      }
    }
  }

  function boundedString(value, maxLength = CONFIG.maxDisplayedValueLength) {
    if (value === null || value === undefined) return "--";

    if (typeof value !== "string" && typeof value !== "number") {
      return "--";
    }

    return String(value).slice(0, maxLength);
  }

  function normalizeStatus(record) {
    const value = record?.status ?? record?.state ?? "unknown";
    const status = String(value).trim().toLowerCase();

    return status || "unknown";
  }

  function getApplicationReference(record) {
    const value =
      record?.application_ref ??
      record?.reference ??
      record?.application_reference ??
      record?.applicationReference ??
      record?.ref ??
      "";

    return String(value)
      .trim()
      .slice(0, CONFIG.maxApplicationReferenceLength);
  }

  function statusLabel(status) {
    return String(status)
      .replace(/[_-]+/g, " ")
      .replace(/\b\w/g, character => character.toUpperCase());
  }

  function isPending(status) {
    return [
      "draft",
      "pending",
      "incomplete",
      "needs_information"
    ].includes(status);
  }

  function isComplete(status) {
    return [
      "submitted",
      "complete",
      "completed",
      "approved"
    ].includes(status);
  }

  function makeElement(tag, className, text) {
    const element = document.createElement(tag);

    if (className) element.className = className;
    if (text !== undefined) element.textContent = String(text);

    return element;
  }

  function makeStatusBadge(status) {
    const badge = makeElement("span", "status", statusLabel(status));
    const safeClass = String(status).replace(/[^a-z0-9_-]/gi, "");

    badge.classList.add(safeClass || "unknown");
    return badge;
  }

  function makeEmptyRow(colspan, message) {
    const row = document.createElement("tr");
    const cell = makeElement("td", "empty", message);

    cell.colSpan = Math.max(1, Number(colspan) || 1);
    row.append(cell);

    return row;
  }

  function formatDate(value) {
    if (!value) return "--";

    const date = new Date(value);

    if (Number.isNaN(date.getTime())) {
      return boundedString(value, 100);
    }

    return date.toLocaleString();
  }

  function apiUrl(path) {
    const base = CONFIG.apiBase.replace(/\/+$/, "");
    const suffix = String(path || "");

    if (!suffix.startsWith("/") || suffix.startsWith("//")) {
      throw new Error("Invalid API endpoint configuration.");
    }

    const url = new URL(base + suffix, window.location.origin);

    if (CONFIG.sameOriginOnly && url.origin !== window.location.origin) {
      throw new Error("Cross-origin API requests are not permitted.");
    }

    return url.pathname + url.search;
  }

  function createAbortController() {
    const controller = new AbortController();

    const timeoutId = window.setTimeout(
      () => controller.abort(),
      CONFIG.requestTimeoutMs
    );

    return {
      controller,
      clearTimeout: () => window.clearTimeout(timeoutId)
    };
  }

  async function readJsonResponse(response) {
    const contentType = (
      response.headers.get("content-type") || ""
    ).toLowerCase();

    if (!contentType.includes("application/json")) {
      throw new Error(
        "The server did not return JSON. Check the API route and deployment."
      );
    }

    try {
      return await response.json();
    } catch {
      throw new Error("The server returned invalid JSON.");
    }
  }

  function getArrayFromPayload(payload, keys, description) {
    if (Array.isArray(payload)) return payload;

    for (const key of keys) {
      if (Array.isArray(payload?.[key])) {
        return payload[key];
      }
    }

    throw new Error(
      "Unexpected " + description + " API response format."
    );
  }

  // =========================================================
  // 3. AUTHENTICATED API CLIENT
  // =========================================================

  async function apiRequest(path, options = {}) {
    if (!state.secret || !state.authenticated) {
      throw new Error("Authenticate before accessing protected data.");
    }

    const timeout = createAbortController();
    const headers = new Headers(options.headers || {});

    headers.set("Authorization", "Bearer " + state.secret);
    headers.set("Accept", "application/json");

    if (options.body !== undefined) {
      headers.set("Content-Type", "application/json");
    }

    try {
      const response = await fetch(apiUrl(path), {
        ...options,
        headers,
        signal: timeout.controller.signal,
        cache: "no-store",
        credentials: "same-origin",
        redirect: "error",
        referrerPolicy: "no-referrer"
      });

      if (response.status === 401 || response.status === 403) {
        signOut("Your session was rejected. Sign in again.");
        throw new Error("Access expired or was denied.");
      }

      if (response.status === 423) {
        throw new Error(
          "The application workflow is currently locked or paused."
        );
      }

      if (response.status === 429) {
        throw new Error(
          "Too many requests. Wait a moment before trying again."
        );
      }

      if (!response.ok) {
        throw new Error("The server returned HTTP " + response.status + ".");
      }

      return await readJsonResponse(response);
    } catch (error) {
      if (error?.name === "AbortError") {
        throw new Error("Request timed out. Check your connection and retry.");
      }

      if (error instanceof TypeError) {
        throw new Error("Network error. Check your connection and API deployment.");
      }

      throw error;
    } finally {
      timeout.clearTimeout();
    }
  }

  // =========================================================
  // 4. APPLICATION REGISTER
  // =========================================================

  function renderApplications() {
    if (!elements.recordsBody) return;

    const query = (elements.searchInput?.value || "")
      .trim()
      .toLowerCase();

    const statusFilter = elements.statusFilter?.value || "all";

    const filtered = state.records.filter(record => {
      const reference = getApplicationReference(record).toLowerCase();
      const status = normalizeStatus(record);

      return (
        reference.includes(query) &&
        (statusFilter === "all" || status === statusFilter)
      );
    });

    $("totalCount").textContent = String(state.records.length);

    $("pendingCount").textContent = String(
      state.records.filter(record => isPending(normalizeStatus(record))).length
    );

    $("completeCount").textContent = String(
      state.records.filter(record => isComplete(normalizeStatus(record))).length
    );

    elements.shownCount.textContent =
      filtered.length + " of " + state.records.length + " loaded records shown";

    elements.recordsBody.replaceChildren();

    if (!filtered.length) {
      elements.recordsBody.append(
        makeEmptyRow(
          2,
          state.records.length
            ? "No matching records."
            : "No application records returned by the API."
        )
      );

      return;
    }

    const fragment = document.createDocumentFragment();

    for (const record of filtered) {
      const row = document.createElement("tr");

      const referenceCell = document.createElement("td");
      referenceCell.append(
        makeElement(
          "span",
          "ref",
          getApplicationReference(record) || "Unavailable"
        )
      );

      const statusCell = document.createElement("td");
      statusCell.append(makeStatusBadge(normalizeStatus(record)));

      row.append(referenceCell, statusCell);
      fragment.append(row);
    }

    elements.recordsBody.append(fragment);
  }

  async function loadApplications() {
    if (state.loadingApplications || !state.secret) return;

    state.loadingApplications = true;
    const requestVersion = ++state.applicationsRequestVersion;

    setBusy(elements.loginBtn, true, "Connecting…");
    setBusy(elements.refreshBtn, true, "Refreshing…");
    setBusy(elements.refreshBtnTop, true, "Refreshing…");

    setConnection("Connecting");
    setMessage(elements.authMessage, "Verifying administrator access…");
    hideMessage(elements.dataMessage);

    try {
      const payload = await apiRequest(CONFIG.endpoints.applications, {
        method: "GET"
      });

      if (requestVersion !== state.applicationsRequestVersion) return;

      const records = getArrayFromPayload(
        payload,
        ["applications", "records", "results", "items"],
        "application"
      );

      state.records = records.map(record => ({
        application_ref: getApplicationReference(record),
        status: normalizeStatus(record)
      }));

      state.authenticated = true;

      elements.dashboard?.classList.remove("hidden");
      elements.identityDashboard?.classList.remove("hidden");
      elements.refreshBtn?.classList.remove("hidden");

      setConnection("Connected", true);
      setMessage(
        elements.authMessage,
        "Authentication succeeded. Your register is ready.",
        "success"
      );

      elements.updatedAt.textContent =
        "Last refreshed · " + new Date().toLocaleString();

      renderApplications();

      // Registry errors must not erase a successfully loaded application list.
      await loadRegistry();
    } catch (error) {
      if (requestVersion !== state.applicationsRequestVersion) return;

      setConnection("Connection issue");

      setMessage(
        elements.authMessage,
        error instanceof Error ? error.message : "Unable to load the register.",
        "error"
      );
    } finally {
      if (requestVersion === state.applicationsRequestVersion) {
        state.loadingApplications = false;
        setBusy(elements.loginBtn, false);
        setBusy(elements.refreshBtn, false);
        setBusy(elements.refreshBtnTop, false);

        if (!state.authenticated) {
          elements.refreshBtn?.classList.add("hidden");
        }
      }
    }
  }

  // =========================================================
  // 5. REGISTRY EXPLORER
  // =========================================================

  function getRegistryRows(payload, type) {
    const keys = REGISTRY_PAYLOAD_KEYS[type];

    if (!keys) {
      throw new Error("Unsupported registry category.");
    }

    return getArrayFromPayload(payload, keys, type + " registry");
  }

  function renderRegistryRows(rows, type) {
    const columns = REGISTRY_COLUMNS[type];

    if (!columns) {
      throw new Error("Unsupported registry category.");
    }

    const query = (elements.registrySearch?.value || "")
      .trim()
      .toLowerCase();

    const filtered = rows.filter(record =>
      columns.some(([key]) =>
        String(record?.[key] ?? "").toLowerCase().includes(query)
      )
    );

    elements.registryHead.replaceChildren();
    elements.registryBody.replaceChildren();

    const header = document.createElement("tr");

    for (const [, title] of columns) {
      const th = makeElement("th", "", title);
      th.scope = "col";
      header.append(th);
    }

    // Keep the header and all data rows aligned.
    if (type === "pages") {
      const qrHeader = makeElement("th", "", "QR preview");
      qrHeader.scope = "col";
      header.append(qrHeader);
    }

    elements.registryHead.append(header);

    if (!filtered.length) {
      elements.registryBody.append(
        makeEmptyRow(
          columns.length + (type === "pages" ? 1 : 0),
          rows.length
            ? "No records match your search."
            : "No records returned by the server."
        )
      );
    } else {
      const fragment = document.createDocumentFragment();

      for (const record of filtered) {
        const row = document.createElement("tr");

        for (const [key] of columns) {
          const cell = document.createElement("td");
          const value = boundedString(record?.[key]);

          if (
            key.endsWith("_id") ||
            key.endsWith("_code") ||
            key === "page_ref" ||
            key === "barcode_value"
          ) {
            cell.append(makeElement("span", "ref", value));
          } else if (
            [
              "form_status",
              "page_status",
              "location_status",
              "outcome",
              "verification_status"
            ].includes(key)
          ) {
            cell.append(makeStatusBadge(value.toLowerCase()));
          } else if (key.endsWith("_at") || key === "created_at") {
            cell.textContent = formatDate(record?.[key]);
          } else {
            cell.textContent = value;
          }

          row.append(cell);
        }

        if (type === "pages") {
          const qrCell = document.createElement("td");

          if (record?.qr_image_url) {
            const qrButton = makeElement("button", "btn btn-quiet", "Show QR");
            qrButton.type = "button";
            qrButton.addEventListener("click", () => showQr(record));
            qrCell.append(qrButton);
          } else {
            qrCell.textContent = "--";
          }

          row.append(qrCell);
        }

        fragment.append(row);
      }

      elements.registryBody.append(fragment);
    }

    elements.registryShown.textContent =
      filtered.length + " of " + rows.length + " records shown";
  }

  async function loadRegistry() {
    if (!state.authenticated || state.loadingRegistry) return;

    const type = elements.registryType?.value || "forms";

    if (!REGISTRY_COLUMNS[type]) {
      setMessage(elements.registryMessage, "Invalid registry category.", "error");
      return;
    }

    state.currentRegistryType = type;
    state.loadingRegistry = true;

    const requestVersion = ++state.registryRequestVersion;

    setBusy(elements.registryRefresh, true, "Loading…");
    setMessage(elements.registryMessage, "Loading " + type + "…");

    try {
      const query = new URLSearchParams({ type });
      const payload = await apiRequest(
        CONFIG.endpoints.registry + "?" + query.toString(),
        { method: "GET" }
      );

      // Ignore stale responses if the selected registry type changed.
      if (requestVersion !== state.registryRequestVersion) return;

      const rows = getRegistryRows(payload, type);

      state.registryRows = rows;
      renderRegistryRows(rows, type);

      if (type === "forms") {
        $("formCount").textContent = String(payload?.total ?? rows.length);
      } else if (type === "pages") {
        $("pageCount").textContent = String(payload?.total ?? rows.length);
      } else if (type === "activity") {
        $("activityCount").textContent = String(payload?.total ?? rows.length);
      }

      setMessage(
        elements.registryMessage,
        "Registry data loaded from the server.",
        "success"
      );
    } catch (error) {
      if (requestVersion !== state.registryRequestVersion) return;

      setMessage(
        elements.registryMessage,
        error instanceof Error ? error.message : "Unable to load registry.",
        "error"
      );

      elements.registryHead.replaceChildren();
      elements.registryBody.replaceChildren();

      elements.registryBody.append(
        makeEmptyRow(
          REGISTRY_COLUMNS[type].length + (type === "pages" ? 1 : 0),
          "Registry unavailable. Confirm that the endpoint is implemented and deployed."
        )
      );
    } finally {
      if (requestVersion === state.registryRequestVersion) {
        state.loadingRegistry = false;
        setBusy(elements.registryRefresh, false);
      }
    }
  }

  // =========================================================
  // 6. QR IMAGE PREVIEW
  // =========================================================

  function clearQr() {
    elements.qrBox.replaceChildren();
    elements.qrBox.textContent = "No QR image loaded";

    elements.qrDescription.textContent =
      "Select a registered page with a QR image URL supplied by your backend.";
  }

  function getSafeSameOriginPath(value) {
    if (typeof value !== "string" || !value.trim()) return null;

    // Only root-relative paths are accepted. Reject protocol-relative
    // URLs, backslashes, data URLs, and external URLs.
    if (
      !value.startsWith("/") ||
      value.startsWith("//") ||
      value.includes("\\") ||
      /[\u0000-\u001f]/.test(value)
    ) {
      return null;
    }

    try {
      const url = new URL(value, window.location.origin);

      if (url.origin !== window.location.origin) return null;
      if (!["http:", "https:"].includes(url.protocol)) return null;

      return url.pathname + url.search;
    } catch {
      return null;
    }
  }

  function showQr(record) {
    clearQr();

    const safePath = getSafeSameOriginPath(record?.qr_image_url);

    elements.qrDescription.textContent =
      boundedString(record?.page_name, 120) + " · " +
      boundedString(record?.page_ref, 200);

    if (!safePath) {
      elements.qrBox.textContent =
        "No valid same-origin QR image URL was supplied by the API.";
      return;
    }

    const image = document.createElement("img");

    image.alt = "QR image for registered page";
    image.referrerPolicy = "no-referrer";
    image.loading = "lazy";
    image.decoding = "async";

    image.addEventListener("error", () => {
      elements.qrBox.replaceChildren();
      elements.qrBox.textContent = "QR image could not be loaded.";
    }, { once: true });

    image.src = safePath;
    elements.qrBox.replaceChildren(image);
  }

  // =========================================================
  // 7. SERVER-SIDE PAGE REFERENCE VERIFICATION
  // =========================================================

  async function verifyPageReference(event) {
    event.preventDefault();

    const reference = elements.pageReference.value.trim();

    if (
      !reference ||
      reference.length > CONFIG.maxPageReferenceLength
    ) {
      setMessage(
        elements.verifyResult,
        "Enter a valid page reference.",
        "error"
      );
      return;
    }

    if (!state.authenticated) {
      setMessage(
        elements.verifyResult,
        "Authenticate before verifying a page reference.",
        "error"
      );
      return;
    }

    setBusy(elements.verifyPageBtn, true, "Verifying…");
    setMessage(
      elements.verifyResult,
      "Verifying reference with the server…"
    );

    try {
      const payload = await apiRequest(CONFIG.endpoints.verifyPage, {
        method: "POST",
        body: JSON.stringify({ page_ref: reference })
      });

      if (payload?.verified === true) {
        setMessage(
          elements.verifyResult,
          "Verified. " + boundedString(
            payload.message || "Reference is valid.",
            300
          ),
          "success"
        );
      } else {
        setMessage(
          elements.verifyResult,
          "Not verified. " + boundedString(
            payload?.message ||
              "Invalid, expired, revoked or unrecognized reference.",
            300
          ),
          "error"
        );
      }
    } catch (error) {
      setMessage(
        elements.verifyResult,
        error instanceof Error ? error.message : "Verification failed.",
        "error"
      );
    } finally {
      setBusy(elements.verifyPageBtn, false);
    }
  }

  // =========================================================
  // 8. SIGN-OUT AND CLEANUP
  // =========================================================

  function signOut(message = "You have been signed out.") {
    state.applicationsRequestVersion++;
    state.registryRequestVersion++;

    state.activeController?.abort();
    state.activeController = null;

    state.secret = "";
    state.records = [];
    state.registryRows = [];
    state.authenticated = false;
    state.loadingApplications = false;
    state.loadingRegistry = false;

    elements.adminSecret.value = "";
    elements.searchInput.value = "";
    elements.statusFilter.value = "all";
    elements.registrySearch.value = "";
    elements.pageReference.value = "";

    elements.dashboard.classList.add("hidden");
    elements.identityDashboard.classList.add("hidden");
    elements.refreshBtn.classList.add("hidden");

    elements.recordsBody.replaceChildren(
      makeEmptyRow(2, "Authenticate to load records.")
    );

    elements.registryHead.replaceChildren();
    elements.registryBody.replaceChildren(
      makeEmptyRow(1, "Authenticate to load registry data.")
    );

    elements.totalCount.textContent = "0";
    elements.pendingCount.textContent = "0";
    elements.completeCount.textContent = "0";
    elements.formCount.textContent = "--";
    elements.pageCount.textContent = "--";
    elements.activityCount.textContent = "--";
    elements.shownCount.textContent = "0 records shown";
    elements.registryShown.textContent = "No registry records loaded";

    clearQr();

    setConnection("Not connected");
    setMessage(elements.authMessage, message);
    hideMessage(elements.dataMessage);
    hideMessage(elements.registryMessage);

    setBusy(elements.loginBtn, false);
    setBusy(elements.refreshBtn, false);
    setBusy(elements.refreshBtnTop, false);
    setBusy(elements.registryRefresh, false);
    setBusy(elements.verifyPageBtn, false);
  }

  // =========================================================
  // 9. EVENT HANDLERS
  // =========================================================

  elements.authForm.addEventListener("submit", async event => {
    event.preventDefault();

    if (state.loadingApplications) return;

    const secret = elements.adminSecret.value;

    if (
      typeof secret !== "string" ||
      secret.length < 16 ||
      secret.length > CONFIG.maxSecretLength
    ) {
      setMessage(
        elements.authMessage,
        "Enter a valid administrator secret.",
        "error"
      );
      return;
    }

    // Remove the secret from the visible input immediately.
    // It remains in this page's memory only until sign-out or page exit.
    state.secret = secret;
    elements.adminSecret.value = "";

    // The server remains responsible for validating this credential.
    await loadApplications();
  });

  elements.clearBtn.addEventListener("click", () => signOut());

  elements.refreshBtn.addEventListener("click", loadApplications);
  elements.refreshBtnTop.addEventListener("click", loadApplications);

  elements.searchInput.addEventListener("input", renderApplications);
  elements.statusFilter.addEventListener("change", renderApplications);

  $("resetFilterBtn").addEventListener("click", () => {
    elements.searchInput.value = "";
    elements.statusFilter.value = "all";
    renderApplications();
  });

  elements.registryType.addEventListener("change", () => {
    state.registryRows = [];
    loadRegistry();
  });

  elements.registrySearch.addEventListener("input", () => {
    if (REGISTRY_COLUMNS[state.currentRegistryType]) {
      renderRegistryRows(
        state.registryRows,
        state.currentRegistryType
      );
    }
  });

  elements.registryRefresh.addEventListener("click", loadRegistry);
  elements.verifyPageForm.addEventListener("submit", verifyPageReference);
  elements.clearQrBtn.addEventListener("click", clearQr);

  window.addEventListener("pagehide", () => {
    // Best-effort in-memory cleanup. This is not a substitute for
    // server-side session expiration or revocation.
    state.secret = "";
    state.records = [];
    state.registryRows = [];
    state.authenticated = false;
    state.activeController?.abort();
  });

  // =========================================================
  // 10. INITIAL STATE
  // =========================================================

  renderApplications();
  clearQr();
  setConnection("Not connected");

})();
