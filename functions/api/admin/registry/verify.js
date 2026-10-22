
const HEADERS = {
  "Content-Type": "application/json; charset=utf-8",
  "Cache-Control": "no-store",
  "X-Content-Type-Options": "nosniff"
};

function respond(data, status = 200) {
  return new Response(JSON.stringify(data), { status, headers: HEADERS });
}

function equalSecret(a, b) {
  const encoder = new TextEncoder();
  const x = encoder.encode(a);
  const y = encoder.encode(b);
  let diff = x.length ^ y.length;

  for (let i = 0; i < Math.max(x.length, y.length); i++) {
    diff |= (x[i] || 0) ^ (y[i] || 0);
  }

  return diff === 0;
}

function isAuthorized(request, env) {
  const secret = String(env.ADMIN_SECRET || "");
  const header = request.headers.get("Authorization") || "";
  const match = /^Bearer\s+(.+)$/i.exec(header);

  return secret.length >= 32 &&
    !!match &&
    equalSecret(match[1], secret);
}

function isOriginAllowed(request, env) {
  const origin = request.headers.get("Origin");
  const origins = String(env.ACCESS_ALLOWED_ORIGINS || "")
    .split(",").map(v => v.trim()).filter(Boolean);

  if (!origin) return env.ACCESS_REQUIRE_ORIGIN !== "true";
  return origins.includes(origin);
}

export async function onRequestPost({ request, env }) {
  if (!isOriginAllowed(request, env)) {
    return respond({ error: "origin_not_allowed" }, 403);
  }

  if (!isAuthorized(request, env)) {
    return respond({ error: "unauthorized" }, 401);
  }

  if (!env.APP_DB) {
    return respond({ error: "database_not_configured" }, 503);
  }

  if (!(request.headers.get("Content-Type") || "")
    .toLowerCase().includes("application/json")) {
    return respond({ error: "application_json_required" }, 415);
  }

  let body;
  try {
    const raw = await request.text();
    if (raw.length > 4096) {
      return respond({ error: "request_too_large" }, 413);
    }
    body = JSON.parse(raw);
  } catch {
    return respond({ error: "invalid_json" }, 400);
  }

  const pageRef = typeof body?.page_ref === "string"
    ? body.page_ref.trim()
    : "";

  if (!pageRef || pageRef.length > 200) {
    return respond({ error: "invalid_page_reference" }, 400);
  }

  try {
    const row = await env.APP_DB.prepare(`
      SELECT
        i.page_instance_id,
        i.application_ref,
        i.page_id,
        i.page_ref,
        i.reference_version,
        i.verification_status,
        i.expires_at,
        p.page_name,
        p.page_version,
        p.page_status,
        f.form_status
      FROM application_page_instances i
      JOIN form_page_registry p ON p.page_id = i.page_id
      JOIN form_registry f ON f.form_id = p.form_id
      WHERE i.page_ref = ?1
      LIMIT 1
    `).bind(pageRef).first();

    const now = Date.now();
    const expiresAt = row?.expires_at
      ? Date.parse(row.expires_at)
      : null;

    const valid = !!row &&
      row.verification_status === "issued" &&
      row.page_status === "active" &&
      row.form_status === "active" &&
      (!expiresAt || (Number.isFinite(expiresAt) && expiresAt > now));

    if (!row || !valid) {
      return respond({
        ok: true,
        verified: false,
        message: "Reference is unknown, expired, revoked or inactive."
      });
    }

    await env.APP_DB.prepare(`
      UPDATE application_page_instances
      SET last_verified_at = CURRENT_TIMESTAMP
      WHERE page_instance_id = ?1
    `).bind(row.page_instance_id).run();

    return respond({
      ok: true,
      verified: true,
      message: "The reference matches an active registered page.",
      page_id: row.page_id,
      page_name: row.page_name,
      page_version: row.page_version,
      reference_version: row.reference_version
    });
  } catch {
    return respond({
      error: "verification_failed",
      message: "Verification could not be completed. Check the D1 schema."
    }, 500);
  }
}
