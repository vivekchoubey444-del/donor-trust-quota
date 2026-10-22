
const JSON_HEADERS = {
  "Content-Type": "application/json; charset=utf-8",
  "Cache-Control": "no-store",
  "X-Content-Type-Options": "nosniff"
};

function json(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: JSON_HEADERS
  });
}

function safeEqual(a, b) {
  const encoder = new TextEncoder();
  const x = encoder.encode(a);
  const y = encoder.encode(b);
  let diff = x.length ^ y.length;
  const length = Math.max(x.length, y.length);

  for (let i = 0; i < length; i++) {
    diff |= (x[i] || 0) ^ (y[i] || 0);
  }

  return diff === 0;
}

function allowedOrigin(request, env) {
  const origin = request.headers.get("Origin");
  const configured = String(env.ACCESS_ALLOWED_ORIGINS || "")
    .split(",").map(v => v.trim()).filter(Boolean);

  if (!origin) return env.ACCESS_REQUIRE_ORIGIN !== "true";
  return configured.includes(origin);
}

function authorized(request, env) {
  const expected = String(env.ADMIN_SECRET || "");
  const header = request.headers.get("Authorization") || "";
  const match = /^Bearer\s+(.+)$/i.exec(header);

  return expected.length >= 32 &&
    !!match &&
    safeEqual(match[1], expected);
}

function clampInteger(value, fallback, min, max) {
  const number = Number.parseInt(value || "", 10);
  if (!Number.isFinite(number)) return fallback;
  return Math.max(min, Math.min(max, number));
}

export async function onRequestGet({ request, env }) {
  if (!allowedOrigin(request, env)) {
    return json({ error: "origin_not_allowed" }, 403);
  }

  if (!authorized(request, env)) {
    return json({ error: "unauthorized" }, 401);
  }

  if (!env.APP_DB) {
    return json({ error: "database_not_configured" }, 503);
  }

  const url = new URL(request.url);
  const type = url.searchParams.get("type") || "forms";
  const limit = clampInteger(url.searchParams.get("limit"), 50, 1, 100);
  const offset = clampInteger(url.searchParams.get("offset"), 0, 0, 1000000);

  const queries = {
    forms: {
      sql: `SELECT form_id, form_code, form_name, form_version,
                   form_status, route_path, created_at, updated_at
            FROM form_registry
            ORDER BY created_at DESC
            LIMIT ?1 OFFSET ?2`,
      count: "SELECT COUNT(*) AS total FROM form_registry"
    },
    pages: {
      sql: `SELECT p.page_id, p.page_code, p.page_name, p.form_id,
                   p.page_number, p.page_version, p.page_status, p.route_path,
                   i.page_ref,
                   i.verification_status,
                   i.expires_at
            FROM form_page_registry p
            LEFT JOIN application_page_instances i
              ON i.page_id = p.page_id
            ORDER BY p.form_id, p.page_number
            LIMIT ?1 OFFSET ?2`,
      count: "SELECT COUNT(*) AS total FROM form_page_registry"
    },
    locations: {
      sql: `SELECT location_id, location_name, location_type, form_id,
                   page_id, route_path, location_status, created_at, updated_at
            FROM shared_form_locations
            ORDER BY created_at DESC
            LIMIT ?1 OFFSET ?2`,
      count: "SELECT COUNT(*) AS total FROM shared_form_locations"
    },
    activity: {
      sql: `SELECT event_id, event_code, actor_role, action, form_id,
                   page_id, application_ref, page_ref, outcome, created_at
            FROM activity_events
            ORDER BY created_at DESC
            LIMIT ?1 OFFSET ?2`,
      count: "SELECT COUNT(*) AS total FROM activity_events"
    }
  };

  const selected = queries[type];
  if (!selected) {
    return json({
      error: "invalid_type",
      allowed: ["forms", "pages", "locations", "activity"]
    }, 400);
  }

  try {
    const [result, count] = await Promise.all([
      env.APP_DB.prepare(selected.sql).bind(limit, offset).all(),
      env.APP_DB.prepare(selected.count).first()
    ]);

    const rows = result.results || [];
    const responseKey = type === "activity" ? "events" : type;

    return json({
      ok: true,
      type,
      total: Number(count?.total || 0),
      limit,
      offset,
      [responseKey]: rows
    });
  } catch {
    return json({
      error: "registry_query_failed",
      message: "The registry could not be read. Check the applied D1 migrations."
    }, 500);
  }
}
