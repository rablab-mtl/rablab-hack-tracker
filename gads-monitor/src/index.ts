// index.ts
// rablab-gads-monitor : Module 2 du rablab-hack-tracker.
//
// Two jobs:
//  1. Cron (every 3 min): scan the MCC Google Ads change_event feed and alert Slack
//     on sensitive operations (manager links, billing, big budgets, API/bulk clients...).
//  2. HTTP routes: serve dynamic config to endpoint agents, an admin page to rotate the
//     Slack webhook / flip the kill switch, a status dashboard, a whitelist link handler,
//     and a heartbeat sink for the agents.
//
// SECURITY NOTE (intentional design):
//  - There is NO remote code-update channel. agent_version_min is advisory only; agents
//    never pull and execute code on command. The kill switch can stop/uninstall agents
//    (a data flag), it cannot run arbitrary code.
//  - /admin, /status and /kill-switch require ADMIN_TOKEN (a strong secret, not in the repo).
//  - /agent-config requires the AGENT_SHARED_TOKEN (anti-bot filter, low sensitivity).
//  - /whitelist links carry a per-event HMAC token derived from WHITELIST_SIGNING_KEY.

import {
  getConfig,
  saveConfig,
  alreadyAlerted,
  addKnownCustomerId,
  saveHeartbeat,
  listHeartbeats,
  storeWhitelistPayload,
  getWhitelistPayload,
  getDeviceWhitelist,
  addDeviceWhitelistPattern,
  type AgentConfig,
  type HeartbeatRecord,
} from "./storage";
import { postSlack, formatGadsAlert } from "./slack";
import { evaluate, type ChangeEvent } from "./detectors";
import {
  getAccessToken,
  listChildAccounts,
  fetchRecentChangeEvents,
  type GadsCreds,
} from "./gads_client";

export interface Env {
  TRACKER_KV: KVNamespace;

  // Secrets (wrangler secret put)
  SLACK_WEBHOOK_URL: string; // seed; live value lives in KV config and is rotatable
  ADMIN_TOKEN: string;
  AGENT_SHARED_TOKEN: string;
  WHITELIST_SIGNING_KEY: string;

  // Google Ads secrets (optional; Module 2 scan stays idle until all are set)
  GOOGLE_CLIENT_ID?: string;
  GOOGLE_CLIENT_SECRET?: string;
  GADS_REFRESH_TOKEN?: string;
  GADS_DEVELOPER_TOKEN?: string;
  GADS_LOGIN_CUSTOMER_ID?: string;

  // Vars (wrangler.jsonc)
  EXPECTED_USERS: string;
  COMPROMISED_ACCOUNTS: string;
  GADS_EXPECTED_USERS: string;
  GADS_API_VERSION: string;
  GADS_BUDGET_WARN_DAILY?: string; // daily budget ($) at/above which a new campaign alerts ⚠️
  GADS_BUDGET_CRIT_DAILY?: string; // daily budget ($) at/above which it is forced 🚨
}

// ----- small helpers -------------------------------------------------------

function csv(v: string | undefined): string[] {
  return (v ?? "").split(",").map((s) => s.trim().toLowerCase()).filter(Boolean);
}

function timingSafeEqual(a: string, b: string): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return diff === 0;
}

async function hmacHex(key: string, message: string): Promise<string> {
  const enc = new TextEncoder();
  const cryptoKey = await crypto.subtle.importKey(
    "raw",
    enc.encode(key),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"],
  );
  const sig = await crypto.subtle.sign("HMAC", cryptoKey, enc.encode(message));
  return [...new Uint8Array(sig)].map((b) => b.toString(16).padStart(2, "0")).join("");
}

function esc(s: string): string {
  return s
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

function htmlPage(title: string, body: string): Response {
  // Rablab colours: vert #26372b, orange #ec662a, gris #f5f5f5.
  const html = `<!doctype html><html lang="fr"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>${esc(title)}</title>
<style>
  body{font-family:-apple-system,Roboto,Segoe UI,sans-serif;margin:0;background:#f5f5f5;color:#1a1a1a}
  header{background:#26372b;color:#fff;padding:18px 24px;font-size:20px;font-weight:600}
  main{max-width:900px;margin:24px auto;padding:0 16px}
  .card{background:#fff;border:1px solid #bfbfbf;border-radius:8px;padding:20px;margin-bottom:18px}
  h2{color:#26372b;border-bottom:3px solid #ec662a;padding-bottom:6px}
  label{display:block;margin:14px 0 4px;font-weight:600}
  input[type=text],input[type=url],textarea{width:100%;padding:9px;border:1px solid #bfbfbf;border-radius:6px;font-size:14px;box-sizing:border-box}
  textarea{min-height:90px;font-family:monospace}
  button{background:#ec662a;color:#fff;border:0;padding:11px 20px;border-radius:6px;font-size:15px;font-weight:600;cursor:pointer;margin-top:16px}
  button.secondary{background:#26372b}
  table{width:100%;border-collapse:collapse;margin-top:10px}
  th{background:#26372b;color:#fff;text-align:left;padding:9px}
  td{padding:9px;border-bottom:1px solid #eee}
  tr:nth-child(even) td{background:#f5f5f5}
  .ok{color:#1a7f37}.warn{color:#b35900}.bad{color:#b00020}
  code{background:#f5f5f5;padding:2px 5px;border-radius:4px}
</style></head><body><header>Rablab Hack Tracker</header><main>${body}</main></body></html>`;
  return new Response(html, { headers: { "Content-Type": "text/html; charset=utf-8" } });
}

function relativeAge(iso: string, now: Date): { text: string; minutes: number } {
  const then = new Date(iso).getTime();
  const min = Math.max(0, Math.round((now.getTime() - then) / 60000));
  if (min < 60) return { text: `il y a ${min} min`, minutes: min };
  const h = Math.round(min / 60);
  if (h < 48) return { text: `il y a ${h} h`, minutes: min };
  return { text: `il y a ${Math.round(h / 24)} j`, minutes: min };
}

function hhmmss(iso: string | undefined): string {
  if (!iso) return "??:??:??";
  // change_date_time looks like "2026-06-03 14:32:18" (account timezone).
  const m = iso.match(/(\d{2}):(\d{2}):(\d{2})/);
  return m ? `${m[1]}:${m[2]}:${m[3]}` : iso;
}

function workerOrigin(req: Request): string {
  return new URL(req.url).origin;
}

// ----- HTTP handler --------------------------------------------------------

async function handleFetch(req: Request, env: Env): Promise<Response> {
  const url = new URL(req.url);
  const path = url.pathname;
  const token = url.searchParams.get("token") ?? "";

  // GET / : harmless landing page, no secrets.
  if (path === "/" || path === "") {
    return htmlPage(
      "Rablab Hack Tracker",
      `<div class="card"><h2>rablab-gads-monitor</h2>
      <p>Worker de monitoring de l'incident de securite Rablab. Endpoints proteges par token.</p>
      <p>Code source : <code>github.com/rablab-mtl/rablab-hack-tracker</code></p></div>`,
    );
  }

  // GET /agent-config : config dynamique pour les agents endpoint.
  if (path === "/agent-config") {
    const provided = req.headers.get("X-Agent-Token") ?? "";
    if (!timingSafeEqual(provided, env.AGENT_SHARED_TOKEN)) {
      return new Response("forbidden", { status: 403 });
    }
    const cfg = await getConfig(env.TRACKER_KV, env.SLACK_WEBHOOK_URL);
    // If the agent identifies itself, also return its permanent whitelist patterns.
    const deviceId = url.searchParams.get("device_id");
    const whitelisted_patterns = deviceId
      ? await getDeviceWhitelist(env.TRACKER_KV, deviceId)
      : [];
    return Response.json({ ...cfg, whitelisted_patterns });
  }

  // POST /endpoint-alert : un agent enregistre une alerte et recoit un lien de whitelist signe.
  // Le worker est le seul a pouvoir signer le lien (cle WHITELIST_SIGNING_KEY).
  if (path === "/endpoint-alert" && req.method === "POST") {
    const provided = req.headers.get("X-Agent-Token") ?? "";
    if (!timingSafeEqual(provided, env.AGENT_SHARED_TOKEN)) {
      return new Response("forbidden", { status: 403 });
    }
    try {
      const body = (await req.json()) as { device_id: string; pattern: string; label: string };
      const eventId = await hmacHex(env.WHITELIST_SIGNING_KEY, `${body.device_id}:${body.pattern}`);
      const wlToken = await hmacHex(env.WHITELIST_SIGNING_KEY, eventId);
      await storeWhitelistPayload(env.TRACKER_KV, eventId, {
        scope: "endpoint",
        label: body.label,
        device_id: body.device_id,
        pattern: body.pattern,
      });
      const whitelistUrl = `${workerOrigin(req)}/whitelist/${encodeURIComponent(eventId)}?token=${wlToken}`;
      return Response.json({ whitelist_url: whitelistUrl });
    } catch {
      return new Response("bad request", { status: 400 });
    }
  }

  // POST /heartbeat : les agents poussent leur etat ici (en plus de Slack).
  if (path === "/heartbeat" && req.method === "POST") {
    const provided = req.headers.get("X-Agent-Token") ?? "";
    if (!timingSafeEqual(provided, env.AGENT_SHARED_TOKEN)) {
      return new Response("forbidden", { status: 403 });
    }
    try {
      const hb = (await req.json()) as HeartbeatRecord;
      hb.last_seen = new Date().toISOString();
      await saveHeartbeat(env.TRACKER_KV, hb);
      return Response.json({ ok: true });
    } catch {
      return new Response("bad request", { status: 400 });
    }
  }

  // /admin : page de gestion (webhook, kill switch, version min, ioc feeds).
  if (path === "/admin") {
    if (!timingSafeEqual(token, env.ADMIN_TOKEN)) {
      return new Response("forbidden", { status: 403 });
    }
    const cfg = await getConfig(env.TRACKER_KV, env.SLACK_WEBHOOK_URL);

    if (req.method === "POST") {
      const form = await req.formData();
      const next: AgentConfig = {
        ...cfg,
        webhook_url: String(form.get("webhook_url") ?? cfg.webhook_url).trim(),
        kill_switch: form.get("kill_switch") === "on",
        agent_version_min: String(form.get("agent_version_min") ?? cfg.agent_version_min).trim(),
        ioc_feeds: String(form.get("ioc_feeds") ?? "")
          .split("\n")
          .map((s) => s.trim())
          .filter(Boolean),
      };
      await saveConfig(env.TRACKER_KV, next);
      return htmlPage(
        "Config sauvegardee",
        `<div class="card"><h2>✅ Config sauvegardee</h2>
        <p>Les agents prendront la nouvelle config a leur prochain refresh (max 1 h).</p>
        <p><a href="/admin?token=${esc(token)}">Retour</a></p></div>`,
      );
    }

    const body = `<div class="card"><h2>Configuration des agents</h2>
    <form method="POST" action="/admin?token=${esc(token)}">
      <label>Slack Webhook URL</label>
      <input type="url" name="webhook_url" value="${esc(cfg.webhook_url)}">
      <label><input type="checkbox" name="kill_switch" ${cfg.kill_switch ? "checked" : ""}> Kill switch (force la desinstallation de tous les agents)</label>
      <label>Agent version min (informatif, ne declenche aucune mise a jour automatique de code)</label>
      <input type="text" name="agent_version_min" value="${esc(cfg.agent_version_min)}">
      <label>IoC feeds (une URL par ligne)</label>
      <textarea name="ioc_feeds">${esc(cfg.ioc_feeds.join("\n"))}</textarea>
      <button type="submit">Save</button>
    </form></div>
    <div class="card"><h2>Pages</h2>
      <p><a href="/status?token=${esc(token)}">Dashboard des devices</a></p>
    </div>`;
    return htmlPage("Admin", body);
  }

  // POST /kill-switch : raccourci pour activer le kill switch.
  if (path === "/kill-switch" && req.method === "POST") {
    if (!timingSafeEqual(token, env.ADMIN_TOKEN)) {
      return new Response("forbidden", { status: 403 });
    }
    const cfg = await getConfig(env.TRACKER_KV, env.SLACK_WEBHOOK_URL);
    cfg.kill_switch = true;
    await saveConfig(env.TRACKER_KV, cfg);
    return Response.json({ ok: true, kill_switch: true });
  }

  // /status : dashboard live des heartbeats vs employes attendus.
  if (path === "/status") {
    if (!timingSafeEqual(token, env.ADMIN_TOKEN)) {
      return new Response("forbidden", { status: 403 });
    }
    const now = new Date();
    const hbs = await listHeartbeats(env.TRACKER_KV);
    const byEmail = new Map<string, HeartbeatRecord>();
    for (const hb of hbs) byEmail.set(hb.email.toLowerCase(), hb);

    const expected = csv(env.EXPECTED_USERS);
    const rows: string[] = [];
    for (const email of expected) {
      const hb = byEmail.get(email);
      if (!hb) {
        rows.push(
          `<tr><td>-</td><td>${esc(email)}</td><td>-</td><td>jamais</td><td class="bad">❌ Pas installe</td></tr>`,
        );
        continue;
      }
      const age = relativeAge(hb.last_seen, now);
      let status = `<span class="ok">✅ Actif</span>`;
      if (hb.status === "uninstalled") status = `<span class="warn">👋 Desinstalle</span>`;
      else if (age.minutes > 24 * 60) status = `<span class="warn">⚠️ Inactif</span>`;
      rows.push(
        `<tr><td>${esc(hb.device_label)}</td><td>${esc(hb.email)}</td><td>${esc(hb.os_platform)}</td><td>${esc(age.text)}</td><td>${status}</td></tr>`,
      );
    }
    // Devices that reported but are not in the expected list (unexpected installs).
    for (const hb of hbs) {
      if (!expected.includes(hb.email.toLowerCase())) {
        const age = relativeAge(hb.last_seen, now);
        rows.push(
          `<tr><td>${esc(hb.device_label)}</td><td>${esc(hb.email)} (hors liste)</td><td>${esc(hb.os_platform)}</td><td>${esc(age.text)}</td><td class="warn">⚠️ Inattendu</td></tr>`,
        );
      }
    }

    const body = `<div class="card"><h2>Devices</h2>
      <table><thead><tr><th>Device</th><th>Email</th><th>OS</th><th>Dernier heartbeat</th><th>Statut</th></tr></thead>
      <tbody>${rows.join("")}</tbody></table>
      <p style="margin-top:14px"><a href="/admin?token=${esc(token)}">Page admin</a></p></div>`;
    return htmlPage("Status", body);
  }

  // /whitelist/<eventId>?token=<hmac> : marquer un pattern comme faux positif.
  if (path.startsWith("/whitelist/")) {
    const eventId = decodeURIComponent(path.slice("/whitelist/".length));
    const expectedToken = await hmacHex(env.WHITELIST_SIGNING_KEY, eventId);
    if (!timingSafeEqual(token, expectedToken)) {
      return new Response("forbidden", { status: 403 });
    }
    const payload = await getWhitelistPayload(env.TRACKER_KV, eventId);
    if (!payload) {
      return htmlPage(
        "Whitelist",
        `<div class="card"><h2>Lien expire</h2><p>Cette alerte n'est plus disponible (plus de 30 jours).</p></div>`,
      );
    }
    if (payload.scope === "gads" && payload.customer_id) {
      await addKnownCustomerId(env.TRACKER_KV, payload.customer_id);
    }
    if (payload.scope === "endpoint" && payload.device_id && payload.pattern) {
      // The agent fetches this list with its config and silences the pattern for good.
      await addDeviceWhitelistPattern(env.TRACKER_KV, payload.device_id, payload.pattern);
    }
    return htmlPage(
      "Whitelist",
      `<div class="card"><h2>✅ Pattern whiteliste</h2>
      <p>${esc(payload.label)}</p>
      <p>Les prochaines detections identiques de ce pattern seront silencieuses.</p></div>`,
    );
  }

  return new Response("not found", { status: 404 });
}

// ----- Cron handler (Google Ads scan) --------------------------------------

function hasGadsCreds(env: Env): boolean {
  return Boolean(
    env.GOOGLE_CLIENT_ID &&
      env.GOOGLE_CLIENT_SECRET &&
      env.GADS_REFRESH_TOKEN &&
      env.GADS_DEVELOPER_TOKEN &&
      env.GADS_LOGIN_CUSTOMER_ID,
  );
}

async function getChildAccounts(
  env: Env,
  creds: GadsCreds,
  accessToken: string,
): Promise<{ id: string; name: string }[]> {
  const cached = await env.TRACKER_KV.get("gads:accounts");
  if (cached) {
    try {
      return JSON.parse(cached) as { id: string; name: string }[];
    } catch {
      // fall through and refresh
    }
  }
  const accounts = await listChildAccounts(creds, accessToken);
  await env.TRACKER_KV.put("gads:accounts", JSON.stringify(accounts), { expirationTtl: 3600 });
  return accounts;
}

async function runGadsScan(env: Env, now: Date): Promise<void> {
  if (!hasGadsCreds(env)) {
    console.log("Google Ads credentials not set; skipping change_event scan.");
    return;
  }
  const cfg = await getConfig(env.TRACKER_KV, env.SLACK_WEBHOOK_URL);
  const creds: GadsCreds = {
    clientId: env.GOOGLE_CLIENT_ID!,
    clientSecret: env.GOOGLE_CLIENT_SECRET!,
    refreshToken: env.GADS_REFRESH_TOKEN!,
    developerToken: env.GADS_DEVELOPER_TOKEN!,
    loginCustomerId: env.GADS_LOGIN_CUSTOMER_ID!,
    apiVersion: env.GADS_API_VERSION || "v18",
  };

  const accessToken = await getAccessToken(creds);
  const accounts = await getChildAccounts(env, creds, accessToken);
  const compromised = csv(env.COMPROMISED_ACCOUNTS);
  const expectedUsers = csv(env.GADS_EXPECTED_USERS);
  const origin = "https://rablab-gads-monitor.rablab.workers.dev";
  const evalOpts = {
    warnMicros: Number(env.GADS_BUDGET_WARN_DAILY || "300") * 1_000_000,
    critMicros: Number(env.GADS_BUDGET_CRIT_DAILY || "1000") * 1_000_000,
  };

  for (const acct of accounts) {
    let rows: any[];
    try {
      // 10 min window overlaps the 3 min cron; KV dedup prevents double alerts.
      rows = await fetchRecentChangeEvents(creds, accessToken, acct.id, now, 10);
    } catch (e) {
      console.log(`change_event fetch failed for ${acct.id}: ${e}`);
      continue;
    }

    for (const row of rows) {
      const ev = (row.changeEvent ?? {}) as ChangeEvent;
      const resourceName: string =
        ev.resourceName ??
        `${acct.id}:${ev.changeDateTime}:${ev.changeResourceType}:${ev.resourceChangeOperation}`;

      const detection = evaluate(ev, evalOpts);
      if (!detection.matched) continue;
      if (await alreadyAlerted(env.TRACKER_KV, resourceName)) continue;

      const userEmail = (ev.userEmail ?? "inconnu").toLowerCase();
      const accountName = row.customer?.descriptiveName ?? acct.name ?? acct.id;

      // Critical detections (e.g. big-budget campaign) force 🚨 regardless of user.
      // Compromised / unknown ops accounts also force 🚨.
      let icon = detection.critical ? "🚨" : "⚠️";
      const extraDetails = [...detection.details];
      if (compromised.includes(userEmail)) {
        icon = "🚨";
        extraDetails.unshift(`COMPTE COMPROMIS : ${userEmail} est un compte vise par l'incident en cours.`);
      } else if (!expectedUsers.includes(userEmail)) {
        icon = "🚨";
        extraDetails.unshift(`USER INCONNU : ${userEmail} n'est pas dans la liste des operateurs Google Ads attendus.`);
      }

      // Per-event whitelist link (HMAC token, payload stored in KV).
      const eventId = await hmacHex(env.WHITELIST_SIGNING_KEY, resourceName + ":id");
      const wlToken = await hmacHex(env.WHITELIST_SIGNING_KEY, eventId);
      await storeWhitelistPayload(env.TRACKER_KV, eventId, {
        scope: "gads",
        label: `Operation ${detection.rule} sur ${accountName} par ${userEmail}`,
        customer_id: acct.id,
      });
      const whitelistUrl = `${origin}/whitelist/${encodeURIComponent(eventId)}?token=${wlToken}`;

      const text = formatGadsAlert({
        icon,
        accountName,
        customerId: acct.id,
        userEmail,
        time: hhmmss(ev.changeDateTime),
        headline: detection.headline,
        details: extraDetails,
        why: detection.why,
        actions: detection.actions,
        whitelistUrl,
      });
      await postSlack(cfg.webhook_url, text);
    }
  }
}

export default {
  async fetch(req: Request, env: Env): Promise<Response> {
    try {
      return await handleFetch(req, env);
    } catch (e) {
      console.log(`fetch error: ${e}`);
      return new Response("internal error", { status: 500 });
    }
  },

  async scheduled(_event: ScheduledController, env: Env, ctx: ExecutionContext): Promise<void> {
    ctx.waitUntil(
      runGadsScan(env, new Date()).catch((e) => console.log(`scheduled error: ${e}`)),
    );
  },
};
