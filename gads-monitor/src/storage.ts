// storage.ts
// All KV access goes through here. One KV namespace (TRACKER_KV) holds:
//   config            -> dynamic agent config (webhook, kill switch, version min, ioc feeds)
//   gads:seen:<hash>  -> dedup marker for an already-alerted Google Ads change_event
//   gads:whitelist    -> { known_customer_ids: [...] } validated by the admin
//   gads:accounts     -> cached list of MCC child customer ids (short TTL)
//   device:<id>       -> last heartbeat record for one endpoint agent
//   wl:<eventId>      -> pending whitelist payload (pattern to add when the link is clicked)

export interface AgentConfig {
  webhook_url: string;
  kill_switch: boolean;
  agent_version_min: string;
  ioc_feeds: string[];
  snapshot_interval_seconds: number;
  config_refresh_interval_seconds: number;
}

export interface HeartbeatRecord {
  device_id: string;
  device_label: string;
  email: string;
  os_platform: string;
  agent_version: string;
  last_seen: string; // ISO timestamp
  alerts_24h: number;
  status: "active" | "uninstalled";
}

const CONFIG_KEY = "config";
const WHITELIST_KEY = "gads:whitelist";

// Default config used the very first time, before anything is saved from /admin.
// webhook_url is seeded from the SLACK_WEBHOOK_URL secret on first read.
export function defaultConfig(webhookSeed: string): AgentConfig {
  return {
    webhook_url: webhookSeed,
    kill_switch: false,
    agent_version_min: "1.0.0",
    ioc_feeds: [
      "https://urlhaus.abuse.ch/downloads/text/",
      "https://threatfox.abuse.ch/export/csv/recent/",
    ],
    snapshot_interval_seconds: 300,
    config_refresh_interval_seconds: 3600,
  };
}

export async function getConfig(kv: KVNamespace, webhookSeed: string): Promise<AgentConfig> {
  const raw = await kv.get(CONFIG_KEY);
  if (!raw) {
    const cfg = defaultConfig(webhookSeed);
    await kv.put(CONFIG_KEY, JSON.stringify(cfg));
    return cfg;
  }
  try {
    const parsed = JSON.parse(raw) as Partial<AgentConfig>;
    // Merge with defaults so a missing field never breaks an agent.
    return { ...defaultConfig(webhookSeed), ...parsed } as AgentConfig;
  } catch {
    return defaultConfig(webhookSeed);
  }
}

export async function saveConfig(kv: KVNamespace, cfg: AgentConfig): Promise<void> {
  await kv.put(CONFIG_KEY, JSON.stringify(cfg));
}

// Dedup: returns true if this change_event was already alerted, otherwise marks it seen.
// Keyed by a stable hash of the resource_name so the same event never alerts twice.
export async function alreadyAlerted(kv: KVNamespace, resourceName: string): Promise<boolean> {
  const key = "gads:seen:" + resourceName;
  const existing = await kv.get(key);
  if (existing) return true;
  // Keep the marker 7 days; change_event only exposes the last 30 days anyway.
  await kv.put(key, "1", { expirationTtl: 7 * 24 * 3600 });
  return false;
}

// GADS whitelist: each entry is a (customer_id + user_email) pair, so whitelisting a
// legitimate automation tool on one account silences THAT actor on THAT account only,
// not every alert for the client. Stored as an array under WHITELIST_KEY.
export interface GadsWhitelistEntry {
  customer_id: string;
  user_email: string;
  label?: string;
}

export async function getGadsWhitelist(kv: KVNamespace): Promise<GadsWhitelistEntry[]> {
  const raw = await kv.get(WHITELIST_KEY);
  if (!raw) return [];
  try {
    const parsed = JSON.parse(raw);
    return Array.isArray(parsed) ? (parsed as GadsWhitelistEntry[]) : [];
  } catch {
    return [];
  }
}

function gadsKey(cid: string, email: string): string {
  return `${cid}|${(email || "").toLowerCase()}`;
}

export async function isGadsWhitelisted(kv: KVNamespace, cid: string, email: string): Promise<boolean> {
  const list = await getGadsWhitelist(kv);
  return list.some((e) => gadsKey(e.customer_id, e.user_email) === gadsKey(cid, email));
}

export async function addGadsWhitelist(
  kv: KVNamespace,
  cid: string,
  email: string,
  label?: string,
): Promise<void> {
  const list = await getGadsWhitelist(kv);
  if (!list.some((e) => gadsKey(e.customer_id, e.user_email) === gadsKey(cid, email))) {
    list.push({ customer_id: cid, user_email: (email || "").toLowerCase(), label });
    await kv.put(WHITELIST_KEY, JSON.stringify(list));
  }
}

export async function removeGadsWhitelist(kv: KVNamespace, cid: string, email: string): Promise<void> {
  const list = await getGadsWhitelist(kv);
  const next = list.filter((e) => gadsKey(e.customer_id, e.user_email) !== gadsKey(cid, email));
  await kv.put(WHITELIST_KEY, JSON.stringify(next));
}

// Heartbeats from the endpoint agents (one record per device).
export async function saveHeartbeat(kv: KVNamespace, hb: HeartbeatRecord): Promise<void> {
  await kv.put("device:" + hb.device_id, JSON.stringify(hb), {
    // Records live 14 days without a refresh; the incident window is ~2 weeks.
    expirationTtl: 14 * 24 * 3600,
  });
}

export async function listHeartbeats(kv: KVNamespace): Promise<HeartbeatRecord[]> {
  const out: HeartbeatRecord[] = [];
  let cursor: string | undefined;
  do {
    const page = await kv.list({ prefix: "device:", cursor });
    for (const k of page.keys) {
      const raw = await kv.get(k.name);
      if (raw) {
        try {
          out.push(JSON.parse(raw) as HeartbeatRecord);
        } catch {
          // skip malformed
        }
      }
    }
    cursor = page.list_complete ? undefined : page.cursor;
  } while (cursor);
  return out;
}

// Whitelist link payload: stored when an alert is sent, consumed when the link is clicked.
export interface WhitelistPayload {
  scope: "gads" | "endpoint";
  label: string; // human readable, shown on the confirmation page
  customer_id?: string; // for gads alerts
  user_email?: string; // for gads alerts (whitelist the actor on that account)
  device_id?: string; // for endpoint alerts
  pattern?: string; // for endpoint alerts (binary hash, extension id, ip, etc.)
}

export async function storeWhitelistPayload(
  kv: KVNamespace,
  eventId: string,
  payload: WhitelistPayload,
): Promise<void> {
  await kv.put("wl:" + eventId, JSON.stringify(payload), { expirationTtl: 30 * 24 * 3600 });
}

export async function getWhitelistPayload(
  kv: KVNamespace,
  eventId: string,
): Promise<WhitelistPayload | null> {
  const raw = await kv.get("wl:" + eventId);
  if (!raw) return null;
  try {
    return JSON.parse(raw) as WhitelistPayload;
  } catch {
    return null;
  }
}

// Per-device whitelist of endpoint patterns (binary hash, extension id, ip...).
// An agent fetches this with its config and silences these patterns permanently.
export async function getDeviceWhitelist(kv: KVNamespace, deviceId: string): Promise<string[]> {
  const raw = await kv.get("dwl:" + deviceId);
  if (!raw) return [];
  try {
    return JSON.parse(raw) as string[];
  } catch {
    return [];
  }
}

export async function addDeviceWhitelistPattern(
  kv: KVNamespace,
  deviceId: string,
  pattern: string,
): Promise<void> {
  const list = await getDeviceWhitelist(kv, deviceId);
  if (!list.includes(pattern)) {
    list.push(pattern);
    await kv.put("dwl:" + deviceId, JSON.stringify(list), { expirationTtl: 30 * 24 * 3600 });
  }
}

export async function removeDeviceWhitelistPattern(
  kv: KVNamespace,
  deviceId: string,
  pattern: string,
): Promise<void> {
  const list = (await getDeviceWhitelist(kv, deviceId)).filter((p) => p !== pattern);
  await kv.put("dwl:" + deviceId, JSON.stringify(list), { expirationTtl: 30 * 24 * 3600 });
}

// Lists every device's whitelisted patterns (for the admin management page).
export async function listDeviceWhitelists(
  kv: KVNamespace,
): Promise<{ device_id: string; patterns: string[] }[]> {
  const out: { device_id: string; patterns: string[] }[] = [];
  let cursor: string | undefined;
  do {
    const page = await kv.list({ prefix: "dwl:", cursor });
    for (const k of page.keys) {
      const deviceId = k.name.slice("dwl:".length);
      const patterns = await getDeviceWhitelist(kv, deviceId);
      if (patterns.length) out.push({ device_id: deviceId, patterns });
    }
    cursor = page.list_complete ? undefined : page.cursor;
  } while (cursor);
  return out;
}

// Endpoint alert timeline: every endpoint alert is recorded here so a Google Ads
// alert can be cross-referenced with devices that showed infostealer behaviour around
// the same time (device <-> operation correlation).
export interface EndpointAlertRecord {
  device_id: string;
  device_label?: string;
  email?: string;
  detector: string;
  headline: string;
  ts: number; // epoch ms, stamped by the worker when received
}

export async function recordEndpointAlert(
  kv: KVNamespace,
  rec: EndpointAlertRecord,
): Promise<void> {
  // Key sorts by time; kept 24h (the correlation window only ever looks back minutes).
  await kv.put(`ea:${rec.ts}:${rec.device_id}`, JSON.stringify(rec), {
    expirationTtl: 24 * 3600,
  });
}

export async function getRecentEndpointAlerts(
  kv: KVNamespace,
  sinceMs: number,
): Promise<EndpointAlertRecord[]> {
  const out: EndpointAlertRecord[] = [];
  let cursor: string | undefined;
  do {
    const page = await kv.list({ prefix: "ea:", cursor });
    for (const k of page.keys) {
      const raw = await kv.get(k.name);
      if (!raw) continue;
      try {
        const rec = JSON.parse(raw) as EndpointAlertRecord;
        if (rec.ts >= sinceMs) out.push(rec);
      } catch {
        // skip malformed
      }
    }
    cursor = page.list_complete ? undefined : page.cursor;
  } while (cursor);
  return out.sort((a, b) => b.ts - a.ts);
}
