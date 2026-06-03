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

export async function getKnownCustomerIds(kv: KVNamespace): Promise<string[]> {
  const raw = await kv.get(WHITELIST_KEY);
  if (!raw) return [];
  try {
    const parsed = JSON.parse(raw) as { known_customer_ids?: string[] };
    return parsed.known_customer_ids ?? [];
  } catch {
    return [];
  }
}

export async function addKnownCustomerId(kv: KVNamespace, customerId: string): Promise<void> {
  const ids = await getKnownCustomerIds(kv);
  if (!ids.includes(customerId)) {
    ids.push(customerId);
    await kv.put(WHITELIST_KEY, JSON.stringify({ known_customer_ids: ids }));
  }
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
