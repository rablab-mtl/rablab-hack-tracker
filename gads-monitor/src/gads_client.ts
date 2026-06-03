// gads_client.ts
// Minimal REST client for the Google Ads API. Reuses the same OAuth client,
// refresh token and developer token already used by mcp-gads (no new OAuth setup).
//
// NOTE on validation: this path cannot be exercised without the live Google Ads
// credentials. It is written to the documented API contract. Validate against the
// real MCC the first time the secrets are set (see gads-monitor/README.md, "Test E2E").

export interface GadsCreds {
  clientId: string;
  clientSecret: string;
  refreshToken: string;
  developerToken: string;
  loginCustomerId: string; // MCC id, digits only (no dashes)
  apiVersion: string; // e.g. "v18"
}

// Exchange the long-lived refresh token for a short-lived access token.
async function getAccessToken(creds: GadsCreds): Promise<string> {
  const body = new URLSearchParams({
    client_id: creds.clientId,
    client_secret: creds.clientSecret,
    refresh_token: creds.refreshToken,
    grant_type: "refresh_token",
  });
  const resp = await fetch("https://oauth2.googleapis.com/token", {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: body.toString(),
  });
  if (!resp.ok) {
    throw new Error(`OAuth token refresh failed: ${resp.status} ${await resp.text()}`);
  }
  const json = (await resp.json()) as { access_token?: string };
  if (!json.access_token) throw new Error("OAuth response had no access_token");
  return json.access_token;
}

function digitsOnly(id: string): string {
  return id.replace(/[^0-9]/g, "");
}

// Runs a GAQL query against searchStream for one customer id. Returns the flattened rows.
async function searchStream(
  creds: GadsCreds,
  accessToken: string,
  customerId: string,
  gaql: string,
): Promise<any[]> {
  const cid = digitsOnly(customerId);
  const url = `https://googleads.googleapis.com/${creds.apiVersion}/customers/${cid}/googleAds:searchStream`;
  const resp = await fetch(url, {
    method: "POST",
    headers: {
      Authorization: `Bearer ${accessToken}`,
      "developer-token": creds.developerToken,
      "login-customer-id": digitsOnly(creds.loginCustomerId),
      "Content-Type": "application/json",
    },
    body: JSON.stringify({ query: gaql }),
  });
  if (!resp.ok) {
    throw new Error(`searchStream failed for ${cid}: ${resp.status} ${await resp.text()}`);
  }
  // searchStream returns an array of response chunks, each with a "results" array.
  const chunks = (await resp.json()) as Array<{ results?: any[] }>;
  const rows: any[] = [];
  for (const chunk of chunks) {
    if (chunk.results) rows.push(...chunk.results);
  }
  return rows;
}

// Lists every child account under the MCC (one level; nested managers are followed).
export async function listChildAccounts(creds: GadsCreds, accessToken: string): Promise<
  { id: string; name: string }[]
> {
  const gaql = `
    SELECT
      customer_client.id,
      customer_client.descriptive_name,
      customer_client.manager,
      customer_client.status
    FROM customer_client
    WHERE customer_client.status = 'ENABLED'`;
  const rows = await searchStream(creds, accessToken, creds.loginCustomerId, gaql);
  const out: { id: string; name: string }[] = [];
  for (const r of rows) {
    const cc = r.customerClient;
    if (!cc) continue;
    // Skip pure manager nodes; we want accounts where ads actually run.
    if (cc.manager === true) continue;
    out.push({ id: String(cc.id), name: cc.descriptiveName ?? "" });
  }
  return out;
}

// change_event does not accept arbitrary "NOW - N MINUTES" strings; it needs an
// explicit datetime lower bound. We compute one from the current request time and
// rely on KV dedup so the exact boundary never causes a double alert.
// (Date is available in the worker runtime, unlike in workflow scripts.)
export function buildChangeEventQuery(now: Date, windowMinutes: number): string {
  const from = new Date(now.getTime() - windowMinutes * 60 * 1000);
  const fmt = (d: Date) => {
    const p = (n: number) => String(n).padStart(2, "0");
    return `${d.getUTCFullYear()}-${p(d.getUTCMonth() + 1)}-${p(d.getUTCDate())} ${p(d.getUTCHours())}:${p(d.getUTCMinutes())}:${p(d.getUTCSeconds())}`;
  };
  return `
    SELECT
      change_event.resource_name,
      change_event.change_date_time,
      change_event.user_email,
      change_event.client_type,
      change_event.change_resource_type,
      change_event.changed_fields,
      change_event.resource_change_operation,
      change_event.campaign,
      change_event.ad_group,
      change_event.old_resource,
      change_event.new_resource,
      customer.descriptive_name
    FROM change_event
    WHERE change_event.change_date_time >= '${fmt(from)}'
    ORDER BY change_event.change_date_time DESC
    LIMIT 500`;
}

export async function fetchRecentChangeEvents(
  creds: GadsCreds,
  accessToken: string,
  customerId: string,
  now: Date,
  windowMinutes: number,
): Promise<any[]> {
  const gaql = buildChangeEventQuery(now, windowMinutes);
  return searchStream(creds, accessToken, customerId, gaql);
}

export { getAccessToken };
