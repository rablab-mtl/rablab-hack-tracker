// slack.ts
// Formats and posts Module 2 (Google Ads) alerts to the shared Slack webhook.
// The webhook URL comes from KV config (rotatable from /admin), not from the repo.

export async function postSlack(webhookUrl: string, text: string): Promise<boolean> {
  if (!webhookUrl) return false;
  try {
    const resp = await fetch(webhookUrl, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ text }),
    });
    return resp.ok;
  } catch {
    return false;
  }
}

export interface GadsAlert {
  icon: string; // 🚨 or ⚠️
  accountName: string;
  customerId: string;
  userEmail: string;
  time: string; // HH:MM:SS
  headline: string;
  details: string[];
  why: string;
  actions: string[];
  whitelistUrl?: string;
}

// Builds the standard Module 2 alert text (see brief "Format alerte Slack (Module 2)").
export function formatGadsAlert(a: GadsAlert): string {
  const lines: string[] = [];
  lines.push(`${a.icon} [GADS] Operation sensible - Compte client : ${a.accountName} (${a.customerId})`);
  lines.push(`Effectuee par : ${a.userEmail}`);
  lines.push(`${a.time} - ${a.headline}`);
  lines.push("");
  lines.push("Details :");
  for (const d of a.details) lines.push(`- ${d}`);
  lines.push("");
  lines.push("Pourquoi c'est en lien avec le hack Google Ads :");
  lines.push(a.why);
  lines.push("");
  lines.push("→ Action :");
  a.actions.forEach((act, i) => lines.push(`${i + 1}. ${act}`));
  if (a.whitelistUrl) {
    lines.push("");
    lines.push(`→ C'etait une operation legitime / faux positif ? Clique pour whitelister :`);
    lines.push(a.whitelistUrl);
  }
  return lines.join("\n");
}
