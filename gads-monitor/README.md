# Module 2 : rablab-gads-monitor (Cloudflare Worker)

Ce worker fait deux choses :

1. **Surveille le MCC Google Ads** toutes les 3 minutes (cron). Il lit le flux `change_event`
   de chaque compte enfant et alerte Slack des qu'une operation sensible apparait (Manager link,
   changement de budget, billing, client API/bulk, etc.), peu importe d'ou elle vient.
2. **Sert de cerveau aux agents endpoint** (Module 1) : config dynamique (webhook Slack, kill switch,
   feeds IoC), page admin, dashboard des devices, gestion des liens de whitelist, reception des heartbeats.

## Choix de securite (important)

- **Aucun canal de mise a jour de code a distance.** `agent_version_min` est purement informatif.
  Les agents ne telechargent jamais de code sur commande. Le kill switch ne fait qu'ecrire un drapeau
  qui dit aux agents de se desinstaller, il n'execute rien.
- `/admin`, `/status`, `/kill-switch` sont proteges par `ADMIN_TOKEN` (secret fort, jamais dans le repo).
- `/agent-config` est protege par `AGENT_SHARED_TOKEN` (simple filtre anti-bot, faible sensibilite).
- Les liens `/whitelist/...` portent un token HMAC derive de `WHITELIST_SIGNING_KEY`.
- Les comptes listes dans `COMPROMISED_ACCOUNTS` declenchent toujours un 🚨, jamais un simple ⚠️.

## Deploiement

Prerequis : `npx wrangler login` deja fait (compte Cloudflare `Rablab`).

```bash
cd gads-monitor
npm install

# 1. Creer le namespace KV et coller l'id retourne dans wrangler.jsonc (champ "id").
npx wrangler kv namespace create TRACKER_KV

# 2. Secrets obligatoires (agents + admin)
npx wrangler secret put SLACK_WEBHOOK_URL       # webhook initial du canal #rablab-security
npx wrangler secret put ADMIN_TOKEN             # 32+ chars aleatoires, connu de l'admin seul
npx wrangler secret put AGENT_SHARED_TOKEN      # token partage des agents (aussi dans le repo public)
npx wrangler secret put WHITELIST_SIGNING_KEY   # cle aleatoire pour signer les liens whitelist

# 3. Secrets Google Ads (Module 2 reste inerte tant qu'ils ne sont pas tous poses)
npx wrangler secret put GOOGLE_CLIENT_ID
npx wrangler secret put GOOGLE_CLIENT_SECRET
npx wrangler secret put GADS_REFRESH_TOKEN
npx wrangler secret put GADS_DEVELOPER_TOKEN
npx wrangler secret put GADS_LOGIN_CUSTOMER_ID  # id du MCC, chiffres seulement

# 4. Deployer
npx wrangler deploy
```

Les variables non secretes (`EXPECTED_USERS`, `COMPROMISED_ACCOUNTS`, `GADS_EXPECTED_USERS`,
`GADS_API_VERSION`) sont dans `wrangler.jsonc` et editables directement.

## Pages

- `https://rablab-gads-monitor.rablab.workers.dev/admin?token=ADMIN_TOKEN` : gestion (webhook, kill switch, feeds)
- `https://rablab-gads-monitor.rablab.workers.dev/status?token=ADMIN_TOKEN` : dashboard des devices

## A valider a la premiere mise en service Google Ads

Le client Google Ads (`gads_client.ts`) est ecrit selon le contrat documente de l'API mais n'a
pas pu etre teste sans les credentials live. A la premiere pose des secrets :

1. Verifier les logs : `npx wrangler tail`
2. Confirmer que `listChildAccounts` retourne bien les comptes du MCC (sinon ajuster `GADS_API_VERSION`).
3. Test E2E : creer un budget de campagne de test dans un compte non-production, l'augmenter de +60%,
   confirmer qu'une alerte ⚠️ arrive dans Slack sous 3 a 5 min, puis supprimer le budget de test.

## Endpoints (resume)

| Methode | Route | Auth | Role |
|---|---|---|---|
| GET | `/agent-config` | `X-Agent-Token` | Config dynamique des agents |
| POST | `/heartbeat` | `X-Agent-Token` | Reception des heartbeats |
| GET/POST | `/admin` | `ADMIN_TOKEN` | Gestion config |
| GET | `/status` | `ADMIN_TOKEN` | Dashboard devices |
| POST | `/kill-switch` | `ADMIN_TOKEN` | Active le kill switch |
| GET | `/whitelist/:id` | HMAC | Whitelist d'un faux positif |
