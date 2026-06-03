# rablab-hack-tracker

Outil interne Rablab pour identifier la source d'un incident de securite Google Ads
(suspicion d'infostealer sur un poste de l'equipe). Deux modules complementaires.

> Outil temporaire d'investigation (environ 2 semaines). Code public et verifiable.
> Aucune donnee personnelle d'activite n'est collectee. Conforme Loi 25.

## Les deux modules

### Module 1 : agent endpoint (Mac + Windows) - dossier `endpoint-agent/`

Un petit agent Python installe sur les postes de l'equipe (avec consentement explicite a
l'install). Il surveille uniquement les patterns connus d'infostealer et envoie une alerte
ciblee dans Slack quand un pattern matche. Le reste du temps : silence.

Sept detections :

1. Un processus non-Chrome lit le fichier Cookies de Chrome.
2. Un processus non-Chrome lit le fichier Login Data (mots de passe Chrome).
3. Un nouveau demarrage automatique suspect (LaunchAgent macOS / tache planifiee ou cle Run Windows).
4. Une connexion vers une IP de serveur de commande connue (liste abuse.ch, filtree infostealers).
5. Un binaire non signe qui tourne depuis un dossier temporaire (pattern faux installeur).
6. Une extension Chrome recente aux permissions sensibles, surtout hors Chrome Web Store.
7. Auto-verification : le code de l'agent a-t-il ete modifie (tamper detection).

### Module 2 : worker Google Ads - dossier `gads-monitor/`

Un worker Cloudflare qui scanne le MCC Google Ads toutes les 3 minutes et alerte Slack sur
les operations sensibles (Manager link, billing, gros budgets, client API/bulk, etc.), peu
importe d'ou vient l'operation. Il sert aussi la config dynamique aux agents endpoint
(webhook, kill switch) et expose un dashboard des installs.

## Choix de securite (a lire)

Cet outil surveille des postes pour trouver un compromis. Il a donc ete construit pour ne
pas devenir lui-meme un risque :

- **Aucune mise a jour de code a distance.** L'agent ne telecharge jamais de code sur commande.
  Une mise a jour = chaque personne recolle la commande d'install (action visible et volontaire).
  `agent_version_min` cote worker est purement informatif.
- **Le kill switch ne fait que desinstaller**, il n'execute aucun code.
- **Aucun secret dans le repo.** Le webhook Slack est servi par le worker au runtime. Le seul
  token present dans le code public est un simple filtre anti-bot, sans valeur critique.
- **Les comptes vises par l'incident** (configures cote worker, hors du repo public)
  declenchent toujours une alerte 🚨, jamais une alerte douce.
- **Vie privee.** L'agent regarde QUEL programme ouvre les fichiers d'identifiants, pas leur
  contenu. Il ne lit pas l'historique, les URLs, les fichiers personnels, l'ecran, la camera ou
  le micro, et ne regarde pas quel compte Google est connecte. Voir `endpoint-agent/DISCLAIMER.txt`.

## Installation (pour l'equipe)

🍎 Mac : ouvre Terminal et colle, puis Enter
```
curl -fsSL https://raw.githubusercontent.com/rablab-mtl/rablab-hack-tracker/main/install-macos.sh | bash
```

🪟 Windows : ouvre PowerShell et colle, puis Enter
```
iwr -useb https://raw.githubusercontent.com/rablab-mtl/rablab-hack-tracker/main/install-windows.ps1 | iex
```

L'install pose UNE seule question (ton email Rablab) et affiche un disclaimer detaille avant de
demarrer. Tu peux refuser. Pour desinstaller a tout moment :
```
rablab-hack-tracker uninstall
```

## Documentation par module

- Agent endpoint (install, desinstall, detections) : [`endpoint-agent/README.md`](endpoint-agent/README.md)
- Worker Google Ads (deploiement, secrets, pages admin) : [`gads-monitor/README.md`](gads-monitor/README.md)

## Licence

MIT. Voir [LICENSE](LICENSE).
