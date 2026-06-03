# Module 1 : agent endpoint (Mac + Windows)

Agent Python qui surveille les patterns d'infostealer et alerte Slack. Installe avec
consentement explicite, desinstallable a tout moment.

## Installation

🍎 Mac :
```
curl -fsSL https://raw.githubusercontent.com/rablab-mtl/rablab-hack-tracker/main/install-macos.sh | bash
```

🪟 Windows (PowerShell) :
```
iwr -useb https://raw.githubusercontent.com/rablab-mtl/rablab-hack-tracker/main/install-windows.ps1 | iex
```

L'installeur :
1. Verifie Python 3.11+ (sinon indique comment l'installer).
2. Clone le repo dans `~/Library/Application Support/rablab-hack-tracker` (Mac) ou `%LOCALAPPDATA%\rablab-hack-tracker` (Windows).
3. Cree un venv et installe `psutil` + `requests`.
4. Pose UNE question : ton email Rablab.
5. Affiche le disclaimer Loi 25 et demande ton accord.
6. Genere la config locale (email + device label auto-detecte) et recupere le webhook depuis le worker.
7. Installe le service (LaunchAgent macOS / tache planifiee Windows) et le demarre.
8. Envoie un message Slack de confirmation d'install.

## Commandes

```
rablab-hack-tracker status      # etat de l'agent sur ce poste
rablab-hack-tracker logs        # dernieres lignes du log local
rablab-hack-tracker uninstall   # desinstaller (demande confirmation)
```

## Ce qui est surveille / ce qui ne l'est pas

Voir [DISCLAIMER.txt](DISCLAIMER.txt). En resume : l'agent regarde QUEL programme ouvre les
fichiers d'identifiants de Chrome (pas leur contenu), les demarrages automatiques, les
extensions Chrome recentes, les binaires lances depuis des dossiers temporaires, et les
connexions vers des IP malveillantes connues. Il ne lit ni l'historique, ni les URLs, ni les
fichiers personnels, ni l'ecran/camera/micro.

## Architecture

```
endpoint-agent/
  DISCLAIMER.txt            disclaimer Loi 25 (affiche a l'install)
  requirements.txt
  uninstall-macos.sh
  uninstall-windows.ps1
  src/
    agent.py                boucle principale + CLI (run/install/status/logs/notify-uninstall)
    config.py               config locale + runtime (webhook fetche au runtime)
    device_id.py            identifiant stable derive du serial machine
    heartbeat.py            heartbeat worker (~10 min) + Slack quotidien 9h Eastern
    alert.py                types partages
    detectors/
      cookies_access.py     detection 1
      passwords_access.py   detection 2
      persistence.py        detection 3
      c2_connections.py     detection 4
      suspicious_install.py detection 5
      browser_extensions.py detection 6
      tamper.py             detection 7
      _procutil.py          inspection des processus (hash, signature)
      _credential_access.py logique partagee detections 1 et 2
    ioc/feed_updater.py     telechargement des IoC abuse.ch (toutes les 4h)
    slack/notifier.py       formatage + envoi des alertes
    storage/db.py           SQLite (dedup, iocs, alertes, whitelist)
```

Les detecteurs sont isoles : si l'un plante, l'agent continue (chaque `run_once()` est
encapsule dans un try/except cote boucle principale).

## Test E2E (sur un poste de test uniquement)

```
python tests/simulate_cookie_read.py
```

Ce script lit l'entete du fichier Cookies de Chrome comme le ferait un stealer. Une alerte
🚨 doit arriver dans Slack en quelques secondes. Le script n'exfiltre rien.

## Notes

- Sur macOS, certaines lectures (signatures, processus) sont best-effort selon les permissions;
  l'agent ne plante jamais sur un acces refuse.
- Le webhook Slack n'est jamais stocke dans le repo : il est recupere du worker au demarrage et
  rafraichi toutes les heures (rotation centralisee possible par l'admin).
