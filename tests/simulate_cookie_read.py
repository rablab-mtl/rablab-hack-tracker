"""Test E2E (endpoint) : simule le comportement n1 d'un infostealer.

Ce script ouvre et lit le fichier Cookies de Chrome (sans rien exfiltrer), comme le
ferait un voleur de cookies. L'agent rablab-hack-tracker doit alors envoyer une alerte
🚨 dans Slack en quelques secondes (le processus "python" n'est pas sur la whitelist).

Usage :
    python tests/simulate_cookie_read.py [secondes_a_garder_ouvert]

Le script garde le fichier ouvert quelques secondes pour que le detecteur (qui poll
toutes les 5 s) le voie. Il ne modifie ni n'envoie aucune donnee.
"""

from __future__ import annotations

import sys
import time
from pathlib import Path

CANDIDATES = [
    Path.home() / "Library/Application Support/Google/Chrome/Default/Cookies",
    Path.home() / "Library/Application Support/Google/Chrome/Default/Network/Cookies",
    Path.home() / "AppData/Local/Google/Chrome/User Data/Default/Network/Cookies",
]


def main() -> int:
    hold = int(sys.argv[1]) if len(sys.argv) > 1 else 8
    target = next((p for p in CANDIDATES if p.exists()), None)
    if not target:
        print("Aucun fichier Cookies Chrome trouve. Ouvre Chrome au moins une fois, puis relance.")
        return 1
    print(f"Lecture simulee de : {target}")
    with open(target, "rb") as f:
        _ = f.read(4096)  # lit l'entete, comme un stealer qui copie le fichier
        print(f"Fichier ouvert et lu. Maintien {hold}s pour laisser l'agent detecter...")
        time.sleep(hold)
    print("Termine. Verifie le canal Slack : une alerte 🚨 INFOSTEALER probable doit apparaitre.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
