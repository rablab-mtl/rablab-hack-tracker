"""Detection 1: a non-Chrome process reading the Chrome Cookies file."""
from __future__ import annotations


from . import Detector
from ._credential_access import scan_credential_access

WHY = (
    "Les cookies Chrome contiennent les sessions actives sur Google Ads. Un process inconnu "
    "qui les lit est le pattern n1 d'un infostealer qui va exfiltrer ces sessions."
)
ACTION = (
    "Debranche ce poste du reseau IMMEDIATEMENT (couper le wifi), puis lance un scan "
    "(Malwarebytes / Defender). Previens Julien."
)


class CookiesAccessDetector(Detector):
    name = "cookies_access"
    interval = 5  # poll often: infostealers hold the file open only briefly

    def run_once(self):
        return scan_credential_access(
            detector_name=self.name,
            filename="Cookies",
            alert_type="INFOSTEALER probable",
            why=WHY,
            action=ACTION,
        )
