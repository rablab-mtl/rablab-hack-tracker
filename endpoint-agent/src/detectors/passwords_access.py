"""Detection 2: a non-Chrome process reading the Chrome Login Data file (passwords)."""
from __future__ import annotations


from . import Detector
from ._credential_access import scan_credential_access

WHY = (
    "Le fichier Login Data contient les mots de passe enregistres dans Chrome, dont ceux des "
    "comptes Google Ads. Un process inconnu qui le lit cherche a voler ces identifiants."
)
ACTION = (
    "Debranche ce poste du reseau immediatement et lance un scan antivirus. "
    "Reset ensuite les mots de passe sensibles depuis un autre appareil sain."
)


class PasswordsAccessDetector(Detector):
    name = "passwords_access"
    interval = 5

    def run_once(self):
        return scan_credential_access(
            detector_name=self.name,
            filename="Login Data",
            alert_type="VOL DE MOTS DE PASSE probable",
            why=WHY,
            action=ACTION,
        )
