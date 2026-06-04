#!/bin/bash
# rablab-hack-tracker - desinstalleur macOS.
# Usage normal : rablab-hack-tracker uninstall
# Usage kill switch (declenche par l'agent) : bash uninstall-macos.sh --kill-switch
set -uo pipefail

INSTALL_DIR="$HOME/Library/Application Support/rablab-hack-tracker"
AGENT_DIR="$INSTALL_DIR/endpoint-agent"
VENV="$INSTALL_DIR/.venv"
PLIST="$HOME/Library/LaunchAgents/com.rablab.hacktracker.plist"
BIN="$HOME/.local/bin/rablab-hack-tracker"
CONFIG_DIR="$HOME/.config/rablab-hack-tracker"

KILL_SWITCH=0
[ "${1:-}" = "--kill-switch" ] && KILL_SWITCH=1

if [ "$KILL_SWITCH" -eq 0 ]; then
  read -r -p "Tu vas desinstaller l'agent rablab-hack-tracker. Sur ? [O/N] > " ans </dev/tty
  case "$ans" in [oO]|[yY]) : ;; *) echo "Annule."; exit 0 ;; esac
  # Message Slack 👋 (le kill switch a deja envoye son propre message 🛑).
  "$VENV/bin/python" "$AGENT_DIR/src/agent.py" notify-uninstall 2>/dev/null || true
fi

# Stop + retrait du LaunchAgent
launchctl unload "$PLIST" 2>/dev/null || true
rm -f "$PLIST"

# Retrait du CLI
rm -f "$BIN"

# Logs : on les garde par defaut (audit), sauf demande explicite.
REMOVE_LOGS=1
if [ "$KILL_SWITCH" -eq 0 ]; then
  read -r -p "Supprimer aussi les logs locaux ? [O/N] (defaut N) > " rl </dev/tty
  case "$rl" in [oO]|[yY]) REMOVE_LOGS=1 ;; *) REMOVE_LOGS=0 ;; esac
fi
if [ "$REMOVE_LOGS" -eq 1 ]; then
  rm -rf "$CONFIG_DIR"
else
  # Garder les logs, retirer seulement les secrets runtime.
  rm -f "$CONFIG_DIR/runtime.json" "$CONFIG_DIR/config.json"
fi

# Retrait du code + venv (le script s'auto-supprime, ok sous Unix une fois lance).
rm -rf "$INSTALL_DIR"
# Python dedie telecharge a l'install (si present) : on le retire aussi.
rm -rf "$HOME/Library/Application Support/rablab-python"

echo "✅ Desinstallation terminee. A plus."
