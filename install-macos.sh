#!/bin/bash
# rablab-hack-tracker - installeur macOS.
# Usage : curl -fsSL https://raw.githubusercontent.com/rablab-mtl/rablab-hack-tracker/main/install-macos.sh | bash
set -euo pipefail

REPO_URL="https://github.com/rablab-mtl/rablab-hack-tracker.git"
INSTALL_DIR="$HOME/Library/Application Support/rablab-hack-tracker"
AGENT_DIR="$INSTALL_DIR/endpoint-agent"
VENV="$INSTALL_DIR/.venv"
PLIST="$HOME/Library/LaunchAgents/com.rablab.hacktracker.plist"
BIN_DIR="$HOME/.local/bin"
WORKER_URL="https://rablab-gads-monitor.rablab.workers.dev"

echo "=== rablab-hack-tracker : installation (macOS) ==="

# 1. Trouver un Python 3.11+
PYBIN=""
for cand in python3.13 python3.12 python3.11 python3; do
  if command -v "$cand" >/dev/null 2>&1; then
    ver=$("$cand" -c 'import sys;print("%d.%d"%sys.version_info[:2])' 2>/dev/null || echo "0.0")
    major=${ver%%.*}; minor=${ver##*.}
    if [ "$major" -eq 3 ] && [ "$minor" -ge 11 ]; then PYBIN="$cand"; break; fi
  fi
done
if [ -z "$PYBIN" ]; then
  echo "Python 3.11+ requis. Installe-le puis relance :"
  echo "  - avec Homebrew : brew install python@3.11"
  echo "  - ou via https://www.python.org/downloads/macos/"
  exit 1
fi
echo "Python : $($PYBIN --version)"

# 2. Cloner ou mettre a jour le repo
if [ -d "$AGENT_DIR/.git" ] || [ -d "$INSTALL_DIR/.git" ]; then
  echo "Mise a jour du depot existant..."
  git -C "$INSTALL_DIR" pull --ff-only || true
else
  mkdir -p "$(dirname "$INSTALL_DIR")"
  echo "Clonage du depot..."
  git clone --depth 1 "$REPO_URL" "$INSTALL_DIR"
fi

# 3. venv + dependances
"$PYBIN" -m venv "$VENV"
"$VENV/bin/pip" install -q --upgrade pip
"$VENV/bin/pip" install -q -r "$AGENT_DIR/requirements.txt"

# 4. UNE seule question : email Rablab
echo ""
read -r -p "Quel est ton email Rablab ? (ex : prenom.n@rablab.ca) > " EMAIL </dev/tty
if [ -z "$EMAIL" ]; then echo "Email vide, annulation."; exit 1; fi

# 5. Disclaimer Loi 25
echo ""
cat "$AGENT_DIR/DISCLAIMER.txt"
echo ""
read -r -p "Tu acceptes l'installation ? [O/N] > " CONSENT </dev/tty
case "$CONSENT" in
  [oО][kK]|[oO]|[yY]) : ;;
  *) echo "Installation annulee. Aucun fichier residuel n'est laisse actif."; exit 0 ;;
esac

# 6. Config locale (device label auto-detecte)
DEVICE_LABEL="$(scutil --get ComputerName 2>/dev/null || hostname)"
CONFIG_DIR="$HOME/.config/rablab-hack-tracker"
mkdir -p "$CONFIG_DIR"
cat > "$CONFIG_DIR/config.json" <<JSON
{
  "email": "$EMAIL",
  "device_label": "$DEVICE_LABEL",
  "worker_url": "$WORKER_URL"
}
JSON
chmod 600 "$CONFIG_DIR/config.json"

# 7. Finaliser l'install (fetch config, hash, message Slack d'install)
"$VENV/bin/python" "$AGENT_DIR/src/agent.py" install || true

# 8. CLI rablab-hack-tracker dans le PATH user
mkdir -p "$BIN_DIR"
cat > "$BIN_DIR/rablab-hack-tracker" <<SHIM
#!/bin/bash
INSTALL_DIR="$INSTALL_DIR"
VENV_PY="$VENV/bin/python"
AGENT="$AGENT_DIR/src/agent.py"
case "\${1:-}" in
  uninstall) exec bash "$AGENT_DIR/uninstall-macos.sh" ;;
  status|logs) exec "\$VENV_PY" "\$AGENT" "\$1" ;;
  *) echo "usage: rablab-hack-tracker [status|logs|uninstall]" ;;
esac
SHIM
chmod 755 "$BIN_DIR/rablab-hack-tracker"
case ":$PATH:" in
  *":$BIN_DIR:"*) : ;;
  *) echo "export PATH=\"\$HOME/.local/bin:\$PATH\"" >> "$HOME/.zshrc" ;;
esac

# 9. LaunchAgent (demarre maintenant + au login, redemarre si crash)
mkdir -p "$HOME/Library/LaunchAgents"
cat > "$PLIST" <<PLISTEOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key><string>com.rablab.hacktracker</string>
  <key>ProgramArguments</key>
  <array>
    <string>$VENV/bin/python</string>
    <string>$AGENT_DIR/src/agent.py</string>
    <string>run</string>
  </array>
  <key>RunAtLoad</key><true/>
  <key>KeepAlive</key><true/>
  <key>StandardOutPath</key><string>$CONFIG_DIR/agent.out.log</string>
  <key>StandardErrorPath</key><string>$CONFIG_DIR/agent.err.log</string>
</dict>
</plist>
PLISTEOF

launchctl unload "$PLIST" 2>/dev/null || true
launchctl load "$PLIST"

echo ""
echo "✅ Installation terminee. Tu peux fermer ce Terminal."
echo "   Verifier : rablab-hack-tracker status"
echo "   Desinstaller : rablab-hack-tracker uninstall"
echo "   (Si 'command not found', ouvre un nouveau Terminal pour recharger le PATH.)"
