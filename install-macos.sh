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

# 1. Trouver un Python 3.9+ deja present, SANS declencher l'installeur Xcode.
# On ne teste que des interpreteurs versionnes ou installes (brew / python.org), et 'python3'
# seulement si les Command Line Tools sont deja la. Si rien n'est utilisable, on guide
# l'utilisateur (voir plus bas) plutot que de declencher Xcode et risquer un Python casse.
PYBIN=""
for cand in python3.13 python3.12 python3.11 python3.10 python3.9 \
            /opt/homebrew/bin/python3 /usr/local/bin/python3; do
  if command -v "$cand" >/dev/null 2>&1; then
    ver=$("$cand" -c 'import sys;print("%d.%d"%sys.version_info[:2])' 2>/dev/null || echo "0.0")
    major=${ver%%.*}; minor=${ver##*.}
    if [ "$major" = "3" ] && [ "$minor" -ge 9 ] 2>/dev/null; then PYBIN="$cand"; break; fi
  fi
done

# Si rien trouve mais que les Command Line Tools sont DEJA installes, 'python3' est sur
# (il ne declenchera pas l'installeur Xcode).
if [ -z "$PYBIN" ] && xcode-select -p >/dev/null 2>&1 && command -v python3 >/dev/null 2>&1; then
  ver=$(python3 -c 'import sys;print("%d.%d"%sys.version_info[:2])' 2>/dev/null || echo "0.0")
  major=${ver%%.*}; minor=${ver##*.}
  if [ "$major" = "3" ] && [ "$minor" -ge 9 ] 2>/dev/null; then PYBIN="python3"; fi
fi

# Aucun Python trouve : on en installe un dedie, automatiquement, SANS Xcode et SANS mot de
# passe. On telecharge un build "install_only" relocalisable (le meme type que uv utilise,
# mais sans l'etape install_name_tool qui declenche Xcode). ~25 Mo, curl + tar (integres).
# Il vit hors du dossier d'install (qui est efface/recree a chaque run).
if [ -z "$PYBIN" ] || ! "$PYBIN" --version >/dev/null 2>&1; then
  echo "Aucun Python sur ce Mac : installation auto d'un Python dedie (~25 Mo, sans Xcode, sans mot de passe)..."
  case "$(uname -m)" in
    arm64) PBS="aarch64-apple-darwin" ;;
    *)     PBS="x86_64-apple-darwin" ;;
  esac
  PYHOME="$HOME/Library/Application Support/rablab-python"
  if [ ! -x "$PYHOME/python/bin/python3" ]; then
    URL=$(curl -fsSL https://api.github.com/repos/astral-sh/python-build-standalone/releases/latest \
      | grep -o "https://[^\"]*cpython-3\.12[^\"]*${PBS}-install_only\.tar\.gz" | head -1)
    if [ -n "$URL" ]; then
      mkdir -p "$PYHOME"
      curl -fsSL "$URL" -o "$PYHOME/py.tar.gz" \
        && tar -xzf "$PYHOME/py.tar.gz" -C "$PYHOME" \
        && rm -f "$PYHOME/py.tar.gz"
    fi
  fi
  [ -x "$PYHOME/python/bin/python3" ] && PYBIN="$PYHOME/python/bin/python3"
fi

if [ -z "$PYBIN" ] || ! "$PYBIN" --version >/dev/null 2>&1; then
  echo ""
  echo "L'installation automatique de Python n'a pas pu se faire (connexion ?)."
  echo "C'est simple a regler, 2 minutes :"
  echo "  1. Va sur  https://www.python.org/downloads/macos/"
  echo "  2. Clique le gros bouton 'Download', ouvre le fichier telecharge, suis les etapes."
  echo "  3. Reviens ici et colle EXACTEMENT la meme commande qu'au depart."
  exit 1
fi
echo "Python : $("$PYBIN" --version)"

# 2. Telecharger le code (tarball via curl + tar, sans git : evite le prompt Xcode).
echo "Telechargement du code..."
TARBALL="https://github.com/rablab-mtl/rablab-hack-tracker/archive/refs/heads/main.tar.gz"
TGZ="$(mktemp -d)/rht.tar.gz"
curl -fsSL "$TARBALL" -o "$TGZ" || { echo "Echec du telechargement du code."; exit 1; }
rm -rf "$INSTALL_DIR"
mkdir -p "$INSTALL_DIR"
tar -xzf "$TGZ" -C "$INSTALL_DIR" --strip-components=1
rm -f "$TGZ"

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
