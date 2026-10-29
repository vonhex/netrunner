#!/usr/bin/env bash
# Install NETRUNNER//OS for the current user: a private venv, the `netrunner` command,
# and an Omarchy/XDG launcher entry with its icon. Safe to run again to update.
set -euo pipefail
cd "$(dirname "$0")"
REPO="$PWD"
BIN="$HOME/.local/bin"
APPS="$HOME/.local/share/applications"
ICONS="$HOME/.local/share/icons/hicolor/scalable/apps"

echo "▸ environment"
if command -v uv >/dev/null 2>&1; then
    [ -x .venv/bin/python ] || uv venv .venv
    uv pip install --python .venv/bin/python -q -e .
else
    [ -x .venv/bin/python ] || python3 -m venv .venv
    .venv/bin/pip install -q -e .
fi

echo "▸ command: $BIN/netrunner"
mkdir -p "$BIN" "$APPS" "$ICONS"
ln -sf "$REPO/.venv/bin/netrunner" "$BIN/netrunner"

echo "▸ launcher + icon"
install -m 644 assets/icon.svg "$ICONS/netrunner.svg"
if command -v xdg-terminal-exec >/dev/null 2>&1; then
    EXEC="xdg-terminal-exec --app-id=TUI.tile -e $BIN/netrunner"   # Omarchy: opens tiled
    TERMINAL=false
else
    EXEC="$BIN/netrunner"
    TERMINAL=true
fi
cat > "$APPS/NETRUNNER.desktop" <<DESKTOP
[Desktop Entry]
Type=Application
Name=NETRUNNER
GenericName=Netrunner suite
Comment=Cyberpunk 2077-style network and system console
Exec=$EXEC
Icon=netrunner
Terminal=$TERMINAL
Categories=System;Network;Monitor;
DESKTOP
command -v update-desktop-database >/dev/null 2>&1 && update-desktop-database -q "$APPS" || true

case ":$PATH:" in *":$BIN:"*) ;; *) echo "note: add $BIN to your PATH to type 'netrunner' anywhere";; esac
echo "done — run 'netrunner', or find NETRUNNER in your app launcher"
