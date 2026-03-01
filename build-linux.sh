#!/usr/bin/env bash
set -euo pipefail

REPO="$(cd "$(dirname "$0")" && pwd)"
BUILD="$REPO/build"
BIN="lancer-sqlmap"

echo "================================================"
echo "  lancer-sqlmap Build"
echo "================================================"
echo ""
echo "  Repo   : $REPO"
echo "  Output : $BUILD/$BIN"
echo ""

echo "[1/2] Building release binary (workspace member: lancer-sqlmap)..."
cargo build --release -p lancer-sqlmap

echo "[2/2] Copying to build/..."
mkdir -p "$BUILD"
cp "$REPO/target/release/$BIN" "$BUILD/"

echo ""
echo "================================================"
echo "  Done!  Binary ready: $BUILD/$BIN"
echo "================================================"

# Optional: --install installs a .desktop entry on Linux.
if [ "${1:-}" = "--install" ]; then
    if command -v desktop-file-install >/dev/null 2>&1; then
        DESKTOP="$HOME/.local/share/applications/lancer-sqlmap.desktop"
        cat >"$DESKTOP" <<DESK
[Desktop Entry]
Type=Application
Name=lancer-sqlmap
Comment=Rust clone of sqlmap (Lancer)
Exec=$BUILD/$BIN
Terminal=false
Categories=Development;Security;
DESK
        echo "Installed desktop entry → $DESKTOP"
    fi
fi
