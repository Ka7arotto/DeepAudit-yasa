#!/usr/bin/env bash
# Install the native tools used by app/services/yasa_audit: codegraph (code index: calls,
# inheritance, routes) and ripgrep. They ship in YASA's native tool bundle.
#
#   bash backend/scripts/setup_yasa.sh            # installs into ~/.yasamcp
#   YASA_HOME=/opt/yasa bash backend/scripts/setup_yasa.sh
#
# Supports Linux x86_64, macOS Apple Silicon and macOS Intel.
set -euo pipefail

HOME_DIR="${YASA_HOME:-${YASAMCP_HOME:-$HOME/.yasamcp}}"
case "$(uname -s)-$(uname -m)" in
  Linux-x86_64) PLAT="linux-x86-64" ;;
  Darwin-arm64|Darwin-aarch64) PLAT="darwin-aarch64" ;;
  Darwin-x86_64) PLAT="darwin-x86-64" ;;
  *) echo "unsupported platform: $(uname -s)-$(uname -m) (supported: Linux x86_64, macOS ARM64/x86_64)" >&2; exit 1 ;;
esac
TOOLS="$HOME_DIR/tools"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

mkdir -p "$TOOLS"

if [ ! -x "$TOOLS/$PLAT/codegraph/bin/codegraph" ] || [ ! -x "$TOOLS/$PLAT/ripgrep/rg" ]; then
  echo "downloading native tools (codegraph, ripgrep)..."
  curl -fsSL --retry 2 -o "$WORK/tools.zip" "https://yasa.oss-cn-beijing.aliyuncs.com/$PLAT.zip"
  unzip -q "$WORK/tools.zip" -d "$WORK/tools"
  rm -rf "$TOOLS/$PLAT"
  mv "$WORK/tools/$PLAT" "$TOOLS/$PLAT"
  rm -rf "$TOOLS/$PLAT/yasa"  # the YASA engine ships in the same bundle; nothing here uses it
  find "$TOOLS/$PLAT" -type f \( -name rg -o -path '*/codegraph/bin/codegraph' -o -path '*/codegraph/node' \) \
    -exec chmod u+x {} +
fi

"$TOOLS/$PLAT/codegraph/bin/codegraph" --version >/dev/null || { echo "codegraph does not start" >&2; exit 1; }
"$TOOLS/$PLAT/ripgrep/rg" --version >/dev/null || { echo "ripgrep does not start" >&2; exit 1; }

echo
echo "done: $HOME_DIR ($PLAT)"
if [ "$HOME_DIR" != "$HOME/.yasamcp" ]; then
  echo "non-default location: start the backend with YASA_HOME=$HOME_DIR"
fi
