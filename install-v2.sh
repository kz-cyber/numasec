#!/usr/bin/env bash
set -euo pipefail

# numasec v2 installer (local source)
# - builds current source
# - installs side-by-side as numasec-v2 (default)
# - runs smoke checks
# - optional: runs targeted v2 validation tests

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

info() { echo -e "${CYAN}▸${NC} $*"; }
ok() { echo -e "${GREEN}✓${NC} $*"; }
warn() { echo -e "${YELLOW}!${NC} $*"; }
fail() { echo -e "${RED}✗${NC} $*"; exit 1; }

usage() {
  cat <<EOF
Usage: bash install-v2.sh [options]

Options:
  --validate             Run typecheck + targeted v2 test suite
  --install-dir <path>   Installation dir (default: \$HOME/.bun/bin if present, else \$HOME/.local/bin)
  --bin-name <name>      Installed binary name (default: numasec-v2)
  --link-default         Also symlink as <install-dir>/numasec
  -h, --help             Show this help

Examples:
  bash install-v2.sh
  bash install-v2.sh --validate
  bash install-v2.sh --install-dir /usr/local/bin --bin-name numasec-v2
EOF
}

REPO_ROOT="$(cd "$(dirname "$0")" && pwd)"
AGENT_DIR="$REPO_ROOT/agent"
PKG_DIR="$AGENT_DIR/packages/numasec"
DEFAULT_INSTALL_DIR="$HOME/.local/bin"
if [[ -d "$HOME/.bun/bin" ]]; then
  DEFAULT_INSTALL_DIR="$HOME/.bun/bin"
fi
INSTALL_DIR="${NUMASEC_INSTALL_DIR:-$DEFAULT_INSTALL_DIR}"
BIN_NAME="${NUMASEC_BIN_NAME:-numasec-v2}"
RUN_VALIDATE=0
LINK_DEFAULT=0

while [[ $# -gt 0 ]]; do
  case "$1" in
  --validate)
    RUN_VALIDATE=1
    shift
    ;;
  --install-dir)
    [[ $# -ge 2 ]] || fail "--install-dir requires a value"
    INSTALL_DIR="$2"
    shift 2
    ;;
  --bin-name)
    [[ $# -ge 2 ]] || fail "--bin-name requires a value"
    BIN_NAME="$2"
    shift 2
    ;;
  --link-default)
    LINK_DEFAULT=1
    shift
    ;;
  -h | --help)
    usage
    exit 0
    ;;
  *)
    fail "Unknown option: $1"
    ;;
  esac
done

command -v bun >/dev/null 2>&1 || fail "bun is required. Install via https://bun.sh"
command -v git >/dev/null 2>&1 || fail "git is required"

[[ -d "$AGENT_DIR" ]] || fail "agent/ directory not found at $AGENT_DIR"

cd "$REPO_ROOT"
BRANCH="$(git --no-pager branch --show-current 2>/dev/null || true)"
if [[ "$BRANCH" != "release-1.0.5" ]]; then
  warn "Current branch is '$BRANCH' (expected 'release-1.0.5' for this migration build)."
else
  ok "On branch release-1.0.5"
fi

info "Installing dependencies..."
cd "$AGENT_DIR"
bun install --frozen-lockfile 2>/dev/null || bun install
ok "Dependencies installed"

if [[ "$RUN_VALIDATE" -eq 1 ]]; then
  info "Running typecheck..."
  bun run typecheck
  ok "Typecheck passed"

  info "Running targeted v2 validation tests..."
  cd "$PKG_DIR"
  bun test --timeout 30000 \
    test/security/primitive-tools.test.ts \
    test/security/legacy-wrappers.test.ts \
    test/security/planner-policy.test.ts \
    test/security/plan-next.test.ts \
    test/security/report-projection.test.ts \
    test/server/security-read-model.test.ts \
    test/command/taxonomy.test.ts \
    test/command/resolve.test.ts \
    test/permission/approval.test.ts \
    test/cli/tui/security-view-model.test.ts \
    test/cli/tui/sync-pagination.test.ts
  ok "Targeted v2 tests passed"
fi

info "Building numasec binary..."
cd "$AGENT_DIR"
bun run build
ok "Build complete"

PLATFORM="$(uname -s | tr '[:upper:]' '[:lower:]')"
ARCH="$(uname -m)"
case "$ARCH" in
x86_64) ARCH="x64" ;;
aarch64) ARCH="arm64" ;;
esac

DIST_NAME="numasec-${PLATFORM}-${ARCH}"
BINARY="$PKG_DIR/dist/${DIST_NAME}/bin/numasec"
if [[ ! -f "$BINARY" ]]; then
  BINARY="$PKG_DIR/dist/${DIST_NAME}-baseline/bin/numasec"
fi

[[ -f "$BINARY" ]] || fail "No built binary found for ${PLATFORM}-${ARCH}"
ok "Built binary: $BINARY"

mkdir -p "$INSTALL_DIR"
ln -sf "$BINARY" "$INSTALL_DIR/$BIN_NAME"
ok "Installed: $INSTALL_DIR/$BIN_NAME"

if [[ "$LINK_DEFAULT" -eq 1 ]]; then
  ln -sf "$BINARY" "$INSTALL_DIR/numasec"
  ok "Linked default alias: $INSTALL_DIR/numasec"
fi

info "Running smoke checks..."
VERSION="$("$INSTALL_DIR/$BIN_NAME" --version 2>/dev/null || true)"
[[ -n "$VERSION" ]] || fail "Smoke check failed: --version returned empty output"
ok "Version: $VERSION"

HELP_LINE="$("$INSTALL_DIR/$BIN_NAME" --help 2>/dev/null | head -n 1 || true)"
if [[ -n "$HELP_LINE" ]]; then
  ok "Help check passed"
else
  warn "Help output not available (continuing)"
fi

echo ""
echo -e "${BOLD}${GREEN}numasec v2 installed successfully${NC}"
echo -e "Run with: ${CYAN}$INSTALL_DIR/$BIN_NAME${NC}"
if [[ "$LINK_DEFAULT" -eq 0 ]]; then
  echo -e "Optional default alias: ${CYAN}bash install-v2.sh --link-default${NC}"
fi

RESOLVED_NUMASEC="$(command -v numasec 2>/dev/null || true)"
if [[ "$LINK_DEFAULT" -eq 1 ]]; then
  if [[ "$RESOLVED_NUMASEC" != "$INSTALL_DIR/numasec" ]]; then
    echo ""
    warn "numasec currently resolves to: $RESOLVED_NUMASEC"
    warn "Your PATH is picking another installation first."
    echo -e "Put ${CYAN}$INSTALL_DIR${NC} before other entries in PATH, for example:"
    echo -e "  ${CYAN}export PATH=\"$INSTALL_DIR:\$PATH\"${NC}"
  else
    ok "Default numasec command now points to this v2 build"
  fi
  echo -e "If your current shell still executes an old cached path, run: ${CYAN}hash -r${NC}"
fi
