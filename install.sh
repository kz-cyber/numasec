#!/usr/bin/env bash
# numasec installer
# Usage: curl -fsSL https://numasec.dev/install | bash
# Local:  bash install.sh --local
set -euo pipefail

REPO="FrancescoStabile/numasec"
INSTALL_DIR="${NUMASEC_INSTALL_DIR:-$HOME/.numasec}"
BIN_DIR="${NUMASEC_BIN_DIR:-$HOME/.local/bin}"

# If --local is passed (or script is run from inside the repo), skip cloning
LOCAL_INSTALL=false
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]:-$0}")" 2>/dev/null && pwd || echo '')"
for arg in "$@"; do
  [[ "$arg" == "--local" ]] && LOCAL_INSTALL=true
done
# Auto-detect: if this script lives in a repo that already has the agent/ dir
if [[ -z "${LOCAL_INSTALL+x}" ]] || $LOCAL_INSTALL || [[ -d "$SCRIPT_DIR/agent" ]]; then
  if [[ -d "$SCRIPT_DIR/agent" ]]; then
    LOCAL_INSTALL=true
    LOCAL_SRC="$SCRIPT_DIR"
  fi
fi

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

info()  { echo -e "${CYAN}info${NC}  $*"; }
ok()    { echo -e "${GREEN}ok${NC}    $*"; }
warn()  { echo -e "${YELLOW}warn${NC}  $*"; }
error() { echo -e "${RED}error${NC} $*" >&2; }
die()   { error "$@"; exit 1; }

# ── Detect platform ──────────────────────────────────────────────
detect_platform() {
  local os arch
  os="$(uname -s)"
  arch="$(uname -m)"

  case "$os" in
    Linux*)  PLATFORM="linux" ;;
    Darwin*) PLATFORM="darwin" ;;
    *)       die "Unsupported OS: $os" ;;
  esac

  case "$arch" in
    x86_64|amd64)  ARCH="x64" ;;
    aarch64|arm64) ARCH="arm64" ;;
    *)             die "Unsupported architecture: $arch" ;;
  esac

  info "Platform: ${PLATFORM}-${ARCH}"
}

# ── Check dependencies ───────────────────────────────────────────
check_deps() {
  local missing=()

  if ! command -v curl &>/dev/null && ! command -v wget &>/dev/null; then
    missing+=("curl or wget")
  fi

  if ! command -v git &>/dev/null; then
    missing+=("git")
  fi

  if [[ ${#missing[@]} -gt 0 ]]; then
    die "Missing required tools: ${missing[*]}"
  fi
}

# ── Install Bun (if not present) ─────────────────────────────────
ensure_bun() {
  if command -v bun &>/dev/null; then
    ok "Bun $(bun --version) found"
    return
  fi

  info "Installing Bun..."
  curl -fsSL https://bun.sh/install | bash
  export PATH="$HOME/.bun/bin:$PATH"

  if ! command -v bun &>/dev/null; then
    die "Bun installation failed"
  fi
  ok "Bun installed"
}

# ── Install uv (if not present) ──────────────────────────────────
ensure_uv() {
  if command -v uv &>/dev/null; then
    ok "uv $(uv --version 2>/dev/null || echo 'found') ready"
    return
  fi

  info "Installing uv (Python package manager)..."
  curl -LsSf https://astral.sh/uv/install.sh | sh
  export PATH="$HOME/.local/bin:$PATH"

  if ! command -v uv &>/dev/null; then
    die "uv installation failed"
  fi
  ok "uv installed"
}

# ── Install Python env ───────────────────────────────────────────
setup_python() {
  info "Setting up Python environment..."
  cd "$INSTALL_DIR"

  # Sync Python dependencies
  uv sync 2>&1 | tail -5
  ok "Python environment ready"
}

# ── Install numasec ──────────────────────────────────────────────
install_numasec() {
  info "Installing numasec to $INSTALL_DIR..."

  if $LOCAL_INSTALL && [[ -n "${LOCAL_SRC:-}" ]]; then
    info "Local install mode: using $LOCAL_SRC"
    if [[ "$(realpath "$LOCAL_SRC")" != "$(realpath "$INSTALL_DIR" 2>/dev/null || echo '')" ]]; then
      rm -rf "$INSTALL_DIR"
      ln -sfn "$(realpath "$LOCAL_SRC")" "$INSTALL_DIR"
      info "Symlinked $LOCAL_SRC → $INSTALL_DIR"
    else
      info "Already at install dir, skipping symlink"
    fi
  elif [[ -d "$INSTALL_DIR/.git" ]]; then
    info "Updating existing installation..."
    cd "$INSTALL_DIR"
    git pull --ff-only 2>/dev/null || warn "Could not auto-update, continuing with existing version"
  else
    info "Cloning numasec..."
    git clone --depth 1 "https://github.com/${REPO}.git" "$INSTALL_DIR"
    cd "$INSTALL_DIR"
  fi

  # Install TypeScript dependencies
  info "Installing TypeScript dependencies..."
  cd "$INSTALL_DIR/agent"
  bun install 2>&1 | tail -3
  ok "TypeScript dependencies installed"

  # Build
  info "Building..."
  cd "$INSTALL_DIR/agent"
  bun run build 2>&1 | tail -5 || true
  ok "Build complete"
}

# ── Create launcher script ───────────────────────────────────────
create_launcher() {
  mkdir -p "$BIN_DIR"

  cat > "$BIN_DIR/numasec" << 'LAUNCHER'
#!/usr/bin/env bash
set -euo pipefail
NUMASEC_DIR="${NUMASEC_INSTALL_DIR:-$HOME/.numasec}"
export PATH="$HOME/.bun/bin:$HOME/.local/bin:$PATH"
cd "$NUMASEC_DIR/agent/packages/numasec"
exec bun run ./src/index.ts "$@"
LAUNCHER

  chmod +x "$BIN_DIR/numasec"
  ok "Launcher created at $BIN_DIR/numasec"
}

# ── Post-install ─────────────────────────────────────────────────
post_install() {
  echo ""
  echo -e "${GREEN}╔══════════════════════════════════════════╗${NC}"
  echo -e "${GREEN}║${NC}   numasec installed successfully          ${GREEN}║${NC}"
  echo -e "${GREEN}╚══════════════════════════════════════════╝${NC}"
  echo ""

  # Check if BIN_DIR is in PATH
  if [[ ":$PATH:" != *":$BIN_DIR:"* ]]; then
    warn "$BIN_DIR is not in your PATH"
    echo ""
    echo "  Add this to your shell profile (~/.bashrc, ~/.zshrc, etc.):"
    echo ""
    echo "    export PATH=\"$BIN_DIR:\$PATH\""
    echo ""
  fi

  echo "  Get started:"
  echo ""
  echo "    numasec                     # Start interactive session"
  echo "    numasec --help              # Show all options"
  echo ""
  echo "  Inside numasec:"
  echo ""
  echo "    /target https://example.com # Set a target"
  echo "    /findings                   # View findings"
  echo "    /report html                # Generate report"
  echo ""
}

# ── Main ─────────────────────────────────────────────────────────
main() {
  echo ""
  echo -e "${CYAN}  ░▒▓███████▓▒░${NC}"
  echo -e "${CYAN}  ░▒▓█${NC} numasec ${CYAN}█▓▒░${NC}"
  echo -e "${CYAN}  ░▒▓███████▓▒░${NC}"
  echo ""
  echo "  AI Penetration Testing Agent"
  echo ""

  detect_platform
  check_deps
  ensure_bun
  ensure_uv
  install_numasec
  setup_python
  create_launcher
  post_install
}

main "$@"
