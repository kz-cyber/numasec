#!/bin/bash
# NumaSec Container Runner - Production Usage
# Handles common scenarios with proper volume mounts

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
IMAGE_NAME="numasec:latest"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

print_header() {
    echo -e "${BLUE}╔══════════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${BLUE}║${NC}  ${GREEN}NumaSec - Container Runner${NC}                        ${BLUE}║${NC}"
    echo -e "${BLUE}╚══════════════════════════════════════════════════════════════════╝${NC}"
    echo
}

usage() {
    cat << EOF
${GREEN}Usage:${NC}
  $0 build                    Build the container image
  $0 run [args]               Run NumaSec interactively
  $0 shell                    Open bash shell in container
  $0 mcp [--stdio]            Run MCP server (for Claude Desktop)
  $0 test                     Run tests inside container
  $0 clean                    Remove container image

${YELLOW}Examples:${NC}
  $0 build                          # Build image
  $0 run                            # Start interactive session
  $0 run /assess localhost:3000     # Run assessment
  $0 shell                          # Debug inside container
  $0 mcp --stdio                    # MCP server for Claude

${BLUE}Volume Mounts:${NC}
  ~/.numasec          -> /root/.numasec     (persistence)
  ~/.env                -> /root/.env           (API keys)
  $(pwd)/knowledge     -> /app/knowledge        (dev only)

${YELLOW}Network:${NC}
  --network host        Allows access to localhost targets

EOF
}

check_runtime() {
    if command -v podman &> /dev/null; then
        CONTAINER_CMD="podman"
    elif command -v docker &> /dev/null; then
        CONTAINER_CMD="docker"
    else
        echo -e "${RED}ERROR: Neither podman nor docker found${NC}"
        echo "Install podman: sudo apt install podman"
        exit 1
    fi
}

build_image() {
    print_header
    echo -e "${YELLOW}Building NumaSec container...${NC}"
    echo
    
    cd "$PROJECT_ROOT"
    
    $CONTAINER_CMD build \
        --tag "$IMAGE_NAME" \
        --file Containerfile \
        .
    
    echo
    echo -e "${GREEN}✅ Build complete: $IMAGE_NAME${NC}"
    echo -e "${BLUE}Run with: $0 run${NC}"
}

run_interactive() {
    check_image
    
    # Prepare volume mounts
    MOUNTS=(
        -v "$HOME/.numasec:/root/.numasec"
    )
    
    # Security: Use --privileged for pentesting tools (nmap, network scanning)
    # This is standard for security containers (same as Kali Linux containers)
    # Alternatives: --cap-add=NET_RAW,NET_ADMIN,NET_BIND_SERVICE (less reliable)
    SECURITY_OPTS=(--privileged)
    
    # Load .env and pass as environment variables
    ENV_FILE=""
    if [ -f "$HOME/.env" ]; then
        ENV_FILE="$HOME/.env"
    elif [ -f "$PROJECT_ROOT/.env" ]; then
        ENV_FILE="$PROJECT_ROOT/.env"
    fi
    
    # Parse .env and export as container environment variables
    if [ -n "$ENV_FILE" ]; then
        while IFS='=' read -r key value; do
            # Skip empty lines and comments
            [[ -z "$key" || "$key" =~ ^#.* ]] && continue
            # Export as environment variable
            MOUNTS+=(-e "${key}=${value}")
        done < "$ENV_FILE"
    fi
    
    # DEV MODE: Mount source code for live editing (NO REBUILD NEEDED)
    # Enable with: DEV_MODE=1 ./scripts/container-run.sh run
    if [ "${DEV_MODE:-}" = "1" ]; then
        MOUNTS+=(-v "$PROJECT_ROOT/src/numasec:/app/src/numasec")
        MOUNTS+=(-v "$PROJECT_ROOT/knowledge:/app/knowledge")
    fi
    
    $CONTAINER_CMD run -it --rm \
        --network host \
        "${SECURITY_OPTS[@]}" \
        "${MOUNTS[@]}" \
        "$IMAGE_NAME" \
        "$@"
}

run_shell() {
    check_image
    
    print_header
    echo -e "${YELLOW}Opening bash shell in container...${NC}"
    echo
    
    $CONTAINER_CMD run -it --rm \
        --network host \
        -v "$HOME/.numasec:/root/.numasec" \
        --entrypoint /bin/bash \
        "$IMAGE_NAME"
}

run_mcp_server() {
    check_image
    
    print_header
    echo -e "${YELLOW}Starting MCP server...${NC}"
    echo
    
    $CONTAINER_CMD run -i --rm \
        --network host \
        -v "$HOME/.numasec:/root/.numasec" \
        -v "$HOME/.env:/root/.env" \
        "$IMAGE_NAME" \
        mcp "$@"
}

run_tests() {
    check_image
    
    print_header
    echo -e "${YELLOW}Running tests inside container...${NC}"
    echo
    
    $CONTAINER_CMD run -it --rm \
        -v "$PROJECT_ROOT:/app" \
        "$IMAGE_NAME" \
        bash -c "cd /app && python3 -m pytest tests/ -v"
}

clean_image() {
    echo -e "${YELLOW}Removing NumaSec container image...${NC}"
    $CONTAINER_CMD rmi "$IMAGE_NAME" || true
    echo -e "${GREEN}✅ Cleaned${NC}"
}

check_image() {
    if ! $CONTAINER_CMD image exists "$IMAGE_NAME" 2>/dev/null; then
        echo -e "${RED}ERROR: Image $IMAGE_NAME not found${NC}"
        echo -e "Build it first: ${GREEN}$0 build${NC}"
        exit 1
    fi
}

# Main command dispatcher
check_runtime

case "${1:-}" in
    build)
        build_image
        ;;
    run)
        shift
        run_interactive "$@"
        ;;
    shell|bash)
        run_shell
        ;;
    mcp)
        shift
        run_mcp_server "$@"
        ;;
    test|tests)
        run_tests
        ;;
    clean)
        clean_image
        ;;
    -h|--help|help|"")
        usage
        ;;
    *)
        echo -e "${RED}Unknown command: $1${NC}"
        echo
        usage
        exit 1
        ;;
esac
