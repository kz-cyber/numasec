# ══════════════════════════════════════════════════════════════════════════════
# NumaSec - Production Container
# State of the Art AI Pentester (January 2026)
# ══════════════════════════════════════════════════════════════════════════════
# Build:   podman build -t numasec .
# Run:     podman run -it --network host -v ~/.numasec:/root/.numasec numasec
# MCP:     podman run -i --network host numasec mcp --stdio

FROM kalilinux/kali-rolling

ENV DEBIAN_FRONTEND=noninteractive \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

# ══════════════════════════════════════════════════════════════════════════════
# Stage 1: System + Security Tools (from Kali repos)
# ══════════════════════════════════════════════════════════════════════════════

RUN apt-get update && apt-get install -y --no-install-recommends \
    # Python 3.11+
    python3 \
    python3-pip \
    python3-dev \
    # Build tools (for some Python packages)
    gcc \
    g++ \
    make \
    # System utilities
    curl \
    wget \
    git \
    unzip \
    xz-utils \
    ca-certificates \
    # Network utilities
    iputils-ping \
    net-tools \
    dnsutils \
    netcat-openbsd \
    traceroute \
    # Security tools from Kali
    nmap \
    ffuf \
    sqlmap \
    hydra \
    nikto \
    whatweb \
    seclists \
    wordlists \
    # Forensics/CTF tools
    binwalk \
    foremost \
    steghide \
    stegseek \
    xxd \
    file \
    # OCR and QR/barcode
    tesseract-ocr \
    libzbar0 \
    zbar-tools \
    # Crypto libraries
    libssl-dev \
    libffi-dev \
    # Misc
    php-cli \
    jq \
    && rm -rf /var/lib/apt/lists/*

# ══════════════════════════════════════════════════════════════════════════════
# Stage 2: ProjectDiscovery Tools (Go binaries - latest releases)
# ══════════════════════════════════════════════════════════════════════════════

# nuclei - vulnerability scanner
RUN NUCLEI_VERSION=$(curl -sL https://api.github.com/repos/projectdiscovery/nuclei/releases/latest | grep -Po '"tag_name": "v\K[^"]*') && \
    curl -sL "https://github.com/projectdiscovery/nuclei/releases/latest/download/nuclei_${NUCLEI_VERSION}_linux_amd64.zip" -o /tmp/nuclei.zip && \
    unzip -o /tmp/nuclei.zip -d /tmp/nuclei && \
    mv /tmp/nuclei/nuclei /usr/local/bin/ && \
    chmod +x /usr/local/bin/nuclei && \
    rm -rf /tmp/nuclei*

# httpx - HTTP toolkit
RUN HTTPX_VERSION=$(curl -sL https://api.github.com/repos/projectdiscovery/httpx/releases/latest | grep -Po '"tag_name": "v\K[^"]*') && \
    curl -sL "https://github.com/projectdiscovery/httpx/releases/latest/download/httpx_${HTTPX_VERSION}_linux_amd64.zip" -o /tmp/httpx.zip && \
    unzip -o /tmp/httpx.zip -d /tmp/httpx && \
    mv /tmp/httpx/httpx /usr/local/bin/ && \
    chmod +x /usr/local/bin/httpx && \
    rm -rf /tmp/httpx*

# subfinder - subdomain enumeration
RUN SUBFINDER_VERSION=$(curl -sL https://api.github.com/repos/projectdiscovery/subfinder/releases/latest | grep -Po '"tag_name": "v\K[^"]*') && \
    curl -sL "https://github.com/projectdiscovery/subfinder/releases/latest/download/subfinder_${SUBFINDER_VERSION}_linux_amd64.zip" -o /tmp/subfinder.zip && \
    unzip -o /tmp/subfinder.zip -d /tmp/subfinder && \
    mv /tmp/subfinder/subfinder /usr/local/bin/ && \
    chmod +x /usr/local/bin/subfinder && \
    rm -rf /tmp/subfinder*

# Update nuclei templates (background, don't block build)
RUN nuclei -ut || true

# ══════════════════════════════════════════════════════════════════════════════
# Stage 3: NumaSec Installation
# ══════════════════════════════════════════════════════════════════════════════

WORKDIR /app

# Copy Python project files
COPY pyproject.toml README.md ./
COPY src/ ./src/
COPY knowledge/ ./knowledge/
COPY wordlists/ ./wordlists/

# Install Python dependencies from pyproject.toml
# Force CPU-only PyTorch to avoid 3GB CUDA download
RUN pip3 install --no-cache-dir --break-system-packages \
    torch --index-url https://download.pytorch.org/whl/cpu

# Install dependencies WITHOUT installing numasec package
# This allows volume mounting src/ in dev mode without breaking imports
RUN pip3 install --no-cache-dir --break-system-packages \
    typer>=0.12.0 \
    rich>=13.7.0 \
    prompt-toolkit>=3.0.43 \
    mcp>=1.0.0 \
    anthropic>=0.25.0 \
    openai>=1.30.0 \
    httpx>=0.27.0 \
    lancedb>=0.6.0 \
    sentence-transformers>=2.7.0 \
    sqlalchemy[asyncio]>=2.0.29 \
    aiosqlite>=0.20.0 \
    alembic>=1.13.0 \
    pydantic>=2.7.0 \
    pydantic-settings>=2.2.0 \
    pyyaml>=6.0.0 \
    jinja2>=3.1.3 \
    aiofiles>=23.2.0 \
    python-dateutil>=2.9.0 \
    structlog>=24.1.0 \
    python-docx>=1.1.0 \
    defusedxml>=0.7.1 \
    beautifulsoup4>=4.12.0 \
    dnspython>=2.6.0

# Verify installation
RUN python3 -c "import torch; import anthropic; import mcp; print('Dependencies OK')"

# ══════════════════════════════════════════════════════════════════════════════
# Stage 4: Configuration & Entrypoint
# ══════════════════════════════════════════════════════════════════════════════

# Create data directories
RUN mkdir -p /tmp/numasec/{engagements,knowledge,reports,logs,debug,strategy}

# Set Python path and data directory
ENV PYTHONPATH=/app/src \
    NUMASEC_DATA_DIR=/tmp/numasec

# Entrypoint script for flexible usage
COPY <<'EOF' /entrypoint.sh
#!/bin/bash
set -e

# Ensure PYTHONPATH is set
export PYTHONPATH=/app/src:${PYTHONPATH:-}

# Use /tmp for data in container
export NUMASEC_DATA_DIR=${NUMASEC_DATA_DIR:-/tmp/numasec}
mkdir -p "$NUMASEC_DATA_DIR"/engagements
mkdir -p "$NUMASEC_DATA_DIR"/knowledge
mkdir -p "$NUMASEC_DATA_DIR"/reports
mkdir -p "$NUMASEC_DATA_DIR"/logs
mkdir -p "$NUMASEC_DATA_DIR"/debug
mkdir -p "$NUMASEC_DATA_DIR"/strategy

# If first arg is "mcp", run MCP server
if [ "$1" = "mcp" ]; then
    shift
    exec python3 -m numasec.mcp "$@"
fi

# If first arg is "bash" or "sh", run shell
if [ "$1" = "bash" ] || [ "$1" = "sh" ]; then
    exec "$@"
fi

# Otherwise, run numasec
exec python3 -m numasec "$@"
EOF

RUN chmod +x /entrypoint.sh

ENTRYPOINT ["/entrypoint.sh"]
CMD []
