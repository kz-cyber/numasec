FROM python:3.13-slim AS base

# Disable the runtime transpiler cache by default inside Docker containers.
# On ephemeral containers, the cache is not useful
ARG BUN_RUNTIME_TRANSPILER_CACHE_PATH=0
ENV BUN_RUNTIME_TRANSPILER_CACHE_PATH=${BUN_RUNTIME_TRANSPILER_CACHE_PATH}

RUN apt-get update \
    && apt-get install -y --no-install-recommends ripgrep libgcc-s1 libstdc++6 \
    && rm -rf /var/lib/apt/lists/*

# Install numasec Python package (MCP security scanner backend)
COPY pyproject.toml README.md /tmp/numasec/
COPY numasec/ /tmp/numasec/numasec/
RUN pip install --no-cache-dir "/tmp/numasec[mcp]" \
    && rm -rf /tmp/numasec

# TUI binary connects to Python MCP server via this env var
ENV NUMASEC_PYTHON_PATH=/usr/local/bin/python3

FROM base AS build-amd64
COPY agent/packages/numasec/dist/numasec-linux-x64-baseline/bin/numasec /usr/local/bin/numasec

FROM base AS build-arm64
COPY agent/packages/numasec/dist/numasec-linux-arm64/bin/numasec /usr/local/bin/numasec

ARG TARGETARCH
FROM build-${TARGETARCH}
RUN numasec --version
ENTRYPOINT ["numasec"]
