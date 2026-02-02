# Installation Guide

Complete installation instructions for NumaSec.

---

## Quick Start (2 minutes)

```bash
# 1. Install (CPU-optimized)
pip install torch --index-url https://download.pytorch.org/whl/cpu
pip install numasec

# 2. Configure
export DEEPSEEK_API_KEY="sk-..."  # Get from platform.deepseek.com

# 3. Run
numasec
```

**That's it.** NumaSec is ready to use.

---

## System Requirements

| Component | Requirement |
|-----------|-------------|
| **Python** | 3.11+ |
| **RAM** | 2GB minimum (4GB recommended) |
| **Disk** | 500MB for Python packages + 100MB for data |
| **OS** | Linux, macOS, Windows (WSL2) |
| **Network** | Internet access for LLM API |

---

## Installation Methods

### Method 1: PyPI (Recommended)

Standard installation for most users:

```bash
# Step 1: Install CPU-only PyTorch (avoids 3.7GB CUDA download)
pip install torch --index-url https://download.pytorch.org/whl/cpu

# Step 2: Install NumaSec
pip install numasec

# Verify installation
numasec --version
```

### Method 2: From Source (Development)

For contributors or latest features:

```bash
# Clone repository
git clone https://github.com/fstabile/numasec.git
cd numasec

# Install CPU-only PyTorch first
pip install torch --index-url https://download.pytorch.org/whl/cpu

# Install in editable mode with dev dependencies
pip install -e ".[dev]"

# Run tests
pytest
```

### Method 3: Container (Isolated Environment)

For pre-configured environment with security tools:

```bash
# Build container
podman build -t numasec .

# Run interactive mode
podman run -it --network host \
  -v ~/.numasec:/root/.numasec \
  -e DEEPSEEK_API_KEY="$DEEPSEEK_API_KEY" \
  numasec

# Run MCP server mode
podman run -i --network host \
  -v ~/.numasec:/root/.numasec \
  -e DEEPSEEK_API_KEY="$DEEPSEEK_API_KEY" \
  numasec mcp --stdio
```

---

## Configuration

### 1. API Keys (Required)

NumaSec requires an LLM provider. Choose one:

**DeepSeek (Recommended - $0.12/test average)**
```bash
export DEEPSEEK_API_KEY="sk-..."
# Get key: https://platform.deepseek.com
```

**Anthropic Claude (Alternative)**
```bash
export ANTHROPIC_API_KEY="sk-ant-..."
# Get key: https://console.anthropic.com
```

**OpenAI GPT-4 (Alternative)**
```bash
export OPENAI_API_KEY="sk-..."
# Get key: https://platform.openai.com
```

**Ollama (Local/Offline)**
```bash
# Install Ollama: https://ollama.com
ollama pull llama3.3
export NUMASEC_LLM__PRIMARY_PROVIDER=local
```

### 2. Optional Security Tools

NumaSec works without external tools, but reconnaissance capabilities are enhanced with:

**Linux (Debian/Ubuntu)**
```bash
sudo apt update && sudo apt install -y \
  nmap sqlmap hydra nikto whatweb
```

**Linux (Arch/Manjaro)**
```bash
sudo pacman -S nmap sqlmap hydra nikto
yay -S subfinder-bin httpx-bin ffuf nuclei
```

**macOS**
```bash
brew install nmap sqlmap hydra nikto whatweb
# Go tools:
brew install subfinder httpx ffuf nuclei
```

**Check Installation**
```bash
bash scripts/check_tool_dependencies.sh
```

### 3. Configuration File (Optional)

Generate default config:

```bash
numasec --init-config
```

Edit `~/.numasec/config.yaml`:

```yaml
llm:
  primary_provider: deepseek
  deepseek_model: deepseek-chat
  max_tokens: 4096
  temperature: 0.7

approval:
  default_mode: supervised  # supervised, semi_auto, or autonomous
  timeout_seconds: 300

reporting:
  default_template: ptes
  output_dir: ~/.numasec/reports
  include_evidence: true

logging:
  level: INFO
  format: json
```

---

## Verification

Test your installation:

```bash
# Check version
numasec --version

# Check configuration
numasec --check-config

# Run system diagnostics
numasec --diagnose

# Test with a simple query
numasec
> what tools are available?
```

---

## Approval Modes

NumaSec requires approval for actions. Choose your mode:

| Mode | Description | Use Case |
|------|-------------|----------|
| `supervised` | Approve every action | Production targets, learning |
| `semi_auto` | Auto-approve LOW risk only | Experienced users |
| `autonomous` | No approval needed | **Training labs only** |

```bash
# Set mode at runtime
numasec --approval-mode supervised

# Or in config.yaml
approval:
  default_mode: supervised
```

**WARNING:** `autonomous` mode should ONLY be used in isolated training environments.

---

## Troubleshooting

### PyTorch Installation Fails

**Problem:** `pip install numasec` downloads 3.7GB of CUDA dependencies.

**Solution:** Install CPU-only PyTorch first:
```bash
pip install torch --index-url https://download.pytorch.org/whl/cpu
pip install numasec
```

### API Key Not Found

**Problem:** `Error: No LLM provider API key found`

**Solution:** Set environment variable:
```bash
export DEEPSEEK_API_KEY="sk-..."
# Make permanent: echo 'export DEEPSEEK_API_KEY="sk-..."' >> ~/.bashrc
```

### Permission Denied on Tools

**Problem:** `nmap: permission denied`

**Solution:** Tools like `nmap` require root for some features:
```bash
# Option 1: Run specific scans with sudo (safest)
numasec --approval-mode supervised  # Approve sudo commands manually

# Option 2: Grant capabilities (Linux only)
sudo setcap cap_net_raw,cap_net_admin=eip $(which nmap)
```

### Import Error: No module named 'numasec'

**Problem:** Installation path not in Python path.

**Solution:**
```bash
# Check Python version
python --version  # Must be 3.11+

# Verify pip is for correct Python
pip --version

# Reinstall with correct pip
python3.11 -m pip install numasec
```

### Knowledge Base Errors

**Problem:** `LanceDB error: table not found`

**Solution:** Rebuild knowledge base:
```bash
rm -rf ~/.numasec/knowledge
numasec  # Will rebuild automatically on first run
```

---

## Updating

### PyPI Installation
```bash
pip install --upgrade numasec
```

### Source Installation
```bash
cd numasec
git pull
pip install -e ".[dev]"
```

### Container
```bash
podman pull ghcr.io/fstabile/numasec:latest
# Or rebuild:
podman build -t numasec .
```

---

## Uninstallation

```bash
# Remove package
pip uninstall numasec

# Remove data (optional)
rm -rf ~/.numasec
```

---

## Environment Variables Reference

| Variable | Description | Default |
|----------|-------------|---------|
| `DEEPSEEK_API_KEY` | DeepSeek API key | None |
| `ANTHROPIC_API_KEY` | Anthropic Claude API key | None |
| `OPENAI_API_KEY` | OpenAI GPT-4 API key | None |
| `NUMASEC_DATA_DIR` | Base directory for data | `~/.numasec` |
| `NUMASEC_LLM__PRIMARY_PROVIDER` | LLM provider | `deepseek` |
| `NUMASEC_LLM__MAX_TOKENS` | Max tokens per request | `4096` |
| `NUMASEC_LLM__TEMPERATURE` | LLM temperature | `0.7` |
| `NUMASEC_APPROVAL__DEFAULT_MODE` | Approval mode | `supervised` |
| `NUMASEC_LOGGING__LEVEL` | Log level | `INFO` |

**Nested Config:** Use double underscore (`__`) for nested settings:
```bash
export NUMASEC_LLM__DEEPSEEK_MODEL="deepseek-chat"
export NUMASEC_CACHE__ENABLED="false"
```

---

## Next Steps

1. **Read the Quickstart**: [README.md](README.md#-quick-start)
2. **Understand Architecture**: [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md)
3. **Run Your First Test**: `numasec` → `scan localhost:8080`
4. **Configure Advanced Settings**: `~/.numasec/config.yaml`
5. **Join Community**: [GitHub Discussions](https://github.com/fstabile/numasec/discussions)

---

## Support

- 📖 **Documentation**: [README.md](README.md)
- 🐛 **Bug Reports**: [GitHub Issues](https://github.com/fstabile/numasec/issues)
- 💬 **Questions**: [GitHub Discussions](https://github.com/fstabile/numasec/discussions)
- 🔒 **Security**: [SECURITY.md](SECURITY.md)
