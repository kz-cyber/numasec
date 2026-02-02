#!/bin/bash
# Check external tool dependencies for NumaSec

echo "🔍 NumaSec - Tool Dependencies Check"
echo "=========================================="
echo ""

TOOLS=(
    "nmap:Nmap port scanner"
    "subfinder:Subdomain enumeration"
    "httpx:HTTP probing"
    "whatweb:Web fingerprinting"
    "ffuf:Web fuzzing"
    "nuclei:Vulnerability scanning"
    "sqlmap:SQL injection"
    "nikto:Web server scanning"
    "hydra:Brute force"
)

AVAILABLE=0
MISSING=0

for tool_info in "${TOOLS[@]}"; do
    tool="${tool_info%%:*}"
    desc="${tool_info#*:}"
    
    if command -v "$tool" &> /dev/null; then
        version=$(command "$tool" --version 2>&1 | head -1 || echo "unknown")
        echo "✅ $tool - $desc"
        echo "   Version: $version"
        ((AVAILABLE++))
    else
        echo "❌ $tool - $desc (NOT FOUND)"
        ((MISSING++))
    fi
    echo ""
done

echo "=========================================="
echo "Summary: $AVAILABLE available, $MISSING missing"
echo ""

if [ $MISSING -gt 0 ]; then
    echo "⚠️  Some tools are missing. NumaSec will work but some"
    echo "   reconnaissance features will be unavailable."
    echo ""
    echo "Install missing tools:"
    echo "  - Arch/Manjaro: yay -S nmap subfinder-bin httpx-bin whatweb ffuf nuclei sqlmap nikto hydra"
    echo "  - Ubuntu/Debian: apt install nmap whatweb nikto hydra + manual install for Go tools"
    echo "  - macOS: brew install nmap whatweb nikto hydra + Go tools"
fi
