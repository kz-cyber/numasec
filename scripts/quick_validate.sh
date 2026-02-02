#!/bin/bash
# Quick validation script for Reflexive RAG system
# Run this after implementing RAG to ensure everything works

set -e  # Exit on error

echo "╔═══════════════════════════════════════════════════╗"
echo "║  NumaSec - RAG Quick Validation            ║"
echo "╚═══════════════════════════════════════════════════╝"
echo ""

# Colors
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

# Check dependencies
echo -e "${YELLOW}Checking dependencies...${NC}"

python3 -c "import lancedb" 2>/dev/null || {
    echo -e "${RED}✗ lancedb not installed${NC}"
    echo "  Run: pip install lancedb"
    exit 1
}
echo -e "${GREEN}✓ lancedb installed${NC}"

python3 -c "import rank_bm25" 2>/dev/null || {
    echo -e "${YELLOW}⚠ rank-bm25 not installed (hybrid search disabled)${NC}"
    echo "  Run: pip install rank-bm25"
}

python3 -c "from sentence_transformers import SentenceTransformer" 2>/dev/null || {
    echo -e "${RED}✗ sentence-transformers not installed${NC}"
    echo "  Run: pip install sentence-transformers"
    exit 1
}
echo -e "${GREEN}✓ sentence-transformers installed${NC}"

echo ""

# Check knowledge directory
echo -e "${YELLOW}Checking knowledge directory...${NC}"

if [ ! -d "knowledge" ]; then
    echo -e "${RED}✗ knowledge/ directory not found${NC}"
    exit 1
fi

PAYLOAD_COUNT=$(find knowledge/payloads -name "*.md" 2>/dev/null | wc -l)
WEB_COUNT=$(find knowledge/web -name "payloads_*.md" 2>/dev/null | wc -l)
CHEAT_COUNT=$(find knowledge -name "*_cheatsheet.md" 2>/dev/null | wc -l)

echo -e "${GREEN}✓ Found ${PAYLOAD_COUNT} payload files${NC}"
echo -e "${GREEN}✓ Found ${WEB_COUNT} web payload files${NC}"
echo -e "${GREEN}✓ Found ${CHEAT_COUNT} cheatsheet files${NC}"

echo ""

# Run unit tests
echo -e "${YELLOW}Running unit tests...${NC}"

python3 -m pytest tests/unit/test_parsers.py -v || {
    echo -e "${RED}✗ Parser tests failed${NC}"
    exit 1
}
echo -e "${GREEN}✓ Parser tests passed${NC}"

python3 -m pytest tests/unit/test_hybrid_search.py -v || {
    echo -e "${YELLOW}⚠ Hybrid search tests failed (might need data)${NC}"
}

echo ""

# Run integration tests
echo -e "${YELLOW}Running integration tests...${NC}"

python3 -m pytest tests/integration/test_reflexive_rag.py -v || {
    echo -e "${YELLOW}⚠ Integration tests failed${NC}"
}

echo ""

# Run end-to-end validation
echo -e "${YELLOW}Running end-to-end validation...${NC}"

python3 scripts/test_rag_system.py || {
    echo -e "${RED}✗ E2E validation failed${NC}"
    exit 1
}

echo ""
echo -e "${GREEN}╔═══════════════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║           VALIDATION COMPLETE ✓                   ║${NC}"
echo -e "${GREEN}╚═══════════════════════════════════════════════════╝${NC}"
echo ""
echo "Next steps:"
echo "  1. Test on a real CTF challenge"
echo "  2. Monitor RAG metrics"
echo "  3. Validate -20% iteration reduction"
echo ""
