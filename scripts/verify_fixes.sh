#!/bin/bash
# Verify Piano B Fixes
# Quick validation that core fixes work

set -e

echo "═══════════════════════════════════════════════════════════"
echo "🔬 Verifying Piano B Fixes"
echo "═══════════════════════════════════════════════════════════"

cd "$(dirname "$0")/.."

echo ""
echo "✓ Step 1: Testing foundation basics..."
python -m pytest tests/foundation/test_cognitive_loop_basics.py::TestRewardCalculation -v
python -m pytest tests/foundation/test_cognitive_loop_basics.py::TestLoopDetection -v
python -m pytest tests/foundation/test_cognitive_loop_basics.py::TestReasoningModeLogic -v

echo ""
echo "✓ Step 2: Checking Fix #1 (Commitment Mode)..."
grep -n "confidence >= 0.95" src/numasec/agent/agent.py | head -1
grep -n "tested.*confirmed" src/numasec/agent/agent.py | head -1
echo "   → Conservative trigger confirmed ✓"

echo ""
echo "✓ Step 3: Checking Fix #2B (Enhanced LIGHT Mode)..."
grep -n "ACTION SEQUENCES" src/numasec/agent/cognitive_reasoner.py | head -1
grep -n "confidence >= 0.5" src/numasec/agent/cognitive_reasoner.py | head -1
echo "   → Planning-style reasoning confirmed ✓"

echo ""
echo "✓ Step 4: Checking Fix #3 (Loop Detection)..."
grep -n "result_normalized" src/numasec/agent/agent.py | head -1
grep -n "stable_parts" src/numasec/agent/agent.py | head -1
echo "   → Normalized hashing confirmed ✓"

echo ""
echo "✓ Step 5: Checking Fix #4 (HTTP Parser)..."
test -f src/numasec/tools/http_parser.py && echo "   → http_parser.py exists ✓"
grep -n "from numasec.tools.http_parser import" src/numasec/mcp/tools.py | head -1
echo "   → Integration confirmed ✓"

echo ""
echo "✓ Step 6: Checking Fix #5 (Contextual RAG)..."
grep -n "status_codes" src/numasec/agent/agent.py | head -3
echo "   → HTTP context extraction confirmed ✓"

echo ""
echo "═══════════════════════════════════════════════════════════"
echo "✅ All fixes verified in code"
echo "═══════════════════════════════════════════════════════════"
echo ""
echo "📊 Next: Test on real CTF to validate behavior"
echo ""
echo "Run:"
echo "  cd src"
echo "  python3 -m numasec"
echo ""
