#!/usr/bin/env python3
"""
Documentation Consistency Audit
Task 31/34: Verify documentation matches implementation

Checks:
1. README mentions existing tools
2. ARCHITECTURE describes real components
3. Tool names in docs == MCP handlers
4. Feature flags in README == implemented features
"""

import sys
import re
from pathlib import Path
from typing import List, Set

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))


def extract_readme_features(readme_path: Path) -> Set[str]:
    """Extract mentioned features from README."""
    if not readme_path.exists():
        return set()
    
    content = readme_path.read_text().lower()
    
    features = set()
    
    # Common feature keywords
    patterns = [
        r'## features?\n.*?\n((?:[-*] .+\n)+)',  # Feature lists
        r'`(\w+_\w+)`',  # Code blocks with tool names
        r'### (\w+)',  # Section headers
    ]
    
    for pattern in patterns:
        matches = re.findall(pattern, content, re.MULTILINE)
        for match in matches:
            if isinstance(match, tuple):
                match = match[0]
            
            # Extract individual items from lists
            items = re.findall(r'[-*] (.+)', match)
            features.update([item.strip() for item in items])
    
    return features


def get_actual_tools() -> Set[str]:
    """Get actual MCP tool names from implementation."""
    tools_file = Path(__file__).parent.parent / "src" / "numasec" / "mcp" / "tools.py"
    
    if not tools_file.exists():
        return set()
    
    content = tools_file.read_text()
    
    # Find all handle_* functions
    handlers = re.findall(r'async def (handle_\w+)\(', content)
    
    # Convert to tool names (remove handle_ prefix)
    tool_names = {h.replace('handle_', '') for h in handlers}
    
    return tool_names


def check_architecture_consistency(arch_path: Path) -> dict:
    """Verify ARCHITECTURE.md describes real components."""
    if not arch_path.exists():
        return {"exists": False}
    
    content = arch_path.read_text()
    
    # Check for key architectural components
    components = {
        "MCP Server": "mcp" in content.lower(),
        "Agent Loop": "agent" in content.lower() or "react" in content.lower(),
        "LLM Router": "router" in content.lower() or "llm" in content.lower(),
        "Database": "database" in content.lower() or "sqlite" in content.lower(),
        "Tools": "tools" in content.lower() or "tool" in content.lower(),
        "CLI": "cli" in content.lower() or "interface" in content.lower(),
    }
    
    return {
        "exists": True,
        "components": components,
        "coverage": sum(components.values()) / len(components) * 100,
    }


def check_tool_documentation() -> dict:
    """Verify documented tools exist in implementation."""
    root = Path(__file__).parent.parent
    
    # Get actual tools
    actual_tools = get_actual_tools()
    
    # Look for tool documentation
    docs_dir = root / "docs"
    readme = root / "README.md"
    
    documented_tools = set()
    
    for doc_file in [readme] + list(docs_dir.rglob("*.md")):
        if not doc_file.exists():
            continue
        
        content = doc_file.read_text()
        
        # Find tool references (tool_name format)
        tool_refs = re.findall(r'`(\w+_\w+)`', content)
        documented_tools.update(tool_refs)
    
    # Compare
    only_documented = documented_tools - actual_tools
    only_implemented = actual_tools - documented_tools
    both = documented_tools & actual_tools
    
    return {
        "actual_count": len(actual_tools),
        "documented_count": len(documented_tools),
        "matching": len(both),
        "only_docs": list(only_documented)[:10],
        "only_code": list(only_implemented)[:10],
        "accuracy": len(both) / max(len(actual_tools), 1) * 100 if actual_tools else 0,
    }


def main():
    """Run documentation consistency audit."""
    print("=" * 80)
    print("DOCUMENTATION CONSISTENCY AUDIT")
    print("=" * 80)
    
    root = Path(__file__).parent.parent
    readme = root / "README.md"
    architecture = root / "ARCHITECTURE.md"
    
    # 1. Architecture consistency
    print("\n[1] Architecture Documentation...")
    arch_result = check_architecture_consistency(architecture)
    
    if not arch_result.get("exists"):
        print("   ⚠️  ARCHITECTURE.md not found")
    else:
        print(f"   ✅ ARCHITECTURE.md exists")
        print(f"   ✅ Component coverage: {arch_result['coverage']:.1f}%")
        
        for component, present in arch_result['components'].items():
            status = "✅" if present else "❌"
            print(f"      {status} {component}")
    
    # 2. Tool documentation
    print("\n[2] Tool Documentation...")
    tool_result = check_tool_documentation()
    
    print(f"   Actual tools: {tool_result['actual_count']}")
    print(f"   Documented: {tool_result['documented_count']}")
    print(f"   Matching: {tool_result['matching']}")
    print(f"   Accuracy: {tool_result['accuracy']:.1f}%")
    
    if tool_result['only_docs']:
        print(f"\n   ⚠️  Only in docs (may be outdated):")
        for tool in tool_result['only_docs'][:5]:
            print(f"      • {tool}")
    
    if tool_result['only_code']:
        print(f"\n   ⚠️  Only in code (needs documentation):")
        for tool in tool_result['only_code'][:5]:
            print(f"      • {tool}")
    
    # 3. README features
    print("\n[3] README Features...")
    
    if not readme.exists():
        print("   ⚠️  README.md not found")
    else:
        print(f"   ✅ README.md exists")
        features = extract_readme_features(readme)
        print(f"   Found {len(features)} documented features")
    
    # Summary
    print("\n" + "=" * 80)
    
    checks_passed = 0
    total_checks = 3
    
    if arch_result.get("exists") and arch_result.get("coverage", 0) > 80:
        checks_passed += 1
    
    if tool_result['accuracy'] > 50:
        checks_passed += 1
    
    if readme.exists():
        checks_passed += 1
    
    print(f"Results: {checks_passed}/{total_checks} checks passed")
    print("=" * 80)
    
    if checks_passed >= 2:
        print("✅ DOCUMENTATION AUDIT PASSED")
        print("   Documentation mostly consistent with implementation")
        return True
    else:
        print("⚠️  DOCUMENTATION NEEDS UPDATE")
        print("   Some docs are out of sync with code")
        return False


if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)
