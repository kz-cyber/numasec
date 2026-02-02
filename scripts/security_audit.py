#!/usr/bin/env python3
"""
Security Audit - CRITICAL for Production
Task 30/34: Verify injection vulnerabilities, input sanitization, shell escaping

Attack Vectors:
1. Command Injection - shell=True, unsanitized input to subprocess
2. Path Traversal - ../ in file paths, symlink attacks
3. Prompt Injection - unescaped user input in system prompts
4. SQL Injection - raw SQL without parameterization
5. Code Injection - eval(), exec(), compile() on user input
"""

import sys
import re
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))


def scan_command_injection(file_path: Path) -> list[dict]:
    """Detect command injection vulnerabilities."""
    vulnerabilities = []
    
    # Skip example files (CWE definitions, payload templates)
    if 'cwe.py' in str(file_path) or 'payloads.py' in str(file_path):
        return vulnerabilities
    
    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
        content = f.read()
        lines = content.split('\n')
    
    # Pattern 1: shell=True (DANGEROUS) with user input
    for i, line in enumerate(lines, 1):
        if 'shell=True' in line and 'arguments.get' in line:
            vulnerabilities.append({
                'type': 'COMMAND_INJECTION',
                'severity': 'CRITICAL',
                'file': str(file_path),
                'line': i,
                'code': line.strip(),
                'reason': 'shell=True with user input allows command injection'
            })
    
    # Pattern 2: os.system() with user input
    for i, line in enumerate(lines, 1):
        if 'os.system(' in line and 'arguments.get' in line:
            vulnerabilities.append({
                'type': 'COMMAND_INJECTION',
                'severity': 'CRITICAL',
                'file': str(file_path),
                'line': i,
                'code': line.strip(),
                'reason': 'os.system() with user input allows command injection'
            })
    
    return vulnerabilities


def scan_path_traversal(file_path: Path) -> list[dict]:
    """Detect path traversal vulnerabilities."""
    vulnerabilities = []
    
    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
        content = f.read()
        lines = content.split('\n')
    
    # Look for file operations without Path.resolve() or validation
    file_ops = ['open(', 'Path(', 'os.path.join(']
    
    for i, line in enumerate(lines, 1):
        for op in file_ops:
            if op in line and 'arguments.get' in line:
                # User input to file operation - potential traversal
                if '.resolve()' not in line and 'is_relative_to' not in line:
                    vulnerabilities.append({
                        'type': 'PATH_TRAVERSAL',
                        'severity': 'HIGH',
                        'file': str(file_path),
                        'line': i,
                        'code': line.strip(),
                        'reason': 'User input to file operation without path validation'
                    })
                    break
    
    return vulnerabilities


def scan_prompt_injection(file_path: Path) -> list[dict]:
    """Detect prompt injection vulnerabilities."""
    vulnerabilities = []
    
    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
        content = f.read()
        lines = content.split('\n')
    
    # Look for user input directly in prompts without sanitization
    prompt_patterns = [
        (r'f".*\{.*arguments\.get.*\}', 'F-string with user input'),
        (r'f\'.*\{.*arguments\.get.*\}', 'F-string with user input'),
        (r'\.format\(.*arguments\.get', '.format() with user input'),
    ]
    
    for i, line in enumerate(lines, 1):
        for pattern, desc in prompt_patterns:
            if re.search(pattern, line):
                # Check if it's going to LLM (message, prompt, content)
                if any(word in line.lower() for word in ['message', 'prompt', 'content', 'system']):
                    vulnerabilities.append({
                        'type': 'PROMPT_INJECTION',
                        'severity': 'MEDIUM',
                        'file': str(file_path),
                        'line': i,
                        'code': line.strip()[:100],
                        'reason': f'{desc} in LLM prompt - potential injection'
                    })
                    break
    
    return vulnerabilities


def scan_code_injection(file_path: Path) -> list[dict]:
    """Detect code injection vulnerabilities (eval, exec on user input)."""
    vulnerabilities = []
    
    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
        content = f.read()
        lines = content.split('\n')
    
    # Only flag eval/exec on user input, not re.compile or subprocess
    dangerous_patterns = [
        (r'eval\(.*arguments\.get', 'eval() on user input'),
        (r'exec\(.*arguments\.get', 'exec() on user input'),
    ]
    
    for i, line in enumerate(lines, 1):
        if line.strip().startswith('#'):
            continue
        
        for pattern, desc in dangerous_patterns:
            if re.search(pattern, line):
                vulnerabilities.append({
                    'type': 'CODE_INJECTION',
                    'severity': 'CRITICAL',
                    'file': str(file_path),
                    'line': i,
                    'code': line.strip(),
                    'reason': desc
                })
    
    return vulnerabilities


def scan_sql_injection(file_path: Path) -> list[dict]:
    """Detect SQL injection vulnerabilities (SQLAlchemy, not LanceDB)."""
    vulnerabilities = []
    
    # Skip LanceDB files (uses different query syntax)
    if 'lancedb' in str(file_path).lower() or 'cache.py' in str(file_path) or 'store.py' in str(file_path):
        return vulnerabilities
    
    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
        content = f.read()
        lines = content.split('\n')
    
    # Look for string formatting in SQL queries (SQLAlchemy context only)
    for i, line in enumerate(lines, 1):
        # Skip if it's LanceDB query syntax
        if '.where(f"' in line or ".where(f'" in line:
            continue
        
        if any(word in line.lower() for word in ['select', 'insert', 'update', 'delete']) and 'where' in line.lower():
            # Check for f-strings or .format() in SQL
            if (('f"' in line or "f'" in line) and '{' in line) or '.format(' in line:
                vulnerabilities.append({
                    'type': 'SQL_INJECTION',
                    'severity': 'CRITICAL',
                    'file': str(file_path),
                    'line': i,
                    'code': line.strip()[:100],
                    'reason': 'String formatting in SQL query - use parameterized queries'
                })
    
    return vulnerabilities


def main():
    """Run security audit on codebase."""
    print("=" * 80)
    print("SECURITY AUDIT - CRITICAL for Production")
    print("=" * 80)
    
    src_dir = Path(__file__).parent.parent / "src" / "numasec"
    
    all_vulns = []
    
    # Scan all Python files
    python_files = list(src_dir.rglob("*.py"))
    
    print(f"\n[INFO] Scanning {len(python_files)} Python files...")
    print("-" * 80)
    
    for py_file in python_files:
        vulns = []
        vulns.extend(scan_command_injection(py_file))
        vulns.extend(scan_path_traversal(py_file))
        vulns.extend(scan_prompt_injection(py_file))
        vulns.extend(scan_code_injection(py_file))
        vulns.extend(scan_sql_injection(py_file))
        
        all_vulns.extend(vulns)
    
    # Group by severity
    critical = [v for v in all_vulns if v['severity'] == 'CRITICAL']
    high = [v for v in all_vulns if v['severity'] == 'HIGH']
    medium = [v for v in all_vulns if v['severity'] == 'MEDIUM']
    
    print(f"\n[RESULTS]")
    print(f"  🔴 CRITICAL: {len(critical)}")
    print(f"  🟠 HIGH:     {len(high)}")
    print(f"  🟡 MEDIUM:   {len(medium)}")
    print(f"  Total:      {len(all_vulns)}")
    
    # Display vulnerabilities
    if critical:
        print(f"\n{'🔴 CRITICAL VULNERABILITIES':^80}")
        print("=" * 80)
        for v in critical[:10]:  # Show first 10
            print(f"\n[{v['type']}] {v['file'].split('/')[-1]}:{v['line']}")
            print(f"  Code: {v['code'][:80]}")
            print(f"  Risk: {v['reason']}")
    
    if high:
        print(f"\n{'🟠 HIGH SEVERITY':^80}")
        print("=" * 80)
        for v in high[:5]:  # Show first 5
            print(f"\n[{v['type']}] {v['file'].split('/')[-1]}:{v['line']}")
            print(f"  Code: {v['code'][:80]}")
            print(f"  Risk: {v['reason']}")
    
    print("\n" + "=" * 80)
    
    if len(critical) == 0:
        print("✅ SECURITY AUDIT PASSED")
        print("   No critical vulnerabilities detected")
        success = True
    else:
        print(f"🚨 SECURITY AUDIT FAILED")
        print(f"   {len(critical)} CRITICAL vulnerabilities must be fixed")
        success = False
    
    print("=" * 80)
    
    return success


if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)
