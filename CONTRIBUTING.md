# Contributing to NumaSec

Thank you for considering contributing to NumaSec! 🛡️

---

## 🎯 Philosophy: SOTA 2026 Engineering

NumaSec follows strict engineering principles:

1. **Simplicity is the Ultimate Sophistication**  
   Prefer deterministic functions over LLM calls when possible.

2. **Performance as a Feature**  
   Every millisecond of latency counts. Every token costs money.

3. **Type Safety is Non-Negotiable**  
   All code must pass `mypy --strict`.

4. **Zero-Dependency Policy**  
   If stdlib can do it with 5 extra lines, don't import a 50MB package.

5. **Self-Documenting Code**  
   Comments explain *WHY*, not *WHAT*. The code itself explains *WHAT*.

---

## 🚀 Quick Start

### 1. Clone
```bash
git clone <repository_url>
cd numasec
```

### 2. Set Up Environment
```bash
# Create virtual environment
python3.11 -m venv .venv
source .venv/bin/activate  # or `.venv\Scripts\activate` on Windows

# Install dependencies
pip install -r requirements.txt

# Copy env template
cp .env.example .env
# Edit .env and add your API keys
```

### 3. Run Tests
```bash
# Unit tests
pytest tests/unit/ -v

# Integration tests
pytest tests/integration/ -v

# Type checking
mypy src/numasec --strict
```

### 4. Make Your Changes
- Follow the coding standards below
- Add tests for new features
- Update documentation

### 5. Submit PR
- Write clear commit messages
- Reference any related issues
- Ensure all tests pass

---

## 📐 Coding Standards

### Python Style
- **Formatter**: Black (line length 100)
- **Linter**: Ruff
- **Type Checker**: Mypy (strict mode)

```bash
# Auto-format
black src/ tests/

# Lint
ruff check src/

# Type check
mypy src/numasec --strict
```

### Code Structure
```python
"""Module docstring explaining purpose.

Example:
    from numasec.agent import NumaSecAgent
    
    agent = NumaSecAgent()
    result = await agent.run("http://target.com", "Find SQLi")
"""

from typing import Optional


def my_function(arg1: str, arg2: int = 42) -> Optional[str]:
    """
    One-line summary.
    
    Detailed explanation if needed.
    
    Args:
        arg1: Description of arg1
        arg2: Description of arg2 (default: 42)
        
    Returns:
        Description of return value
        
    Raises:
        ValueError: When arg1 is empty
    """
    if not arg1:
        raise ValueError("arg1 cannot be empty")
    
    return f"{arg1}-{arg2}"
```

### Commit Messages
```
feat: Add XPath injection payloads
fix: Resolve race condition in async loop
docs: Update README with installation steps
test: Add unit tests for CWE mapper
refactor: Simplify RAG query logic
perf: Optimize token counting algorithm
```

---

## 🧪 Testing Guidelines

### Test Structure
```python
"""Unit tests for Feature X."""

import pytest


class TestFeatureX:
    """Test suite for Feature X."""
    
    @pytest.fixture
    def feature(self):
        """Create feature instance."""
        return FeatureX()
    
    def test_basic_functionality(self, feature):
        """Test that basic functionality works."""
        result = feature.do_something()
        assert result == expected_value
    
    @pytest.mark.asyncio
    async def test_async_operation(self, feature):
        """Test async operation."""
        result = await feature.async_operation()
        assert result is not None
```

### Coverage Target
- **Minimum**: 60% overall
- **Goal**: 80% overall
- **Critical paths**: 90%+ (agent loop, safety controls)

---

## 🏗️ Architecture Guidelines

### Module Organization
```
src/numasec/
├── agent/          # Core agent logic
├── ai/             # LLM providers and routing
├── cli/            # Cyberpunk interface
├── client/         # MCP client orchestration
├── compliance/     # Legal & safety (CVSS, CWE, authorization)
├── core/           # Engagement lifecycle, scope, approval
├── knowledge/      # RAG knowledge base
├── mcp/            # MCP server implementations
├── reporting/      # Report generation
├── tools/          # Tool integrations (nmap, sqlmap, etc.)
└── utils/          # Shared utilities
```

### Adding New Features

#### 1. New Payload Type
```python
# src/numasec/knowledge/seeds/my_payload.py
from numasec.knowledge.store import PayloadEntry

MY_PAYLOADS = [
    PayloadEntry(
        id="my-001",
        name="Basic Payload",
        category="my_attack",
        payload="<payload_here>",
        description="What this payload does",
        use_case="When to use it",
        tags=["tag1", "tag2"],
    ),
]
```

#### 2. New Tool Integration
```python
# src/numasec/tools/my_tool.py
from numasec.tools.base import ToolResult

async def my_tool(target: str, options: dict) -> ToolResult:
    """
    Run my_tool against target.
    
    Args:
        target: Target URL/IP
        options: Tool-specific options
        
    Returns:
        ToolResult with findings
    """
    # Implementation
    pass
```

#### 3. New Compliance Check
```python
# src/numasec/compliance/my_check.py
def my_compliance_check(data: dict) -> bool:
    """
    Check if data complies with standard X.
    
    Args:
        data: Data to validate
        
    Returns:
        True if compliant, False otherwise
    """
    # Implementation
    pass
```

---

## 📚 Documentation

### README Updates
- Keep quick-start under 5 minutes
- Add GIFs/screenshots for visual features
- Update performance metrics with benchmarks

### Docstrings
- Follow Google style
- Include examples for complex functions
- Document all exceptions

### Knowledge Base
- Add new payloads to `knowledge/` directory
- Follow existing markdown format
- Include source references

---

## 🐛 Bug Reports

When reporting a bug, include:
1. **Environment**: OS, Python version, NumaSec version
2. **Steps to Reproduce**: Minimal example
3. **Expected Behavior**: What should happen
4. **Actual Behavior**: What actually happened
5. **Logs**: Include relevant debug output

---

## 💡 Feature Requests

Before requesting a feature:
1. Check existing issues
2. Explain the use case (not just the solution)
3. Consider if it fits SOTA 2026 philosophy

---

## 📜 License

By contributing, you agree that your contributions will be licensed under the MIT License.

---

**Questions?** Open an issue on the repository for technical discussions.
