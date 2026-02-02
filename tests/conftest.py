"""Test suite for NumaSec.

Unit tests for:
- CVSS Calculator
- CWE Mapper
- Scope Enforcer
- Tool Parsers
- Knowledge Store
"""

import pytest

# Configure pytest-asyncio if available
try:
    import pytest_asyncio
    pytest_plugins = ('pytest_asyncio',)
except ImportError:
    pass  # pytest-asyncio not installed, async tests will be skipped


def pytest_configure(config):
    """Configure pytest markers."""
    config.addinivalue_line(
        "markers", "unit: Unit tests for individual components"
    )
    config.addinivalue_line(
        "markers", "integration: Integration tests"
    )
    config.addinivalue_line(
        "markers", "e2e: End-to-end tests"
    )
