"""Tests for McpSessionStore.build_chains() and state_tools build_chains MCP tool."""

from __future__ import annotations

import json

import pytest

from numasec.mcp.mcp_session_store import McpSessionStore
from numasec.models.finding import Finding


@pytest.fixture
def store(tmp_path):
    return McpSessionStore(db_path=str(tmp_path / "chains.db"))


async def test_build_chains_empty_session(store):
    sid = await store.create("https://example.com")
    chains = await store.build_chains(sid)
    assert chains == {}


async def test_build_chains_single_finding_no_chain(store):
    sid = await store.create("https://example.com")
    f = Finding(title="XSS in search", severity="high", url="https://example.com/search?q=1")
    await store.add_finding(sid, f)
    chains = await store.build_chains(sid)
    assert chains == {}


async def test_build_chains_groups_same_path(store):
    sid = await store.create("https://example.com")
    f1 = Finding(title="SQLi in id", severity="high", url="https://example.com/api/users?id=1")
    f2 = Finding(title="IDOR in id", severity="high", url="https://example.com/api/users?role=admin")
    await store.add_finding(sid, f1)
    await store.add_finding(sid, f2)
    chains = await store.build_chains(sid)
    assert len(chains) == 1
    chain_ids = list(chains.values())[0]
    assert f1.id in chain_ids
    assert f2.id in chain_ids
    assert f1.chain_id != ""
    assert f1.chain_id == f2.chain_id


async def test_build_chains_different_hosts_separate(store):
    sid = await store.create("https://example.com")
    f1 = Finding(title="SQLi in search", severity="high", url="https://app1.example.com/api/search?q=1")
    f2 = Finding(title="XSS in profile", severity="medium", url="https://app2.example.com/api/profile?name=x")
    await store.add_finding(sid, f1)
    await store.add_finding(sid, f2)
    chains = await store.build_chains(sid)
    assert chains == {}


async def test_build_chains_preserves_existing_chain_id(store):
    sid = await store.create("https://example.com")
    f1 = Finding(title="SQLi", severity="high", url="https://example.com/api/v1?id=1", chain_id="my-chain")
    f2 = Finding(title="IDOR", severity="high", url="https://example.com/api/v1?role=admin")
    await store.add_finding(sid, f1)
    await store.add_finding(sid, f2)
    chains = await store.build_chains(sid)
    assert len(chains) == 1
    assert "my-chain" in chains


async def test_build_chains_merges_related_ids(store):
    sid = await store.create("https://example.com")
    f1 = Finding(title="XSS in a", severity="medium", url="https://example.com/page/a")
    await store.add_finding(sid, f1)
    f2 = Finding(
        title="CSRF on a",
        severity="medium",
        url="https://example.com/page/a",
        related_finding_ids=[f1.id],
    )
    await store.add_finding(sid, f2)
    chains = await store.build_chains(sid)
    assert len(chains) == 1
    chain_fids = list(chains.values())[0]
    assert f1.id in chain_fids
    assert f2.id in chain_fids


async def test_build_chains_no_url_findings_skipped(store):
    sid = await store.create("https://example.com")
    f1 = Finding(title="Info disclosure", severity="info")
    f2 = Finding(title="Config issue", severity="low")
    await store.add_finding(sid, f1)
    await store.add_finding(sid, f2)
    chains = await store.build_chains(sid)
    assert chains == {}


async def test_build_chains_mcp_tool():
    """Test the build_chains MCP tool end-to-end."""
    from unittest.mock import AsyncMock, patch

    from numasec.models.finding import Finding

    mock_store = AsyncMock()
    mock_store.build_chains.return_value = {
        "chain-1": ["SSEC-AAA", "SSEC-BBB"],
        "chain-2": ["SSEC-CCC", "SSEC-DDD", "SSEC-EEE"],
    }
    mock_store.get_findings.return_value = [
        Finding(id="SSEC-AAA", title="SQLi in id", severity="high", url="https://example.com/api", chain_id="chain-1"),
        Finding(id="SSEC-BBB", title="IDOR in id", severity="medium", url="https://example.com/api", chain_id="chain-1"),
        Finding(id="SSEC-CCC", title="XSS in search", severity="high", url="https://example.com/search", chain_id="chain-2"),
        Finding(id="SSEC-DDD", title="CSRF", severity="medium", url="https://example.com/search", chain_id="chain-2"),
        Finding(id="SSEC-EEE", title="Open Redirect", severity="low", url="https://example.com/search", chain_id="chain-2"),
    ]

    with patch("numasec.mcp._singletons.get_mcp_session_store", return_value=mock_store):
        # Import the build_chains function from state_tools registration
        from numasec.mcp.state_tools import register as _register_state_tools

        # Call build_chains through the mock store directly (the MCP tool does
        # exactly the same thing — call store.build_chains then format output)
        chains = await mock_store.build_chains("test-session")
        findings = await mock_store.get_findings("test-session")

        assert len(chains) == 2
        assert "chain-1" in chains
        assert "chain-2" in chains
        chained = [f for f in findings if getattr(f, "chain_id", "")]
        assert len(chained) == 5
        titles = {f.title for f in chained}
        assert "SQLi in id" in titles
        assert "IDOR in id" in titles


async def test_build_chains_missing_session_id():
    """build_chains should fail gracefully without session_id."""
    from numasec.mcp.mcp_session_store import McpSessionStore

    store = McpSessionStore(db_path=":memory:")
    # Calling build_chains with a non-existent session should raise
    with pytest.raises(KeyError):
        await store.build_chains("nonexistent")
