"""Tests for run_scanner_batch parameter normalisation (url↔target alias + filtering)."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from numasec.mcp import state_tools


class _FakeMCP:
    def __init__(self) -> None:
        self.tools: dict[str, object] = {}

    def tool(self, *, name: str, description: str = ""):
        def decorator(fn):
            self.tools[name] = fn
            return fn
        return decorator


@pytest.fixture
def tmp_db(tmp_path: Path) -> Path:
    return tmp_path / "test_batch.db"


@pytest.fixture
async def store(tmp_db: Path):
    from numasec.mcp.mcp_session_store import McpSessionStore
    return McpSessionStore(db_path=str(tmp_db))


@pytest.fixture(autouse=True)
def patch_mcp_store(store, monkeypatch):
    monkeypatch.setattr(
        "numasec.mcp._singletons.get_mcp_session_store",
        lambda: store,
    )


@pytest.fixture
def mcp():
    fake = _FakeMCP()
    state_tools.register(fake)
    return fake


# -- Helpers: fake tools registered in a real ToolRegistry ----------------


async def _fake_url_tool(url: str, mode: str = "default") -> dict:
    """Tool that accepts url (like injection_test, xss_test, etc.)."""
    return {"url": url, "mode": mode, "status": "ok"}


async def _fake_target_tool(target: str, ports: str = "top-100") -> dict:
    """Tool that accepts target (like recon, port_scan)."""
    return {"target": target, "ports": ports, "status": "ok"}


async def _fake_kwargs_tool(**kwargs) -> dict:
    """Tool that accepts **kwargs."""
    return {"received": kwargs, "status": "ok"}


@pytest.fixture
def fake_registry(monkeypatch):
    """Patch get_tool_registry to return a registry with fake tools."""
    from numasec.tools._base import ToolRegistry

    registry = ToolRegistry()
    registry.register("url_tool", _fake_url_tool, {"name": "url_tool", "parameters": {"required": ["url"]}})
    registry.register("target_tool", _fake_target_tool, {"name": "target_tool", "parameters": {"required": ["target"]}})
    registry.register("kwargs_tool", _fake_kwargs_tool, {"name": "kwargs_tool"})
    monkeypatch.setattr(
        "numasec.mcp._singletons.get_tool_registry",
        lambda: registry,
    )
    return registry


# -- Tests ----------------------------------------------------------------


class TestBatchParamNormalisation:
    """Verify run_scanner_batch normalises url↔target and filters unknown params."""

    async def _create_session(self, mcp) -> str:
        return json.loads(await mcp.tools["create_session"](target="http://test"))["session_id"]

    async def test_target_aliased_to_url(self, mcp, fake_registry):
        """LLM passes 'target' but tool expects 'url' → should alias."""
        sid = await self._create_session(mcp)
        tasks = json.dumps([{"tool": "url_tool", "params": {"target": "http://x.com"}}])
        result = json.loads(await mcp.tools["run_scanner_batch"](session_id=sid, tasks=tasks))

        assert result["succeeded"] == 1
        inner = json.loads(result["results"][0]["result"])
        assert inner["url"] == "http://x.com"

    async def test_url_aliased_to_target(self, mcp, fake_registry):
        """LLM passes 'url' but tool expects 'target' → should alias."""
        sid = await self._create_session(mcp)
        tasks = json.dumps([{"tool": "target_tool", "params": {"url": "http://x.com"}}])
        result = json.loads(await mcp.tools["run_scanner_batch"](session_id=sid, tasks=tasks))

        assert result["succeeded"] == 1
        inner = json.loads(result["results"][0]["result"])
        assert inner["target"] == "http://x.com"

    async def test_correct_param_not_aliased(self, mcp, fake_registry):
        """When the correct param is already used, no aliasing needed."""
        sid = await self._create_session(mcp)
        tasks = json.dumps([{"tool": "url_tool", "params": {"url": "http://correct.com"}}])
        result = json.loads(await mcp.tools["run_scanner_batch"](session_id=sid, tasks=tasks))

        assert result["succeeded"] == 1
        inner = json.loads(result["results"][0]["result"])
        assert inner["url"] == "http://correct.com"

    async def test_unknown_params_filtered(self, mcp, fake_registry):
        """Extra params the tool doesn't accept should be silently dropped."""
        sid = await self._create_session(mcp)
        tasks = json.dumps([{"tool": "url_tool", "params": {"url": "http://x.com", "bogus": 42}}])
        result = json.loads(await mcp.tools["run_scanner_batch"](session_id=sid, tasks=tasks))

        assert result["succeeded"] == 1
        # url_tool does NOT accept 'bogus', so no TypeError should occur

    async def test_kwargs_tool_keeps_all_params(self, mcp, fake_registry):
        """Tools with **kwargs should keep all params, no filtering."""
        sid = await self._create_session(mcp)
        tasks = json.dumps([{"tool": "kwargs_tool", "params": {"foo": 1, "bar": 2}}])
        result = json.loads(await mcp.tools["run_scanner_batch"](session_id=sid, tasks=tasks))

        assert result["succeeded"] == 1
        inner = json.loads(result["results"][0]["result"])
        assert inner["received"]["foo"] == 1
        assert inner["received"]["bar"] == 2

    async def test_no_double_alias_when_both_present(self, mcp, fake_registry):
        """If LLM sends both 'url' and 'target', don't overwrite — keep url for url_tool."""
        sid = await self._create_session(mcp)
        tasks = json.dumps([{"tool": "url_tool", "params": {"url": "http://a.com", "target": "http://b.com"}}])
        result = json.loads(await mcp.tools["run_scanner_batch"](session_id=sid, tasks=tasks))

        assert result["succeeded"] == 1
        inner = json.loads(result["results"][0]["result"])
        # url should stay "http://a.com", target gets filtered out (not in signature)
        assert inner["url"] == "http://a.com"

    async def test_multiple_tasks_mixed(self, mcp, fake_registry):
        """Batch with mixed url/target tools, all with wrong param names."""
        sid = await self._create_session(mcp)
        tasks = json.dumps([
            {"tool": "url_tool", "params": {"target": "http://a.com"}},
            {"tool": "target_tool", "params": {"url": "http://b.com"}},
        ])
        result = json.loads(await mcp.tools["run_scanner_batch"](session_id=sid, tasks=tasks))

        assert result["succeeded"] == 2
        r0 = json.loads(result["results"][0]["result"])
        r1 = json.loads(result["results"][1]["result"])
        assert r0["url"] == "http://a.com"
        assert r1["target"] == "http://b.com"
