"""
NumaSec - Tool Registry

Central registry for all security tools with decorator-based registration.
"""

from __future__ import annotations

from typing import Any, Callable, Type

from numasec.tools.base import (
    BaseTool,
    ToolCategory,
    ToolMetadata,
    ToolRisk,
)


# ══════════════════════════════════════════════════════════════════════════════
# Tool Registry
# ══════════════════════════════════════════════════════════════════════════════


class ToolRegistry:
    """
    Central registry for security tools.

    Usage:
        registry = ToolRegistry()

        @registry.register
        class NmapTool(BaseTool):
            ...

        # Or register manually
        registry.add(NmapTool)

        # Get tool by name
        tool = registry.get("nmap")

        # Get all tools
        all_tools = registry.all()
    """

    _instance: "ToolRegistry | None" = None

    def __new__(cls) -> "ToolRegistry":
        """Singleton pattern."""
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance._tools = {}
            cls._instance._initialized = False
        return cls._instance

    def __init__(self) -> None:
        """Initialize registry."""
        if not self._initialized:
            self._tools: dict[str, Type[BaseTool]] = {}
            self._instances: dict[str, BaseTool] = {}
            self._initialized = True

    def register(self, cls: Type[BaseTool]) -> Type[BaseTool]:
        """
        Decorator to register a tool class.

        Usage:
            @registry.register
            class NmapTool(BaseTool):
                name = "nmap"
                ...
        """
        self.add(cls)
        return cls

    def add(self, cls: Type[BaseTool]) -> None:
        """Add a tool class to the registry."""
        if not hasattr(cls, "name"):
            raise ValueError(f"Tool class {cls.__name__} must have a 'name' attribute")

        self._tools[cls.name] = cls

    def get(self, name: str) -> BaseTool | None:
        """
        Get a tool instance by name.

        Returns a cached instance or creates new one.
        """
        if name not in self._tools:
            return None

        if name not in self._instances:
            self._instances[name] = self._tools[name]()

        return self._instances[name]

    def get_class(self, name: str) -> Type[BaseTool] | None:
        """Get a tool class by name."""
        return self._tools.get(name)

    def all(self) -> list[BaseTool]:
        """Get all tool instances."""
        return [self.get(name) for name in self._tools if self.get(name)]

    def all_classes(self) -> list[Type[BaseTool]]:
        """Get all tool classes."""
        return list(self._tools.values())

    def list_tools(self) -> dict[str, Type[BaseTool]]:
        """Get dictionary of all registered tools by name."""
        return dict(self._tools)

    def names(self) -> list[str]:
        """Get all registered tool names."""
        return list(self._tools.keys())

    def by_category(self, category: ToolCategory) -> list[BaseTool]:
        """Get tools by category."""
        return [
            tool for tool in self.all()
            if tool and tool.category == category
        ]

    def by_risk(self, risk: ToolRisk) -> list[BaseTool]:
        """Get tools by risk level."""
        return [
            tool for tool in self.all()
            if tool and tool.risk == risk
        ]

    def get_metadata(self) -> list[ToolMetadata]:
        """Get metadata for all tools."""
        return [tool.metadata for tool in self.all() if tool]

    def get_mcp_definitions(self) -> list[dict[str, Any]]:
        """Get MCP tool definitions for all tools."""
        return [
            cls.get_mcp_tool_definition()
            for cls in self._tools.values()
        ]

    def has(self, name: str) -> bool:
        """Check if a tool is registered."""
        return name in self._tools

    def remove(self, name: str) -> bool:
        """Remove a tool from the registry."""
        if name in self._tools:
            del self._tools[name]
            if name in self._instances:
                del self._instances[name]
            return True
        return False

    def clear(self) -> None:
        """Clear all tools from the registry."""
        self._tools.clear()
        self._instances.clear()

    def __len__(self) -> int:
        return len(self._tools)

    def __contains__(self, name: str) -> bool:
        return name in self._tools

    def __iter__(self):
        return iter(self._tools.values())


# Global registry instance
_registry = ToolRegistry()


def get_registry() -> ToolRegistry:
    """Get the global tool registry."""
    return _registry


# Alias for backwards compatibility
registry = _registry


# ══════════════════════════════════════════════════════════════════════════════
# Registration Decorator
# ══════════════════════════════════════════════════════════════════════════════


def register_tool(cls: Type[BaseTool]) -> Type[BaseTool]:
    """
    Decorator to register a tool in the global registry.

    Usage:
        @register_tool
        class NmapTool(BaseTool):
            name = "nmap"
            ...
    """
    _registry.add(cls)
    return cls


# ══════════════════════════════════════════════════════════════════════════════
# Tool Risk Map
# ══════════════════════════════════════════════════════════════════════════════

# Map tool names to risk levels for quick lookup
TOOL_RISK_MAP: dict[str, ToolRisk] = {
    # Reconnaissance - LOW
    "nmap": ToolRisk.LOW,
    "httpx": ToolRisk.LOW,
    "whatweb": ToolRisk.LOW,
    "subfinder": ToolRisk.LOW,
    "dns": ToolRisk.LOW,
    # Web - MEDIUM
    "ffuf": ToolRisk.MEDIUM,
    "nuclei": ToolRisk.MEDIUM,
    "nikto": ToolRisk.MEDIUM,
    "crawl": ToolRisk.MEDIUM,
    # Intrusive - HIGH
    "sqlmap": ToolRisk.HIGH,
    "request": ToolRisk.MEDIUM,
    # Exploitation - CRITICAL
    "hydra": ToolRisk.CRITICAL,
    "script": ToolRisk.CRITICAL,
}


def get_tool_risk(tool_name: str) -> ToolRisk:
    """Get risk level for a tool."""
    return TOOL_RISK_MAP.get(tool_name, ToolRisk.MEDIUM)
