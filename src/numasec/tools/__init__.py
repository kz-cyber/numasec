"""Security tools package for NumaSec.

Tool wrappers with structured JSON output for nmap, nuclei, ffuf, etc.
"""

from numasec.tools.base import (
    BaseTool,
    ToolCategory,
    ToolResult,
    ToolRisk,
    ToolStatus,
    Host,
    Port,
    Vulnerability,
    HTTPResponse,
    FuzzResult,
    Credential,
)
from numasec.tools.registry import ToolRegistry, register_tool, get_registry
from numasec.tools.executor import ToolExecutor, ExecutionResult, get_executor

# Import all tool wrappers to register them
from numasec.tools.nmap import NmapTool, NmapResult, NmapHost, NmapPort
from numasec.tools.nuclei import NucleiTool, NucleiResult, NucleiMatch
from numasec.tools.httpx_tool import HttpxTool, HttpxResult, HttpxProbe
from numasec.tools.ffuf import FfufTool, FfufResult, FfufMatch
from numasec.tools.sqlmap import SQLMapTool, SQLMapResult, SQLiInjection
from numasec.tools.hydra import HydraTool, HydraResult, HydraCredential
from numasec.tools.nikto import NiktoTool, NiktoResult, NiktoFinding
from numasec.tools.whatweb import WhatWebTool, WhatWebResult, WhatWebTarget
from numasec.tools.subfinder import SubfinderTool, SubfinderResult, Subdomain
from numasec.tools.scripts import ScriptTool, PythonScriptTool, ShellScriptTool, ScriptResult

__all__ = [
    # Base classes
    "BaseTool",
    "ToolCategory",
    "ToolResult",
    "ToolRisk",
    "ToolStatus",
    # Common models
    "Host",
    "Port",
    "Vulnerability",
    "HTTPResponse",
    "FuzzResult",
    "Credential",
    # Registry
    "ToolRegistry",
    "register_tool",
    "get_registry",
    # Executor
    "ToolExecutor",
    "ExecutionResult",
    "get_executor",
    # Nmap
    "NmapTool",
    "NmapResult",
    "NmapHost",
    "NmapPort",
    # Nuclei
    "NucleiTool",
    "NucleiResult",
    "NucleiMatch",
    # httpx
    "HttpxTool",
    "HttpxResult",
    "HttpxProbe",
    # Ffuf
    "FfufTool",
    "FfufResult",
    "FfufMatch",
    # SQLMap
    "SQLMapTool",
    "SQLMapResult",
    "SQLiInjection",
    # Hydra
    "HydraTool",
    "HydraResult",
    "HydraCredential",
    # Nikto
    "NiktoTool",
    "NiktoResult",
    "NiktoFinding",
    # WhatWeb
    "WhatWebTool",
    "WhatWebResult",
    "WhatWebTarget",
    # Subfinder
    "SubfinderTool",
    "SubfinderResult",
    "Subdomain",
    # Scripts
    "ScriptTool",
    "PythonScriptTool",
    "ShellScriptTool",
    "ScriptResult",
]
