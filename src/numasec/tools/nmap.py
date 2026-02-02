"""
NumaSec - Nmap Tool Wrapper

Nmap port scanner with structured output parsing.
"""

from __future__ import annotations

import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from typing import Any

from pydantic import BaseModel, Field

from numasec.tools.base import (
    BaseTool,
    Host,
    Port,
    ToolCategory,
    ToolResult,
    ToolRisk,
    ToolStatus,
)
from numasec.tools.executor import get_executor
from numasec.tools.registry import register_tool


# ══════════════════════════════════════════════════════════════════════════════
# Output Models
# ══════════════════════════════════════════════════════════════════════════════


class NmapPort(BaseModel):
    """Port discovered by nmap."""

    port: int
    protocol: str = "tcp"
    state: str = "open"
    service: str = ""
    product: str = ""
    version: str = ""
    extra_info: str = ""
    conf: int = 0
    cpe: list[str] = Field(default_factory=list)


class NmapHost(BaseModel):
    """Host discovered by nmap."""

    ip: str
    hostnames: list[str] = Field(default_factory=list)
    state: str = "up"
    state_reason: str = ""
    os_matches: list[str] = Field(default_factory=list)
    ports: list[NmapPort] = Field(default_factory=list)
    mac_address: str = ""
    vendor: str = ""


class NmapResult(BaseModel):
    """Complete nmap scan result."""

    hosts: list[NmapHost] = Field(default_factory=list)
    scan_info: dict[str, Any] = Field(default_factory=dict)
    run_stats: dict[str, Any] = Field(default_factory=dict)
    command: str = ""
    start_time: datetime | None = None
    end_time: datetime | None = None
    elapsed_seconds: float = 0

    @property
    def total_hosts(self) -> int:
        return len(self.hosts)

    @property
    def total_open_ports(self) -> int:
        return sum(len(h.ports) for h in self.hosts)

    @property
    def hosts_up(self) -> int:
        return sum(1 for h in self.hosts if h.state == "up")


# ══════════════════════════════════════════════════════════════════════════════
# Nmap Tool
# ══════════════════════════════════════════════════════════════════════════════


@register_tool
class NmapTool(BaseTool[NmapResult]):
    """
    Nmap port scanner wrapper.

    Supports:
    - Quick scan (-T4 -F)
    - Full scan (-sS -sV -sC)
    - Service detection (-sV)
    - Vulnerability scan (--script vuln)
    - Custom port ranges
    - XML output parsing
    """

    name = "nmap"
    description = "Network port scanner with service detection"
    category = ToolCategory.RECONNAISSANCE
    risk = ToolRisk.LOW
    command = "nmap"

    # Scan type presets
    # NOTE: Using -sT (TCP connect) instead of -sS (SYN) for container compatibility
    # -sS requires CAP_NET_RAW which is often restricted
    SCAN_PRESETS = {
        "quick": ["-sT", "-T4", "-F"],
        "full": ["-sT", "-sV", "-sC", "-p-"],
        "service": ["-sT", "-sV"],
        "stealth": ["-sT", "-T2"],
        "vuln": ["-sT", "--script", "vuln"],
        "top100": ["-sT", "--top-ports", "100"],
        "top1000": ["-sT", "--top-ports", "1000"],
    }

    async def execute(
        self,
        targets: list[str],
        scan_type: str = "quick",
        ports: str | None = None,
        extra_args: list[str] | None = None,
        timeout: int = 600,
    ) -> ToolResult[NmapResult]:
        """
        Execute nmap scan.

        Args:
            targets: List of IPs, CIDRs, or hostnames
            scan_type: Scan preset (quick, full, service, stealth, vuln)
            ports: Custom port specification (e.g., "80,443,8080" or "1-1000")
            extra_args: Additional nmap arguments
            timeout: Scan timeout in seconds

        Returns:
            ToolResult with NmapResult data
        """
        start_time = datetime.now(timezone.utc)

        # Build command
        cmd = ["nmap", "-oX", "-"]  # XML output to stdout

        # Add scan preset
        if scan_type in self.SCAN_PRESETS:
            cmd.extend(self.SCAN_PRESETS[scan_type])

        # Add port specification
        if ports:
            cmd.extend(["-p", ports])

        # Add extra arguments
        if extra_args:
            cmd.extend(extra_args)

        # Add targets
        cmd.extend(targets)

        # Execute
        executor = get_executor()
        result = await executor.execute(cmd, timeout=timeout)

        if not result.success:
            return ToolResult[NmapResult](
                tool_name=self.name,
                status=result.status,
                data=None,
                raw_output=result.stderr or result.stdout,
                error=result.stderr,
                command=" ".join(cmd),
                exit_code=result.exit_code,
                started_at=start_time,
                completed_at=datetime.now(timezone.utc),
            )

        # Parse XML output
        try:
            nmap_result = self.parse_output(result.stdout)
            nmap_result.command = " ".join(cmd)
        except Exception as e:
            return ToolResult[NmapResult](
                tool_name=self.name,
                status=ToolStatus.FAILED,
                data=None,
                raw_output=result.stdout,
                error=f"Failed to parse nmap output: {e}",
                command=" ".join(cmd),
                exit_code=result.exit_code,
                started_at=start_time,
                completed_at=datetime.now(timezone.utc),
            )

        completed_at = datetime.now(timezone.utc)
        duration_ms = (completed_at - start_time).total_seconds() * 1000

        return ToolResult[NmapResult](
            tool_name=self.name,
            status=ToolStatus.SUCCESS,
            data=nmap_result,
            raw_output=result.stdout,
            command=" ".join(cmd),
            exit_code=result.exit_code,
            started_at=start_time,
            completed_at=completed_at,
            duration_ms=duration_ms,
        )

    def parse_output(self, raw_output: str) -> NmapResult:
        """Parse nmap XML output."""
        result = NmapResult()

        try:
            root = ET.fromstring(raw_output)
        except ET.ParseError:
            # Try to extract partial results
            return result

        # Parse scan info
        if root.attrib:
            result.scan_info = {
                "scanner": root.get("scanner", "nmap"),
                "args": root.get("args", ""),
                "start": root.get("start", ""),
                "startstr": root.get("startstr", ""),
                "version": root.get("version", ""),
            }

            if root.get("start"):
                try:
                    result.start_time = datetime.fromtimestamp(int(root.get("start", 0)))
                except (ValueError, TypeError):
                    pass

        # Parse hosts
        for host_elem in root.findall(".//host"):
            host = self._parse_host(host_elem)
            if host:
                result.hosts.append(host)

        # Parse run stats
        runstats = root.find("runstats")
        if runstats is not None:
            finished = runstats.find("finished")
            if finished is not None:
                result.run_stats["elapsed"] = finished.get("elapsed", "")
                result.elapsed_seconds = float(finished.get("elapsed", 0))

                if finished.get("time"):
                    try:
                        result.end_time = datetime.fromtimestamp(int(finished.get("time", 0)))
                    except (ValueError, TypeError):
                        pass

            hosts_stat = runstats.find("hosts")
            if hosts_stat is not None:
                result.run_stats["hosts_up"] = int(hosts_stat.get("up", 0))
                result.run_stats["hosts_down"] = int(hosts_stat.get("down", 0))
                result.run_stats["hosts_total"] = int(hosts_stat.get("total", 0))

        return result

    def _parse_host(self, host_elem: ET.Element) -> NmapHost | None:
        """Parse a single host element."""
        # Get status
        status_elem = host_elem.find("status")
        if status_elem is None:
            return None

        state = status_elem.get("state", "unknown")

        # Get IP address
        address_elem = host_elem.find("address[@addrtype='ipv4']")
        if address_elem is None:
            address_elem = host_elem.find("address[@addrtype='ipv6']")
        if address_elem is None:
            return None

        ip = address_elem.get("addr", "")

        host = NmapHost(
            ip=ip,
            state=state,
            state_reason=status_elem.get("reason", ""),
        )

        # Get MAC address
        mac_elem = host_elem.find("address[@addrtype='mac']")
        if mac_elem is not None:
            host.mac_address = mac_elem.get("addr", "")
            host.vendor = mac_elem.get("vendor", "")

        # Get hostnames
        for hostname_elem in host_elem.findall(".//hostname"):
            name = hostname_elem.get("name", "")
            if name:
                host.hostnames.append(name)

        # Get OS matches
        for osmatch_elem in host_elem.findall(".//osmatch"):
            name = osmatch_elem.get("name", "")
            if name:
                host.os_matches.append(name)

        # Get ports
        for port_elem in host_elem.findall(".//port"):
            port = self._parse_port(port_elem)
            if port:
                host.ports.append(port)

        return host

    def _parse_port(self, port_elem: ET.Element) -> NmapPort | None:
        """Parse a single port element."""
        port_id = port_elem.get("portid")
        if not port_id:
            return None

        state_elem = port_elem.find("state")
        if state_elem is None:
            return None

        port = NmapPort(
            port=int(port_id),
            protocol=port_elem.get("protocol", "tcp"),
            state=state_elem.get("state", "unknown"),
        )

        # Get service info
        service_elem = port_elem.find("service")
        if service_elem is not None:
            port.service = service_elem.get("name", "")
            port.product = service_elem.get("product", "")
            port.version = service_elem.get("version", "")
            port.extra_info = service_elem.get("extrainfo", "")
            port.conf = int(service_elem.get("conf", 0))

            # Get CPE
            for cpe_elem in service_elem.findall("cpe"):
                if cpe_elem.text:
                    port.cpe.append(cpe_elem.text)

        return port

    @classmethod
    def get_schema(cls) -> dict[str, Any]:
        """Get JSON schema for tool parameters."""
        return {
            "type": "object",
            "properties": {
                "targets": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "Target IPs, CIDRs, or hostnames",
                },
                "scan_type": {
                    "type": "string",
                    "enum": ["quick", "full", "service", "stealth", "vuln", "top100", "top1000"],
                    "default": "quick",
                    "description": "Scan preset to use",
                },
                "ports": {
                    "type": "string",
                    "description": "Custom port specification (e.g., '80,443' or '1-1000')",
                },
                "extra_args": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "Additional nmap arguments",
                },
            },
            "required": ["targets"],
        }
