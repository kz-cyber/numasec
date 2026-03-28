"""Tests for numasec.tools.security_shell."""
from __future__ import annotations

import asyncio
import json
import textwrap
from unittest.mock import AsyncMock, patch

import pytest

from numasec.tools.security_shell import (
    KNOWN_TOOLS,
    _parse_ffuf_json,
    _parse_httpx_json,
    _parse_line_list,
    _parse_nikto_json,
    _parse_nmap_xml,
    _parse_nuclei_jsonl,
    _parse_sqlmap_output,
    _validate_target,
    detect_available_tools,
    security_shell,
)

# ---------------------------------------------------------------------------
# detect_available_tools
# ---------------------------------------------------------------------------

class TestDetectAvailableTools:
    def test_returns_dict(self):
        result = detect_available_tools()
        assert isinstance(result, dict)

    def test_keys_match_known_tools(self):
        result = detect_available_tools()
        assert set(result.keys()) == set(KNOWN_TOOLS.keys())

    def test_values_are_bools(self):
        result = detect_available_tools()
        for val in result.values():
            assert isinstance(val, bool)


# ---------------------------------------------------------------------------
# _validate_target
# ---------------------------------------------------------------------------

class TestValidateTarget:
    @pytest.mark.parametrize("target", [
        "example.com",
        "https://example.com",
        "http://example.com/path?q=1",
        "sub.domain.example.com",
        "https://scanme.nmap.org",
        "8.8.8.8",
        "https://user:pass@example.com/path",
    ])
    def test_accepts_valid_targets(self, target: str):
        assert _validate_target(target) is True

    @pytest.mark.parametrize("target", [
        "/etc/passwd",
        "file:///etc/shadow",
        "\\\\server\\share",
        "../../../etc/passwd",
        "127.0.0.1",
        "localhost",
        "http://127.0.0.1:8080",
        "10.0.0.1",
        "172.16.0.1",
        "192.168.1.1",
        "http://192.168.1.1",
        "169.254.169.254",
        "0.0.0.0",
        "::1",
        "[::1]",
        "",
        "   ",
    ])
    def test_rejects_unsafe_targets(self, target: str):
        assert _validate_target(target) is False


# ---------------------------------------------------------------------------
# Parsers
# ---------------------------------------------------------------------------

class TestParseNmapXml:
    SAMPLE_XML = textwrap.dedent("""\
        <?xml version="1.0"?>
        <nmaprun>
          <host>
            <address addr="93.184.216.34" addrtype="ipv4"/>
            <ports>
              <port protocol="tcp" portid="80">
                <state state="open"/>
                <service name="http" product="Apache" version="2.4.41"/>
              </port>
              <port protocol="tcp" portid="443">
                <state state="open"/>
                <service name="https" product="nginx" version="1.18"/>
              </port>
            </ports>
          </host>
        </nmaprun>
    """)

    def test_parses_hosts(self):
        result = _parse_nmap_xml(self.SAMPLE_XML)
        assert len(result["hosts"]) == 1
        host = result["hosts"][0]
        assert host["ip"] == "93.184.216.34"
        assert len(host["ports"]) == 2

    def test_parses_port_details(self):
        result = _parse_nmap_xml(self.SAMPLE_XML)
        port = result["hosts"][0]["ports"][0]
        assert port["port"] == 80
        assert port["service"] == "http"
        assert "Apache" in port["version"]

    def test_handles_invalid_xml(self):
        result = _parse_nmap_xml("not xml at all")
        assert result["hosts"] == []
        assert "parse_error" in result


class TestParseFfufJson:
    SAMPLE = json.dumps({
        "results": [
            {"url": "https://example.com/admin", "status": 200, "length": 1234, "words": 50, "lines": 10},
            {"url": "https://example.com/login", "status": 302, "length": 0, "words": 0, "lines": 0},
        ]
    })

    def test_parses_results(self):
        result = _parse_ffuf_json(self.SAMPLE)
        assert len(result["results"]) == 2
        assert result["results"][0]["url"] == "https://example.com/admin"
        assert result["results"][0]["status"] == 200
        assert result["results"][0]["length"] == 1234

    def test_handles_invalid_json(self):
        result = _parse_ffuf_json("{bad json")
        assert result["results"] == []
        assert "parse_error" in result


class TestParseLineList:
    def test_parses_lines(self):
        output = "sub1.example.com\nsub2.example.com\n\nsub3.example.com\n"
        result = _parse_line_list(output)
        assert result["items"] == ["sub1.example.com", "sub2.example.com", "sub3.example.com"]

    def test_empty_output(self):
        result = _parse_line_list("")
        assert result["items"] == []


class TestParseNucleiJsonl:
    SAMPLE = "\n".join([
        json.dumps({"template-id": "cve-2021-1234", "info": {"severity": "high", "name": "Test CVE"}, "matched-at": "https://example.com/vuln"}),
        json.dumps({"template-id": "misc-info", "info": {"severity": "info", "name": "Info Leak"}, "matched-at": "https://example.com/info"}),
    ])

    def test_parses_findings(self):
        result = _parse_nuclei_jsonl(self.SAMPLE)
        assert len(result["findings"]) == 2
        assert result["findings"][0]["template"] == "cve-2021-1234"
        assert result["findings"][0]["severity"] == "high"
        assert result["findings"][0]["matched"] == "https://example.com/vuln"

    def test_skips_invalid_lines(self):
        result = _parse_nuclei_jsonl("not json\n{\"template-id\": \"ok\", \"info\": {\"severity\": \"low\", \"name\": \"x\"}, \"matched-at\": \"x\"}")
        assert len(result["findings"]) == 1


class TestParseSqlmapOutput:
    SAMPLE = textwrap.dedent("""\
        [INFO] testing 'id' parameter
        Parameter 'id' is injectable
        back-end DBMS: MySQL >= 5.0
        | users
        | orders
    """)

    def test_parses_injectable_params(self):
        result = _parse_sqlmap_output(self.SAMPLE)
        assert "id" in result["injectable_params"]

    def test_parses_dbms(self):
        result = _parse_sqlmap_output(self.SAMPLE)
        assert "MySQL" in result["dbms"]

    def test_parses_tables(self):
        result = _parse_sqlmap_output(self.SAMPLE)
        assert "users" in result["tables"]
        assert "orders" in result["tables"]

    def test_empty_output(self):
        result = _parse_sqlmap_output("")
        assert result["injectable_params"] == []
        assert result["dbms"] == ""
        assert result["tables"] == []


class TestParseNiktoJson:
    SAMPLE = json.dumps({
        "vulnerabilities": [
            {"id": "001", "msg": "Server leaks version", "method": "GET"},
            {"id": "002", "msg": "Directory listing", "method": "GET"},
        ]
    })

    def test_parses_vulnerabilities(self):
        result = _parse_nikto_json(self.SAMPLE)
        assert len(result["vulnerabilities"]) == 2
        assert result["vulnerabilities"][0]["id"] == "001"
        assert result["vulnerabilities"][0]["msg"] == "Server leaks version"

    def test_handles_list_format(self):
        data = [{"id": "1", "msg": "test"}]
        result = _parse_nikto_json(json.dumps(data))
        assert len(result["vulnerabilities"]) == 1

    def test_handles_invalid_json(self):
        result = _parse_nikto_json("<<<not json>>>")
        assert result["vulnerabilities"] == []
        assert "parse_error" in result


class TestParseHttpxJson:
    SAMPLE = "\n".join([
        json.dumps({"url": "https://example.com", "status_code": 200, "tech": ["Nginx"], "title": "Example", "content_length": 500}),
        json.dumps({"url": "https://example.com/api", "status_code": 404, "title": "Not Found"}),
    ])

    def test_parses_probes(self):
        result = _parse_httpx_json(self.SAMPLE)
        assert len(result["probes"]) == 2
        assert result["probes"][0]["url"] == "https://example.com"
        assert result["probes"][0]["status"] == 200
        assert result["probes"][0]["tech"] == ["Nginx"]

    def test_empty_output(self):
        result = _parse_httpx_json("")
        assert result["probes"] == []


# ---------------------------------------------------------------------------
# security_shell — main function
# ---------------------------------------------------------------------------

class TestSecurityShell:
    @pytest.mark.asyncio
    async def test_unknown_tool_returns_error(self):
        result = await security_shell(tool="nonexistent", target="example.com")
        assert result["status"] == "error"
        assert "Unknown tool" in result["error"]

    @pytest.mark.asyncio
    async def test_unavailable_tool_returns_helpful_message(self):
        with patch("numasec.tools.security_shell.shutil.which", return_value=None):
            result = await security_shell(tool="nmap", target="example.com")
        assert result["status"] == "error"
        assert "not installed" in result["error"]
        assert "available_tools" in result

    @pytest.mark.asyncio
    async def test_unsafe_target_rejected(self):
        with patch("numasec.tools.security_shell.shutil.which", return_value="/usr/bin/nmap"):
            result = await security_shell(tool="nmap", target="127.0.0.1")
        assert result["status"] == "error"
        assert "not allowed" in result["error"]

    @pytest.mark.asyncio
    async def test_successful_execution(self):
        nmap_xml = textwrap.dedent("""\
            <?xml version="1.0"?>
            <nmaprun>
              <host>
                <address addr="93.184.216.34" addrtype="ipv4"/>
                <ports>
                  <port protocol="tcp" portid="80">
                    <state state="open"/>
                    <service name="http" product="Apache" version="2.4"/>
                  </port>
                </ports>
              </host>
            </nmaprun>
        """)

        mock_proc = AsyncMock()
        mock_proc.communicate = AsyncMock(return_value=(nmap_xml.encode(), b""))
        mock_proc.returncode = 0
        mock_proc.kill = AsyncMock()
        mock_proc.wait = AsyncMock()

        with (
            patch("numasec.tools.security_shell.shutil.which", return_value="/usr/bin/nmap"),
            patch("numasec.tools.security_shell.asyncio.create_subprocess_exec", return_value=mock_proc),
        ):
            result = await security_shell(tool="nmap", target="example.com")

        assert result["success"] is True
        assert result["tool"] == "nmap"
        assert len(result["hosts"]) == 1
        assert result["hosts"][0]["ports"][0]["port"] == 80

    @pytest.mark.asyncio
    async def test_timeout_enforcement(self):
        mock_proc = AsyncMock()
        mock_proc.communicate = AsyncMock(side_effect=asyncio.TimeoutError)
        mock_proc.kill = AsyncMock()
        mock_proc.wait = AsyncMock()

        with (
            patch("numasec.tools.security_shell.shutil.which", return_value="/usr/bin/nmap"),
            patch("numasec.tools.security_shell.asyncio.create_subprocess_exec", return_value=mock_proc),
        ):
            result = await security_shell(tool="nmap", target="example.com", timeout=1)

        assert result["status"] == "error"
        assert "timed out" in result["error"]

    @pytest.mark.asyncio
    async def test_options_are_split_into_args(self):
        mock_proc = AsyncMock()
        mock_proc.communicate = AsyncMock(return_value=(b"<nmaprun></nmaprun>", b""))
        mock_proc.returncode = 0

        with (
            patch("numasec.tools.security_shell.shutil.which", return_value="/usr/bin/nmap"),
            patch("numasec.tools.security_shell.asyncio.create_subprocess_exec", return_value=mock_proc) as mock_exec,
        ):
            await security_shell(tool="nmap", target="example.com", options="-p 1-1000 -T4")

        # Verify the command was built correctly
        call_args = mock_exec.call_args[0]
        assert "-p" in call_args
        assert "1-1000" in call_args
        assert "-T4" in call_args
        assert "example.com" in call_args

    @pytest.mark.asyncio
    async def test_stderr_included_when_present(self):
        mock_proc = AsyncMock()
        mock_proc.communicate = AsyncMock(return_value=(b"", b"WARNING: something went wrong"))
        mock_proc.returncode = 1

        with (
            patch("numasec.tools.security_shell.shutil.which", return_value="/usr/bin/nmap"),
            patch("numasec.tools.security_shell.asyncio.create_subprocess_exec", return_value=mock_proc),
        ):
            result = await security_shell(tool="nmap", target="example.com")

        assert "stderr" in result
        assert "WARNING" in result["stderr"]

    @pytest.mark.asyncio
    async def test_os_error_handled(self):
        with (
            patch("numasec.tools.security_shell.shutil.which", return_value="/usr/bin/nmap"),
            patch(
                "numasec.tools.security_shell.asyncio.create_subprocess_exec",
                side_effect=OSError("Permission denied"),
            ),
        ):
            result = await security_shell(tool="nmap", target="example.com")

        assert result["status"] == "error"
        assert "Permission denied" in result["error"]
