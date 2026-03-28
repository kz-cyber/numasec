"""Tests for numasec.tools.burp_bridge — Burp Suite import/export bridge."""

from __future__ import annotations

import base64
import json
import xml.etree.ElementTree as ET

from numasec.tools.burp_bridge import (
    BurpIssue,
    _confidence_to_burp,
    findings_to_burp_xml,
    parse_burp_sitemap,
    parse_burp_xml,
    python_burp_bridge,
)

# ---------------------------------------------------------------------------
# Sample XML fixtures
# ---------------------------------------------------------------------------

BURP_ISSUES_XML = """\
<?xml version="1.0" encoding="UTF-8"?>
<issues burpVersion="2024.1" exportTime="Thu Jan 01 00:00:00 UTC 2024">
  <issue>
    <serialNumber>1234567890</serialNumber>
    <type>1049088</type>
    <name>SQL injection</name>
    <host ip="10.0.0.1">https://example.com</host>
    <path>/api/users?id=1</path>
    <location>/api/users</location>
    <severity>High</severity>
    <confidence>Certain</confidence>
    <issueBackground>SQL injection vulnerabilities arise when user input is used in SQL queries.</issueBackground>
    <issueDetail>The id parameter appears to be vulnerable to SQL injection.</issueDetail>
    <remediationDetail>Use parameterised queries.</remediationDetail>
    <requestresponse>
      <request base64="true">{req_b64}</request>
      <response base64="true">{resp_b64}</response>
    </requestresponse>
  </issue>
  <issue>
    <serialNumber>9876543210</serialNumber>
    <type>5244928</type>
    <name>Cross-site scripting (reflected)</name>
    <host ip="10.0.0.1">https://example.com</host>
    <path>/search?q=test</path>
    <severity>Medium</severity>
    <confidence>Firm</confidence>
    <issueDetail>The q parameter is reflected without encoding.</issueDetail>
  </issue>
  <issue>
    <serialNumber>5555555555</serialNumber>
    <type>6291456</type>
    <name>Cookie without HttpOnly flag</name>
    <host ip="10.0.0.1">https://example.com</host>
    <path>/</path>
    <severity>Low</severity>
    <confidence>Certain</confidence>
    <issueDetail>A cookie is set without the HttpOnly flag.</issueDetail>
  </issue>
  <issue>
    <serialNumber>1111111111</serialNumber>
    <type>0</type>
    <name>Information disclosure</name>
    <host ip="10.0.0.1">https://example.com</host>
    <path>/robots.txt</path>
    <severity>Information</severity>
    <confidence>Tentative</confidence>
    <issueDetail>The robots.txt file reveals hidden paths.</issueDetail>
  </issue>
</issues>
""".format(
    req_b64=base64.b64encode(b"GET /api/users?id=1 HTTP/1.1\r\nHost: example.com\r\n\r\n").decode(),
    resp_b64=base64.b64encode(b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{\"id\":1}").decode(),
)

BURP_ISSUES_PLAIN_TEXT_XML = """\
<issues>
  <issue>
    <name>Plain text issue</name>
    <host>http://plain.example.com</host>
    <path>/test</path>
    <severity>Medium</severity>
    <confidence>Firm</confidence>
    <issueDetail>Some detail</issueDetail>
    <request>GET /test HTTP/1.1</request>
    <response>HTTP/1.1 200 OK</response>
  </issue>
</issues>
"""

BURP_SITEMAP_XML = """\
<?xml version="1.0" encoding="UTF-8"?>
<items>
  <item>
    <url>https://example.com/api/v1/users</url>
    <host>example.com</host>
    <port>443</port>
    <protocol>https</protocol>
    <path>/api/v1/users</path>
    <method>GET</method>
    <status>200</status>
    <mimetype>application/json</mimetype>
  </item>
  <item>
    <url>https://example.com/api/v1/login</url>
    <host>example.com</host>
    <port>443</port>
    <protocol>https</protocol>
    <path>/api/v1/login</path>
    <method>POST</method>
    <status>200</status>
    <mimetype>application/json</mimetype>
  </item>
  <item>
    <url>https://example.com/static/app.js</url>
    <host>example.com</host>
    <port>443</port>
    <protocol>https</protocol>
    <path>/static/app.js</path>
    <method>GET</method>
    <status>200</status>
    <mimetype>application/javascript</mimetype>
  </item>
</items>
"""


# ---------------------------------------------------------------------------
# parse_burp_xml tests
# ---------------------------------------------------------------------------


class TestParseBurpXml:
    def test_parse_multiple_issues(self):
        issues = parse_burp_xml(BURP_ISSUES_XML)
        assert len(issues) == 4

    def test_issue_fields_high_severity(self):
        issues = parse_burp_xml(BURP_ISSUES_XML)
        sqli = issues[0]
        assert sqli.name == "SQL injection"
        assert sqli.host == "https://example.com"
        assert sqli.path == "/api/users?id=1"
        assert sqli.severity == "High"
        assert sqli.confidence == "Certain"
        assert "id parameter" in sqli.detail

    def test_base64_request_response_decoded(self):
        issues = parse_burp_xml(BURP_ISSUES_XML)
        sqli = issues[0]
        assert b"GET /api/users?id=1" in sqli.request
        assert b"200 OK" in sqli.response

    def test_medium_severity_no_request(self):
        issues = parse_burp_xml(BURP_ISSUES_XML)
        xss = issues[1]
        assert xss.severity == "Medium"
        assert xss.confidence == "Firm"
        assert xss.request == b""
        assert xss.response == b""

    def test_low_severity(self):
        issues = parse_burp_xml(BURP_ISSUES_XML)
        cookie = issues[2]
        assert cookie.severity == "Low"
        assert cookie.name == "Cookie without HttpOnly flag"

    def test_information_severity(self):
        issues = parse_burp_xml(BURP_ISSUES_XML)
        info = issues[3]
        assert info.severity == "Information"
        assert info.confidence == "Tentative"

    def test_plain_text_request_response(self):
        issues = parse_burp_xml(BURP_ISSUES_PLAIN_TEXT_XML)
        assert len(issues) == 1
        assert issues[0].request == b"GET /test HTTP/1.1"
        assert issues[0].response == b"HTTP/1.1 200 OK"

    def test_empty_string_returns_empty_list(self):
        assert parse_burp_xml("") == []

    def test_none_like_empty_string(self):
        assert parse_burp_xml("   ") == []

    def test_malformed_xml_returns_empty_list(self):
        assert parse_burp_xml("<issues><issue><name>Broken") == []
        assert parse_burp_xml("not xml at all") == []

    def test_single_issue_root(self):
        xml = "<issue><name>Solo</name><host>http://solo.test</host><path>/</path><severity>Low</severity><confidence>Firm</confidence></issue>"
        issues = parse_burp_xml(xml)
        assert len(issues) == 1
        assert issues[0].name == "Solo"

    def test_unrelated_root_tag(self):
        xml = "<something><child>text</child></something>"
        assert parse_burp_xml(xml) == []


# ---------------------------------------------------------------------------
# BurpIssue conversion tests
# ---------------------------------------------------------------------------


class TestBurpIssueConversion:
    def test_to_numasec_finding_severity_mapping(self):
        for burp_sev, numa_sev in [("High", "high"), ("Medium", "medium"), ("Low", "low"), ("Information", "info")]:
            issue = BurpIssue(name="Test", host="https://t.com", path="/", severity=burp_sev, confidence="Firm")
            finding = issue.to_numasec_finding()
            assert finding["severity"] == numa_sev

    def test_to_numasec_finding_confidence_mapping(self):
        for burp_conf, expected in [("Certain", 1.0), ("Firm", 0.8), ("Tentative", 0.5)]:
            issue = BurpIssue(name="Test", host="https://t.com", path="/x", severity="High", confidence=burp_conf)
            finding = issue.to_numasec_finding()
            assert finding["confidence"] == expected

    def test_to_numasec_finding_url_composition(self):
        issue = BurpIssue(
            name="Test", host="https://example.com", path="/api/v1", severity="High", confidence="Certain"
        )
        finding = issue.to_numasec_finding()
        assert finding["url"] == "https://example.com/api/v1"

    def test_to_numasec_finding_url_no_path(self):
        issue = BurpIssue(name="Test", host="https://example.com", path="", severity="High", confidence="Firm")
        finding = issue.to_numasec_finding()
        assert finding["url"] == "https://example.com"

    def test_to_numasec_finding_tool_used(self):
        issue = BurpIssue(name="X", host="h", path="/", severity="Low", confidence="Tentative")
        assert issue.to_numasec_finding()["tool_used"] == "burp_suite"

    def test_to_numasec_finding_evidence_includes_request(self):
        issue = BurpIssue(
            name="X", host="h", path="/", severity="Low", confidence="Firm",
            detail="detail text", request=b"GET / HTTP/1.1",
        )
        finding = issue.to_numasec_finding()
        assert "detail text" in finding["evidence"]
        assert "Request:" in finding["evidence"]

    def test_to_dict_base64_encodes_bytes(self):
        issue = BurpIssue(
            name="T", host="h", path="/", severity="Low", confidence="Firm",
            request=b"\x00\x01\x02", response=b"OK",
        )
        d = issue.to_dict()
        assert base64.b64decode(d["request"]) == b"\x00\x01\x02"
        assert base64.b64decode(d["response"]) == b"OK"

    def test_to_dict_empty_bytes(self):
        issue = BurpIssue(name="T", host="h", path="/", severity="Low", confidence="Firm")
        d = issue.to_dict()
        assert d["request"] == ""
        assert d["response"] == ""


# ---------------------------------------------------------------------------
# findings_to_burp_xml tests
# ---------------------------------------------------------------------------

SAMPLE_FINDINGS: list[dict] = [
    {
        "id": "finding-001",
        "title": "SQL Injection in login",
        "severity": "high",
        "confidence": 1.0,
        "url": "https://example.com/api/login",
        "description": "The login endpoint is vulnerable to SQL injection.",
        "evidence": "Input: ' OR 1=1-- resulted in HTTP 200",
        "cwe_id": "CWE-89",
        "remediation_summary": "Use parameterised queries.",
        "request_dump": "POST /api/login HTTP/1.1\r\nHost: example.com\r\n\r\nuser=admin",
    },
    {
        "id": "finding-002",
        "title": "Missing HSTS header",
        "severity": "info",
        "confidence": 0.5,
        "url": "https://example.com/",
        "description": "No Strict-Transport-Security header.",
    },
]


class TestFindingsToBurpXml:
    def test_output_is_valid_xml(self):
        xml_str = findings_to_burp_xml(SAMPLE_FINDINGS)
        root = ET.fromstring(xml_str)
        assert root.tag == "issues"

    def test_correct_issue_count(self):
        xml_str = findings_to_burp_xml(SAMPLE_FINDINGS)
        root = ET.fromstring(xml_str)
        assert len(root.findall("issue")) == 2

    def test_severity_mapping(self):
        xml_str = findings_to_burp_xml(SAMPLE_FINDINGS)
        root = ET.fromstring(xml_str)
        issues = root.findall("issue")
        assert issues[0].findtext("severity") == "High"
        assert issues[1].findtext("severity") == "Information"

    def test_confidence_mapping(self):
        xml_str = findings_to_burp_xml(SAMPLE_FINDINGS)
        root = ET.fromstring(xml_str)
        issues = root.findall("issue")
        assert issues[0].findtext("confidence") == "Certain"
        assert issues[1].findtext("confidence") == "Tentative"

    def test_host_and_path_extracted(self):
        xml_str = findings_to_burp_xml(SAMPLE_FINDINGS)
        root = ET.fromstring(xml_str)
        issue = root.findall("issue")[0]
        assert "example.com" in (issue.findtext("host") or "")
        assert issue.findtext("path") == "/api/login"

    def test_request_base64_encoded(self):
        xml_str = findings_to_burp_xml(SAMPLE_FINDINGS)
        root = ET.fromstring(xml_str)
        issue = root.findall("issue")[0]
        rr = issue.find("requestresponse")
        assert rr is not None
        req = rr.find("request")
        assert req is not None
        assert req.get("base64") == "true"
        decoded = base64.b64decode(req.text)
        assert b"POST /api/login" in decoded

    def test_empty_findings_list(self):
        xml_str = findings_to_burp_xml([])
        root = ET.fromstring(xml_str)
        assert root.tag == "issues"
        assert len(root.findall("issue")) == 0

    def test_critical_maps_to_high(self):
        f = [{"title": "RCE", "severity": "critical", "url": "https://x.com/cmd"}]
        xml_str = findings_to_burp_xml(f)
        root = ET.fromstring(xml_str)
        assert root.findall("issue")[0].findtext("severity") == "High"

    def test_missing_url_handled(self):
        f = [{"title": "Orphan finding", "severity": "low"}]
        xml_str = findings_to_burp_xml(f)
        root = ET.fromstring(xml_str)
        assert len(root.findall("issue")) == 1


# ---------------------------------------------------------------------------
# Roundtrip tests
# ---------------------------------------------------------------------------


class TestRoundtrip:
    def test_export_then_import_preserves_titles(self):
        xml_str = findings_to_burp_xml(SAMPLE_FINDINGS)
        issues = parse_burp_xml(xml_str)
        assert len(issues) == len(SAMPLE_FINDINGS)
        for orig, imported in zip(SAMPLE_FINDINGS, issues, strict=True):
            assert imported.name == orig["title"]

    def test_export_then_import_preserves_severities(self):
        xml_str = findings_to_burp_xml(SAMPLE_FINDINGS)
        issues = parse_burp_xml(xml_str)
        expected_burp_sevs = ["High", "Information"]
        for expected, imported in zip(expected_burp_sevs, issues, strict=True):
            assert imported.severity == expected

    def test_roundtrip_numasec_conversion(self):
        """export → import → to_numasec_finding → check severity preserved."""
        xml_str = findings_to_burp_xml(SAMPLE_FINDINGS)
        issues = parse_burp_xml(xml_str)
        converted = [i.to_numasec_finding() for i in issues]
        assert converted[0]["severity"] == "high"
        assert converted[1]["severity"] == "info"


# ---------------------------------------------------------------------------
# parse_burp_sitemap tests
# ---------------------------------------------------------------------------


class TestParseBurpSitemap:
    def test_parse_endpoints(self):
        endpoints = parse_burp_sitemap(BURP_SITEMAP_XML)
        assert len(endpoints) == 3

    def test_endpoint_fields(self):
        endpoints = parse_burp_sitemap(BURP_SITEMAP_XML)
        first = endpoints[0]
        assert first["url"] == "https://example.com/api/v1/users"
        assert first["method"] == "GET"
        assert first["host"] == "example.com"
        assert first["port"] == 443
        assert first["protocol"] == "https"
        assert first["status_code"] == 200

    def test_post_method(self):
        endpoints = parse_burp_sitemap(BURP_SITEMAP_XML)
        login = endpoints[1]
        assert login["method"] == "POST"
        assert login["path"] == "/api/v1/login"

    def test_mimetype_preserved(self):
        endpoints = parse_burp_sitemap(BURP_SITEMAP_XML)
        js = endpoints[2]
        assert js["mimetype"] == "application/javascript"

    def test_empty_returns_empty(self):
        assert parse_burp_sitemap("") == []

    def test_malformed_returns_empty(self):
        assert parse_burp_sitemap("<broken>") == []

    def test_constructs_url_from_components(self):
        xml = """\
<items>
  <item>
    <host>myhost.com</host>
    <port>8080</port>
    <protocol>http</protocol>
    <path>/admin</path>
    <method>GET</method>
  </item>
</items>"""
        endpoints = parse_burp_sitemap(xml)
        assert len(endpoints) == 1
        assert endpoints[0]["url"] == "http://myhost.com:8080/admin"

    def test_standard_port_no_suffix(self):
        xml = """\
<items>
  <item>
    <host>myhost.com</host>
    <port>443</port>
    <protocol>https</protocol>
    <path>/</path>
    <method>GET</method>
  </item>
</items>"""
        endpoints = parse_burp_sitemap(xml)
        assert ":443" not in endpoints[0]["url"]

    def test_single_item_root(self):
        xml = "<item><url>http://x.com/a</url><host>x.com</host><path>/a</path><method>GET</method></item>"
        endpoints = parse_burp_sitemap(xml)
        assert len(endpoints) == 1


# ---------------------------------------------------------------------------
# Confidence helper tests
# ---------------------------------------------------------------------------


class TestConfidenceMapping:
    def test_certain(self):
        assert _confidence_to_burp(1.0) == "Certain"

    def test_firm(self):
        assert _confidence_to_burp(0.8) == "Firm"
        assert _confidence_to_burp(0.7) == "Firm"

    def test_tentative(self):
        assert _confidence_to_burp(0.5) == "Tentative"
        assert _confidence_to_burp(0.0) == "Tentative"


# ---------------------------------------------------------------------------
# MCP tool wrapper tests
# ---------------------------------------------------------------------------


class TestPythonBurpBridge:
    async def test_import_issues(self):
        result_str = await python_burp_bridge(action="import_issues", data=BURP_ISSUES_XML)
        result = json.loads(result_str)
        assert result["status"] == "findings"
        assert result["tool"] == "burp_bridge"
        assert result["imported_count"] == 4
        assert len(result["findings"]) == 4

    async def test_import_issues_empty(self):
        result_str = await python_burp_bridge(action="import_issues", data="")
        result = json.loads(result_str)
        assert result["imported_count"] == 0

    async def test_export_findings(self):
        findings_json = json.dumps(SAMPLE_FINDINGS)
        result_str = await python_burp_bridge(action="export_findings", findings=findings_json)
        result = json.loads(result_str)
        assert result["status"] == "ok"
        assert result["exported_count"] == 2
        assert "xml" in result
        # Verify the XML is parseable
        ET.fromstring(result["xml"])

    async def test_export_findings_bad_json(self):
        result_str = await python_burp_bridge(action="export_findings", findings="not json!")
        result = json.loads(result_str)
        assert "error" in result

    async def test_export_findings_empty(self):
        result_str = await python_burp_bridge(action="export_findings", findings="[]")
        result = json.loads(result_str)
        assert result["exported_count"] == 0

    async def test_import_sitemap(self):
        result_str = await python_burp_bridge(action="import_sitemap", data=BURP_SITEMAP_XML)
        result = json.loads(result_str)
        assert result["status"] == "ok"
        assert result["endpoint_count"] == 3
        assert len(result["endpoints"]) == 3

    async def test_unknown_action(self):
        result_str = await python_burp_bridge(action="invalid_action")
        result = json.loads(result_str)
        assert "error" in result
        assert "Unknown action" in result["error"]

    async def test_import_issues_severity_in_findings(self):
        result_str = await python_burp_bridge(action="import_issues", data=BURP_ISSUES_XML)
        result = json.loads(result_str)
        severities = [f["severity"] for f in result["findings"]]
        assert severities == ["high", "medium", "low", "info"]

    async def test_export_then_import_roundtrip(self):
        """Full roundtrip through the MCP tool wrapper."""
        findings_json = json.dumps(SAMPLE_FINDINGS)
        export_str = await python_burp_bridge(action="export_findings", findings=findings_json)
        export_result = json.loads(export_str)
        xml_content = export_result["xml"]

        import_str = await python_burp_bridge(action="import_issues", data=xml_content)
        import_result = json.loads(import_str)
        assert import_result["imported_count"] == len(SAMPLE_FINDINGS)
        titles = [f["title"] for f in import_result["findings"]]
        assert SAMPLE_FINDINGS[0]["title"] in titles
