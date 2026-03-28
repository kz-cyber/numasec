"""Tests for numasec.scanners.poc_validator — PoC validation framework."""

from __future__ import annotations

import json

import httpx
import pytest

from numasec.scanners.poc_validator import (
    PocResult,
    PocValidator,
    ValidationResult,
    python_poc_validate,
)

# ---------------------------------------------------------------------------
# Helpers — httpx.MockTransport factories
# ---------------------------------------------------------------------------


def _make_transport(handler):
    """Wrap a sync handler into an httpx.MockTransport."""
    return httpx.MockTransport(handler)


def _text_response(
    body: str,
    status_code: int = 200,
    headers: dict[str, str] | None = None,
) -> httpx.Response:
    return httpx.Response(status_code, text=body, headers=headers or {})


def _patch_client(handler):
    """Monkeypatch httpx.AsyncClient to use a MockTransport."""
    original_init = httpx.AsyncClient.__init__

    def patched_init(self_client, **kwargs):
        kwargs["transport"] = _make_transport(handler)
        kwargs.pop("proxy", None)
        original_init(self_client, **kwargs)

    return original_init, patched_init


# ---------------------------------------------------------------------------
# PocResult / ValidationResult data model tests
# ---------------------------------------------------------------------------


class TestDataModels:
    def test_poc_result_defaults(self):
        r = PocResult(finding_id="f-1", validated=False, confidence=0.0)
        d = r.to_dict()
        assert d["finding_id"] == "f-1"
        assert d["validated"] is False
        assert d["confidence"] == 0.0
        assert d["evidence"] == ""
        assert d["technique"] == ""

    def test_poc_result_full(self):
        r = PocResult(
            finding_id="f-2",
            validated=True,
            confidence=0.9,
            evidence="SQL error found",
            request_dump="GET /page?id=1'",
            response_status=500,
            response_snippet="error in SQL",
            technique="sqli_error",
        )
        d = r.to_dict()
        assert d["validated"] is True
        assert d["confidence"] == 0.9
        assert d["response_status"] == 500

    def test_validation_result_empty(self):
        v = ValidationResult(target="http://example.com")
        d = v.to_dict()
        assert d["target"] == "http://example.com"
        assert d["total_tested"] == 0
        assert d["summary"] == "No findings tested"

    def test_validation_result_with_results(self):
        v = ValidationResult(
            target="http://example.com",
            total_tested=3,
            validated=2,
            failed=1,
            results=[
                PocResult(finding_id="f-1", validated=True, confidence=0.9),
                PocResult(finding_id="f-2", validated=True, confidence=0.8),
                PocResult(finding_id="f-3", validated=False, confidence=0.0),
            ],
        )
        d = v.to_dict()
        assert d["validated"] == 2
        assert d["failed"] == 1
        assert len(d["results"]) == 3
        assert d["summary"] == "2/3 findings validated"


# ---------------------------------------------------------------------------
# CWE-89: SQL Injection validation
# ---------------------------------------------------------------------------


class TestSqliValidation:
    @pytest.mark.asyncio
    async def test_sqli_error_detected(self):
        """SQL error in response → validated with high confidence."""

        def handler(request: httpx.Request) -> httpx.Response:
            url_str = str(request.url)
            if "'" in url_str or "%27" in url_str:
                return _text_response(
                    "You have an error in your SQL syntax near '1''",
                    status_code=500,
                )
            return _text_response("<html>Normal page</html>")

        original_init, patched_init = _patch_client(handler)
        httpx.AsyncClient.__init__ = patched_init
        try:
            validator = PocValidator(timeout=5.0)
            result = await validator.validate({
                "id": "sqli-1",
                "cwe_id": "CWE-89",
                "url": "http://target/search?q=test",
                "parameter": "q",
                "payload": "' OR '1'='1",
            })
        finally:
            httpx.AsyncClient.__init__ = original_init

        assert result.validated is True
        assert result.confidence >= 0.8
        assert "SQL error" in result.evidence
        assert result.technique == "sqli_error"
        assert result.response_status == 500

    @pytest.mark.asyncio
    async def test_sqli_boolean_detected(self):
        """Significant content length change → boolean-based SQLi."""

        def handler(request: httpx.Request) -> httpx.Response:
            url_str = str(request.url)
            if "'" in url_str or "%27" in url_str:
                return _text_response("A" * 5000)  # Much larger response
            return _text_response("Short response")

        original_init, patched_init = _patch_client(handler)
        httpx.AsyncClient.__init__ = patched_init
        try:
            validator = PocValidator(timeout=5.0)
            result = await validator.validate({
                "id": "sqli-2",
                "cwe_id": "CWE-89",
                "url": "http://target/search?q=test",
                "parameter": "q",
                "payload": "' OR '1'='1",
            })
        finally:
            httpx.AsyncClient.__init__ = original_init

        assert result.validated is True
        assert result.technique == "sqli_boolean"

    @pytest.mark.asyncio
    async def test_sqli_not_validated(self):
        """Identical responses → not validated."""

        def handler(request: httpx.Request) -> httpx.Response:
            return _text_response("<html>Normal page</html>")

        original_init, patched_init = _patch_client(handler)
        httpx.AsyncClient.__init__ = patched_init
        try:
            validator = PocValidator(timeout=5.0)
            result = await validator.validate({
                "id": "sqli-3",
                "cwe_id": "CWE-89",
                "url": "http://target/search?q=test",
                "parameter": "q",
                "payload": "' OR '1'='1",
            })
        finally:
            httpx.AsyncClient.__init__ = original_init

        assert result.validated is False
        assert result.technique == "sqli"


# ---------------------------------------------------------------------------
# CWE-79: XSS validation
# ---------------------------------------------------------------------------


class TestXssValidation:
    @pytest.mark.asyncio
    async def test_xss_reflected_detected(self):
        """Payload reflected unescaped → validated."""

        def handler(request: httpx.Request) -> httpx.Response:
            url_str = str(request.url)
            if "script" in url_str.lower():
                return _text_response(
                    '<html><body>Search: <script>alert(1)</script></body></html>',
                    headers={"content-type": "text/html"},
                )
            return _text_response("<html>Normal</html>")

        original_init, patched_init = _patch_client(handler)
        httpx.AsyncClient.__init__ = patched_init
        try:
            validator = PocValidator(timeout=5.0)
            result = await validator.validate({
                "id": "xss-1",
                "cwe_id": "CWE-79",
                "url": "http://target/search?q=test",
                "parameter": "q",
                "payload": "<script>alert(1)</script>",
            })
        finally:
            httpx.AsyncClient.__init__ = original_init

        assert result.validated is True
        assert result.confidence >= 0.8
        assert result.technique == "xss_reflected"

    @pytest.mark.asyncio
    async def test_xss_not_reflected(self):
        """Payload is HTML-encoded → not validated."""

        def handler(request: httpx.Request) -> httpx.Response:
            return _text_response(
                "<html>&lt;script&gt;alert(1)&lt;/script&gt;</html>",
                headers={"content-type": "text/html"},
            )

        original_init, patched_init = _patch_client(handler)
        httpx.AsyncClient.__init__ = patched_init
        try:
            validator = PocValidator(timeout=5.0)
            result = await validator.validate({
                "id": "xss-2",
                "cwe_id": "CWE-79",
                "url": "http://target/search?q=test",
                "parameter": "q",
                "payload": "<script>alert(1)</script>",
            })
        finally:
            httpx.AsyncClient.__init__ = original_init

        assert result.validated is False
        assert result.technique == "xss"


# ---------------------------------------------------------------------------
# CWE-22: LFI / Path Traversal validation
# ---------------------------------------------------------------------------


class TestLfiValidation:
    @pytest.mark.asyncio
    async def test_lfi_passwd_detected(self):
        """/etc/passwd content in response → validated."""

        def handler(request: httpx.Request) -> httpx.Response:
            url_str = str(request.url)
            if ".." in url_str or "%2e%2e" in url_str.lower():
                return _text_response(
                    "root:x:0:0:root:/root:/bin/bash\n"
                    "daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n"
                    "nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin\n"
                )
            return _text_response("<html>Normal page</html>")

        original_init, patched_init = _patch_client(handler)
        httpx.AsyncClient.__init__ = patched_init
        try:
            validator = PocValidator(timeout=5.0)
            result = await validator.validate({
                "id": "lfi-1",
                "cwe_id": "CWE-22",
                "url": "http://target/read?file=readme.txt",
                "parameter": "file",
                "payload": "../../../etc/passwd",
            })
        finally:
            httpx.AsyncClient.__init__ = original_init

        assert result.validated is True
        assert result.confidence >= 0.8
        assert result.technique == "lfi_marker"
        assert "root:" in result.evidence

    @pytest.mark.asyncio
    async def test_lfi_not_detected(self):
        """No /etc/passwd markers → not validated."""

        def handler(request: httpx.Request) -> httpx.Response:
            return _text_response("<html>File not found</html>", status_code=404)

        original_init, patched_init = _patch_client(handler)
        httpx.AsyncClient.__init__ = patched_init
        try:
            validator = PocValidator(timeout=5.0)
            result = await validator.validate({
                "id": "lfi-2",
                "cwe_id": "CWE-22",
                "url": "http://target/read?file=readme.txt",
                "parameter": "file",
                "payload": "../../../etc/passwd",
            })
        finally:
            httpx.AsyncClient.__init__ = original_init

        assert result.validated is False

    @pytest.mark.asyncio
    async def test_lfi_size_diff_fallback(self):
        """Large size difference with traversal payload → low-confidence validation."""

        def handler(request: httpx.Request) -> httpx.Response:
            url_str = str(request.url)
            if ".." in url_str:
                return _text_response("X" * 10000)  # Much larger, no markers
            return _text_response("Small content")

        original_init, patched_init = _patch_client(handler)
        httpx.AsyncClient.__init__ = patched_init
        try:
            validator = PocValidator(timeout=5.0)
            result = await validator.validate({
                "id": "lfi-3",
                "cwe_id": "CWE-22",
                "url": "http://target/read?file=readme.txt",
                "parameter": "file",
                "payload": "../../../etc/passwd",
            })
        finally:
            httpx.AsyncClient.__init__ = original_init

        assert result.validated is True
        assert result.technique == "lfi_size_diff"
        assert result.confidence < 0.8


# ---------------------------------------------------------------------------
# CWE-918: SSRF validation
# ---------------------------------------------------------------------------


class TestSsrfValidation:
    @pytest.mark.asyncio
    async def test_ssrf_cloud_metadata_detected(self):
        """Cloud metadata indicator in response → validated."""

        def handler(request: httpx.Request) -> httpx.Response:
            url_str = str(request.url)
            if "169.254.169.254" in url_str:
                return _text_response('{"ami-id": "ami-12345678", "meta-data": "iam/info"}')
            return _text_response("<html>Normal</html>")

        original_init, patched_init = _patch_client(handler)
        httpx.AsyncClient.__init__ = patched_init
        try:
            validator = PocValidator(timeout=5.0)
            result = await validator.validate({
                "id": "ssrf-1",
                "cwe_id": "CWE-918",
                "url": "http://target/proxy?url=http://example.com",
                "parameter": "url",
                "payload": "http://169.254.169.254/latest/meta-data/",
            })
        finally:
            httpx.AsyncClient.__init__ = original_init

        assert result.validated is True
        assert result.confidence >= 0.7
        assert result.technique == "ssrf_indicator"

    @pytest.mark.asyncio
    async def test_ssrf_not_detected(self):
        """No SSRF indicators → not validated."""

        def handler(request: httpx.Request) -> httpx.Response:
            return _text_response("<html>Access Denied</html>")

        original_init, patched_init = _patch_client(handler)
        httpx.AsyncClient.__init__ = patched_init
        try:
            validator = PocValidator(timeout=5.0)
            result = await validator.validate({
                "id": "ssrf-2",
                "cwe_id": "CWE-918",
                "url": "http://target/proxy?url=http://example.com",
                "parameter": "url",
                "payload": "http://169.254.169.254/latest/meta-data/",
            })
        finally:
            httpx.AsyncClient.__init__ = original_init

        assert result.validated is False


# ---------------------------------------------------------------------------
# CWE-78: Command Injection validation
# ---------------------------------------------------------------------------


class TestCmdiValidation:
    @pytest.mark.asyncio
    async def test_cmdi_id_output_detected(self):
        """'uid=0(root)' in response → validated."""

        def handler(request: httpx.Request) -> httpx.Response:
            url_str = str(request.url)
            if "id" in url_str and (";" in url_str or "|" in url_str or "%7C" in url_str or "%3B" in url_str):
                return _text_response("uid=0(root) gid=0(root) groups=0(root)")
            return _text_response("<html>Normal</html>")

        original_init, patched_init = _patch_client(handler)
        httpx.AsyncClient.__init__ = patched_init
        try:
            validator = PocValidator(timeout=5.0)
            result = await validator.validate({
                "id": "cmdi-1",
                "cwe_id": "CWE-78",
                "url": "http://target/ping?host=127.0.0.1",
                "parameter": "host",
                "payload": "; id",
            })
        finally:
            httpx.AsyncClient.__init__ = original_init

        assert result.validated is True
        assert result.confidence >= 0.8
        assert result.technique == "cmdi_output"
        assert "uid=0" in result.evidence

    @pytest.mark.asyncio
    async def test_cmdi_not_detected(self):
        """No command output → not validated."""

        def handler(request: httpx.Request) -> httpx.Response:
            return _text_response("<html>Ping result: OK</html>")

        original_init, patched_init = _patch_client(handler)
        httpx.AsyncClient.__init__ = patched_init
        try:
            validator = PocValidator(timeout=5.0)
            result = await validator.validate({
                "id": "cmdi-2",
                "cwe_id": "CWE-78",
                "url": "http://target/ping?host=127.0.0.1",
                "parameter": "host",
                "payload": "; id",
            })
        finally:
            httpx.AsyncClient.__init__ = original_init

        assert result.validated is False


# ---------------------------------------------------------------------------
# CWE-113: CRLF Injection validation
# ---------------------------------------------------------------------------


class TestCrlfValidation:
    @pytest.mark.asyncio
    async def test_crlf_header_detected(self):
        """Injected header in response → validated with high confidence."""

        def handler(request: httpx.Request) -> httpx.Response:
            url_str = str(request.url)
            if "numasec" in url_str.lower():
                return _text_response(
                    "<html>OK</html>",
                    headers={"X-Injected": "numasec-poc"},
                )
            return _text_response("<html>OK</html>")

        original_init, patched_init = _patch_client(handler)
        httpx.AsyncClient.__init__ = patched_init
        try:
            validator = PocValidator(timeout=5.0)
            result = await validator.validate({
                "id": "crlf-1",
                "cwe_id": "CWE-113",
                "url": "http://target/redirect?url=http://example.com",
                "parameter": "url",
                "payload": "%0d%0aX-Injected: numasec-poc",
            })
        finally:
            httpx.AsyncClient.__init__ = original_init

        assert result.validated is True
        assert result.confidence >= 0.9
        assert result.technique == "crlf_header"
        assert "x-injected" in result.evidence.lower()

    @pytest.mark.asyncio
    async def test_crlf_body_splitting_detected(self):
        """Marker in body → response splitting detected."""

        def handler(request: httpx.Request) -> httpx.Response:
            url_str = str(request.url)
            if "numasec" in url_str.lower():
                return _text_response("<html>OK numasec-poc injected</html>")
            return _text_response("<html>OK</html>")

        original_init, patched_init = _patch_client(handler)
        httpx.AsyncClient.__init__ = patched_init
        try:
            validator = PocValidator(timeout=5.0)
            result = await validator.validate({
                "id": "crlf-2",
                "cwe_id": "CWE-113",
                "url": "http://target/redirect?url=http://example.com",
                "parameter": "url",
                "payload": "%0d%0aX-Injected: numasec-poc",
            })
        finally:
            httpx.AsyncClient.__init__ = original_init

        assert result.validated is True
        assert result.technique == "crlf_splitting"

    @pytest.mark.asyncio
    async def test_crlf_not_detected(self):
        """No injected headers or body markers → not validated."""

        def handler(request: httpx.Request) -> httpx.Response:
            return _text_response("<html>Normal page</html>")

        original_init, patched_init = _patch_client(handler)
        httpx.AsyncClient.__init__ = patched_init
        try:
            validator = PocValidator(timeout=5.0)
            result = await validator.validate({
                "id": "crlf-3",
                "cwe_id": "CWE-113",
                "url": "http://target/redirect?url=http://example.com",
                "parameter": "url",
                "payload": "%0d%0aX-Injected: numasec-poc",
            })
        finally:
            httpx.AsyncClient.__init__ = original_init

        assert result.validated is False


# ---------------------------------------------------------------------------
# Generic validation (unknown CWE)
# ---------------------------------------------------------------------------


class TestGenericValidation:
    @pytest.mark.asyncio
    async def test_generic_status_code_change(self):
        """Different status code → validated."""

        call_count = 0

        def handler(request: httpx.Request) -> httpx.Response:
            nonlocal call_count
            call_count += 1
            url_str = str(request.url)
            if "payload" in url_str:
                return _text_response("<html>Error</html>", status_code=500)
            return _text_response("<html>Normal</html>")

        original_init, patched_init = _patch_client(handler)
        httpx.AsyncClient.__init__ = patched_init
        try:
            validator = PocValidator(timeout=5.0)
            result = await validator.validate({
                "id": "gen-1",
                "cwe_id": "CWE-999",
                "url": "http://target/page?id=1",
                "parameter": "id",
                "payload": "payload",
            })
        finally:
            httpx.AsyncClient.__init__ = original_init

        assert result.validated is True
        assert result.technique == "generic_status"

    @pytest.mark.asyncio
    async def test_generic_size_change(self):
        """Significant content size change → validated."""

        def handler(request: httpx.Request) -> httpx.Response:
            url_str = str(request.url)
            if "payload" in url_str:
                return _text_response("X" * 5000)
            return _text_response("Short")

        original_init, patched_init = _patch_client(handler)
        httpx.AsyncClient.__init__ = patched_init
        try:
            validator = PocValidator(timeout=5.0)
            result = await validator.validate({
                "id": "gen-2",
                "cwe_id": "CWE-999",
                "url": "http://target/page?id=1",
                "parameter": "id",
                "payload": "payload",
            })
        finally:
            httpx.AsyncClient.__init__ = original_init

        assert result.validated is True
        assert result.technique == "generic_size"

    @pytest.mark.asyncio
    async def test_generic_reflection(self):
        """Payload reflected in exploit response only → validated."""

        def handler(request: httpx.Request) -> httpx.Response:
            url_str = str(request.url)
            if "INJECTED" in url_str:
                return _text_response("<html>Result: INJECTED</html>")
            return _text_response("<html>Result: normal</html>")

        original_init, patched_init = _patch_client(handler)
        httpx.AsyncClient.__init__ = patched_init
        try:
            validator = PocValidator(timeout=5.0)
            result = await validator.validate({
                "id": "gen-3",
                "cwe_id": "",
                "url": "http://target/page?id=1",
                "parameter": "id",
                "payload": "INJECTED",
            })
        finally:
            httpx.AsyncClient.__init__ = original_init

        assert result.validated is True
        assert result.technique == "generic_reflection"

    @pytest.mark.asyncio
    async def test_generic_no_difference(self):
        """Same responses → not validated."""

        def handler(request: httpx.Request) -> httpx.Response:
            return _text_response("<html>Same page</html>")

        original_init, patched_init = _patch_client(handler)
        httpx.AsyncClient.__init__ = patched_init
        try:
            validator = PocValidator(timeout=5.0)
            result = await validator.validate({
                "id": "gen-4",
                "cwe_id": "",
                "url": "http://target/page?id=1",
                "parameter": "id",
                "payload": "test",
            })
        finally:
            httpx.AsyncClient.__init__ = original_init

        assert result.validated is False

    @pytest.mark.asyncio
    async def test_generic_missing_fields(self):
        """Missing url/parameter/payload → not validated."""
        validator = PocValidator(timeout=5.0)
        result = await validator.validate({
            "id": "gen-5",
            "cwe_id": "",
            "url": "",
            "parameter": "",
            "payload": "",
        })
        assert result.validated is False
        assert "Insufficient" in result.evidence


# ---------------------------------------------------------------------------
# Multiple findings validation
# ---------------------------------------------------------------------------


class TestMultipleFindings:
    @pytest.mark.asyncio
    async def test_validate_multiple_findings(self):
        """Batch validation of several findings."""

        def handler(request: httpx.Request) -> httpx.Response:
            url_str = str(request.url)
            if "'" in url_str or "%27" in url_str:
                return _text_response("You have an error in your SQL syntax")
            if "script" in url_str.lower():
                return _text_response(
                    '<html><script>alert(1)</script></html>',
                    headers={"content-type": "text/html"},
                )
            return _text_response("<html>Normal</html>")

        findings = [
            {
                "id": "f-sqli",
                "cwe_id": "CWE-89",
                "url": "http://target/search?q=test",
                "parameter": "q",
                "payload": "' OR '1'='1",
            },
            {
                "id": "f-xss",
                "cwe_id": "CWE-79",
                "url": "http://target/search?q=test",
                "parameter": "q",
                "payload": "<script>alert(1)</script>",
            },
        ]

        original_init, patched_init = _patch_client(handler)
        httpx.AsyncClient.__init__ = patched_init
        try:
            validator = PocValidator(timeout=5.0)
            result = await validator.validate_findings(findings, target="http://target")
        finally:
            httpx.AsyncClient.__init__ = original_init

        assert result.total_tested == 2
        assert result.validated == 2
        assert result.failed == 0
        d = result.to_dict()
        assert d["summary"] == "2/2 findings validated"

    @pytest.mark.asyncio
    async def test_validate_mixed_results(self):
        """Some validated, some not."""

        def handler(request: httpx.Request) -> httpx.Response:
            url_str = str(request.url)
            if "'" in url_str or "%27" in url_str:
                return _text_response("You have an error in your SQL syntax")
            return _text_response("<html>Normal</html>")

        findings = [
            {
                "id": "f-sqli",
                "cwe_id": "CWE-89",
                "url": "http://target/search?q=test",
                "parameter": "q",
                "payload": "' OR '1'='1",
            },
            {
                "id": "f-xss",
                "cwe_id": "CWE-79",
                "url": "http://target/search?q=test",
                "parameter": "q",
                "payload": "<img src=x onerror=alert(1)>",
            },
        ]

        original_init, patched_init = _patch_client(handler)
        httpx.AsyncClient.__init__ = patched_init
        try:
            validator = PocValidator(timeout=5.0)
            result = await validator.validate_findings(findings, target="http://target")
        finally:
            httpx.AsyncClient.__init__ = original_init

        assert result.total_tested == 2
        assert result.validated == 1
        assert result.failed == 1


# ---------------------------------------------------------------------------
# Tool wrapper (python_poc_validate)
# ---------------------------------------------------------------------------


class TestToolWrapper:
    @pytest.mark.asyncio
    async def test_json_output(self):
        """Tool returns valid JSON with envelope."""

        def handler(request: httpx.Request) -> httpx.Response:
            url_str = str(request.url)
            if "'" in url_str or "%27" in url_str:
                return _text_response("You have an error in your SQL syntax")
            return _text_response("<html>Normal</html>")

        findings = [
            {
                "id": "f-1",
                "cwe_id": "CWE-89",
                "url": "http://target/page?id=1",
                "parameter": "id",
                "payload": "'",
            },
        ]

        original_init, patched_init = _patch_client(handler)
        httpx.AsyncClient.__init__ = patched_init
        try:
            raw = await python_poc_validate(
                findings=json.dumps(findings),
                timeout=5.0,
            )
        finally:
            httpx.AsyncClient.__init__ = original_init

        data = json.loads(raw)
        assert data["tool"] == "poc_validate"
        assert data["target"] == "http://target/page?id=1"
        assert "results" in data
        assert data["validated"] >= 1

    @pytest.mark.asyncio
    async def test_url_override(self):
        """URL parameter overrides missing urls in findings."""

        def handler(request: httpx.Request) -> httpx.Response:
            return _text_response("<html>OK</html>")

        findings = [
            {
                "id": "f-1",
                "cwe_id": "",
                "url": "",
                "parameter": "q",
                "payload": "test",
            },
        ]

        original_init, patched_init = _patch_client(handler)
        httpx.AsyncClient.__init__ = patched_init
        try:
            raw = await python_poc_validate(
                findings=json.dumps(findings),
                url="http://override/page?q=default",
                timeout=5.0,
            )
        finally:
            httpx.AsyncClient.__init__ = original_init

        data = json.loads(raw)
        assert data["target"] == "http://override/page?q=default"

    @pytest.mark.asyncio
    async def test_invalid_json_findings(self):
        """Invalid JSON string returns error."""
        raw = await python_poc_validate(findings="not valid json")
        data = json.loads(raw)
        assert "error" in data

    @pytest.mark.asyncio
    async def test_non_array_findings(self):
        """Non-array findings returns error."""
        raw = await python_poc_validate(findings='{"not": "an array"}')
        data = json.loads(raw)
        assert "error" in data

    @pytest.mark.asyncio
    async def test_empty_findings(self):
        """Empty array returns zero-tested result."""
        raw = await python_poc_validate(findings="[]")
        data = json.loads(raw)
        assert data["total_tested"] == 0


# ---------------------------------------------------------------------------
# Error handling
# ---------------------------------------------------------------------------


class TestErrorHandling:
    @pytest.mark.asyncio
    async def test_connection_error_handled(self):
        """Connection error doesn't crash; produces graceful not-validated result."""

        def handler(request: httpx.Request) -> httpx.Response:
            raise httpx.ConnectError("Connection refused")

        original_init, patched_init = _patch_client(handler)
        httpx.AsyncClient.__init__ = patched_init
        try:
            validator = PocValidator(timeout=5.0)
            result = await validator.validate({
                "id": "err-1",
                "cwe_id": "CWE-89",
                "url": "http://unreachable/page?id=1",
                "parameter": "id",
                "payload": "'",
            })
        finally:
            httpx.AsyncClient.__init__ = original_init

        assert result.validated is False
        assert result.finding_id == "err-1"

    @pytest.mark.asyncio
    async def test_timeout_handled(self):
        """Timeout doesn't crash; produces graceful not-validated result."""

        def handler(request: httpx.Request) -> httpx.Response:
            raise httpx.ReadTimeout("Read timed out")

        original_init, patched_init = _patch_client(handler)
        httpx.AsyncClient.__init__ = patched_init
        try:
            validator = PocValidator(timeout=1.0)
            result = await validator.validate({
                "id": "err-2",
                "cwe_id": "CWE-79",
                "url": "http://slow/page?q=test",
                "parameter": "q",
                "payload": "<script>alert(1)</script>",
            })
        finally:
            httpx.AsyncClient.__init__ = original_init

        assert result.validated is False
        assert result.finding_id == "err-2"

    @pytest.mark.asyncio
    async def test_finding_id_fallback(self):
        """Finding without 'id' uses 'finding_id' or 'unknown'."""
        validator = PocValidator(timeout=5.0)

        result = await validator.validate({
            "finding_id": "alt-id",
            "cwe_id": "",
            "url": "",
            "parameter": "",
            "payload": "",
        })
        assert result.finding_id == "alt-id"

        result2 = await validator.validate({
            "cwe_id": "",
            "url": "",
            "parameter": "",
            "payload": "",
        })
        assert result2.finding_id == "unknown"

    @pytest.mark.asyncio
    async def test_cwe_field_alias(self):
        """'cwe' field works as alias for 'cwe_id'."""

        def handler(request: httpx.Request) -> httpx.Response:
            url_str = str(request.url)
            if "'" in url_str or "%27" in url_str:
                return _text_response("You have an error in your SQL syntax")
            return _text_response("<html>Normal</html>")

        original_init, patched_init = _patch_client(handler)
        httpx.AsyncClient.__init__ = patched_init
        try:
            validator = PocValidator(timeout=5.0)
            result = await validator.validate({
                "id": "alias-1",
                "cwe": "CWE-89",
                "url": "http://target/search?q=test",
                "parameter": "q",
                "payload": "'",
            })
        finally:
            httpx.AsyncClient.__init__ = original_init

        assert result.validated is True
        assert "sqli" in result.technique
