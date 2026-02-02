"""
NumaSec - CWE Mapper

Comprehensive CWE (Common Weakness Enumeration) database and mapper.
Reference: https://cwe.mitre.org/

Provides:
- Lookup by CWE ID
- Suggestion from vulnerability description
- OWASP Top 10 mapping
- Common pentest vulnerability mapping
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Any


# ══════════════════════════════════════════════════════════════════════════════
# Data Classes
# ══════════════════════════════════════════════════════════════════════════════


class CWECategory(str, Enum):
    """High-level CWE categories."""
    INJECTION = "Injection"
    BROKEN_AUTH = "Broken Authentication"
    SENSITIVE_DATA = "Sensitive Data Exposure"
    XXE = "XML External Entities"
    BROKEN_ACCESS = "Broken Access Control"
    MISCONFIGURATION = "Security Misconfiguration"
    XSS = "Cross-Site Scripting"
    DESERIALIZATION = "Insecure Deserialization"
    COMPONENTS = "Using Components with Known Vulnerabilities"
    LOGGING = "Insufficient Logging & Monitoring"
    SSRF = "Server-Side Request Forgery"
    CRYPTO = "Cryptographic Failures"
    OTHER = "Other"


@dataclass
class CWEEntry:
    """A single CWE entry."""
    
    id: str                          # e.g., "CWE-89"
    name: str                        # Short name
    description: str                 # Full description
    category: CWECategory = CWECategory.OTHER  # High-level category
    owasp_top_10: str | None = None  # e.g., "A03:2021"
    remediation: str = ""            # How to fix
    examples: list[str] = field(default_factory=list)
    related_cwes: list[str] = field(default_factory=list)
    keywords: list[str] = field(default_factory=list)  # For suggestion matching
    url: str | None = None           # Optional URL to CWE definition
    
    def __post_init__(self) -> None:
        """Generate URL if not provided."""
        if self.url is None:
            # Extract number from CWE-XX format
            cwe_num = self.id.replace("CWE-", "").replace("cwe-", "")
            self.url = f"https://cwe.mitre.org/data/definitions/{cwe_num}.html"
    
    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "id": self.id,
            "name": self.name,
            "description": self.description,
            "category": self.category.value,
            "owasp_top_10": self.owasp_top_10,
            "remediation": self.remediation,
            "examples": self.examples,
            "related_cwes": self.related_cwes,
            "url": self.url,
        }
    
    def model_dump(self) -> dict[str, Any]:
        """Pydantic-style serialization (alias for to_dict)."""
        return self.to_dict()


# ══════════════════════════════════════════════════════════════════════════════
# CWE Database - Top 100+ Most Common Vulnerabilities
# ══════════════════════════════════════════════════════════════════════════════


CWE_DATABASE: dict[str, CWEEntry] = {
    # ──────────────────────────────────────────────────────────────────────────
    # Injection (OWASP A03:2021)
    # ──────────────────────────────────────────────────────────────────────────
    "CWE-89": CWEEntry(
        id="CWE-89",
        name="SQL Injection",
        description="The software constructs all or part of an SQL command using externally-influenced input from an upstream component, but it does not neutralize or incorrectly neutralizes special elements that could modify the intended SQL command.",
        category=CWECategory.INJECTION,
        owasp_top_10="A03:2021",
        remediation="Use parameterized queries or prepared statements. Never concatenate user input into SQL queries.",
        examples=["SELECT * FROM users WHERE id = '" + "user_input" + "'"],
        related_cwes=["CWE-564", "CWE-566"],
        keywords=["sql", "query", "database", "injection", "union", "select", "insert", "update", "delete", "drop", "truncate"],
    ),
    "CWE-78": CWEEntry(
        id="CWE-78",
        name="OS Command Injection",
        description="The software constructs all or part of an OS command using externally-influenced input from an upstream component, but it does not neutralize or incorrectly neutralizes special elements that could modify the intended OS command.",
        category=CWECategory.INJECTION,
        owasp_top_10="A03:2021",
        remediation="Avoid OS commands if possible. If necessary, use allowlists and strict input validation. Never pass user input directly to shell.",
        examples=["os.system('ping ' + user_input)", "subprocess.call(user_input, shell=True)"],
        related_cwes=["CWE-77", "CWE-88"],
        keywords=["command", "shell", "os", "exec", "system", "popen", "subprocess", "backtick", "pipe", "rce"],
    ),
    "CWE-77": CWEEntry(
        id="CWE-77",
        name="Command Injection",
        description="The software constructs all or part of a command using externally-influenced input from an upstream component, but it does not neutralize or incorrectly neutralizes special elements that could modify the intended command.",
        category=CWECategory.INJECTION,
        owasp_top_10="A03:2021",
        remediation="Use APIs that don't invoke shell interpreters. Validate and sanitize all input.",
        examples=["eval(user_input)", "new Function(user_input)"],
        related_cwes=["CWE-78", "CWE-94"],
        keywords=["command", "injection", "eval", "execute"],
    ),
    "CWE-94": CWEEntry(
        id="CWE-94",
        name="Improper Control of Generation of Code ('Code Injection')",
        description="The software constructs all or part of a code segment using externally-influenced input from an upstream component, but it does not neutralize or incorrectly neutralizes special elements that could modify the syntax or behavior of the intended code segment.",
        category=CWECategory.INJECTION,
        owasp_top_10="A03:2021",
        remediation="Avoid dynamic code generation with user input. Use sandboxing if unavoidable.",
        examples=["exec(user_input)", "eval(user_input)"],
        related_cwes=["CWE-95", "CWE-96"],
        keywords=["code", "injection", "eval", "exec", "dynamic"],
    ),
    "CWE-90": CWEEntry(
        id="CWE-90",
        name="LDAP Injection",
        description="The software constructs all or part of an LDAP query using externally-influenced input from an upstream component, but it does not neutralize or incorrectly neutralizes special elements that could modify the intended LDAP query.",
        category=CWECategory.INJECTION,
        owasp_top_10="A03:2021",
        remediation="Use parameterized LDAP queries. Escape special LDAP characters.",
        examples=["(&(uid=" + "user_input" + ")(password=*))"],
        related_cwes=["CWE-89"],
        keywords=["ldap", "directory", "active directory", "filter"],
    ),
    "CWE-643": CWEEntry(
        id="CWE-643",
        name="XPath Injection",
        description="The software uses external input to dynamically construct an XPath expression used to retrieve data from an XML document, but it does not neutralize or incorrectly neutralizes that input.",
        category=CWECategory.INJECTION,
        owasp_top_10="A03:2021",
        remediation="Use parameterized XPath queries or precompiled XPath expressions.",
        examples=["//users/user[name='" + "user_input" + "']"],
        related_cwes=["CWE-91"],
        keywords=["xpath", "xml", "query", "path"],
    ),
    "CWE-917": CWEEntry(
        id="CWE-917",
        name="Expression Language Injection",
        description="The software constructs all or part of an expression language (EL) statement in a Java Server Pages (JSP) using externally-influenced input, but it does not neutralize special elements.",
        category=CWECategory.INJECTION,
        owasp_top_10="A03:2021",
        remediation="Avoid dynamic EL expressions with user input. Use strict input validation.",
        examples=["${user_input}"],
        related_cwes=["CWE-94"],
        keywords=["expression", "el", "jsp", "template", "jinja", "ssti", "freemarker", "thymeleaf", "velocity"],
    ),
    
    # ──────────────────────────────────────────────────────────────────────────
    # Cross-Site Scripting (OWASP A03:2021)
    # ──────────────────────────────────────────────────────────────────────────
    "CWE-79": CWEEntry(
        id="CWE-79",
        name="Cross-site Scripting (XSS)",
        description="The software does not neutralize or incorrectly neutralizes user-controllable input before it is placed in output that is used as a web page that is served to other users.",
        category=CWECategory.XSS,
        owasp_top_10="A03:2021",
        remediation="Encode output based on context (HTML, JavaScript, URL, CSS). Use Content-Security-Policy headers.",
        examples=["<script>alert(document.cookie)</script>", "<img src=x onerror=alert(1)>"],
        related_cwes=["CWE-80", "CWE-81", "CWE-83"],
        keywords=["xss", "cross-site", "scripting", "javascript", "script", "html", "dom", "reflected", "stored", "alert"],
    ),
    "CWE-80": CWEEntry(
        id="CWE-80",
        name="Basic XSS",
        description="The software receives input from an upstream component, but it does not neutralize or incorrectly neutralizes special characters before being reflected.",
        category=CWECategory.XSS,
        owasp_top_10="A03:2021",
        remediation="HTML-encode all user input before rendering.",
        related_cwes=["CWE-79"],
        keywords=["xss", "html", "encode", "escape"],
    ),
    
    # ──────────────────────────────────────────────────────────────────────────
    # Broken Access Control (OWASP A01:2021)
    # ──────────────────────────────────────────────────────────────────────────
    "CWE-22": CWEEntry(
        id="CWE-22",
        name="Path Traversal",
        description="The software uses external input to construct a pathname that is intended to identify a file or directory that is located underneath a restricted parent directory, but the software does not properly neutralize special elements within the pathname.",
        category=CWECategory.BROKEN_ACCESS,
        owasp_top_10="A01:2021",
        remediation="Use allowlists for file paths. Canonicalize paths and verify they're within expected directory.",
        examples=["../../etc/passwd", "..\\..\\windows\\system32\\config\\sam"],
        related_cwes=["CWE-23", "CWE-36"],
        keywords=["path", "traversal", "directory", "lfi", "file", "include", "dot dot", ".."],
    ),
    "CWE-98": CWEEntry(
        id="CWE-98",
        name="Remote File Inclusion (RFI)",
        description="The software uses external input to include a file from a remote location.",
        category=CWECategory.BROKEN_ACCESS,
        owasp_top_10="A01:2021",
        remediation="Disable allow_url_include. Use allowlists for file inclusion.",
        examples=["include($_GET['file'])"],
        related_cwes=["CWE-22", "CWE-434"],
        keywords=["rfi", "remote", "include", "file"],
    ),
    "CWE-639": CWEEntry(
        id="CWE-639",
        name="Insecure Direct Object Reference (IDOR)",
        description="The system's authorization functionality does not prevent one user from gaining access to another user's data or record by modifying the key value identifying the data.",
        category=CWECategory.BROKEN_ACCESS,
        owasp_top_10="A01:2021",
        remediation="Implement proper authorization checks. Use indirect references (e.g., session-specific mapping).",
        examples=["GET /api/users/123", "GET /documents?id=456"],
        related_cwes=["CWE-284", "CWE-285"],
        keywords=["idor", "object", "reference", "authorization", "access", "user", "id"],
    ),
    "CWE-284": CWEEntry(
        id="CWE-284",
        name="Improper Access Control",
        description="The software does not restrict or incorrectly restricts access to a resource from an unauthorized actor.",
        category=CWECategory.BROKEN_ACCESS,
        owasp_top_10="A01:2021",
        remediation="Implement role-based access control. Deny by default.",
        related_cwes=["CWE-285", "CWE-639"],
        keywords=["access", "control", "authorization", "permission", "privilege"],
    ),
    "CWE-862": CWEEntry(
        id="CWE-862",
        name="Missing Authorization",
        description="The software does not perform an authorization check when an actor attempts to access a resource or perform an action.",
        category=CWECategory.BROKEN_ACCESS,
        owasp_top_10="A01:2021",
        remediation="Always verify authorization for protected resources.",
        related_cwes=["CWE-284", "CWE-863"],
        keywords=["authorization", "missing", "check", "access"],
    ),
    
    # ──────────────────────────────────────────────────────────────────────────
    # Authentication (OWASP A07:2021)
    # ──────────────────────────────────────────────────────────────────────────
    "CWE-287": CWEEntry(
        id="CWE-287",
        name="Improper Authentication",
        description="When an actor claims to have a given identity, the software does not prove or insufficiently proves that the claim is correct.",
        category=CWECategory.BROKEN_AUTH,
        owasp_top_10="A07:2021",
        remediation="Implement strong authentication. Use multi-factor authentication where possible.",
        related_cwes=["CWE-306", "CWE-798"],
        keywords=["authentication", "login", "credential", "password", "session"],
    ),
    "CWE-306": CWEEntry(
        id="CWE-306",
        name="Missing Authentication for Critical Function",
        description="The software does not perform any authentication for functionality that requires a provable user identity.",
        category=CWECategory.BROKEN_AUTH,
        owasp_top_10="A07:2021",
        remediation="Require authentication for all sensitive operations.",
        related_cwes=["CWE-287", "CWE-862"],
        keywords=["authentication", "missing", "critical", "function"],
    ),
    "CWE-384": CWEEntry(
        id="CWE-384",
        name="Session Fixation",
        description="The software regenerates the session ID after a successful authentication, allowing an attacker to hijack the authenticated session.",
        category=CWECategory.BROKEN_AUTH,
        owasp_top_10="A07:2021",
        remediation="Regenerate session ID after authentication.",
        related_cwes=["CWE-287"],
        keywords=["session", "fixation", "hijack", "cookie"],
    ),
    "CWE-798": CWEEntry(
        id="CWE-798",
        name="Use of Hard-coded Credentials",
        description="The software contains hard-coded credentials, such as a password or cryptographic key.",
        category=CWECategory.BROKEN_AUTH,
        owasp_top_10="A07:2021",
        remediation="Store credentials securely. Use environment variables or secret management.",
        related_cwes=["CWE-259", "CWE-321"],
        keywords=["hardcoded", "password", "credential", "secret", "key", "api"],
    ),
    
    # ──────────────────────────────────────────────────────────────────────────
    # SSRF (OWASP A10:2021)
    # ──────────────────────────────────────────────────────────────────────────
    "CWE-918": CWEEntry(
        id="CWE-918",
        name="Server-Side Request Forgery (SSRF)",
        description="The web server receives a URL or similar request from an upstream component and retrieves the contents of this URL, but it does not sufficiently ensure that the request is being sent to the expected destination.",
        category=CWECategory.SSRF,
        owasp_top_10="A10:2021",
        remediation="Validate and sanitize all URLs. Use allowlists for external requests. Block internal IP ranges.",
        examples=["curl http://169.254.169.254/latest/meta-data/", "http://localhost:6379/"],
        related_cwes=["CWE-441"],
        keywords=["ssrf", "server-side", "request", "forgery", "url", "fetch", "internal", "metadata"],
    ),
    
    # ──────────────────────────────────────────────────────────────────────────
    # XXE (OWASP A05:2021)
    # ──────────────────────────────────────────────────────────────────────────
    "CWE-611": CWEEntry(
        id="CWE-611",
        name="XML External Entity (XXE)",
        description="The software processes an XML document that can contain XML entities with URIs that resolve to documents outside of the intended sphere of control.",
        category=CWECategory.XXE,
        owasp_top_10="A05:2021",
        remediation="Disable external entity processing. Use JSON instead of XML where possible.",
        examples=["<!DOCTYPE foo [<!ENTITY xxe SYSTEM 'file:///etc/passwd'>]>"],
        related_cwes=["CWE-827"],
        keywords=["xxe", "xml", "entity", "external", "dtd", "doctype"],
    ),
    
    # ──────────────────────────────────────────────────────────────────────────
    # Deserialization (OWASP A08:2021)
    # ──────────────────────────────────────────────────────────────────────────
    "CWE-502": CWEEntry(
        id="CWE-502",
        name="Deserialization of Untrusted Data",
        description="The software deserializes untrusted data without sufficiently verifying that the resulting data will be valid.",
        category=CWECategory.DESERIALIZATION,
        owasp_top_10="A08:2021",
        remediation="Avoid deserializing untrusted data. Use safer formats like JSON. Implement integrity checks.",
        examples=["pickle.loads(user_input)", "ObjectInputStream.readObject()"],
        related_cwes=["CWE-94"],
        keywords=["deserialization", "pickle", "serialize", "unmarshal", "object", "java", "php", "python"],
    ),
    
    # ──────────────────────────────────────────────────────────────────────────
    # Cryptographic Failures (OWASP A02:2021)
    # ──────────────────────────────────────────────────────────────────────────
    "CWE-327": CWEEntry(
        id="CWE-327",
        name="Use of Broken or Risky Cryptographic Algorithm",
        description="The use of a broken or risky cryptographic algorithm is an unnecessary risk that may result in the exposure of sensitive information.",
        category=CWECategory.CRYPTO,
        owasp_top_10="A02:2021",
        remediation="Use modern, well-tested cryptographic algorithms (AES-256, RSA-2048+, SHA-256+).",
        examples=["MD5", "SHA1", "DES", "RC4"],
        related_cwes=["CWE-328", "CWE-326"],
        keywords=["crypto", "encryption", "hash", "md5", "sha1", "des", "weak"],
    ),
    "CWE-326": CWEEntry(
        id="CWE-326",
        name="Inadequate Encryption Strength",
        description="The software stores or transmits sensitive data using an encryption scheme that is theoretically sound, but is not strong enough for the level of protection required.",
        category=CWECategory.CRYPTO,
        owasp_top_10="A02:2021",
        remediation="Use adequate key lengths (AES-256, RSA-2048+).",
        related_cwes=["CWE-327"],
        keywords=["encryption", "key", "strength", "weak", "bits"],
    ),
    "CWE-312": CWEEntry(
        id="CWE-312",
        name="Cleartext Storage of Sensitive Information",
        description="The software stores sensitive information in cleartext within a resource that might be accessible to another control sphere.",
        category=CWECategory.SENSITIVE_DATA,
        owasp_top_10="A02:2021",
        remediation="Encrypt sensitive data at rest. Use proper key management.",
        related_cwes=["CWE-311", "CWE-319"],
        keywords=["cleartext", "plaintext", "storage", "sensitive", "password"],
    ),
    "CWE-319": CWEEntry(
        id="CWE-319",
        name="Cleartext Transmission of Sensitive Information",
        description="The software transmits sensitive or security-critical data in cleartext in a communication channel that can be sniffed by unauthorized actors.",
        category=CWECategory.SENSITIVE_DATA,
        owasp_top_10="A02:2021",
        remediation="Use TLS/HTTPS for all sensitive data transmission.",
        related_cwes=["CWE-311", "CWE-312"],
        keywords=["cleartext", "http", "transmission", "network", "sniff", "tls", "ssl"],
    ),
    
    # ──────────────────────────────────────────────────────────────────────────
    # File Upload
    # ──────────────────────────────────────────────────────────────────────────
    "CWE-434": CWEEntry(
        id="CWE-434",
        name="Unrestricted Upload of File with Dangerous Type",
        description="The software allows the attacker to upload or transfer files of dangerous types that can be automatically processed within the product's environment.",
        category=CWECategory.INJECTION,
        owasp_top_10="A04:2021",
        remediation="Validate file type, extension, and content. Store uploads outside web root. Use random filenames.",
        examples=["shell.php", "webshell.jsp", "cmd.aspx"],
        related_cwes=["CWE-78", "CWE-94"],
        keywords=["upload", "file", "extension", "mime", "shell", "webshell"],
    ),
    
    # ──────────────────────────────────────────────────────────────────────────
    # Security Misconfiguration (OWASP A05:2021)
    # ──────────────────────────────────────────────────────────────────────────
    "CWE-16": CWEEntry(
        id="CWE-16",
        name="Configuration",
        description="Weaknesses in this category are typically introduced during the configuration of the software.",
        category=CWECategory.MISCONFIGURATION,
        owasp_top_10="A05:2021",
        remediation="Follow security hardening guidelines. Remove default credentials and unnecessary features.",
        keywords=["configuration", "config", "default", "setting"],
    ),
    "CWE-200": CWEEntry(
        id="CWE-200",
        name="Exposure of Sensitive Information",
        description="The software exposes sensitive information to an actor that is not explicitly authorized to have access to that information.",
        category=CWECategory.SENSITIVE_DATA,
        owasp_top_10="A01:2021",
        remediation="Implement proper access controls. Minimize data exposure.",
        related_cwes=["CWE-201", "CWE-209"],
        keywords=["exposure", "sensitive", "information", "disclosure", "leak"],
    ),
    "CWE-209": CWEEntry(
        id="CWE-209",
        name="Information Exposure Through Error Message",
        description="The software generates an error message that includes sensitive information about its environment, users, or associated data.",
        category=CWECategory.SENSITIVE_DATA,
        owasp_top_10="A05:2021",
        remediation="Use generic error messages in production. Log detailed errors server-side only.",
        related_cwes=["CWE-200"],
        keywords=["error", "message", "stack", "trace", "debug", "verbose"],
    ),
    
    # ──────────────────────────────────────────────────────────────────────────
    # CSRF
    # ──────────────────────────────────────────────────────────────────────────
    "CWE-352": CWEEntry(
        id="CWE-352",
        name="Cross-Site Request Forgery (CSRF)",
        description="The web application does not, or cannot, sufficiently verify whether a well-formed, valid, consistent request was intentionally provided by the user who submitted the request.",
        category=CWECategory.BROKEN_ACCESS,
        owasp_top_10="A01:2021",
        remediation="Use anti-CSRF tokens. Implement SameSite cookie attribute. Verify Origin/Referer headers.",
        examples=["<img src='http://bank.com/transfer?to=attacker&amount=1000'>"],
        related_cwes=["CWE-346"],
        keywords=["csrf", "cross-site", "request", "forgery", "token"],
    ),
    
    # ──────────────────────────────────────────────────────────────────────────
    # Race Conditions
    # ──────────────────────────────────────────────────────────────────────────
    "CWE-362": CWEEntry(
        id="CWE-362",
        name="Race Condition",
        description="The software contains a code sequence that can run concurrently with other code, and the code sequence requires temporary, exclusive access to a shared resource.",
        category=CWECategory.OTHER,
        remediation="Use proper synchronization (locks, mutexes). Make operations atomic.",
        related_cwes=["CWE-367"],
        keywords=["race", "condition", "concurrent", "thread", "toctou"],
    ),
    "CWE-367": CWEEntry(
        id="CWE-367",
        name="TOCTOU Race Condition",
        description="The software checks the state of a resource before using that resource, but the resource's state can change between the check and the use in a way that invalidates the check.",
        category=CWECategory.OTHER,
        remediation="Use atomic operations. Avoid separating check and use.",
        related_cwes=["CWE-362"],
        keywords=["toctou", "race", "time", "check", "use"],
    ),
    
    # ──────────────────────────────────────────────────────────────────────────
    # Buffer/Memory Issues
    # ──────────────────────────────────────────────────────────────────────────
    "CWE-120": CWEEntry(
        id="CWE-120",
        name="Buffer Overflow",
        description="The program copies an input buffer to an output buffer without verifying that the size of the input buffer is less than the size of the output buffer.",
        category=CWECategory.OTHER,
        remediation="Use safe string functions. Validate buffer sizes. Use memory-safe languages.",
        keywords=["buffer", "overflow", "memory", "stack", "heap", "bof"],
    ),
    "CWE-416": CWEEntry(
        id="CWE-416",
        name="Use After Free",
        description="Referencing memory after it has been freed can cause a program to crash, use unexpected values, or execute code.",
        category=CWECategory.OTHER,
        remediation="Set pointers to NULL after freeing. Use smart pointers.",
        keywords=["use", "after", "free", "memory", "uaf", "pointer"],
    ),
    
    # ──────────────────────────────────────────────────────────────────────────
    # JWT/Token Issues
    # ──────────────────────────────────────────────────────────────────────────
    "CWE-347": CWEEntry(
        id="CWE-347",
        name="Improper Verification of Cryptographic Signature",
        description="The software does not verify, or incorrectly verifies, the cryptographic signature for data.",
        category=CWECategory.CRYPTO,
        owasp_top_10="A02:2021",
        remediation="Always verify signatures. Don't accept 'none' algorithm. Use strong keys.",
        related_cwes=["CWE-345"],
        keywords=["signature", "jwt", "token", "verify", "none", "algorithm"],
    ),
}


# ══════════════════════════════════════════════════════════════════════════════
# CWE Database Wrapper
# ══════════════════════════════════════════════════════════════════════════════


class CWEDatabase:
    """Wrapper around CWE database for typed access."""
    
    def __init__(self) -> None:
        self._db = CWE_DATABASE
    
    def get(self, cwe_id: str) -> CWEEntry | None:
        """Get CWE by ID."""
        # Normalize ID format
        if not cwe_id.upper().startswith("CWE-"):
            cwe_id = f"CWE-{cwe_id}"
        return self._db.get(cwe_id.upper())
    
    def all(self) -> list[CWEEntry]:
        """Get all CWE entries."""
        return list(self._db.values())
    
    def by_category(self, category: CWECategory) -> list[CWEEntry]:
        """Get all CWEs in a category."""
        return [e for e in self._db.values() if e.category == category]
    
    def count(self) -> int:
        """Get total number of CWEs."""
        return len(self._db)


# ══════════════════════════════════════════════════════════════════════════════
# CWE Mapper - Main Interface
# ══════════════════════════════════════════════════════════════════════════════


class CWEMapper:
    """
    Maps vulnerability descriptions to CWE entries.
    
    Usage:
        mapper = CWEMapper()
        
        # Lookup by ID
        entry = mapper.get("CWE-89")
        
        # Suggest from description
        suggestions = mapper.suggest("SQL query with user input")
    """
    
    def __init__(self) -> None:
        self._db = CWEDatabase()
    
    def get(self, cwe_id: str) -> CWEEntry | None:
        """
        Lookup CWE by ID.
        
        Args:
            cwe_id: CWE identifier (e.g., "CWE-89" or "89")
            
        Returns:
            CWEEntry or None if not found
        """
        return self._db.get(cwe_id)
    
    def suggest(self, description: str, top_n: int = 5, *, limit: int | None = None) -> list[CWEEntry]:
        """
        Suggest CWE entries based on vulnerability description.
        
        Uses keyword matching to find relevant CWEs.
        
        Args:
            description: Vulnerability description text
            top_n: Maximum number of suggestions (deprecated, use limit)
            limit: Maximum number of suggestions
            
        Returns:
            List of matching CWEEntry objects, sorted by relevance
        """
        # Handle limit alias
        max_results = limit if limit is not None else top_n
        
        description_lower = description.lower()
        
        scores: list[tuple[CWEEntry, int]] = []
        
        for entry in self._db.all():
            score = 0
            
            # Check keywords
            for keyword in entry.keywords:
                if keyword.lower() in description_lower:
                    score += 10
                    
                    # Bonus for exact word match
                    if re.search(rf'\b{re.escape(keyword)}\b', description_lower):
                        score += 5
            
            # Check name match
            if entry.name.lower() in description_lower:
                score += 20
            
            # Check category name
            if entry.category.value.lower() in description_lower:
                score += 5
            
            if score > 0:
                scores.append((entry, score))
        
        # Sort by score descending
        scores.sort(key=lambda x: x[1], reverse=True)
        
        return [entry for entry, _ in scores[:max_results]]
    
    def search(self, query: str) -> list[CWEEntry]:
        """
        Search CWE database by keyword.
        
        Args:
            query: Search term
            
        Returns:
            List of matching CWE entries
        """
        query_lower = query.lower()
        results = []
        
        for entry in self._db.all():
            # Check name
            if query_lower in entry.name.lower():
                results.append(entry)
                continue
            
            # Check description
            if query_lower in entry.description.lower():
                results.append(entry)
                continue
            
            # Check keywords
            for keyword in entry.keywords:
                if query_lower in keyword.lower():
                    results.append(entry)
                    break
        
        return results
    
    def get_by_category(self, category: str | CWECategory) -> list[CWEEntry]:
        """
        Get all CWEs in a category.
        
        Args:
            category: Category enum or string name
            
        Returns:
            List of CWE entries in that category
        """
        if isinstance(category, str):
            # Try to match by name
            category_lower = category.lower()
            results = []
            for entry in self._db.all():
                if category_lower in entry.category.value.lower():
                    results.append(entry)
            return results
        else:
            return self._db.by_category(category)
    
    def suggest_from_vuln_type(self, vuln_type: str) -> CWEEntry | None:
        """
        Get CWE from common vulnerability type name.
        
        Args:
            vuln_type: Common name like "SQL Injection", "XSS", "RCE"
            
        Returns:
            Most relevant CWEEntry or None
        """
        vuln_map = {
            "sql injection": "CWE-89",
            "sqli": "CWE-89",
            "xss": "CWE-79",
            "cross-site scripting": "CWE-79",
            "command injection": "CWE-78",
            "rce": "CWE-94",
            "remote code execution": "CWE-94",
            "path traversal": "CWE-22",
            "lfi": "CWE-22",
            "local file inclusion": "CWE-22",
            "rfi": "CWE-98",
            "remote file inclusion": "CWE-98",
            "ssrf": "CWE-918",
            "xxe": "CWE-611",
            "idor": "CWE-639",
            "csrf": "CWE-352",
            "deserialization": "CWE-502",
            "file upload": "CWE-434",
            "open redirect": "CWE-601",
            "xpath injection": "CWE-643",
            "ldap injection": "CWE-90",
            "ssti": "CWE-917",
            "template injection": "CWE-917",
            "jwt": "CWE-347",
            "buffer overflow": "CWE-120",
            "race condition": "CWE-362",
        }
        
        vuln_lower = vuln_type.lower().strip()
        
        if vuln_lower in vuln_map:
            return self.get(vuln_map[vuln_lower])
        
        # Try partial match
        for key, cwe_id in vuln_map.items():
            if key in vuln_lower or vuln_lower in key:
                return self.get(cwe_id)
        
        return None
    
    def get_owasp_mapping(self) -> dict[str, list[CWEEntry]]:
        """
        Get CWEs grouped by OWASP Top 10 (2021).
        
        Returns:
            Dictionary mapping OWASP ID to list of CWEs
        """
        mapping: dict[str, list[CWEEntry]] = {}
        
        for entry in self._db.all():
            if entry.owasp_top_10:
                if entry.owasp_top_10 not in mapping:
                    mapping[entry.owasp_top_10] = []
                mapping[entry.owasp_top_10].append(entry)
        
        return mapping
    
    def count(self) -> int:
        """Get total number of CWEs in database."""
        return self._db.count()
    
    def all(self) -> list[CWEEntry]:
        """Get all CWE entries."""
        return self._db.all()


# ══════════════════════════════════════════════════════════════════════════════
# Convenience Functions
# ══════════════════════════════════════════════════════════════════════════════


def get_cwe(cwe_id: str) -> CWEEntry | None:
    """Convenience function for CWE lookup."""
    return CWEMapper().get(cwe_id)


def suggest_cwe(description: str) -> list[CWEEntry]:
    """Convenience function for CWE suggestion."""
    return CWEMapper().suggest(description)
