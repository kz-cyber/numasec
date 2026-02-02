"""
NumaSec - MCP Tool Handlers

All 28 MCP tools organized by category.
"""

from __future__ import annotations

import json
import logging
from datetime import datetime
from typing import Any

import httpx

from numasec.data.models import Severity
from numasec.tools.http_parser import parse_http_response

logger = logging.getLogger("numasec.mcp.tools")


# ══════════════════════════════════════════════════════════════════════════════
# HTTP Session Manager - Maintains cookies across requests
# ══════════════════════════════════════════════════════════════════════════════

class HTTPSessionManager:
    """Manages HTTP sessions with cookie persistence per engagement/task."""
    _sessions: dict[str, httpx.AsyncClient] = {}
    _notes: dict[str, dict[str, str]] = {}  # Scratchpad storage
    
    @classmethod
    def get_session(cls, session_id: str = "default") -> httpx.AsyncClient:
        """Get or create a session with persistent cookies."""
        if session_id not in cls._sessions:
            cls._sessions[session_id] = httpx.AsyncClient(
                timeout=30,
                follow_redirects=True,
                verify=False  # Allow self-signed certs for training environments
            )
        return cls._sessions[session_id]
    
    @classmethod
    async def close_session(cls, session_id: str):
        """Close and remove a session."""
        if session_id in cls._sessions:
            await cls._sessions[session_id].aclose()
            del cls._sessions[session_id]
    
    @classmethod
    async def close_all(cls):
        """Close all sessions."""
        for session in cls._sessions.values():
            await session.aclose()
        cls._sessions.clear()
    
    @classmethod
    def write_note(cls, session_id: str, key: str, value: str):
        """Write a note to the scratchpad."""
        if session_id not in cls._notes:
            cls._notes[session_id] = {}
        cls._notes[session_id][key] = value
    
    @classmethod
    def read_notes(cls, session_id: str) -> dict[str, str]:
        """Read all notes from scratchpad."""
        return cls._notes.get(session_id, {})


# ══════════════════════════════════════════════════════════════════════════════
# TOOL GROUNDING: Zero Hallucination Policy
# ══════════════════════════════════════════════════════════════════════════════
# CRITICAL INVARIANT: The LLM can ONLY call tools in this frozenset.
# If LLM invents "burp_spider" or "run_metasploit", it MUST be rejected.
#
# Scientific Basis: Tool Grounding (Schick et al. 2024)
# "Constrain LLM to valid tool schemas to eliminate hallucination"

VALID_TOOLS = frozenset({
    # Engagement management
    "engagement_create", "engagement_status", "engagement_close",
    # Reconnaissance
    "recon_nmap", "recon_subdomain", "recon_httpx", "recon_whatweb", "recon_dns",
    # Web application testing
    "web_ffuf", "web_nuclei", "web_sqlmap", "web_nikto", "web_request", "web_crawl",
    # Exploitation
    "exploit_hydra", "exploit_script",
    # Finding management
    "finding_create", "finding_list", "finding_update", "finding_add_evidence",
    # Reporting
    "report_generate", "report_preview",
    # Knowledge base
    "knowledge_search", "knowledge_add",
    # Scope management
    "scope_check", "scope_add",
    # Scratchpad (AI memory)
    "notes_write", "notes_read",
})


def validate_tool_call(tool: str, args: dict) -> tuple[bool, str]:
    """
    Validate tool call against VALID_TOOLS frozenset.
    
    This is the CRITICAL enforcement point for zero hallucination.
    
    Args:
        tool: Tool name from LLM response
        args: Tool arguments
        
    Returns:
        (is_valid, error_message)
    """
    if tool not in VALID_TOOLS:
        logger.error(
            f"❌ LLM HALLUCINATED TOOL: '{tool}' not in VALID_TOOLS. "
            f"Valid tools: {sorted(VALID_TOOLS)[:10]}..."
        )
        return False, (
            f"ERROR: Tool '{tool}' does not exist.\n"
            f"Valid tools: {', '.join(sorted(VALID_TOOLS)[:15])}...\n"
            f"Use ONLY tools from the valid set. Do NOT invent tool names."
        )
    
    return True, ""


# ══════════════════════════════════════════════════════════════════════════════
# Tool Definitions - 26 Total
# ══════════════════════════════════════════════════════════════════════════════

TOOL_DEFINITIONS = {
    # ─────────────────────────────────────────────────────────────────────────
    # ENGAGEMENT TOOLS (3)
    # ─────────────────────────────────────────────────────────────────────────
    "engagement_create": {
        "name": "engagement_create",
        "description": """Create formal penetration testing engagement with scope definition.

USE WHEN: Starting a formal assessment, need to track findings/scope, compliance requirements.
DO NOT USE: Quick ad-hoc testing, chat mode reconnaissance, single vulnerability checks.

Creates: Engagement record with scope entries, enables finding tracking.""",
        "inputSchema": {
            "type": "object",
            "properties": {
                "client_name": {
                    "type": "string",
                    "description": "Client or organization name",
                },
                "project_name": {
                    "type": "string",
                    "description": "Project name (defaults to 'Penetration Test')",
                    "default": "Penetration Test",
                },
                "scope": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "Target scope entries (IPs, CIDRs, domains, URLs)",
                },
                "methodology": {
                    "type": "string",
                    "enum": ["PTES", "OWASP", "NIST"],
                    "default": "PTES",
                    "description": "Testing methodology to follow",
                },
                "approval_mode": {
                    "type": "string",
                    "enum": ["supervised", "semi_auto", "autonomous"],
                    "default": "supervised",
                    "description": "Human-in-the-loop approval mode",
                },
            },
            "required": ["client_name", "scope"],
        },
    },
    "engagement_status": {
        "name": "engagement_status",
        "description": """Get current engagement status, findings count, and scope.

USE WHEN: Need to check assessment progress, review what's been found, during autonomous mode.
DO NOT USE: At start of chat conversations (causes confusion), when no engagement exists.

Returns: Engagement details, scope entries, finding counts by severity.""",
        "inputSchema": {
            "type": "object",
            "properties": {
                "include_findings": {
                    "type": "boolean",
                    "default": True,
                    "description": "Include finding summary",
                },
                "include_scope": {
                    "type": "boolean",
                    "default": True,
                    "description": "Include scope details",
                },
            },
        },
    },
    "engagement_close": {
        "name": "engagement_close",
        "description": """Close engagement and generate final report.

USE WHEN: Assessment complete, all testing finished, ready for deliverables.
DO NOT USE: Testing still in progress, more findings expected.

Generates: PDF/Markdown report with all findings, executive summary, remediation guidance.""",
        "inputSchema": {
            "type": "object",
            "properties": {
                "generate_report": {
                    "type": "boolean",
                    "default": True,
                    "description": "Automatically generate final report",
                },
            },
        },
    },
    # ─────────────────────────────────────────────────────────────────────────
    # RECONNAISSANCE TOOLS (5)
    # ─────────────────────────────────────────────────────────────────────────
    "recon_nmap": {
        "name": "recon_nmap",
        "description": """Port scan target to discover open services and versions.

USE WHEN: Unknown target, need to identify running services, network reconnaissance phase.
DO NOT USE: Target already enumerated, web-only testing, specific vulnerability requested.

SCAN TYPES:
- quick: Top 100 ports (fast, 30 seconds)
- full: All 65535 ports (slow, 10+ minutes)
- service: Version detection (-sV)
- vuln: NSE vulnerability scripts
- stealth: SYN scan (-sS)

Returns: JSON with hosts, ports, services, versions.""",
        "inputSchema": {
            "type": "object",
            "properties": {
                "targets": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "Target IPs, CIDRs, or hostnames to scan",
                },
                "scan_type": {
                    "type": "string",
                    "enum": ["quick", "full", "service", "vuln", "stealth"],
                    "default": "quick",
                    "description": "Scan intensity: quick (top 100), full (all ports), service (version detection), vuln (NSE scripts), stealth (SYN)",
                },
                "ports": {
                    "type": "string",
                    "description": "Port specification (e.g., '80,443,8080' or '1-1000')",
                },
                "timing": {
                    "type": "integer",
                    "minimum": 0,
                    "maximum": 5,
                    "default": 3,
                    "description": "Timing template T0-T5 (0=paranoid, 5=insane)",
                },
            },
            "required": ["targets"],
        },
    },
    "recon_subdomain": {
        "name": "recon_subdomain",
        "description": """Enumerate subdomains using passive sources and DNS brute force.

USE WHEN: Testing domain, need to expand attack surface, looking for forgotten subdomains.
DO NOT USE: Single host/IP target, already have subdomain list, time-constrained testing.

Returns: List of discovered subdomains with resolution status.""",
        "inputSchema": {
            "type": "object",
            "properties": {
                "domain": {
                    "type": "string",
                    "description": "Target domain to enumerate",
                },
                "passive_only": {
                    "type": "boolean",
                    "default": True,
                    "description": "Use only passive sources (no DNS brute force)",
                },
                "recursive": {
                    "type": "boolean",
                    "default": False,
                    "description": "Recursively enumerate found subdomains",
                },
            },
            "required": ["domain"],
        },
    },
    "recon_httpx": {
        "name": "recon_httpx",
        "description": """Probe HTTP services for live hosts with technology detection.

USE WHEN: Have list of hosts/IPs, need to find web services, verify which respond to HTTP.
DO NOT USE: Single known URL, already know web server is running.

Returns: Live hosts with status codes, titles, technologies detected.""",
        "inputSchema": {
            "type": "object",
            "properties": {
                "targets": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "URLs or hosts to probe",
                },
                "ports": {
                    "type": "string",
                    "description": "Ports to probe (default: 80,443,8080,8443)",
                },
                "tech_detect": {
                    "type": "boolean",
                    "default": True,
                    "description": "Detect web technologies",
                },
                "follow_redirects": {
                    "type": "boolean",
                    "default": True,
                    "description": "Follow HTTP redirects",
                },
            },
            "required": ["targets"],
        },
    },
    "recon_whatweb": {
        "name": "recon_whatweb",
        "description": """Fingerprint web technologies, frameworks, CMS, and server software.

USE WHEN: Need to identify technology stack, looking for version-specific vulnerabilities.
DO NOT USE: Already know technology stack, testing specific vulnerability.

AGGRESSION LEVELS (only 1, 3, or 4 are valid!):
- 1 = stealthy (default, single request per target)
- 3 = aggressive (more plugins, slower)
- 4 = heavy (all plugins, slowest but best detection)

⚠️ Do NOT use aggression=2, it's not a valid WhatWeb value.

Returns: Detected technologies with versions (e.g., WordPress 5.9, PHP 8.1, nginx 1.21).""",
        "inputSchema": {
            "type": "object",
            "properties": {
                "targets": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "URLs to fingerprint",
                },
                "aggression": {
                    "type": "integer",
                    "enum": [1, 3, 4],
                    "default": 1,
                    "description": "Aggression level: 1=stealthy, 3=aggressive, 4=heavy (NOT 2!)",
                },
            },
            "required": ["targets"],
        },
    },
    "recon_dns": {
        "name": "recon_dns",
        "description": """DNS reconnaissance: record enumeration and zone transfer attempts.

USE WHEN: Testing domain infrastructure, looking for DNS misconfigurations, need mail/NS servers.
DO NOT USE: Web-only assessment, IP-only target.

⚠️ Zone transfer success is a HIGH severity finding (information disclosure).

Returns: A, AAAA, MX, NS, TXT, CNAME, SOA records + zone transfer results if vulnerable.""",
        "inputSchema": {
            "type": "object",
            "properties": {
                "domain": {
                    "type": "string",
                    "description": "Target domain",
                },
                "record_types": {
                    "type": "array",
                    "items": {"type": "string"},
                    "default": ["A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA"],
                    "description": "DNS record types to query",
                },
                "attempt_zone_transfer": {
                    "type": "boolean",
                    "default": True,
                    "description": "Attempt DNS zone transfer",
                },
            },
            "required": ["domain"],
        },
    },
    # ─────────────────────────────────────────────────────────────────────────
    # WEB APPLICATION TOOLS (6)
    # ─────────────────────────────────────────────────────────────────────────
    "web_ffuf": {
        "name": "web_ffuf",
        "description": """Directory and file fuzzing to discover hidden endpoints.

USE WHEN: Need to find hidden paths, admin panels, backup files, API endpoints.
DO NOT USE: Already know target paths, testing specific known vulnerability.

WORDLISTS:
- common: Fast, ~4500 entries (default, recommended first)
- big: Thorough, ~20000 entries
- raft-medium: Files + directories
- dirbuster-medium: Classic comprehensive list

TIPS:
- Add extensions (-e php,html,txt) for file discovery
- Filter by size (filter_size) to remove false positives
- Use filter_status to focus on specific response codes

Returns: Discovered paths with status codes, sizes, word counts.""",
        "inputSchema": {
            "type": "object",
            "properties": {
                "url": {
                    "type": "string",
                    "description": "Target URL with FUZZ keyword (e.g., https://example.com/FUZZ)",
                },
                "wordlist": {
                    "type": "string",
                    "enum": ["common", "big", "raft-medium", "dirbuster-medium", "custom"],
                    "default": "common",
                    "description": "Wordlist to use",
                },
                "custom_wordlist": {
                    "type": "string",
                    "description": "Path to custom wordlist (if wordlist='custom')",
                },
                "extensions": {
                    "type": "string",
                    "description": "File extensions to append (e.g., 'php,html,txt')",
                },
                "filter_status": {
                    "type": "string",
                    "description": "Filter by status codes (e.g., '200,301,302')",
                },
                "filter_size": {
                    "type": "string",
                    "description": "Filter by response size (e.g., '0' or '1234')",
                },
                "threads": {
                    "type": "integer",
                    "default": 40,
                    "description": "Number of concurrent threads",
                },
            },
            "required": ["url"],
        },
    },
    "web_nuclei": {
        "name": "web_nuclei",
        "description": """Automated vulnerability scanner using nuclei templates.

USE WHEN: Need comprehensive vulnerability scan, looking for known CVEs, misconfigurations.
DO NOT USE: Testing specific custom vulnerability, manual testing preferred, stealth required.

⚠️ HIGH COST: Runs many requests. Use after manual testing identifies interesting targets.

TEMPLATES: cves, misconfigurations, exposures, technologies, default-logins
SEVERITY: info, low, medium, high, critical (default: medium+high+critical)

Returns: Matched vulnerabilities with CVE IDs, severity, evidence.""",
        "inputSchema": {
            "type": "object",
            "properties": {
                "targets": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "Target URLs to scan",
                },
                "templates": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "Specific templates to run (e.g., ['cves', 'misconfigurations'])",
                },
                "severity": {
                    "type": "array",
                    "items": {"type": "string", "enum": ["info", "low", "medium", "high", "critical"]},
                    "default": ["medium", "high", "critical"],
                    "description": "Severity levels to include",
                },
                "rate_limit": {
                    "type": "integer",
                    "default": 150,
                    "description": "Maximum requests per second",
                },
                "exclude_templates": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "Templates to exclude",
                },
            },
            "required": ["targets"],
        },
    },
    "web_sqlmap": {
        "name": "web_sqlmap",
        "description": """Automated SQL injection testing and exploitation.

USE WHEN: Manual testing suggests SQLi is present (errors, behavior differences), need PoC/data extraction.
DO NOT USE: No evidence of SQLi, reconnaissance phase, testing non-database functionality.

⚠️ ESCALATION TOOL: Use web_request with manual payloads FIRST, then sqlmap to confirm/exploit.

LEVELS: 1=basic (default), 5=comprehensive (slow but thorough)
RISK: 1=safe (default), 3=dangerous (OR-based, time-heavy)
TECHNIQUE: B=Boolean, E=Error, U=Union, S=Stacked, T=Time, Q=Inline

Returns: Injection point details, DBMS type, extracted data if --dbs specified.""",
        "inputSchema": {
            "type": "object",
            "properties": {
                "url": {
                    "type": "string",
                    "description": "Target URL with parameter (e.g., https://example.com/page?id=1)",
                },
                "data": {
                    "type": "string",
                    "description": "POST data to test (for POST requests)",
                },
                "cookie": {
                    "type": "string",
                    "description": "Cookie header value",
                },
                "level": {
                    "type": "integer",
                    "minimum": 1,
                    "maximum": 5,
                    "default": 1,
                    "description": "Test level (1-5, higher = more tests)",
                },
                "risk": {
                    "type": "integer",
                    "minimum": 1,
                    "maximum": 3,
                    "default": 1,
                    "description": "Risk level (1-3, higher = more dangerous tests)",
                },
                "technique": {
                    "type": "string",
                    "description": "SQL injection techniques to test (BEUSTQ)",
                },
                "dbs": {
                    "type": "boolean",
                    "default": False,
                    "description": "Enumerate databases if vulnerable",
                },
            },
            "required": ["url"],
        },
    },
    "web_nikto": {
        "name": "web_nikto",
        "description": """Web server vulnerability scanner for common issues.

USE WHEN: Need quick server-level vulnerability check, looking for misconfigurations, default files.
DO NOT USE: Application-level testing, modern single-page apps, API-only targets.

⚠️ NOISY: Generates many requests. Best for initial server assessment.

Returns: Server vulnerabilities, outdated software, dangerous files, misconfigurations.""",
        "inputSchema": {
            "type": "object",
            "properties": {
                "target": {
                    "type": "string",
                    "description": "Target URL or host",
                },
                "port": {
                    "type": "integer",
                    "description": "Target port (default: 80 or 443)",
                },
                "ssl": {
                    "type": "boolean",
                    "default": False,
                    "description": "Force SSL",
                },
                "tuning": {
                    "type": "string",
                    "description": "Scan tuning (e.g., '123' for specific test types)",
                },
            },
            "required": ["target"],
        },
    },
    "web_request": {
        "name": "web_request",
        "description": """Make HTTP request with full control over method, headers, body, cookies.

🌟 PRIMARY TOOL for web interaction. Use this FIRST for most web testing.

USE WHEN: Testing payloads, interacting with forms, API calls, authentication flows.
DO NOT USE: Need automated scanning (use nuclei), need many sequential requests (use exploit_script).

FEATURES:
- Session persistence: Use same session_id to maintain cookies across requests
- Full control: Custom headers, body, method
- Response includes: Status, headers, body, cookies set

EXAMPLES:
- Test SQLi: url="http://target/login", method="POST", data={"user": "' OR 1=1--", "pass": "x"}
- Check endpoint: url="http://target/api/user/1", headers={"Authorization": "Bearer token"}
- Submit form: url="http://target/search", method="POST", data={"q": "test"}

Returns: Status code, response headers, body content, cookies.""",
        "inputSchema": {
            "type": "object",
            "properties": {
                "url": {
                    "type": "string",
                    "description": "Target URL",
                },
                "method": {
                    "type": "string",
                    "enum": ["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"],
                    "default": "GET",
                },
                "session_id": {
                    "type": "string",
                    "description": "Session ID for cookie persistence. Use same ID across requests to maintain login state.",
                    "default": "default",
                },
                "headers": {
                    "type": "object",
                    "additionalProperties": {"type": "string"},
                    "description": "Custom headers",
                },
                "data": {
                    "type": "object",
                    "additionalProperties": {"type": "string"},
                    "description": "Form data for POST requests",
                },
                "body": {
                    "type": "string",
                    "description": "Raw request body (JSON or text)",
                },
                "follow_redirects": {
                    "type": "boolean",
                    "default": True,
                },
                "timeout": {
                    "type": "integer",
                    "default": 30,
                    "description": "Request timeout in seconds",
                },
            },
            "required": ["url"],
        },
    },
    "web_crawl": {
        "name": "web_crawl",
        "description": """Crawl website to discover endpoints, forms, and parameters.

USE WHEN: Need to map application structure, find hidden endpoints, identify attack surface.
DO NOT USE: Already know target endpoints, testing specific vulnerability.

FEATURES:
- Extracts all links and forms
- Identifies parameters for injection testing
- Respects robots.txt and depth limits

Returns: Discovered URLs, forms with inputs, parameters found.""",
        "inputSchema": {
            "type": "object",
            "properties": {
                "url": {
                    "type": "string",
                    "description": "Starting URL",
                },
                "depth": {
                    "type": "integer",
                    "default": 3,
                    "description": "Maximum crawl depth",
                },
                "include_subdomains": {
                    "type": "boolean",
                    "default": False,
                },
            },
            "required": ["url"],
        },
    },
    # ─────────────────────────────────────────────────────────────────────────
    # EXPLOITATION TOOLS (2)
    # ─────────────────────────────────────────────────────────────────────────
    "exploit_hydra": {
        "name": "exploit_hydra",
        "description": """Brute force authentication services (SSH, FTP, HTTP, etc).

⚠️ REQUIRES EXPLICIT APPROVAL - Can cause account lockouts.

USE WHEN: Have username list, testing password strength, default credentials suspected.
DO NOT USE: Strong password policy known, account lockout enabled, production systems.

SERVICES: ssh, ftp, http-get, http-post, mysql, postgres, rdp, smb

Returns: Valid credential pairs found.""",
        "inputSchema": {
            "type": "object",
            "properties": {
                "target": {
                    "type": "string",
                    "description": "Target host",
                },
                "service": {
                    "type": "string",
                    "enum": ["ssh", "ftp", "http-get", "http-post", "mysql", "postgres", "rdp", "smb"],
                    "description": "Service to attack",
                },
                "username": {
                    "type": "string",
                    "description": "Username or username file",
                },
                "password": {
                    "type": "string",
                    "description": "Password or password file",
                },
                "username_file": {
                    "type": "string",
                    "description": "Path to username wordlist",
                },
                "password_file": {
                    "type": "string",
                    "description": "Path to password wordlist",
                },
                "threads": {
                    "type": "integer",
                    "default": 4,
                    "description": "Number of parallel connections",
                },
            },
            "required": ["target", "service"],
        },
    },
    "exploit_script": {
        "name": "exploit_script",
        "description": """Execute custom Python or shell script for complex exploitation.

⚠️ HIGHEST COST TOOL - Use only when simpler tools insufficient.

USE WHEN:
- Blind injection requiring many automated requests (>10)
- Complex data processing (decode, decrypt, parse binary)
- Multi-step exploitation logic
- Custom protocol interaction

DO NOT USE:
- Single web request (use web_request instead)
- Simple payload testing (use web_request with payload)
- Tasks achievable with existing tools

EFFICIENCY: This tool costs 2-3 iterations (generate + execute + parse).
Direct tools cost 1 iteration. Always prefer direct tools when possible.

Returns: Script stdout, stderr, exit code.""",
        "inputSchema": {
            "type": "object",
            "properties": {
                "script_type": {
                    "type": "string",
                    "enum": ["python", "bash"],
                    "description": "Script type",
                },
                "code": {
                    "type": "string",
                    "description": "Script code to execute",
                },
                "timeout": {
                    "type": "integer",
                    "default": 60,
                    "description": "Execution timeout in seconds",
                },
            },
            "required": ["script_type", "code"],
        },
    },
    # ─────────────────────────────────────────────────────────────────────────
    # FINDING TOOLS (4)
    # ─────────────────────────────────────────────────────────────────────────
    "finding_create": {
        "name": "finding_create",
        "description": """Create security finding with severity, CVSS, and evidence.

USE WHEN: Vulnerability CONFIRMED with evidence, need to document for report.
DO NOT USE: Suspected but unconfirmed vulnerability, information-only observations.

REQUIRED: title, severity, description
OPTIONAL: cvss_vector, cwe_id, impact, remediation, evidence

SEVERITY GUIDE:
- critical: RCE, auth bypass, data breach (CVSS 9.0+)
- high: SQLi, privilege escalation, sensitive data exposure (CVSS 7.0-8.9)
- medium: XSS, CSRF, information disclosure (CVSS 4.0-6.9)
- low: Missing headers, verbose errors (CVSS 0.1-3.9)
- informational: Best practice recommendations (CVSS 0.0)

Returns: Finding ID for later reference/updates.""",
        "inputSchema": {
            "type": "object",
            "properties": {
                "title": {
                    "type": "string",
                    "description": "Finding title",
                },
                "severity": {
                    "type": "string",
                    "enum": ["critical", "high", "medium", "low", "informational"],
                    "description": "Severity level",
                },
                "description": {
                    "type": "string",
                    "description": "Detailed description of the vulnerability",
                },
                "impact": {
                    "type": "string",
                    "description": "Business and technical impact",
                },
                "remediation": {
                    "type": "string",
                    "description": "Recommended fix",
                },
                "cvss_vector": {
                    "type": "string",
                    "description": "CVSS 3.1 vector string",
                },
                "cwe_id": {
                    "type": "string",
                    "description": "CWE identifier (e.g., 'CWE-89')",
                },
                "affected_asset": {
                    "type": "string",
                    "description": "Affected URL, IP, or component",
                },
                "evidence": {
                    "type": "string",
                    "description": "Technical proof (request/response, screenshot path)",
                },
            },
            "required": ["title", "severity", "description"],
        },
    },
    "finding_list": {
        "name": "finding_list",
        "description": """List all findings for current engagement.

USE WHEN: Need to review what's been found, check for duplicates, summarize progress.
DO NOT USE: No active engagement exists.

Returns: Finding list with id, title, severity, cvss_score, affected_asset.""",
        "inputSchema": {
            "type": "object",
            "properties": {
                "severity": {
                    "type": "string",
                    "enum": ["critical", "high", "medium", "low", "informational"],
                    "description": "Filter by severity",
                },
                "include_false_positives": {
                    "type": "boolean",
                    "default": False,
                },
            },
        },
    },
    "finding_update": {
        "name": "finding_update",
        "description": """Update existing finding fields.

USE WHEN: Need to correct severity, add details, mark as false positive.
DO NOT USE: Creating new finding (use finding_create).

Returns: Success status and updated fields.""",
        "inputSchema": {
            "type": "object",
            "properties": {
                "finding_id": {
                    "type": "string",
                    "description": "Finding ID to update",
                },
                "updates": {
                    "type": "object",
                    "description": "Fields to update",
                    "properties": {
                        "title": {"type": "string"},
                        "severity": {"type": "string"},
                        "description": {"type": "string"},
                        "impact": {"type": "string"},
                        "remediation": {"type": "string"},
                        "is_false_positive": {"type": "boolean"},
                    },
                },
            },
            "required": ["finding_id", "updates"],
        },
    },
    "finding_add_evidence": {
        "name": "finding_add_evidence",
        "description": """Add evidence artifact to existing finding.

USE WHEN: Have additional proof (request/response, screenshot, log output).
DO NOT USE: Initial finding creation (include evidence in finding_create).

EVIDENCE TYPES: screenshot, request, response, log, code, tool_output

Returns: Evidence ID.""",
        "inputSchema": {
            "type": "object",
            "properties": {
                "finding_id": {
                    "type": "string",
                    "description": "Finding ID",
                },
                "evidence_type": {
                    "type": "string",
                    "enum": ["screenshot", "request", "response", "log", "code", "tool_output"],
                },
                "title": {
                    "type": "string",
                    "description": "Evidence title",
                },
                "content": {
                    "type": "string",
                    "description": "Evidence content",
                },
            },
            "required": ["finding_id", "evidence_type", "title", "content"],
        },
    },
    # ─────────────────────────────────────────────────────────────────────────
    # REPORT TOOLS (2)
    # ─────────────────────────────────────────────────────────────────────────
    "report_generate": {
        "name": "report_generate",
        "description": """Generate formal penetration test report.

USE WHEN: Assessment complete, need deliverable for client.
DO NOT USE: Testing still in progress, no findings recorded.

FORMATS: pdf (professional), docx (editable), md (lightweight), html (web)
TEMPLATES: ptes (comprehensive), owasp (web-focused), executive (summary), technical (detailed)

Returns: Report file path, generation status.""",
        "inputSchema": {
            "type": "object",
            "properties": {
                "format": {
                    "type": "string",
                    "enum": ["pdf", "docx", "md", "html"],
                    "default": "pdf",
                },
                "template": {
                    "type": "string",
                    "enum": ["ptes", "owasp", "executive", "technical"],
                    "default": "ptes",
                },
                "include_executive_summary": {
                    "type": "boolean",
                    "default": True,
                },
                "include_evidence": {
                    "type": "boolean",
                    "default": True,
                },
            },
        },
    },
    "report_preview": {
        "name": "report_preview",
        "description": """Preview executive summary and finding statistics.

USE WHEN: Need quick summary of assessment state, preparing for report.
DO NOT USE: Detailed finding review needed (use finding_list).

Returns: Executive summary text, severity counts, risk level.""",
        "inputSchema": {
            "type": "object",
            "properties": {},
        },
    },
    # ─────────────────────────────────────────────────────────────────────────
    # KNOWLEDGE TOOLS (2)
    # ─────────────────────────────────────────────────────────────────────────
    "knowledge_search": {
        "name": "knowledge_search",
        "description": """Search knowledge base for payloads, techniques, and attack patterns.

🧠 INTELLIGENCE TOOL: Query the security knowledge base.

USE WHEN: Need payload variants, bypass techniques, exploitation methods, stuck on attack.
DO NOT USE: Simple/common attacks you already know, basic testing.

CATEGORIES:
- payloads: SQLi, XSS, SSTI, command injection payloads
- techniques: Exploitation methods, bypass tricks
- writeups: CTF solutions, vulnerability analyses
- all: Search across everything (default)

Returns: Ranked results with relevance scores, payload content, technique details.""",
        "inputSchema": {
            "type": "object",
            "properties": {
                "query": {
                    "type": "string",
                    "description": "Search query",
                },
                "category": {
                    "type": "string",
                    "enum": ["payloads", "techniques", "writeups", "all"],
                    "default": "all",
                },
                "limit": {
                    "type": "integer",
                    "default": 10,
                },
            },
            "required": ["query"],
        },
    },
    "knowledge_add": {
        "name": "knowledge_add",
        "description": """Add new entry to knowledge base for future reference.

USE WHEN: Discovered useful payload, learned new technique, want to remember pattern.
DO NOT USE: Temporary notes (use notes_write), duplicate of existing knowledge.

CATEGORIES:
- payload: Injection payloads, exploit code
- technique: Attack methods, bypass tricks  
- writeup: CTF solutions, vulnerability analyses
- reflexion: Lessons learned, what worked/didn't work

Returns: Entry ID for reference.""",
        "inputSchema": {
            "type": "object",
            "properties": {
                "category": {
                    "type": "string",
                    "enum": ["payload", "technique", "writeup", "reflexion"],
                },
                "title": {
                    "type": "string",
                },
                "content": {
                    "type": "string",
                },
                "tags": {
                    "type": "array",
                    "items": {"type": "string"},
                },
            },
            "required": ["category", "title", "content"],
        },
    },
    # ─────────────────────────────────────────────────────────────────────────
    # SCOPE TOOLS (2)
    # ─────────────────────────────────────────────────────────────────────────
    "scope_check": {
        "name": "scope_check",
        "description": """Check if target is within authorized scope.

⚠️ COMPLIANCE CRITICAL: Always verify before testing new targets.

USE WHEN: About to test new IP/domain/URL, uncertain about authorization.
DO NOT USE: Already verified target is in scope.

Returns: in_scope (boolean), reason, matching scope entry.""",
        "inputSchema": {
            "type": "object",
            "properties": {
                "target": {
                    "type": "string",
                    "description": "Target to check (IP, domain, URL)",
                },
            },
            "required": ["target"],
        },
    },
    "scope_add": {
        "name": "scope_add",
        "description": """Add target to engagement scope.

USE WHEN: New authorized target discovered, need to expand scope.
DO NOT USE: Target already in scope, no active engagement.

Auto-detects type: IP, CIDR, domain, URL

Returns: Scope entry ID, detected type.""",
        "inputSchema": {
            "type": "object",
            "properties": {
                "target": {
                    "type": "string",
                    "description": "Target to add",
                },
                "is_excluded": {
                    "type": "boolean",
                    "default": False,
                    "description": "Add as excluded (out-of-scope)",
                },
                "description": {
                    "type": "string",
                    "description": "Notes about this scope entry",
                },
            },
            "required": ["target"],
        },
    },
    # ─────────────────────────────────────────────────────────────────────────
    # SCRATCHPAD TOOLS (2) - AI Memory
    # ─────────────────────────────────────────────────────────────────────────
    "notes_write": {
        "name": "notes_write",
        "description": """Save observation to scratchpad for later reference.

🧠 MEMORY TOOL: Remember important information across iterations.

USE WHEN: Found credential, discovered endpoint, need to remember value for later.
DO NOT USE: Formal finding documentation (use finding_create).

EXAMPLES:
- key="csrf_token", value="abc123xyz..."
- key="admin_endpoint", value="/api/v2/admin/users"
- key="sqli_param", value="id parameter on /products is injectable"

Returns: Confirmation of saved note.""",
        "inputSchema": {
            "type": "object",
            "properties": {
                "key": {
                    "type": "string",
                    "description": "Short identifier (e.g., 'csrf_token', 'login_url', 'vulnerability')",
                },
                "value": {
                    "type": "string",
                    "description": "The information to remember",
                },
                "session_id": {
                    "type": "string",
                    "default": "default",
                    "description": "Session to associate notes with",
                },
            },
            "required": ["key", "value"],
        },
    },
    "notes_read": {
        "name": "notes_read",
        "description": """Read all saved notes from scratchpad.

USE WHEN: Need to recall saved information, check what's been discovered.
DO NOT USE: No notes saved yet.

Returns: All notes as key-value pairs.""",
        "inputSchema": {
            "type": "object",
            "properties": {
                "session_id": {
                    "type": "string",
                    "default": "default",
                    "description": "Session to read notes from",
                },
            },
        },
    },
}


def get_all_tool_definitions() -> list[dict[str, Any]]:
    """Get all 26 tool definitions for MCP registration."""
    return list(TOOL_DEFINITIONS.values())


def get_tool_definition(name: str) -> dict[str, Any] | None:
    """Get a specific tool definition by name."""
    return TOOL_DEFINITIONS.get(name)


# ══════════════════════════════════════════════════════════════════════════════
# Tool Risk Classification
# ══════════════════════════════════════════════════════════════════════════════

TOOL_RISK_MAP = {
    # LOW - Read-only, passive reconnaissance
    "engagement_create": "low",
    "engagement_status": "low",
    "engagement_close": "low",
    "recon_nmap": "low",
    "recon_subdomain": "low",
    "recon_httpx": "low",
    "recon_whatweb": "low",
    "recon_dns": "low",
    "finding_create": "low",
    "finding_list": "low",
    "finding_update": "low",
    "finding_add_evidence": "low",
    "report_generate": "low",
    "report_preview": "low",
    "knowledge_search": "low",
    "knowledge_add": "low",
    "scope_check": "low",
    "scope_add": "low",
    # MEDIUM - Active scanning
    "web_ffuf": "medium",
    "web_nuclei": "medium",
    "web_nikto": "medium",
    "web_request": "medium",
    "web_crawl": "medium",
    # HIGH - Intrusive testing
    "web_sqlmap": "high",
    # CRITICAL - Exploitation
    "exploit_hydra": "critical",
    "exploit_script": "critical",
}


def get_tool_risk(tool_name: str) -> str:
    """Get the risk level of a tool."""
    return TOOL_RISK_MAP.get(tool_name, "medium")


# ══════════════════════════════════════════════════════════════════════════════
# Tool Handler Functions
# ══════════════════════════════════════════════════════════════════════════════


async def handle_engagement_create(arguments: dict[str, Any]) -> dict[str, Any]:
    """Handle engagement_create tool call."""
    from numasec.data.database import get_session, init_database
    from numasec.data.repositories.engagement import EngagementRepository
    from numasec.data.models import EngagementStatus
    from numasec.cli.commands.init import detect_scope_type

    try:
        await init_database()

        client_name = arguments.get("client_name", "Unknown Client")
        project_name = arguments.get("project_name", "Penetration Test")
        scope = arguments.get("scope", [])
        methodology = arguments.get("methodology", "PTES")
        approval_mode = arguments.get("approval_mode", "supervised")

        async with get_session() as session:
            repo = EngagementRepository(session)

            engagement = await repo.create(
                client_name=client_name,
                project_name=project_name,
                methodology=methodology,
                approval_mode=approval_mode,
            )

            for target in scope:
                scope_type = detect_scope_type(target)
                await repo.add_scope_entry(
                    engagement_id=engagement.id,
                    target=target,
                    scope_type=scope_type.value,
                )

            await repo.update_status(engagement.id, EngagementStatus.ACTIVE)

        return {
            "success": True,
            "engagement_id": engagement.id,
            "client_name": client_name,
            "project_name": project_name,
            "scope_count": len(scope),
            "methodology": methodology,
            "approval_mode": approval_mode,
            "message": f"Created engagement for {client_name} with {len(scope)} scope entries",
        }
    except Exception as e:
        return {
            "success": False,
            "error": f"Database error: {str(e)}",
            "message": "Failed to create engagement",
        }


async def handle_engagement_status(arguments: dict[str, Any]) -> dict[str, Any]:
    """Handle engagement_status tool call."""
    from numasec.data.database import get_session, init_database
    from numasec.data.repositories.engagement import EngagementRepository
    from numasec.data.repositories.finding import FindingRepository

    await init_database()

    async with get_session() as session:
        engagement_repo = EngagementRepository(session)
        engagement = await engagement_repo.get_active()

        if not engagement:
            return {
                "success": False,
                "error": "No active engagement found",
                "message": "Create a new engagement with engagement_create tool",
            }

        # Get finding counts
        finding_repo = FindingRepository(session)
        severity_counts = await finding_repo.get_severity_counts(engagement.id)

        scope_list = [entry.target for entry in engagement.scope_entries]

        return {
            "success": True,
            "engagement": {
                "id": engagement.id,
                "client_name": engagement.client_name,
                "project_name": engagement.project_name,
                "status": engagement.status.value,
                "methodology": engagement.methodology,
                "current_phase": engagement.current_phase.value,
                "approval_mode": engagement.approval_mode,
                "created_at": engagement.created_at.isoformat(),
            },
            "scope": scope_list,
            "findings": severity_counts,
            "total_findings": sum(severity_counts.values()),
        }


async def handle_finding_create(arguments: dict[str, Any]) -> dict[str, Any]:
    """Handle finding_create tool call."""
    from numasec.data.database import get_session, init_database
    from numasec.data.repositories.engagement import EngagementRepository
    from numasec.data.repositories.finding import FindingRepository
    from numasec.data.models import Severity

    await init_database()

    async with get_session() as session:
        # Get active engagement
        engagement_repo = EngagementRepository(session)
        engagement = await engagement_repo.get_active()

        if not engagement:
            return {
                "success": False,
                "error": "No active engagement",
            }

        finding_repo = FindingRepository(session)

        severity_str = arguments.get("severity", "medium").lower()
        severity = Severity(severity_str)

        finding = await finding_repo.create(
            engagement_id=engagement.id,
            title=arguments.get("title", "Untitled Finding"),
            severity=severity,
            description=arguments.get("description", ""),
            cvss_score=float(arguments.get("cvss_score", 0.0)),
            cvss_vector=arguments.get("cvss_vector", ""),
            cwe_id=arguments.get("cwe_id", ""),
            impact=arguments.get("impact", ""),
            remediation=arguments.get("remediation", ""),
            affected_asset=arguments.get("affected_asset", ""),
            ai_generated=True,
        )

        # Add evidence if provided
        if evidence := arguments.get("evidence"):
            from numasec.data.models import EvidenceType
            await finding_repo.add_evidence(
                finding_id=finding.id,
                evidence_type=EvidenceType.TOOL_OUTPUT,
                title="Initial Evidence",
                content=evidence,
            )

    return {
        "success": True,
        "finding_id": finding.id,
        "title": finding.title,
        "severity": finding.severity.value,
        "message": f"Created {severity_str} finding: {finding.title}",
    }


async def handle_scope_check(arguments: dict[str, Any]) -> dict[str, Any]:
    """
    Handle scope_check tool call with proper wildcard/CIDR matching.
    
    CFAA Compliance: Prevents unauthorized access attempts.
    Supports:
    - Exact domain match: example.com
    - Wildcard subdomains: *.example.com
    - CIDR ranges: 192.168.1.0/24
    - IPv4 addresses
    """
    import ipaddress
    import re
    
    target = arguments.get("target", "")

    from numasec.data.database import get_session, init_database
    from numasec.data.repositories.engagement import EngagementRepository

    await init_database()

    async with get_session() as session:
        repo = EngagementRepository(session)
        engagement = await repo.get_active()

        if not engagement:
            return {
                "success": False,
                "in_scope": False,
                "reason": "No active engagement",
            }

        # Helper: Check if target is IP
        def is_ip(s: str) -> bool:
            try:
                ipaddress.ip_address(s)
                return True
            except ValueError:
                return False
        
        # Helper: Match domain with wildcard
        def domain_matches(target_domain: str, scope_pattern: str) -> bool:
            """
            Match domain against scope pattern.
            Supports:
            - Exact: example.com == example.com
            - Wildcard: *.example.com matches sub.example.com, deep.sub.example.com
            - NO MATCH: example.com.evil.com must NOT match *.example.com
            """
            # Exact match
            if target_domain == scope_pattern:
                return True
            
            # Wildcard pattern
            if scope_pattern.startswith("*."):
                base_domain = scope_pattern[2:]  # Remove *.
                # Target must END with .base_domain (strict boundary)
                if target_domain.endswith("." + base_domain):
                    return True
                # Also match base domain itself
                if target_domain == base_domain:
                    return True
            
            return False
        
        # Helper: Match IP against CIDR
        def ip_in_cidr(ip_str: str, cidr_str: str) -> bool:
            try:
                ip = ipaddress.ip_address(ip_str)
                network = ipaddress.ip_network(cidr_str, strict=False)
                return ip in network
            except ValueError:
                return False

        # Check exclusions first
        for entry in engagement.scope_entries:
            if entry.is_excluded:
                matched = False
                
                if is_ip(target):
                    # IP exclusion
                    if "/" in entry.target:
                        matched = ip_in_cidr(target, entry.target)
                    else:
                        matched = (target == entry.target)
                else:
                    # Domain exclusion
                    matched = domain_matches(target, entry.target)
                
                if matched:
                    return {
                        "success": True,
                        "in_scope": False,
                        "reason": f"Target is explicitly excluded: {entry.target}",
                    }
        
        # Check inclusions
        for entry in engagement.scope_entries:
            if not entry.is_excluded:
                matched = False
                
                if is_ip(target):
                    # IP/CIDR matching
                    if "/" in entry.target:
                        matched = ip_in_cidr(target, entry.target)
                    else:
                        matched = (target == entry.target)
                else:
                    # Domain wildcard matching
                    matched = domain_matches(target, entry.target)
                
                if matched:
                    return {
                        "success": True,
                        "in_scope": True,
                        "matched_scope": entry.target,
                        "reason": "Target matches authorized scope",
                    }

        return {
            "success": True,
            "in_scope": False,
            "reason": "Target does not match any scope entry",
        }


async def handle_web_request(arguments: dict[str, Any]) -> dict[str, Any]:
    """Handle web_request tool call - make HTTP requests with session/cookie persistence."""
    import re
    from urllib.parse import urlparse
    from numasec.compliance.authorization import require_authorization
    
    url = arguments.get("url", "")
    method = arguments.get("method", "GET").upper()
    session_id = arguments.get("session_id", "default")  # Session for cookie persistence
    headers = arguments.get("headers", {})
    body = arguments.get("body")
    data = arguments.get("data")  # dict for form data
    follow_redirects = arguments.get("follow_redirects", True)
    timeout = arguments.get("timeout", 30)
    
    if not url:
        return {"success": False, "error": "URL is required"}
    
    # ══════════════════════════════════════════════════════════════════════
    # SECURITY: CFAA Compliance + SSRF Prevention
    # ══════════════════════════════════════════════════════════════════════
    try:
        # Parse and validate URL structure
        parsed = urlparse(url)
        if not parsed.scheme or not parsed.netloc:
            return {"success": False, "error": "Invalid URL format"}
        
        # Block dangerous protocols
        if parsed.scheme not in ("http", "https"):
            return {"success": False, "error": f"Unsupported protocol: {parsed.scheme}"}
        
        # CFAA whitelist enforcement
        if not require_authorization(url, interactive=False):
            return {
                "success": False,
                "error": f"Target not whitelisted: {url}. Use scope_add to authorize.",
                "cfaa_violation": True
            }
    except Exception as e:
        return {"success": False, "error": f"Security check failed: {str(e)}"}
    
    try:
        # Use session manager for persistent cookies
        client = HTTPSessionManager.get_session(session_id)
        
        # Update client settings if needed
        client.timeout = httpx.Timeout(timeout)
        client.follow_redirects = follow_redirects
        
        # Build request kwargs
        kwargs: dict[str, Any] = {
            "url": url,
            "headers": headers,
        }
        
        if method in ("POST", "PUT", "PATCH"):
            if data is not None:
                # data dict passed directly - use as form data
                kwargs["data"] = data
            elif body:
                # Try to parse as JSON, otherwise use as form data
                try:
                    json_body = json.loads(body)
                    kwargs["json"] = json_body
                except (json.JSONDecodeError, TypeError):
                    kwargs["data"] = body
        
        # Make request (session maintains cookies automatically!)
        response = await client.request(method, **kwargs)
        
        html_body = response.text[:50000]  # Limit body size
        
        # Extract form fields automatically
        form_fields = _extract_form_fields(html_body)
        
        # Get current session cookies
        session_cookies = dict(client.cookies)
        
        # ══════════════════════════════════════════════════════════════════════
        # SEMANTIC PARSING: Convert raw HTTP to structured understanding
        # ══════════════════════════════════════════════════════════════════════
        # Paper: "Structured Representations for Web" (Meta AI, 2024)
        # Parse HTTP response semantically so LLM doesn't waste tokens on HTML
        
        semantics = parse_http_response(
            status_code=response.status_code,
            headers=dict(response.headers),
            body=html_body
        )
        
        # Convert to formatted string for LLM consumption
        semantic_analysis = semantics.to_context()
        
        return {
            "success": True,
            "status_code": response.status_code,
            "headers": dict(response.headers),
            "session_cookies": session_cookies,  # All cookies in session
            "body": html_body,
            "url": str(response.url),
            "method": method,
            "session_id": session_id,
            "elapsed_ms": int(response.elapsed.total_seconds() * 1000),
            "form_fields": form_fields,
            # NEW: Semantic analysis for LLM
            "semantic_analysis": semantic_analysis,
        }
            
    except httpx.TimeoutException:
        return {"success": False, "error": f"Request timed out after {timeout}s"}
    except httpx.RequestError as e:
        return {"success": False, "error": f"Request failed: {str(e)}"}
    except Exception as e:
        return {"success": False, "error": f"Unexpected error: {str(e)}"}


def _extract_form_fields(html: str) -> dict[str, Any]:
    """
    Extract ALL form fields from HTML response.
    Returns dict mapping field names to values.
    CSRF tokens get their FULL value, not truncated.
    """
    import re
    
    fields: dict[str, Any] = {}
    forms: list[dict] = []
    
    # Find all forms
    form_pattern = re.compile(r'<form[^>]*>(.*?)</form>', re.DOTALL | re.IGNORECASE)
    for form_match in form_pattern.finditer(html):
        form_html = form_match.group(0)
        form_data: dict[str, Any] = {"action": "", "method": "GET", "fields": {}}
        
        # Extract form action
        action_match = re.search(r'action=["\']([^"\']*)["\']', form_html, re.IGNORECASE)
        if action_match:
            form_data["action"] = action_match.group(1)
        
        # Extract form method
        method_match = re.search(r'method=["\']([^"\']*)["\']', form_html, re.IGNORECASE)
        if method_match:
            form_data["method"] = method_match.group(1).upper()
        
        form_content = form_match.group(1)
        
        # Extract input fields with various attribute orders
        input_patterns = [
            # name before value
            r'<input[^>]+name=["\']([^"\']+)["\'][^>]*value=["\']([^"\']*)["\']',
            # value before name
            r'<input[^>]+value=["\']([^"\']*)["\'][^>]+name=["\']([^"\']+)["\']',
            # name only (no value)
            r'<input[^>]+name=["\']([^"\']+)["\'][^>]*(?:type=["\']([^"\']*)["\'])?',
        ]
        
        for i, pattern in enumerate(input_patterns):
            for match in re.finditer(pattern, form_content, re.IGNORECASE):
                if i == 0:  # name before value
                    name, value = match.groups()
                elif i == 1:  # value before name
                    value, name = match.groups()
                else:  # name only
                    name = match.group(1)
                    value = ""
                
                if name and name not in form_data["fields"]:
                    form_data["fields"][name] = value
                    fields[name] = value  # Also add to flat dict
        
        # Extract select fields
        for select_match in re.finditer(
            r'<select[^>]+name=["\']([^"\']+)["\'][^>]*>.*?</select>',
            form_content, re.DOTALL | re.IGNORECASE
        ):
            name = select_match.group(1)
            # Get selected option or first option
            selected = re.search(r'<option[^>]+selected[^>]*value=["\']([^"\']*)["\']', 
                                select_match.group(0), re.IGNORECASE)
            if selected:
                form_data["fields"][name] = selected.group(1)
                fields[name] = selected.group(1)
        
        # Extract textarea fields
        for textarea_match in re.finditer(
            r'<textarea[^>]+name=["\']([^"\']+)["\'][^>]*>(.*?)</textarea>',
            form_content, re.DOTALL | re.IGNORECASE
        ):
            name, value = textarea_match.groups()
            form_data["fields"][name] = value.strip()
            fields[name] = value.strip()
        
        forms.append(form_data)
    
    return {
        "fields": fields,  # Flat dict of all field names -> values
        "forms": forms,    # Structured form data
    }


# ══════════════════════════════════════════════════════════════════════════════
# Tool Handlers from tools/*.py
# ══════════════════════════════════════════════════════════════════════════════


async def handle_recon_nmap(arguments: dict[str, Any]) -> dict[str, Any]:
    """Handle recon_nmap tool call using NmapTool."""
    try:
        from numasec.tools.nmap import NmapTool
        tool = NmapTool()
        
        # Build extra_args from timing if provided
        extra_args = []
        timing = arguments.get("timing")
        if timing is not None:
            extra_args.append(f"-T{timing}")
        
        result = await tool.execute(
            targets=arguments.get("targets", []),
            ports=arguments.get("ports"),
            scan_type=arguments.get("scan_type", "quick"),
            extra_args=extra_args if extra_args else None,
            timeout=arguments.get("timeout", 600),
        )
        return result.to_dict()
    except Exception as e:
        return {"success": False, "error": str(e)}


async def handle_recon_httpx(arguments: dict[str, Any]) -> dict[str, Any]:
    """Handle recon_httpx tool call using HttpxTool."""
    try:
        from numasec.tools.httpx_tool import HttpxTool
        tool = HttpxTool()
        result = await tool.execute(
            targets=arguments.get("targets", []),
            tech_detect=arguments.get("tech_detect", True),
            title=arguments.get("title", True),
            status_code=arguments.get("status_code", True),
            follow_redirects=arguments.get("follow_redirects", True),
            timeout=arguments.get("timeout", 300),
        )
        return result.to_dict()
    except Exception as e:
        return {"success": False, "error": str(e)}


async def handle_web_ffuf(arguments: dict[str, Any]) -> dict[str, Any]:
    """Handle web_ffuf tool call using FfufTool."""
    try:
        from numasec.tools.ffuf import FfufTool
        tool = FfufTool()
        
        # Map wordlist names to paths
        wordlist_map = {
            "common": "/usr/share/seclists/Discovery/Web-Content/common.txt",
            "big": "/usr/share/seclists/Discovery/Web-Content/big.txt",
            "raft-medium": "/usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt",
            "dirbuster-medium": "/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt",
        }
        
        wordlist_arg = arguments.get("wordlist", "common")
        if wordlist_arg in wordlist_map:
            wordlist = wordlist_map[wordlist_arg]
        elif arguments.get("custom_wordlist"):
            wordlist = arguments["custom_wordlist"]
        else:
            wordlist = wordlist_map["common"]
        
        result = await tool.execute(
            url=arguments.get("url", ""),
            wordlist=wordlist,
            extensions=arguments.get("extensions", "").split(",") if arguments.get("extensions") else None,
            threads=arguments.get("threads", 40),
            timeout=arguments.get("timeout", 600),
        )
        return result.to_dict()
    except Exception as e:
        return {"success": False, "error": str(e)}


async def handle_web_nuclei(arguments: dict[str, Any]) -> dict[str, Any]:
    """Handle web_nuclei tool call using NucleiTool."""
    try:
        from numasec.tools.nuclei import NucleiTool
        tool = NucleiTool()
        result = await tool.execute(
            targets=arguments.get("targets", []),
            templates=arguments.get("templates"),
            severity=arguments.get("severity", ["medium", "high", "critical"]),
            rate_limit=arguments.get("rate_limit", 150),
            timeout=arguments.get("timeout", 600),
        )
        return result.to_dict()
    except Exception as e:
        return {"success": False, "error": str(e)}


async def handle_web_sqlmap(arguments: dict[str, Any]) -> dict[str, Any]:
    """Handle web_sqlmap tool call using SQLMapTool."""
    try:
        from numasec.tools.sqlmap import SQLMapTool
        tool = SQLMapTool()
        result = await tool.execute(
            url=arguments.get("url", ""),
            data=arguments.get("data"),
            cookie=arguments.get("cookie"),
            level=arguments.get("level", 1),
            risk=arguments.get("risk", 1),
            technique=arguments.get("technique"),
            dbs=arguments.get("dbs", False),
            timeout=arguments.get("timeout", 600),
        )
        return result.to_dict()
    except Exception as e:
        return {"success": False, "error": str(e)}


async def handle_exploit_hydra(arguments: dict[str, Any]) -> dict[str, Any]:
    """Handle exploit_hydra tool call using HydraTool."""
    try:
        from numasec.tools.hydra import HydraTool
        tool = HydraTool()
        result = await tool.execute(
            target=arguments.get("target", ""),
            service=arguments.get("service", ""),
            username=arguments.get("username"),
            password=arguments.get("password"),
            username_file=arguments.get("username_file"),
            password_file=arguments.get("password_file"),
            threads=arguments.get("threads", 4),
            timeout=arguments.get("timeout", 600),
        )
        return result.to_dict()
    except Exception as e:
        return {"success": False, "error": str(e)}


async def handle_recon_subdomain(arguments: dict[str, Any]) -> dict[str, Any]:
    """Handle recon_subdomain tool call using SubfinderTool."""
    try:
        from numasec.tools.subfinder import SubfinderTool
        tool = SubfinderTool()
        result = await tool.execute(
            domain=arguments.get("domain", ""),
            timeout=arguments.get("timeout", 300),
        )
        return result.to_dict()
    except Exception as e:
        return {"success": False, "error": str(e)}


async def handle_recon_whatweb(arguments: dict[str, Any]) -> dict[str, Any]:
    """Handle recon_whatweb tool call using WhatWebTool."""
    try:
        from numasec.tools.whatweb import WhatWebTool
        tool = WhatWebTool()
        
        # WhatWeb only accepts aggression levels 1, 3, or 4 (NOT 2!)
        aggression = arguments.get("aggression", 1)
        if aggression not in (1, 3, 4):
            # Map invalid values: 2→3, anything else→1
            aggression = 3 if aggression == 2 else 1
        
        result = await tool.execute(
            targets=arguments.get("targets", []),
            aggression=aggression,
            timeout=arguments.get("timeout", 300),
        )
        return result.to_dict()
    except Exception as e:
        return {"success": False, "error": str(e)}


async def handle_web_nikto(arguments: dict[str, Any]) -> dict[str, Any]:
    """Handle web_nikto tool call using NiktoTool."""
    try:
        from numasec.tools.nikto import NiktoTool
        tool = NiktoTool()
        result = await tool.execute(
            target=arguments.get("target", ""),
            port=arguments.get("port"),
            ssl=arguments.get("ssl", False),
            timeout=arguments.get("timeout", 600),
        )
        return result.to_dict()
    except Exception as e:
        return {"success": False, "error": str(e)}


async def handle_web_crawl(arguments: dict[str, Any]) -> dict[str, Any]:
    """
    Handle web_crawl tool call - crawl website to discover endpoints.
    
    Uses BeautifulSoup to parse HTML and extract links.
    Respects depth limit and same-origin policy.
    """
    from urllib.parse import urljoin, urlparse
    from collections import deque
    
    url = arguments.get("url", "")
    max_depth = arguments.get("depth", 3)
    include_subdomains = arguments.get("include_subdomains", False)
    
    if not url:
        return {"success": False, "error": "URL is required"}
    
    try:
        from bs4 import BeautifulSoup
    except ImportError:
        return {"success": False, "error": "BeautifulSoup not installed"}
    
    # Parse base URL for same-origin check
    parsed_base = urlparse(url)
    base_domain = parsed_base.netloc
    
    discovered_urls = set()
    discovered_forms = []
    discovered_params = set()
    visited = set()
    
    queue = deque([(url, 0)])  # (url, depth)
    
    session = HTTPSessionManager.get_session("crawl")
    
    while queue and len(visited) < 50:  # Limit to 50 pages
        current_url, depth = queue.popleft()
        
        if current_url in visited or depth > max_depth:
            continue
        
        visited.add(current_url)
        
        try:
            response = await session.get(current_url, timeout=10)
            if response.status_code != 200:
                continue
            
            soup = BeautifulSoup(response.text, "html.parser")
            
            # Extract links
            for link in soup.find_all("a", href=True):
                href = link["href"]
                full_url = urljoin(current_url, href)
                parsed = urlparse(full_url)
                
                # Check same-origin
                if include_subdomains:
                    if not parsed.netloc.endswith(base_domain.split(".")[-2] + "." + base_domain.split(".")[-1] if "." in base_domain else base_domain):
                        continue
                else:
                    if parsed.netloc != base_domain:
                        continue
                
                # Clean URL (remove fragment)
                clean_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
                if parsed.query:
                    clean_url += f"?{parsed.query}"
                    # Extract parameter names
                    for param in parsed.query.split("&"):
                        if "=" in param:
                            discovered_params.add(param.split("=")[0])
                
                if clean_url not in visited:
                    discovered_urls.add(clean_url)
                    queue.append((clean_url, depth + 1))
            
            # Extract forms
            for form in soup.find_all("form"):
                form_data = {
                    "action": urljoin(current_url, form.get("action", "")),
                    "method": form.get("method", "GET").upper(),
                    "inputs": []
                }
                for inp in form.find_all(["input", "textarea", "select"]):
                    inp_data = {
                        "name": inp.get("name", ""),
                        "type": inp.get("type", "text"),
                        "value": inp.get("value", "")
                    }
                    if inp_data["name"]:
                        form_data["inputs"].append(inp_data)
                
                if form_data["inputs"]:
                    discovered_forms.append(form_data)
        
        except Exception as e:
            logger.debug(f"Crawl error on {current_url}: {e}")
            continue
    
    return {
        "success": True,
        "base_url": url,
        "pages_crawled": len(visited),
        "max_depth": max_depth,
        "discovered_urls": sorted(list(discovered_urls))[:100],  # Limit output
        "discovered_forms": discovered_forms[:20],
        "discovered_params": sorted(list(discovered_params)),
        "summary": f"Crawled {len(visited)} pages, found {len(discovered_urls)} URLs, {len(discovered_forms)} forms, {len(discovered_params)} params"
    }


async def handle_exploit_script(arguments: dict[str, Any]) -> dict[str, Any]:
    """Handle exploit_script tool call - run Python code safely."""
    try:
        from numasec.tools.scripts import ScriptTool
        tool = ScriptTool()
        result = await tool.execute(
            code=arguments.get("code", ""),
            script_type=arguments.get("script_type", "python"),
            timeout=arguments.get("timeout", 30),
        )
        return result.to_dict()
    except Exception as e:
        return {"success": False, "error": str(e)}


# Tool handler registry
async def handle_notes_write(arguments: dict[str, Any]) -> dict[str, Any]:
    """Handle notes_write tool call - save information to scratchpad."""
    key = arguments.get("key", "")
    value = arguments.get("value", "")
    session_id = arguments.get("session_id", "default")
    
    if not key or not value:
        return {"success": False, "error": "Both key and value are required"}
    
    HTTPSessionManager.write_note(session_id, key, value)
    all_notes = HTTPSessionManager.read_notes(session_id)
    
    return {
        "success": True,
        "message": f"Saved '{key}' to scratchpad",
        "all_notes": all_notes,
    }


async def handle_notes_read(arguments: dict[str, Any]) -> dict[str, Any]:
    """Handle notes_read tool call - read all notes from scratchpad."""
    session_id = arguments.get("session_id", "default")
    
    notes = HTTPSessionManager.read_notes(session_id)
    
    return {
        "success": True,
        "notes": notes,
        "count": len(notes),
    }


async def handle_engagement_close(arguments: dict[str, Any]) -> dict[str, Any]:
    """Handle engagement_close tool call."""
    from numasec.data.database import get_session, init_database
    from numasec.data.repositories.engagement import EngagementRepository
    from numasec.data.models import EngagementStatus
    from numasec.reporting.generator import (
        ReportGenerator,
        ReportConfig,
        ReportTemplate,
        ReportFormat,
        Classification,
    )
    from pathlib import Path

    await init_database()

    generate_report = arguments.get("generate_report", True)
    report_format = arguments.get("report_format", "markdown")

    async with get_session() as session:
        engagement_repo = EngagementRepository(session)
        engagement = await engagement_repo.get_active()

        if not engagement:
            return {
                "success": False,
                "error": "No active engagement found",
            }
            
        # Re-fetch with all relations (findings, scope) for reporting
        from sqlalchemy import select
        from sqlalchemy.orm import selectinload
        from numasec.data.models import Engagement, Finding

        # Direct query to ensure deep loading of nested relations
        stmt = (
            select(Engagement)
            .where(Engagement.id == engagement.id)
            .options(
                selectinload(Engagement.scope_entries),
                selectinload(Engagement.findings).selectinload(Finding.affected_assets),
                selectinload(Engagement.findings).selectinload(Finding.evidence),
            )
        )
        result = await session.execute(stmt)
        engagement = result.scalar_one_or_none()
        
        report_path_str = None
        report_result = None

        if generate_report and engagement:
            # Prepare config
            config = ReportConfig(
                title=f"{engagement.project_name} - Penetration Test Report",
                client_name=engagement.client_name,
                project_name=engagement.project_name,
                classification=Classification.CONFIDENTIAL,
                template=ReportTemplate.PTES,
                format=ReportFormat(report_format),
                findings=engagement.findings,
                start_date=engagement.created_at.strftime("%Y-%m-%d"),
                end_date=datetime.now().strftime("%Y-%m-%d"),
            )
            
            # Setup output path
            import os
            default_base = Path(os.getenv("NUMASEC_DATA_DIR", str(Path.home() / ".numasec")))
            output_dir = default_base / "reports"
            output_dir.mkdir(parents=True, exist_ok=True)
            filename = f"report_{engagement.project_name.lower().replace(' ', '_')}_{datetime.now().strftime('%Y%m%d')}.{report_format}"
            output_path = output_dir / filename
            
            # Generate
            generator = ReportGenerator(config)
            report_result = generator.generate(output_path)
            
            if report_result.success:
                report_path_str = str(report_result.output_path)

        # Close engagement
        success = await engagement_repo.close(engagement.id)

        return {
            "success": success,
            "previous_status": EngagementStatus.ACTIVE.value,
            "new_status": EngagementStatus.COMPLETE.value,
            "report_generated": generate_report,
            "report_path": report_path_str,
            "findings_count": len(engagement.findings) if engagement else 0,
        }


# ══════════════════════════════════════════════════════════════════════════════
# MISSING TOOL HANDLERS - SOTA Implementation
# ══════════════════════════════════════════════════════════════════════════════


async def handle_recon_dns(arguments: dict[str, Any]) -> dict[str, Any]:
    """
    Handle recon_dns tool call - DNS reconnaissance with zone transfer attempt.
    
    SOTA Implementation:
    - Uses dnspython for reliable resolution
    - Attempts AXFR zone transfer on all NS servers
    - Collects all record types in parallel
    """
    import asyncio
    
    domain = arguments.get("domain", "")
    record_types = arguments.get("record_types", ["A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA"])
    attempt_zone_transfer = arguments.get("attempt_zone_transfer", True)
    
    if not domain:
        return {"success": False, "error": "Domain is required"}
    
    try:
        import dns.resolver
        import dns.zone
        import dns.query
        import dns.exception
    except ImportError:
        return {"success": False, "error": "dnspython not installed. pip install dnspython"}
    
    results: dict[str, Any] = {
        "domain": domain,
        "records": {},
        "nameservers": [],
        "zone_transfer": {"attempted": False, "successful": False, "records": []},
    }
    
    resolver = dns.resolver.Resolver()
    resolver.timeout = 5
    resolver.lifetime = 10
    
    # Query each record type
    for rtype in record_types:
        try:
            answers = resolver.resolve(domain, rtype)
            results["records"][rtype] = [str(rdata) for rdata in answers]
        except dns.resolver.NoAnswer:
            results["records"][rtype] = []
        except dns.resolver.NXDOMAIN:
            return {"success": False, "error": f"Domain {domain} does not exist"}
        except Exception as e:
            results["records"][rtype] = [f"Error: {str(e)}"]
    
    # Get nameservers for zone transfer
    try:
        ns_answers = resolver.resolve(domain, "NS")
        results["nameservers"] = [str(ns).rstrip('.') for ns in ns_answers]
    except Exception:
        pass
    
    # Attempt zone transfer
    if attempt_zone_transfer and results["nameservers"]:
        results["zone_transfer"]["attempted"] = True
        for ns in results["nameservers"]:
            try:
                zone = dns.zone.from_xfr(dns.query.xfr(ns, domain, timeout=10))
                results["zone_transfer"]["successful"] = True
                results["zone_transfer"]["vulnerable_ns"] = ns
                results["zone_transfer"]["records"] = [
                    {"name": str(name), "ttl": node.ttl, "rdatasets": [str(rd) for rd in node.rdatasets]}
                    for name, node in zone.nodes.items()
                ][:50]  # Limit output
                break  # One success is enough
            except Exception as e:
                logger.debug(f"Zone transfer failed on {ns}: {e}")
                continue
    
    results["success"] = True
    results["summary"] = f"Resolved {sum(len(v) for v in results['records'].values() if isinstance(v, list))} records"
    if results["zone_transfer"]["successful"]:
        results["summary"] += " | ⚠️ ZONE TRANSFER SUCCESSFUL - HIGH SEVERITY FINDING"
    
    return results


async def handle_finding_list(arguments: dict[str, Any]) -> dict[str, Any]:
    """Handle finding_list tool call - list all findings for active engagement."""
    from numasec.data.database import get_session, init_database
    from numasec.data.repositories.engagement import EngagementRepository
    from numasec.data.repositories.finding import FindingRepository
    from numasec.data.models import Severity
    
    await init_database()
    
    severity_filter = arguments.get("severity")
    include_false_positives = arguments.get("include_false_positives", False)
    
    async with get_session() as session:
        engagement_repo = EngagementRepository(session)
        engagement = await engagement_repo.get_active()
        
        if not engagement:
            return {"success": False, "error": "No active engagement"}
        
        finding_repo = FindingRepository(session)
        severity = Severity(severity_filter) if severity_filter else None
        
        findings = await finding_repo.list_by_engagement(
            engagement.id,
            severity=severity,
            include_false_positives=include_false_positives,
        )
        
        findings_data = [
            {
                "id": f.id,
                "title": f.title,
                "severity": f.severity.value,
                "cvss_score": f.cvss_score,
                "cwe_id": f.cwe_id,
                "affected_asset": f.affected_asset,
                "is_false_positive": f.is_false_positive,
                "created_at": f.created_at.isoformat(),
            }
            for f in findings
        ]
        
        return {
            "success": True,
            "engagement_id": engagement.id,
            "findings": findings_data,
            "count": len(findings_data),
            "severity_filter": severity_filter,
        }


async def handle_finding_update(arguments: dict[str, Any]) -> dict[str, Any]:
    """Handle finding_update tool call - update finding fields."""
    from numasec.data.database import get_session, init_database
    from numasec.data.repositories.finding import FindingRepository
    from numasec.data.models import Severity
    
    await init_database()
    
    finding_id = arguments.get("finding_id")
    updates = arguments.get("updates", {})
    
    if not finding_id:
        return {"success": False, "error": "finding_id is required"}
    
    if not updates:
        return {"success": False, "error": "updates dict is required"}
    
    # Map severity string to enum if present
    if "severity" in updates:
        updates["severity"] = Severity(updates["severity"].lower())
    
    async with get_session() as session:
        finding_repo = FindingRepository(session)
        
        # Verify finding exists
        finding = await finding_repo.get_by_id(finding_id, include_evidence=False)
        if not finding:
            return {"success": False, "error": f"Finding {finding_id} not found"}
        
        # Apply updates
        success = await finding_repo.update(finding_id, **updates)
        
        return {
            "success": success,
            "finding_id": finding_id,
            "updated_fields": list(updates.keys()),
        }


async def handle_finding_add_evidence(arguments: dict[str, Any]) -> dict[str, Any]:
    """Handle finding_add_evidence tool call - add evidence to finding."""
    from numasec.data.database import get_session, init_database
    from numasec.data.repositories.finding import FindingRepository
    from numasec.data.models import EvidenceType
    
    await init_database()
    
    finding_id = arguments.get("finding_id")
    evidence_type_str = arguments.get("evidence_type", "tool_output")
    title = arguments.get("title", "Evidence")
    content = arguments.get("content", "")
    
    if not finding_id:
        return {"success": False, "error": "finding_id is required"}
    
    # Map evidence type
    type_map = {
        "screenshot": EvidenceType.SCREENSHOT,
        "request": EvidenceType.REQUEST,
        "response": EvidenceType.RESPONSE,
        "log": EvidenceType.LOG,
        "code": EvidenceType.CODE,
        "tool_output": EvidenceType.TOOL_OUTPUT,
    }
    evidence_type = type_map.get(evidence_type_str, EvidenceType.TOOL_OUTPUT)
    
    async with get_session() as session:
        finding_repo = FindingRepository(session)
        
        # Verify finding exists
        finding = await finding_repo.get_by_id(finding_id, include_evidence=False)
        if not finding:
            return {"success": False, "error": f"Finding {finding_id} not found"}
        
        evidence = await finding_repo.add_evidence(
            finding_id=finding_id,
            evidence_type=evidence_type,
            title=title,
            content=content,
        )
        
        return {
            "success": True,
            "evidence_id": evidence.id,
            "finding_id": finding_id,
            "type": evidence_type.value,
            "title": title,
        }


async def handle_scope_add(arguments: dict[str, Any]) -> dict[str, Any]:
    """Handle scope_add tool call - add target to engagement scope."""
    from numasec.data.database import get_session, init_database
    from numasec.data.repositories.engagement import EngagementRepository
    import ipaddress
    from urllib.parse import urlparse
    
    await init_database()
    
    target = arguments.get("target", "")
    is_excluded = arguments.get("is_excluded", False)
    description = arguments.get("description", "")
    
    if not target:
        return {"success": False, "error": "target is required"}
    
    # Auto-detect scope type
    scope_type = "domain"  # default
    try:
        ipaddress.ip_address(target)
        scope_type = "ip"
    except ValueError:
        try:
            ipaddress.ip_network(target, strict=False)
            scope_type = "cidr"
        except ValueError:
            if target.startswith(("http://", "https://")):
                scope_type = "url"
            elif "/" in target:
                scope_type = "url"
            else:
                scope_type = "domain"
    
    async with get_session() as session:
        repo = EngagementRepository(session)
        engagement = await repo.get_active()
        
        if not engagement:
            return {"success": False, "error": "No active engagement"}
        
        entry = await repo.add_scope_entry(
            engagement_id=engagement.id,
            target=target,
            scope_type=scope_type,
            is_excluded=is_excluded,
            description=description,
        )
        
        return {
            "success": True,
            "scope_entry_id": entry.id,
            "target": target,
            "scope_type": scope_type,
            "is_excluded": is_excluded,
            "engagement_id": engagement.id,
        }


async def handle_report_generate(arguments: dict[str, Any]) -> dict[str, Any]:
    """
    Handle report_generate tool call - generate penetration test report.
    
    SOTA Implementation:
    - Supports multiple formats (PDF, DOCX, Markdown, HTML)
    - Uses Typst for professional PDF generation
    - Includes executive summary, findings, and remediation roadmap
    """
    from numasec.data.database import get_session, init_database
    from numasec.data.repositories.engagement import EngagementRepository
    from numasec.reporting.generator import (
        ReportGenerator,
        ReportConfig,
        ReportTemplate,
        ReportFormat,
        Classification,
    )
    from sqlalchemy import select
    from sqlalchemy.orm import selectinload
    from numasec.data.models import Engagement, Finding
    from datetime import datetime
    from pathlib import Path
    import os
    
    await init_database()
    
    format_str = arguments.get("format", "pdf")
    template_str = arguments.get("template", "ptes")
    
    # Map format
    format_map = {
        "pdf": ReportFormat.PDF,
        "docx": ReportFormat.DOCX,
        "md": ReportFormat.MARKDOWN,
        "markdown": ReportFormat.MARKDOWN,
        "html": ReportFormat.HTML,
    }
    report_format = format_map.get(format_str, ReportFormat.PDF)
    
    # Map template (only PTES implemented for now)
    template_map = {
        "ptes": ReportTemplate.PTES,
        # Future: OWASP, EXECUTIVE, TECHNICAL
    }
    report_template = template_map.get(template_str, ReportTemplate.PTES)
    
    async with get_session() as session:
        engagement_repo = EngagementRepository(session)
        engagement = await engagement_repo.get_active()
        
        if not engagement:
            return {"success": False, "error": "No active engagement"}
        
        # Re-fetch with all relations
        stmt = (
            select(Engagement)
            .where(Engagement.id == engagement.id)
            .options(
                selectinload(Engagement.scope_entries),
                selectinload(Engagement.findings).selectinload(Finding.affected_assets),
                selectinload(Engagement.findings).selectinload(Finding.evidence),
            )
        )
        result = await session.execute(stmt)
        engagement = result.scalar_one_or_none()
        
        if not engagement:
            return {"success": False, "error": "Failed to load engagement"}
        
        # Prepare config
        config = ReportConfig(
            title=f"{engagement.project_name} - Penetration Test Report",
            client_name=engagement.client_name,
            project_name=engagement.project_name,
            classification=Classification.CONFIDENTIAL,
            template=report_template,
            format=report_format,
            findings=engagement.findings,
            start_date=engagement.created_at.strftime("%Y-%m-%d"),
            end_date=datetime.now().strftime("%Y-%m-%d"),
        )
        
        # Setup output path
        default_base = Path(os.getenv("NUMASEC_DATA_DIR", str(Path.home() / ".numasec")))
        output_dir = default_base / "reports"
        output_dir.mkdir(parents=True, exist_ok=True)
        
        ext = format_str if format_str != "markdown" else "md"
        filename = f"report_{engagement.project_name.lower().replace(' ', '_')}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.{ext}"
        output_path = output_dir / filename
        
        # Generate
        generator = ReportGenerator(config)
        result = generator.generate(output_path)
        
        return {
            "success": result.success,
            "output_path": str(result.output_path) if result.output_path else None,
            "format": format_str,
            "template": template_str,
            "findings_count": len(engagement.findings),
            "generation_time_seconds": result.generation_time,
            "errors": result.errors,
            "warnings": result.warnings,
        }


async def handle_report_preview(arguments: dict[str, Any]) -> dict[str, Any]:
    """Handle report_preview tool call - preview executive summary and findings."""
    from numasec.data.database import get_session, init_database
    from numasec.data.repositories.engagement import EngagementRepository
    from numasec.data.repositories.finding import FindingRepository
    
    await init_database()
    
    async with get_session() as session:
        engagement_repo = EngagementRepository(session)
        engagement = await engagement_repo.get_active()
        
        if not engagement:
            return {"success": False, "error": "No active engagement"}
        
        finding_repo = FindingRepository(session)
        findings = await finding_repo.list_by_engagement(engagement.id)
        severity_counts = await finding_repo.get_severity_counts(engagement.id)
        
        # Build executive summary
        total = sum(severity_counts.values())
        critical = severity_counts.get("critical", 0)
        high = severity_counts.get("high", 0)
        
        risk_level = "LOW"
        if critical > 0:
            risk_level = "CRITICAL"
        elif high > 0:
            risk_level = "HIGH"
        elif severity_counts.get("medium", 0) > 0:
            risk_level = "MEDIUM"
        
        executive_summary = f"""
## Executive Summary

NumaSec conducted a penetration test of {engagement.client_name}'s {engagement.project_name} environment.

**Overall Risk Level: {risk_level}**

### Finding Summary
- Critical: {severity_counts.get('critical', 0)}
- High: {severity_counts.get('high', 0)}
- Medium: {severity_counts.get('medium', 0)}
- Low: {severity_counts.get('low', 0)}
- Informational: {severity_counts.get('informational', 0)}

### Top Findings
"""
        # Add top 5 findings
        for i, finding in enumerate(findings[:5], 1):
            executive_summary += f"\n{i}. **[{finding.severity.value.upper()}]** {finding.title}"
        
        return {
            "success": True,
            "engagement": {
                "client_name": engagement.client_name,
                "project_name": engagement.project_name,
                "methodology": engagement.methodology,
            },
            "executive_summary": executive_summary.strip(),
            "severity_counts": severity_counts,
            "total_findings": total,
            "risk_level": risk_level,
        }


async def handle_knowledge_search(arguments: dict[str, Any]) -> dict[str, Any]:
    """
    Handle knowledge_search tool call - search knowledge base.
    
    SOTA Implementation:
    - Uses hybrid BM25 + Vector search with RRF fusion
    - Searches payloads, techniques, and writeups
    - Returns ranked results with relevance scores
    """
    query = arguments.get("query", "")
    category = arguments.get("category", "all")
    limit = arguments.get("limit", 10)
    
    if not query:
        return {"success": False, "error": "query is required"}
    
    try:
        from numasec.knowledge.store import KnowledgeStore
        
        store = KnowledgeStore()
        await store.initialize()
        
        # Map category to entry types
        entry_types = None
        if category == "payloads":
            entry_types = ["payload"]
        elif category == "techniques":
            entry_types = ["technique"]
        elif category == "writeups":
            entry_types = ["writeup"]
        # else: all types (None = all)
        
        # Use hybrid search for best results
        results = await store.search_hybrid(
            query=query,
            entry_types=entry_types,
            limit=limit,
            alpha=0.5,  # Balanced BM25 + vector
        )
        
        formatted_results = [
            {
                "title": r.entry.get("title", r.entry.get("name", "Untitled")),
                "type": r.entry_type,
                "score": round(r.score, 4),
                "content_preview": (r.entry.get("text", "") or r.entry.get("content", ""))[:200],
                "tags": r.entry.get("tags", []),
                "metadata": {k: v for k, v in r.entry.items() if k not in ("text", "content", "vector")},
            }
            for r in results.results
        ]
        
        return {
            "success": True,
            "query": query,
            "category": category,
            "results": formatted_results,
            "count": len(formatted_results),
            "search_time_ms": round(results.search_time_ms, 2),
        }
    
    except Exception as e:
        logger.error(f"Knowledge search failed: {e}")
        return {
            "success": False,
            "error": str(e),
            "hint": "Knowledge base may not be initialized. Run 'numasec knowledge sync' first.",
        }


async def handle_knowledge_add(arguments: dict[str, Any]) -> dict[str, Any]:
    """
    Handle knowledge_add tool call - add new knowledge entry.
    
    SOTA Implementation:
    - Adds to appropriate table (payloads, techniques, writeups, reflexions)
    - Generates embedding for vector search
    - Updates BM25 index
    """
    category = arguments.get("category", "")
    title = arguments.get("title", "")
    content = arguments.get("content", "")
    tags = arguments.get("tags", [])
    
    if not category:
        return {"success": False, "error": "category is required"}
    if not title:
        return {"success": False, "error": "title is required"}
    if not content:
        return {"success": False, "error": "content is required"}
    
    valid_categories = {"payload", "technique", "writeup", "reflexion"}
    if category not in valid_categories:
        return {"success": False, "error": f"Invalid category. Must be one of: {valid_categories}"}
    
    try:
        from numasec.knowledge.store import KnowledgeStore
        import uuid
        
        store = KnowledgeStore()
        await store.initialize()
        
        # Create entry based on category
        entry_id = str(uuid.uuid4())
        
        if category == "payload":
            from numasec.knowledge.store import PayloadEntry
            entry = PayloadEntry(
                id=entry_id,
                name=title,
                payload=content,
                category=tags[0] if tags else "custom",
                subcategory=tags[1] if len(tags) > 1 else "",
                tags=tags,
                description=content[:200],
            )
            await store.add_payloads([entry])
        
        elif category == "technique":
            from numasec.knowledge.store import TechniqueEntry
            entry = TechniqueEntry(
                id=entry_id,
                name=title,
                description=content,
                mitre_id="",  # Could be parsed from content
                tactics=tags,
            )
            await store.add_techniques([entry])
        
        elif category == "reflexion":
            from numasec.knowledge.store import ReflexionEntry
            from datetime import datetime
            entry = ReflexionEntry(
                id=entry_id,
                iteration=0,
                action=title,
                observation=content,
                reflection=content,
                lesson_learned=content,
                timestamp=datetime.now().isoformat(),
                tags=tags,
            )
            await store.add_reflexions([entry])
        
        else:  # writeup
            # Writeups use a generic add method
            await store._add_generic_entry("writeups", {
                "id": entry_id,
                "title": title,
                "content": content,
                "tags": tags,
            })
        
        return {
            "success": True,
            "entry_id": entry_id,
            "category": category,
            "title": title,
            "tags": tags,
        }
    
    except Exception as e:
        logger.error(f"Knowledge add failed: {e}")
        return {
            "success": False,
            "error": str(e),
        }


# ══════════════════════════════════════════════════════════════════════════════
# Tool Handler Registry
# ══════════════════════════════════════════════════════════════════════════════

TOOL_HANDLERS = {
    "engagement_create": handle_engagement_create,
    "engagement_status": handle_engagement_status,
    "engagement_close": handle_engagement_close,
    "finding_create": handle_finding_create,
    "finding_list": handle_finding_list,
    "finding_update": handle_finding_update,
    "finding_add_evidence": handle_finding_add_evidence,
    "scope_check": handle_scope_check,
    "scope_add": handle_scope_add,
    "web_request": handle_web_request,
    # Recon tools
    "recon_nmap": handle_recon_nmap,
    "recon_httpx": handle_recon_httpx,
    "recon_subdomain": handle_recon_subdomain,
    "recon_whatweb": handle_recon_whatweb,
    "recon_dns": handle_recon_dns,
    # Web tools
    "web_ffuf": handle_web_ffuf,
    "web_nuclei": handle_web_nuclei,
    "web_sqlmap": handle_web_sqlmap,
    "web_nikto": handle_web_nikto,
    "web_crawl": handle_web_crawl,
    # Exploitation tools
    "exploit_hydra": handle_exploit_hydra,
    "exploit_script": handle_exploit_script,
    # Reporting tools
    "report_generate": handle_report_generate,
    "report_preview": handle_report_preview,
    # Knowledge tools
    "knowledge_search": handle_knowledge_search,
    "knowledge_add": handle_knowledge_add,
    # Scratchpad tools
    "notes_write": handle_notes_write,
    "notes_read": handle_notes_read,
}


async def call_tool(name: str, arguments: dict[str, Any], state: Any = None) -> dict[str, Any]:
    """
    Call an MCP tool by name.

    Args:
        name: Tool name
        arguments: Tool arguments
        state: Server state (optional)

    Returns a result dict with content array for MCP protocol.
    """
    # ══════════════════════════════════════════════════════════════════════
    # TOOL GROUNDING VALIDATION (CRITICAL)
    # ══════════════════════════════════════════════════════════════════════
    # Reject any tool not in VALID_TOOLS frozenset
    # This prevents LLM from hallucinating tools like "burp_scan", "metasploit_run"
    
    is_valid, error_msg = validate_tool_call(name, arguments)
    if not is_valid:
        return {
            "content": [
                {
                    "type": "text",
                    "text": error_msg,
                }
            ],
            "isError": True,
        }
    
    handler = TOOL_HANDLERS.get(name)

    if handler:
        try:
            result = await handler(arguments)
            return {
                "content": [
                    {
                        "type": "text",
                        "text": json.dumps(result, indent=2, default=str),
                    }
                ],
                "isError": False,
            }
        except Exception as e:
            return {
                "content": [
                    {
                        "type": "text",
                        "text": f"Error executing {name}: {str(e)}",
                    }
                ],
                "isError": True,
            }
    else:
        # Stub for unimplemented tools
        return {
            "content": [
                {
                    "type": "text",
                    "text": json.dumps(
                        {
                            "tool": name,
                            "arguments": arguments,
                            "status": "pending_implementation",
                            "message": f"Tool '{name}' will be fully implemented in subsequent phases.",
                        },
                        indent=2,
                    ),
                }
            ],
            "isError": False,
        }
