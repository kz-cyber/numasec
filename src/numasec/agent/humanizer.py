"""
NumaSec - Response Humanizer

Transforms technical tool outputs into conversational, human-readable messages.
Makes the AI seem intelligent and context-aware (Claude Code style).

Phase 2: Conversational Intelligence
"""

from __future__ import annotations

import random
from typing import Any


class ResponseHumanizer:
    """Transform technical events into natural conversation."""
    
    # Action templates (randomized for variety)
    ACTION_TEMPLATES = {
        "web_request": [
            "Let me check {url}...",
            "Sending a request to {url} to see what happens",
            "I'll test this endpoint: {url}",
            "Checking {url} for interesting behavior",
        ],
        "web_ffuf": [
            "I'm going to scan for hidden directories...",
            "Let me look for interesting paths on this server",
            "Starting directory enumeration to find entry points",
            "Searching for hidden resources...",
        ],
        "recon_nmap": [
            "Checking which ports are open...",
            "Let me see what services are running",
            "I'll scan for accessible network services",
            "Analyzing the attack surface...",
        ],
        "web_nikto": [
            "Running a comprehensive web vulnerability scan...",
            "Let me check for known vulnerabilities",
            "Scanning for common web misconfigurations...",
        ],
        "web_sqlmap": [
            "Testing for SQL injection vulnerabilities...",
            "Let me probe the database layer",
            "Checking if the database is properly secured...",
        ],
        "recon_subfinder": [
            "Discovering subdomains...",
            "Let me map out the attack surface",
            "Finding additional entry points...",
        ],
    }
    
    # Result analysis patterns
    RESULT_PATTERNS = {
        "error": {
            "403": "The server blocked me with a 403. This could be a WAF. Let me try something else...",
            "404": "Got a 404 - this path doesn't exist. Moving on to the next test...",
            "500": "Internal server error. The application might be vulnerable, or I hit something sensitive.",
            "timeout": "Request timed out. The server might be overloaded or blocking me.",
            "connection refused": "Can't connect - the service might be down or firewalled.",
        },
        "success": {
            "admin": "Interesting! I found an admin endpoint. This could be an entry point...",
            "login": "Found a login form. Let me test for authentication bypasses...",
            "api": "Discovered an API endpoint. APIs often have security issues...",
            "upload": "File upload functionality detected. This is a common vulnerability vector...",
            "jwt": "JWT token found. Let me analyze the signature validation...",
        },
        "vulnerability": {
            "SQL syntax error": "🎯 Bingo! The application returned a SQL error. This is vulnerable to SQL injection.",
            "mysql_fetch": "🎯 Database function exposed. Confirmed SQL injection vulnerability.",
            "root:x:0:0": "🎯 Critical! I can read /etc/passwd. This is a path traversal or command injection vulnerability.",
            "<script": "🎯 XSS vulnerability detected - the application reflects unsanitized input.",
            "uid=": "🎯 Command injection confirmed! I can execute arbitrary commands.",
        }
    }
    
    def __init__(self):
        """Initialize humanizer."""
        pass
    
    def humanize_action(self, tool: str, args: dict[str, Any]) -> str:
        """
        Convert tool call to natural language.
        
        Args:
            tool: Tool name (e.g., "web_request")
            args: Tool arguments dict
            
        Returns:
            Human-readable action description
        """
        templates = self.ACTION_TEMPLATES.get(tool, [f"Running {tool}..."])
        template = random.choice(templates)
        
        # Fill in template variables
        try:
            return template.format(**args)
        except (KeyError, ValueError):
            # Fallback if args don't match template
            return f"Executing {tool} with {len(args)} parameters..."
    
    def humanize_result(self, tool: str, result: str) -> str:
        """
        Convert technical output to conversational update.
        
        Args:
            tool: Tool that produced the result
            result: Raw tool output
            
        Returns:
            Human-readable result summary
        """
        result_lower = result.lower()
        
        # 1. Check for vulnerabilities (highest priority)
        for pattern, message in self.RESULT_PATTERNS["vulnerability"].items():
            if pattern.lower() in result_lower:
                return message
        
        # 2. Check for interesting findings
        for pattern, message in self.RESULT_PATTERNS["success"].items():
            if pattern in result_lower:
                return message
        
        # 3. Check for errors/blocks
        for pattern, message in self.RESULT_PATTERNS["error"].items():
            if pattern in result_lower:
                return message
        
        # 4. Default: abbreviated technical summary
        if len(result) > 200:
            preview = result[:200].strip()
            return f"Got response ({len(result)} chars): {preview}..."
        else:
            return f"Response: {result.strip()}"
    
    def humanize_finding(self, vuln_type: str, severity: str, evidence: str) -> str:
        """
        Convert vulnerability finding to conversational announcement.
        
        Args:
            vuln_type: Vulnerability type (e.g., "sql_injection")
            severity: CVSS severity (CRITICAL/HIGH/MEDIUM/LOW)
            evidence: Evidence snippet
            
        Returns:
            Human-readable finding announcement
        """
        severity_emoji = {
            "CRITICAL": "🔴",
            "HIGH": "🟠",
            "MEDIUM": "🟡",
            "LOW": "🔵",
        }
        
        emoji = severity_emoji.get(severity, "⚪")
        
        # Friendly vulnerability names
        vuln_names = {
            "sql_injection": "SQL Injection",
            "xss": "Cross-Site Scripting (XSS)",
            "command_injection": "Command Injection",
            "path_traversal": "Path Traversal",
            "ssrf": "Server-Side Request Forgery",
            "authentication_bypass": "Authentication Bypass",
            "idor": "Insecure Direct Object Reference",
        }
        
        vuln_name = vuln_names.get(vuln_type, vuln_type.replace("_", " ").title())
        
        return f"""{emoji} **{severity}**: {vuln_name} Detected

Evidence: {evidence[:150]}{'...' if len(evidence) > 150 else ''}"""
    
    def humanize_thinking(self, reasoning: str) -> str:
        """
        Make LLM reasoning more conversational.
        
        Args:
            reasoning: Raw LLM reasoning text
            
        Returns:
            Cleaned, conversational reasoning
        """
        # Remove overly technical markers
        cleaned = reasoning.replace("```", "").strip()
        
        # Add conversational connectors if missing
        if not any(word in cleaned.lower()[:50] for word in ["let", "i'll", "i'm", "i think", "based on"]):
            # Add natural language prefix
            prefixes = [
                "Based on what I see, ",
                "Looking at this, ",
                "From my analysis, ",
            ]
            cleaned = random.choice(prefixes) + cleaned
        
        return cleaned
    
    def suggest_next_action(self, findings: list[dict], tested_vectors: set[str]) -> str:
        """
        Suggest what to test next based on context.
        
        Args:
            findings: List of findings so far
            tested_vectors: Set of tested attack vectors
            
        Returns:
            Conversational suggestion
        """
        if not findings:
            return "I haven't found any vulnerabilities yet. Should I try a different approach?"
        
        critical = [f for f in findings if f.get("severity") == "CRITICAL"]
        if critical:
            return f"⚠️ I found {len(critical)} critical vulnerabilities. Should I continue testing or generate a report?"
        
        return f"I've found {len(findings)} issues so far. Want me to keep testing or focus on exploiting these?"
