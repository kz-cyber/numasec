"""
NumaSec - MCP Resources

5 MCP resources for context sharing with AI clients.
"""

from __future__ import annotations

import json
from typing import Any


# ══════════════════════════════════════════════════════════════════════════════
# Resource Definitions - 5 Total
# ══════════════════════════════════════════════════════════════════════════════

RESOURCE_DEFINITIONS = [
    {
        "uri": "engagement://current",
        "name": "Current Engagement",
        "description": "Active engagement context including scope, phase, and settings",
        "mimeType": "application/json",
    },
    {
        "uri": "findings://all",
        "name": "All Findings",
        "description": "Complete list of security findings for the current engagement",
        "mimeType": "application/json",
    },
    {
        "uri": "audit://log",
        "name": "Audit Log",
        "description": "Immutable action log with hash-chain integrity",
        "mimeType": "application/json",
    },
    {
        "uri": "knowledge://recent",
        "name": "Recent Knowledge",
        "description": "Recently used payloads, techniques, and learned patterns",
        "mimeType": "application/json",
    },
    {
        "uri": "methodology://current",
        "name": "Current Methodology Phase",
        "description": "Current PTES phase with requirements and next steps",
        "mimeType": "application/json",
    },
]


def get_all_resource_definitions() -> list[dict[str, Any]]:
    """Get all resource definitions for MCP registration."""
    return RESOURCE_DEFINITIONS


# ══════════════════════════════════════════════════════════════════════════════
# Resource Handlers
# ══════════════════════════════════════════════════════════════════════════════


async def read_resource(uri: str, state: Any = None) -> dict[str, Any]:
    """
    Read a resource by URI.

    Returns the resource content for MCP protocol.
    """
    if uri == "engagement://current":
        return await read_current_engagement()
    elif uri == "findings://all":
        return await read_all_findings()
    elif uri == "audit://log":
        return await read_audit_log()
    elif uri == "knowledge://recent":
        return await read_recent_knowledge()
    elif uri.startswith("methodology://"):
        phase = uri.replace("methodology://", "")
        return await read_methodology_phase(phase)
    else:
        return {
            "contents": [
                {
                    "uri": uri,
                    "mimeType": "text/plain",
                    "text": f"Resource not found: {uri}",
                }
            ]
        }


async def read_current_engagement() -> dict[str, Any]:
    """Read current engagement context."""
    from numasec.data.database import get_session, init_database
    from numasec.data.repositories.engagement import EngagementRepository
    from numasec.data.repositories.finding import FindingRepository

    try:
        await init_database()

        async with get_session() as session:
            engagement_repo = EngagementRepository(session)
            engagement = await engagement_repo.get_active()

            if not engagement:
                content = {
                    "status": "no_active_engagement",
                    "message": "No active engagement. Create one with engagement_create tool.",
                }
            else:
                finding_repo = FindingRepository(session)
                severity_counts = await finding_repo.get_severity_counts(engagement.id)

                content = {
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
                    "scope": [
                        {
                            "target": entry.target,
                            "type": entry.scope_type.value,
                            "excluded": entry.is_excluded,
                        }
                        for entry in engagement.scope_entries
                    ],
                    "findings_summary": severity_counts,
                    "total_findings": sum(severity_counts.values()),
                }

        return {
            "contents": [
                {
                    "uri": "engagement://current",
                    "mimeType": "application/json",
                    "text": json.dumps(content, indent=2, default=str),
                }
            ]
        }
    except Exception as e:
        return {
            "contents": [
                {
                    "uri": "engagement://current",
                    "mimeType": "application/json",
                    "text": json.dumps({"error": str(e)}),
                }
            ]
        }


async def read_all_findings() -> dict[str, Any]:
    """Read all findings for current engagement."""
    from numasec.data.database import get_session, init_database
    from numasec.data.repositories.engagement import EngagementRepository
    from numasec.data.repositories.finding import FindingRepository

    try:
        await init_database()

        async with get_session() as session:
            engagement_repo = EngagementRepository(session)
            engagement = await engagement_repo.get_active()

            if not engagement:
                content = {"findings": [], "message": "No active engagement"}
            else:
                finding_repo = FindingRepository(session)
                findings = await finding_repo.list_by_engagement(engagement.id)

                content = {
                    "engagement_id": engagement.id,
                    "findings": [
                        {
                            "id": f.id,
                            "title": f.title,
                            "severity": f.severity.value,
                            "cvss_score": f.cvss_score,
                            "cvss_vector": f.cvss_vector,
                            "cwe_id": f.cwe_id,
                            "affected_asset": f.affected_asset,
                            "is_confirmed": f.is_confirmed,
                            "created_at": f.created_at.isoformat(),
                        }
                        for f in findings
                    ],
                    "total": len(findings),
                }

        return {
            "contents": [
                {
                    "uri": "findings://all",
                    "mimeType": "application/json",
                    "text": json.dumps(content, indent=2, default=str),
                }
            ]
        }
    except Exception as e:
        return {
            "contents": [
                {
                    "uri": "findings://all",
                    "mimeType": "application/json",
                    "text": json.dumps({"error": str(e)}),
                }
            ]
        }


async def read_audit_log() -> dict[str, Any]:
    """Read audit log for current engagement."""
    from numasec.data.database import get_session, init_database
    from numasec.data.repositories.engagement import EngagementRepository
    from numasec.data.repositories.audit import AuditRepository

    try:
        await init_database()

        async with get_session() as session:
            engagement_repo = EngagementRepository(session)
            engagement = await engagement_repo.get_active()

            if not engagement:
                content = {"log_entries": [], "message": "No active engagement"}
            else:
                audit_repo = AuditRepository(session)
                entries = await audit_repo.get_by_engagement(
                    engagement.id, limit=100
                )

                content = {
                    "engagement_id": engagement.id,
                    "log_entries": [
                        {
                            "id": e.id,
                            "action_type": e.action_type.value,
                            "action": e.action,
                            "tool": e.tool,
                            "target": e.target,
                            "success": e.success,
                            "timestamp": e.timestamp.isoformat(),
                            "entry_hash": e.entry_hash[:16] + "...",
                        }
                        for e in entries
                    ],
                    "total": len(entries),
                    "chain_verified": await audit_repo.verify_chain(engagement.id),
                }

        return {
            "contents": [
                {
                    "uri": "audit://log",
                    "mimeType": "application/json",
                    "text": json.dumps(content, indent=2, default=str),
                }
            ]
        }
    except Exception as e:
        return {
            "contents": [
                {
                    "uri": "audit://log",
                    "mimeType": "application/json",
                    "text": json.dumps({"error": str(e)}),
                }
            ]
        }


async def read_recent_knowledge() -> dict[str, Any]:
    """Read recently used knowledge entries."""
    # Stub - full implementation in Phase 9
    content = {
        "payloads": [
            {"name": "SQL Auth Bypass", "payload": "' OR '1'='1", "category": "sqli"},
            {"name": "XSS Alert", "payload": "<script>alert(1)</script>", "category": "xss"},
        ],
        "techniques": [
            {"name": "Union-based SQLi", "description": "Extract data using UNION SELECT"},
        ],
        "message": "Full knowledge base coming in Phase 9",
    }

    return {
        "contents": [
            {
                "uri": "knowledge://recent",
                "mimeType": "application/json",
                "text": json.dumps(content, indent=2),
            }
        ]
    }


async def read_methodology_phase(phase: str = "current") -> dict[str, Any]:
    """Read methodology phase information."""
    from numasec.data.database import get_session, init_database
    from numasec.data.repositories.engagement import EngagementRepository

    # PTES phase requirements
    PTES_PHASES = {
        "pre_engagement": {
            "name": "Pre-engagement Interactions",
            "description": "Scope definition, rules of engagement, authorization",
            "required_activities": [
                "Define scope boundaries",
                "Get written authorization",
                "Establish communication channels",
                "Set testing windows",
            ],
            "deliverables": ["Scope document", "Authorization letter"],
            "next_phase": "intelligence_gathering",
        },
        "intelligence_gathering": {
            "name": "Intelligence Gathering",
            "description": "Passive and active reconnaissance",
            "required_activities": [
                "Subdomain enumeration",
                "Port scanning",
                "Service identification",
                "Technology fingerprinting",
            ],
            "tools": ["nmap", "subfinder", "httpx", "whatweb"],
            "next_phase": "threat_modeling",
        },
        "threat_modeling": {
            "name": "Threat Modeling",
            "description": "Identify attack vectors and prioritize targets",
            "required_activities": [
                "Analyze attack surface",
                "Identify high-value targets",
                "Map data flows",
                "Prioritize testing areas",
            ],
            "next_phase": "vulnerability_analysis",
        },
        "vulnerability_analysis": {
            "name": "Vulnerability Analysis",
            "description": "Discover and validate vulnerabilities",
            "required_activities": [
                "Automated scanning",
                "Manual testing",
                "Vulnerability validation",
                "False positive elimination",
            ],
            "tools": ["nuclei", "nikto", "ffuf", "sqlmap"],
            "next_phase": "exploitation",
        },
        "exploitation": {
            "name": "Exploitation",
            "description": "Exploit confirmed vulnerabilities",
            "required_activities": [
                "Develop exploits",
                "Execute attacks",
                "Document success",
                "Capture evidence",
            ],
            "next_phase": "post_exploitation",
        },
        "post_exploitation": {
            "name": "Post Exploitation",
            "description": "Determine value of compromised systems",
            "required_activities": [
                "Privilege escalation",
                "Lateral movement",
                "Data exfiltration testing",
                "Persistence analysis",
            ],
            "next_phase": "reporting",
        },
        "reporting": {
            "name": "Reporting",
            "description": "Document findings and recommendations",
            "required_activities": [
                "Write executive summary",
                "Document all findings",
                "Provide remediation guidance",
                "Generate final report",
            ],
            "deliverables": ["Executive summary", "Technical report", "Remediation plan"],
            "next_phase": None,
        },
    }

    try:
        await init_database()

        async with get_session() as session:
            engagement_repo = EngagementRepository(session)
            engagement = await engagement_repo.get_active()

            if engagement and phase == "current":
                phase = engagement.current_phase.value

        phase_info = PTES_PHASES.get(phase, PTES_PHASES["pre_engagement"])
        content = {
            "current_phase": phase,
            "phase_info": phase_info,
            "all_phases": list(PTES_PHASES.keys()),
        }

        return {
            "contents": [
                {
                    "uri": f"methodology://{phase}",
                    "mimeType": "application/json",
                    "text": json.dumps(content, indent=2),
                }
            ]
        }
    except Exception as e:
        return {
            "contents": [
                {
                    "uri": f"methodology://{phase}",
                    "mimeType": "application/json",
                    "text": json.dumps({"error": str(e)}),
                }
            ]
        }
