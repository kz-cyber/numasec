"""
NumaSec - MCP Prompts

12 MCP prompt templates for AI-assisted pentesting.
"""

from __future__ import annotations

from typing import Any


# ══════════════════════════════════════════════════════════════════════════════
# Prompt Definitions - 12 Total
# ══════════════════════════════════════════════════════════════════════════════

PROMPT_DEFINITIONS = [
    # ─────────────────────────────────────────────────────────────────────────
    # SESSION PROMPTS
    # ─────────────────────────────────────────────────────────────────────────
    {
        "name": "pentest_start",
        "description": "Begin a new penetration test with methodology guidance",
        "arguments": [
            {
                "name": "target_type",
                "description": "Type of target (web, network, api, mobile)",
                "required": True,
            },
            {
                "name": "methodology",
                "description": "Testing methodology (PTES, OWASP, NIST)",
                "required": False,
            },
        ],
    },
    {
        "name": "phase_transition",
        "description": "Guide transition to the next PTES phase",
        "arguments": [
            {
                "name": "current_phase",
                "description": "Current PTES phase",
                "required": True,
            },
            {
                "name": "findings_so_far",
                "description": "Summary of findings discovered",
                "required": False,
            },
        ],
    },
    # ─────────────────────────────────────────────────────────────────────────
    # ANALYSIS PROMPTS
    # ─────────────────────────────────────────────────────────────────────────
    {
        "name": "analyze_output",
        "description": "Analyze security tool output for vulnerabilities",
        "arguments": [
            {
                "name": "tool_name",
                "description": "Name of the security tool (nmap, nuclei, etc.)",
                "required": True,
            },
            {
                "name": "output",
                "description": "Raw tool output to analyze",
                "required": True,
            },
        ],
    },
    {
        "name": "suggest_next_action",
        "description": "Suggest the next testing action based on current context",
        "arguments": [
            {
                "name": "recent_findings",
                "description": "Recent discoveries or findings",
                "required": False,
            },
        ],
    },
    {
        "name": "attack_chain",
        "description": "Build an attack chain from multiple vulnerabilities",
        "arguments": [
            {
                "name": "vulnerabilities",
                "description": "List of discovered vulnerabilities",
                "required": True,
            },
        ],
    },
    # ─────────────────────────────────────────────────────────────────────────
    # FINDING PROMPTS
    # ─────────────────────────────────────────────────────────────────────────
    {
        "name": "create_finding_narrative",
        "description": "Generate professional finding description",
        "arguments": [
            {
                "name": "vulnerability_type",
                "description": "Type of vulnerability (SQLi, XSS, etc.)",
                "required": True,
            },
            {
                "name": "technical_details",
                "description": "Technical evidence and details",
                "required": True,
            },
            {
                "name": "affected_asset",
                "description": "Affected URL, host, or component",
                "required": True,
            },
        ],
    },
    {
        "name": "calculate_cvss",
        "description": "Calculate CVSS 3.1 score with explanation",
        "arguments": [
            {
                "name": "vulnerability_description",
                "description": "Description of the vulnerability",
                "required": True,
            },
            {
                "name": "exploitation_context",
                "description": "How the vulnerability was exploited",
                "required": True,
            },
        ],
    },
    {
        "name": "map_cwe",
        "description": "Map vulnerability to appropriate CWE",
        "arguments": [
            {
                "name": "vulnerability_type",
                "description": "Type of vulnerability",
                "required": True,
            },
            {
                "name": "technical_details",
                "description": "Technical details for accurate mapping",
                "required": False,
            },
        ],
    },
    {
        "name": "write_remediation",
        "description": "Write remediation guidance for a finding",
        "arguments": [
            {
                "name": "vulnerability_type",
                "description": "Type of vulnerability",
                "required": True,
            },
            {
                "name": "technology_stack",
                "description": "Affected technology (PHP, Java, etc.)",
                "required": False,
            },
        ],
    },
    # ─────────────────────────────────────────────────────────────────────────
    # REPORT PROMPTS
    # ─────────────────────────────────────────────────────────────────────────
    {
        "name": "executive_summary",
        "description": "Generate executive summary for the report",
        "arguments": [
            {
                "name": "engagement_context",
                "description": "Client and project information",
                "required": True,
            },
            {
                "name": "findings_summary",
                "description": "Summary of all findings by severity",
                "required": True,
            },
        ],
    },
    {
        "name": "strategic_recommendations",
        "description": "Generate strategic security recommendations",
        "arguments": [
            {
                "name": "findings_overview",
                "description": "Overview of discovered issues",
                "required": True,
            },
            {
                "name": "industry",
                "description": "Client's industry for tailored advice",
                "required": False,
            },
        ],
    },
    {
        "name": "risk_assessment",
        "description": "Perform overall risk assessment",
        "arguments": [
            {
                "name": "findings",
                "description": "All findings with CVSS scores",
                "required": True,
            },
            {
                "name": "business_context",
                "description": "Business impact context",
                "required": False,
            },
        ],
    },
]


def get_all_prompt_definitions() -> list[dict[str, Any]]:
    """Get all prompt definitions for MCP registration."""
    return PROMPT_DEFINITIONS


def get_prompt_definition(name: str) -> dict[str, Any] | None:
    """Get a specific prompt definition by name."""
    for prompt in PROMPT_DEFINITIONS:
        if prompt["name"] == name:
            return prompt
    return None


# ══════════════════════════════════════════════════════════════════════════════
# Prompt Templates
# ══════════════════════════════════════════════════════════════════════════════

PROMPT_TEMPLATES = {
    "pentest_start": """
You are NumaSec, an AI assistant specialized in penetration testing.

A new penetration test is starting with the following parameters:
- Target Type: {target_type}
- Methodology: {methodology}

Your role is to:
1. Guide the tester through the {methodology} methodology
2. Suggest appropriate tools and techniques for {target_type} testing
3. Ensure all actions stay within the authorized scope
4. Help document findings professionally

Let's begin with the first phase: Pre-engagement Interactions.

What information do you have about the scope and authorization?
""",

    "phase_transition": """
Current PTES Phase: {current_phase}
Findings so far: {findings_so_far}

Based on the progress and findings, let's evaluate readiness to move to the next phase.

Phase Transition Checklist:
1. Have all required activities for {current_phase} been completed?
2. Are there any gaps in coverage?
3. What should be prioritized in the next phase?

Recommendation:
""",

    "analyze_output": """
Analyze the following {tool_name} output for security issues:

```
{output}
```

Provide:
1. Summary of findings
2. Potential vulnerabilities identified
3. Recommended next steps
4. Any indicators of interesting targets

Focus on actionable security insights.
""",

    "suggest_next_action": """
Based on the current engagement context and recent findings:

Recent discoveries: {recent_findings}

Suggest the most effective next testing action, considering:
1. Current PTES phase
2. Discovered attack surface
3. Potential high-impact vulnerabilities
4. Efficient use of testing time

Recommendation should include:
- Specific tool or technique to use
- Expected outcome
- Reasoning for this choice
""",

    "attack_chain": """
Analyze these vulnerabilities for attack chain potential:

Vulnerabilities:
{vulnerabilities}

Build a coherent attack chain that:
1. Combines multiple weaknesses
2. Demonstrates realistic attack path
3. Shows business impact
4. Follows logical exploitation sequence

Attack Chain Analysis:
""",

    "create_finding_narrative": """
Create a professional vulnerability finding report for:

Vulnerability Type: {vulnerability_type}
Affected Asset: {affected_asset}
Technical Details: {technical_details}

Generate:
1. Clear, non-technical description for executives
2. Technical description for developers
3. Step-by-step reproduction steps
4. Business impact assessment
5. Remediation recommendations

Write in professional penetration testing report style.
""",

    "calculate_cvss": """
Calculate CVSS 3.1 Base Score for:

Vulnerability Description: {vulnerability_description}
Exploitation Context: {exploitation_context}

Analyze each metric:
1. Attack Vector (AV): Network, Adjacent, Local, or Physical?
2. Attack Complexity (AC): Low or High?
3. Privileges Required (PR): None, Low, or High?
4. User Interaction (UI): None or Required?
5. Scope (S): Unchanged or Changed?
6. Confidentiality Impact (C): None, Low, or High?
7. Integrity Impact (I): None, Low, or High?
8. Availability Impact (A): None, Low, or High?

For each metric, provide reasoning and final value.

Output the CVSS vector string and calculated score.
""",

    "map_cwe": """
Map the following vulnerability to the appropriate CWE:

Vulnerability Type: {vulnerability_type}
Technical Details: {technical_details}

Consider:
1. Root cause of the vulnerability
2. Most specific applicable CWE
3. Related CWEs for comprehensive coverage

Provide:
- Primary CWE ID and name
- Brief explanation of why this CWE applies
- Related CWEs if applicable
""",

    "write_remediation": """
Write remediation guidance for:

Vulnerability Type: {vulnerability_type}
Technology Stack: {technology_stack}

Provide:
1. Short-term fix (immediate mitigation)
2. Long-term solution (proper remediation)
3. Code examples if applicable
4. Security best practices
5. Testing verification steps

Make recommendations specific to {technology_stack} when possible.
""",

    "executive_summary": """
Generate an executive summary for the penetration test report:

Engagement: {engagement_context}
Findings Summary: {findings_summary}

The executive summary should:
1. Be 1-2 paragraphs maximum
2. Highlight critical business risks
3. Provide overall security posture assessment
4. Recommend immediate priorities
5. Be understandable by non-technical executives

Write in professional, clear language.
""",

    "strategic_recommendations": """
Generate strategic security recommendations based on:

Findings Overview: {findings_overview}
Industry: {industry}

Provide:
1. Top 5 prioritized recommendations
2. Quick wins (easy to implement)
3. Long-term security improvements
4. Industry-specific considerations
5. Compliance implications if relevant

Focus on practical, actionable advice.
""",

    "risk_assessment": """
Perform overall risk assessment:

Findings: {findings}
Business Context: {business_context}

Calculate:
1. Overall risk rating (Critical, High, Medium, Low)
2. Risk distribution analysis
3. Most critical attack paths
4. Potential business impact scenarios
5. Risk trending compared to industry standards

Provide a comprehensive risk summary suitable for management presentation.
""",
}


async def get_prompt(name: str, arguments: dict[str, Any]) -> dict[str, Any]:
    """
    Get a rendered prompt by name with arguments.

    Returns the prompt content for MCP protocol.
    """
    template = PROMPT_TEMPLATES.get(name)

    if not template:
        return {
            "messages": [
                {
                    "role": "user",
                    "content": {
                        "type": "text",
                        "text": f"Unknown prompt: {name}",
                    },
                }
            ]
        }

    # Fill in template with arguments, using empty string for missing values
    try:
        rendered = template.format(**{
            k: arguments.get(k, f"[{k}]")
            for k in _extract_template_keys(template)
        })
    except Exception as e:
        rendered = f"Error rendering prompt: {e}"

    return {
        "messages": [
            {
                "role": "user",
                "content": {
                    "type": "text",
                    "text": rendered,
                },
            }
        ]
    }


def _extract_template_keys(template: str) -> list[str]:
    """Extract format keys from a template string."""
    import re
    return re.findall(r'\{(\w+)\}', template)
