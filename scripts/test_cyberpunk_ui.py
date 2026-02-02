"""
Quick test of the cyberpunk CLI components
"""

from rich.console import Console
from numasec.cli.cyberpunk_theme import CyberpunkUI, CyberpunkArt, CYBERPUNK_THEME

def test_theme():
    """Test the cyberpunk theme rendering"""
    console = Console(theme=CYBERPUNK_THEME)
    ui = CyberpunkUI(console)
    
    # Test banner
    print("\n=== BANNER ===")
    ui.show_banner()
    
    # Test panels
    print("\n=== THINKING PANEL ===")
    console.print(ui.panel_thinking("Analyzing target for SQL injection vulnerabilities...", 1))
    
    print("\n=== TOOL PANEL ===")
    console.print(ui.panel_tool("nmap_scan", {"target": "192.168.1.1", "ports": "1-1000"}))
    
    print("\n=== VULNERABILITY PANEL ===")
    console.print(ui.panel_vulnerability(
        "SQL Injection",
        "CRITICAL",
        "Parameter 'id' is vulnerable to UNION-based SQL injection. Payload: ' UNION SELECT 1,2,3--"
    ))
    
    print("\n=== COMPLETION PANEL ===")
    console.print(ui.panel_complete(15, 3, "completed"))
    
    print("\n=== STATUS LINES ===")
    ui.status_line("Connected to MCP server", "success")
    ui.status_line("Scanning in progress...", "info")
    ui.status_line("Warning: High CPU usage", "warning")
    ui.status_line("Connection failed", "error")
    
    print("\n=== TOOLS TABLE ===")
    tools = [
        {"name": "nmap_scan", "description": "Scan target for open ports and services"},
        {"name": "sqlmap", "description": "Test for SQL injection vulnerabilities"},
        {"name": "dirb", "description": "Brute force directories and files"},
    ]
    console.print(ui.table_tools(tools))
    
    print("\n✓ Theme test complete!\n")


if __name__ == "__main__":
    test_theme()
