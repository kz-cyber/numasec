"""
NumaSec - Authorization and Scope Enforcement

Legal compliance for ethical hacking operations.
Ensures user has explicit authorization before testing any target.

Compliance:
- Computer Fraud and Abuse Act (CFAA) - US
- Computer Misuse Act - UK
- EU Cybersecurity Laws
"""

from urllib.parse import urlparse
from typing import List
import sys
import logging

logger = logging.getLogger("numasec.compliance")

# ══════════════════════════════════════════════════════════════════════════════
# Safe Targets Whitelist
# ══════════════════════════════════════════════════════════════════════════════

# Domains that don't require explicit authorization
# (Training platforms, practice labs, localhost)
SAFE_DOMAINS = [
    # Localhost / Private
    'localhost',
    '127.0.0.1',
    '0.0.0.0',
    '::1',
    '10.',      # Private network 10.0.0.0/8
    '172.16.',  # Private network 172.16.0.0/12
    '192.168.', # Private network 192.168.0.0/16
    
    # Training Platforms
    'picoctf.org',
    'picoctf.com',
    'ctf.hacker101.com',
    'ctftime.org',
    'hackthebox.eu',
    'hackthebox.com',
    'tryhackme.com',
    'overthewire.org',
    
    # Practice Labs
    'portswigger.net',      # Burp Suite Academy
    'pentesterlab.com',
    'hackthissite.org',
    'webhacking.kr',
    'pwnable.kr',
    'pwnable.tw',
    'crackmes.one',
    'root-me.org',
    'ringzer0ctf.com',
    
    # Intentionally Vulnerable Apps (Local)
    'dvwa',
    'webgoat',
    'juice-shop',
    'mutillidae',
    'bwapp',
]


def is_safe_target(target: str) -> bool:
    """
    Check if target is in safe whitelist.
    
    Args:
        target: Target URL, IP, or hostname
        
    Returns:
        True if target is whitelisted, False otherwise
    """
    # Normalize target
    if not target:
        return False
    
    # Extract URL if embedded in text
    import re
    url_match = re.search(r'https?://[^\s]+', target)
    if url_match:
        target = url_match.group(0)
    
    # Add protocol if missing for parsing
    if '://' not in target:
        target_parsed = f'http://{target}'
    else:
        target_parsed = target
    
    try:
        parsed = urlparse(target_parsed)
        hostname = parsed.hostname or parsed.path.split('/')[0]
        
        if not hostname:
            return False
        
        # Check against whitelist
        hostname_lower = hostname.lower()
        
        for safe in SAFE_DOMAINS:
            # Match exact domain or subdomain
            # e.g., "example.org" matches "example.org" AND "sub.example.org"
            if hostname_lower == safe or hostname_lower.endswith('.' + safe):
                logger.info(f"Target {hostname} matched whitelist: {safe}")
                return True
            
            # Also check if it starts with safe domain (for IP ranges like "10.")
            if hostname_lower.startswith(safe):
                logger.info(f"Target {hostname} matched whitelist prefix: {safe}")
                return True
        
        return False
        
    except Exception as e:
        logger.error(f"Error parsing target {target}: {e}")
        return False


def require_authorization(target: str, interactive: bool = True) -> bool:
    """
    Require explicit user authorization for non-whitelisted targets.
    
    This function enforces legal compliance by:
    1. Auto-approving whitelisted targets (training platforms, localhost)
    2. Prompting user for explicit authorization for other targets
    3. Logging all authorization decisions for audit trail
    
    Args:
        target: Target URL, IP, hostname, or description containing URL
        interactive: If False, auto-denies non-whitelisted targets
        
    Returns:
        True if authorized, False if denied
        
    Raises:
        PermissionError: If authorization is denied
    """
    # Extract URL if target contains description
    # Example: "Training challenge... http://saturn.training.net:49383/"
    import re
    url_match = re.search(r'https?://[^\s]+', target)
    if url_match:
        extracted_url = url_match.group(0)
        logger.info(f"Extracted URL from target: {extracted_url}")
        target = extracted_url
    
    # Check whitelist first
    if is_safe_target(target):
        logger.info(f"✅ Target {target} is whitelisted (auto-approved)")
        return True
    
    # Non-interactive mode: auto-deny
    if not interactive:
        logger.warning(f"❌ Target {target} not whitelisted (auto-denied in non-interactive mode)")
        return False
    
    # Interactive: Prompt user
    print("\n" + "="*70)
    print("⚠️  AUTHORIZATION REQUIRED")
    print("="*70)
    print(f"\nTarget: {target}")
    print("\n⚠️  This target is NOT in the safe whitelist.")
    print("\n📋 You MUST have WRITTEN AUTHORIZATION to test this target.")
    print("\nContinuing without authorization may violate:")
    print("  • Computer Fraud and Abuse Act (CFAA) - US")
    print("  • Computer Misuse Act 1990 - UK")
    print("  • EU Cybersecurity Laws")
    print("  • Your country's cybercrime laws")
    print("  • Target's Terms of Service")
    print("\n⚖️  Penalties may include:")
    print("  • Criminal prosecution")
    print("  • Up to 10 years imprisonment")
    print("  • Substantial fines")
    print("  • Civil liability")
    print("\n" + "="*70)
    
    # Get explicit confirmation
    try:
        response = input("\nI have WRITTEN AUTHORIZATION to test this target [yes/NO]: ").strip()
    except (EOFError, KeyboardInterrupt):
        print("\n\n❌ Authorization denied. Exiting for your safety.")
        return False
    
    if response.lower() == 'yes':
        # Authorization confirmed - no additional hostname verification needed
        print(f"\n✅ Authorization confirmed for {target}")
        print("📝 Action logged in audit trail\n")
        logger.warning(f"⚠️ USER AUTHORIZED non-whitelisted target: {target}")
        return True
    else:
        print("\n❌ Authorization denied. Exiting for your safety.")
        print("💡 To test this target, obtain written authorization first.\n")
        return False


def add_to_whitelist(domain: str) -> None:
    """
    Add a domain to the runtime whitelist.
    
    Note: This does NOT persist across sessions.
    For permanent additions, edit SAFE_DOMAINS list.
    
    Args:
        domain: Domain to whitelist
    """
    if domain not in SAFE_DOMAINS:
        SAFE_DOMAINS.append(domain)
        logger.info(f"Added {domain} to runtime whitelist")


def get_whitelist() -> List[str]:
    """
    Get current whitelist.
    
    Returns:
        List of whitelisted domains
    """
    return SAFE_DOMAINS.copy()
