"""
NumaSec - Scope Enforcer

Enforces target scope with support for hosts, networks, domains, and URLs.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any
from urllib.parse import urlparse


# ══════════════════════════════════════════════════════════════════════════════
# Enums
# ══════════════════════════════════════════════════════════════════════════════


class ScopeDecision(str, Enum):
    """Scope check decision."""

    IN_SCOPE = "in_scope"
    OUT_OF_SCOPE = "out_of_scope"
    REQUIRES_APPROVAL = "requires_approval"
    UNKNOWN = "unknown"  # For edge cases


class ScopeEntryType(str, Enum):
    """Type of scope entry."""

    HOST = "host"  # IP address
    NETWORK = "network"  # CIDR range
    DOMAIN = "domain"  # Domain/subdomain pattern
    URL = "url"  # Specific URL pattern
    WILDCARD = "wildcard"  # Wildcard pattern


# Alias for backward compatibility (tests use ScopeType)
ScopeType = ScopeEntryType

# Map from test-style type names to actual enum values
_TYPE_ALIASES: dict[str, ScopeEntryType] = {
    "ip": ScopeEntryType.HOST,
    "ip_range": ScopeEntryType.NETWORK,
    "wildcard_domain": ScopeEntryType.WILDCARD,
}


class _ScopeTypeCompat:
    """
    Compatibility wrapper that allows ScopeType.IP_RANGE etc.
    
    Maps test-style names to actual enum values.
    """
    
    # Direct mappings
    HOST = ScopeEntryType.HOST
    NETWORK = ScopeEntryType.NETWORK
    DOMAIN = ScopeEntryType.DOMAIN
    URL = ScopeEntryType.URL
    WILDCARD = ScopeEntryType.WILDCARD
    
    # Compatibility aliases
    IP = ScopeEntryType.HOST
    IP_RANGE = ScopeEntryType.NETWORK
    WILDCARD_DOMAIN = ScopeEntryType.WILDCARD


# Override ScopeType with the compat wrapper
ScopeType = _ScopeTypeCompat  # type: ignore


# ══════════════════════════════════════════════════════════════════════════════
# Data Classes
# ══════════════════════════════════════════════════════════════════════════════


@dataclass
class ScopeEntry:
    """A single scope entry."""

    value: str
    entry_type: ScopeEntryType | None = None
    is_exclusion: bool = False  # If True, explicitly exclude this
    notes: str = ""
    added_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    
    # Compatibility aliases for tests
    type: ScopeEntryType | None = field(default=None, repr=False)
    in_scope: bool | None = field(default=None, repr=False)
    note: str | None = field(default=None, repr=False)
    
    def __post_init__(self) -> None:
        """Handle compatibility aliases."""
        # Handle `type=` parameter (test compatibility)
        if self.type is not None and self.entry_type is None:
            # Convert test-style type to actual enum
            if isinstance(self.type, str):
                type_lower = self.type.lower()
                self.entry_type = _TYPE_ALIASES.get(type_lower) or ScopeEntryType(type_lower)
            else:
                # It's already an enum, check if it needs mapping
                type_name = self.type.name.lower()
                self.entry_type = _TYPE_ALIASES.get(type_name, self.type)
        elif self.entry_type is not None and self.type is None:
            self.type = self.entry_type
            
        # Handle `in_scope=` parameter (test compatibility)
        if self.in_scope is not None:
            self.is_exclusion = not self.in_scope
        elif self.in_scope is None:
            self.in_scope = not self.is_exclusion
            
        # Handle `note=` parameter (test compatibility)  
        if self.note is not None and not self.notes:
            self.notes = self.note
        elif self.notes and self.note is None:
            self.note = self.notes

    def matches(self, target: str) -> bool:
        """Check if target matches this entry."""
        if self.entry_type == ScopeEntryType.HOST:
            return self._match_host(target)
        elif self.entry_type == ScopeEntryType.NETWORK:
            return self._match_network(target)
        elif self.entry_type == ScopeEntryType.DOMAIN:
            return self._match_domain(target)
        elif self.entry_type == ScopeEntryType.URL:
            return self._match_url(target)
        elif self.entry_type == ScopeEntryType.WILDCARD:
            return self._match_wildcard(target)
        return False

    def _match_host(self, target: str) -> bool:
        """Match IP address."""
        try:
            # Extract IP from target if it's a URL
            host = self._extract_host(target)
            target_ip = ipaddress.ip_address(host)
            scope_ip = ipaddress.ip_address(self.value)
            return target_ip == scope_ip
        except ValueError:
            return self.value.lower() == target.lower()

    def _match_network(self, target: str) -> bool:
        """Match CIDR network."""
        try:
            host = self._extract_host(target)
            target_ip = ipaddress.ip_address(host)
            network = ipaddress.ip_network(self.value, strict=False)
            return target_ip in network
        except ValueError:
            return False

    def _match_domain(self, target: str) -> bool:
        """Match domain/subdomain."""
        host = self._extract_host(target).lower()
        scope_domain = self.value.lower().lstrip(".")

        # Exact match
        if host == scope_domain:
            return True

        # Subdomain match (e.g., *.example.com matches sub.example.com)
        if host.endswith("." + scope_domain):
            return True

        return False

    def _match_url(self, target: str) -> bool:
        """Match URL pattern."""
        target_lower = target.lower()
        pattern_lower = self.value.lower()

        # Exact match
        if target_lower == pattern_lower:
            return True

        # Prefix match (URL starts with pattern)
        if target_lower.startswith(pattern_lower):
            return True

        return False

    def _match_wildcard(self, target: str) -> bool:
        """Match wildcard pattern."""
        # Convert wildcard to regex
        pattern = self.value.replace(".", r"\.").replace("*", ".*")
        pattern = f"^{pattern}$"

        try:
            return bool(re.match(pattern, target, re.IGNORECASE))
        except re.error:
            return False

    def _extract_host(self, target: str) -> str:
        """Extract host from target (URL or plain host)."""
        if "://" in target:
            parsed = urlparse(target)
            return parsed.hostname or target
        return target.split("/")[0].split(":")[0]
    
    def model_dump(self) -> dict[str, Any]:
        """Pydantic-style serialization."""
        return {
            "value": self.value,
            "type": self.entry_type.value if self.entry_type else None,
            "in_scope": self.in_scope,
            "note": self.note,
        }


@dataclass
class ScopeCheckResult:
    """Result of a scope check."""

    target: str
    decision: ScopeDecision
    reason: str
    matched_entry: ScopeEntry | None = None
    checked_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


# ══════════════════════════════════════════════════════════════════════════════
# Scope Enforcer
# ══════════════════════════════════════════════════════════════════════════════


class ScopeEnforcer:
    """
    Enforces target scope for penetration testing.

    All tool executions must pass scope validation before proceeding.
    Exclusions take precedence over inclusions.
    """

    def __init__(self) -> None:
        """Initialize enforcer."""
        self._inclusions: list[ScopeEntry] = []
        self._exclusions: list[ScopeEntry] = []
        self._check_history: list[ScopeCheckResult] = []
        self._strict_mode: bool = True  # If True, deny unlisted targets

    @property
    def strict_mode(self) -> bool:
        """Get strict mode status."""
        return self._strict_mode

    @strict_mode.setter
    def strict_mode(self, value: bool) -> None:
        """Set strict mode."""
        self._strict_mode = value

    def add_scope(self, entry: ScopeEntry) -> ScopeEntry:
        """
        Add a scope entry (compatibility method for tests).
        
        Args:
            entry: ScopeEntry with in_scope=True for inclusion, False for exclusion
            
        Returns:
            The added entry
        """
        if entry.is_exclusion:
            self._exclusions.append(entry)
        else:
            self._inclusions.append(entry)
        return entry

    def add_inclusion(
        self,
        value: str,
        entry_type: ScopeEntryType | str,
        notes: str = "",
    ) -> ScopeEntry:
        """
        Add an inclusion to scope.

        Args:
            value: The scope value (IP, domain, network, etc.)
            entry_type: Type of entry
            notes: Optional notes

        Returns:
            The created ScopeEntry
        """
        if isinstance(entry_type, str):
            entry_type = ScopeEntryType(entry_type)

        entry = ScopeEntry(
            value=value,
            entry_type=entry_type,
            is_exclusion=False,
            notes=notes,
        )
        self._inclusions.append(entry)
        return entry

    def add_exclusion(
        self,
        value: str,
        entry_type: ScopeEntryType | str,
        notes: str = "",
    ) -> ScopeEntry:
        """
        Add an exclusion to scope.

        Args:
            value: The scope value to exclude
            entry_type: Type of entry
            notes: Optional notes

        Returns:
            The created ScopeEntry
        """
        if isinstance(entry_type, str):
            entry_type = ScopeEntryType(entry_type)

        entry = ScopeEntry(
            value=value,
            entry_type=entry_type,
            is_exclusion=True,
            notes=notes,
        )
        self._exclusions.append(entry)
        return entry

    def check(self, target: str) -> ScopeCheckResult:
        """
        Check if a target is in scope.

        Args:
            target: The target to check (IP, domain, URL)

        Returns:
            ScopeCheckResult with decision
        """
        # First check exclusions (they take precedence)
        for exclusion in self._exclusions:
            if exclusion.matches(target):
                result = ScopeCheckResult(
                    target=target,
                    decision=ScopeDecision.OUT_OF_SCOPE,
                    reason=f"Matched exclusion: {exclusion.value}",
                    matched_entry=exclusion,
                )
                self._check_history.append(result)
                return result

        # Then check inclusions
        for inclusion in self._inclusions:
            if inclusion.matches(target):
                result = ScopeCheckResult(
                    target=target,
                    decision=ScopeDecision.IN_SCOPE,
                    reason=f"Matched inclusion: {inclusion.value}",
                    matched_entry=inclusion,
                )
                self._check_history.append(result)
                return result

        # No match found
        if self._strict_mode:
            result = ScopeCheckResult(
                target=target,
                decision=ScopeDecision.OUT_OF_SCOPE,
                reason="Target not explicitly in scope (strict mode)",
            )
        else:
            result = ScopeCheckResult(
                target=target,
                decision=ScopeDecision.REQUIRES_APPROVAL,
                reason="Target not in scope, requires manual approval",
            )

        self._check_history.append(result)
        return result

    def is_in_scope(self, target: str) -> bool:
        """Quick check if target is in scope."""
        return self.check(target).decision == ScopeDecision.IN_SCOPE

    def validate_targets(self, targets: list[str]) -> tuple[list[str], list[ScopeCheckResult]]:
        """
        Validate multiple targets.

        Args:
            targets: List of targets to check

        Returns:
            (valid_targets, all_results)
        """
        valid = []
        results = []

        for target in targets:
            result = self.check(target)
            results.append(result)
            if result.decision == ScopeDecision.IN_SCOPE:
                valid.append(target)

        return valid, results

    def clear_scope(self) -> None:
        """Clear all scope entries."""
        self._inclusions.clear()
        self._exclusions.clear()
    
    def clear(self) -> None:
        """Alias for clear_scope()."""
        self.clear_scope()
    
    @property
    def scope_entries(self) -> list[ScopeEntry]:
        """Get all scope entries (inclusions + exclusions)."""
        return self._inclusions + self._exclusions
    
    def list_entries(self) -> list[ScopeEntry]:
        """List all scope entries."""
        return self.scope_entries
    
    def check_multiple(self, targets: list[str]) -> dict[str, ScopeCheckResult]:
        """
        Check multiple targets and return dict mapping target to result.
        
        Args:
            targets: List of targets to check
            
        Returns:
            Dictionary mapping target string to ScopeCheckResult
        """
        return {target: self.check(target) for target in targets}

    def get_scope(self) -> dict[str, list[dict[str, Any]]]:
        """Get current scope as dictionary."""
        return {
            "inclusions": [
                {
                    "value": e.value,
                    "type": e.entry_type.value,
                    "notes": e.notes,
                }
                for e in self._inclusions
            ],
            "exclusions": [
                {
                    "value": e.value,
                    "type": e.entry_type.value,
                    "notes": e.notes,
                }
                for e in self._exclusions
            ],
        }

    def get_history(self, limit: int = 100) -> list[ScopeCheckResult]:
        """Get recent scope check history."""
        return self._check_history[-limit:]

    def load_from_config(self, config: dict[str, Any]) -> None:
        """
        Load scope from configuration.

        Args:
            config: Dictionary with 'inclusions' and 'exclusions' lists
        """
        for item in config.get("inclusions", []):
            self.add_inclusion(
                value=item["value"],
                entry_type=item.get("type", "host"),
                notes=item.get("notes", ""),
            )

        for item in config.get("exclusions", []):
            self.add_exclusion(
                value=item["value"],
                entry_type=item.get("type", "host"),
                notes=item.get("notes", ""),
            )


# Global instance
_enforcer: ScopeEnforcer | None = None


def get_scope_enforcer() -> ScopeEnforcer:
    """Get the global scope enforcer."""
    global _enforcer
    if _enforcer is None:
        _enforcer = ScopeEnforcer()
    return _enforcer


# ══════════════════════════════════════════════════════════════════════════════
# Exception
# ══════════════════════════════════════════════════════════════════════════════


class ScopeViolationError(Exception):
    """Raised when a target is out of scope."""

    def __init__(self, target: str, reason: str) -> None:
        self.target = target
        self.reason = reason
        super().__init__(f"Target '{target}' is out of scope: {reason}")
