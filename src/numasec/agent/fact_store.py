"""
NumaSec - Epistemic State (Fact Store)

Persistent storage of CONFIRMED truths discovered during engagement.
Critical for multi-step exploitation and maintaining awareness across iterations.

Scientific Basis:
- Paper: "Episodic Memory in LLM Agents" (Huang et al. 2022)
- Used in: WebGPT, ReAct, Toolformer
- Key Insight: Separate "hypotheses" from "confirmed facts" to reduce hallucination

Fact Types:
1. Vulnerability (confirmed exploitable weakness)
2. Credential (working username/password)
3. Flag Fragment (partial flag for multi-part challenges)
4. Asset (discovered URL, endpoint, file)
5. Session (auth token, cookie, API key)
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any
import logging

logger = logging.getLogger("numasec.factstore")


class FactType(Enum):
    """Types of confirmed facts."""
    VULNERABILITY = "vulnerability"  # Confirmed exploitable weakness
    CREDENTIAL = "credential"        # Working login credentials
    FLAG_FRAGMENT = "flag_fragment"  # Partial flag (multi-part challenges)
    ASSET = "asset"                  # Discovered resource (URL, file, endpoint)
    SESSION = "session"              # Auth token, cookie, session ID
    TECHNIQUE = "technique"          # Successful attack technique
    INTELLIGENCE = "intelligence"    # OSINT data (email, name, version)


@dataclass
class Fact:
    """
    A confirmed truth discovered during the engagement.
    
    Facts are IMMUTABLE once created. They represent ground truth.
    """
    
    id: str  # Unique identifier
    type: FactType
    key: str  # Semantic key (e.g., "sql_injection_login", "admin_password")
    value: str  # The actual fact (e.g., "' OR 1=1--", "password123")
    confidence: float  # 0.0-1.0, must be >= 0.8 to store
    evidence: str  # How it was confirmed (tool output, observation)
    iteration: int  # When discovered
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    tags: list[str] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "id": self.id,
            "type": self.type.value,
            "key": self.key,
            "value": self.value,
            "confidence": self.confidence,
            "evidence": self.evidence[:500],  # Truncate for storage
            "iteration": self.iteration,
            "timestamp": self.timestamp.isoformat(),
            "tags": self.tags,
            "metadata": self.metadata,
        }
    
    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "Fact":
        """Create from dictionary."""
        return cls(
            id=data["id"],
            type=FactType(data["type"]),
            key=data["key"],
            value=data["value"],
            confidence=data["confidence"],
            evidence=data["evidence"],
            iteration=data["iteration"],
            timestamp=datetime.fromisoformat(data["timestamp"]),
            tags=data.get("tags", []),
            metadata=data.get("metadata", {}),
        )


class FactStore:
    """
    Persistent storage of confirmed facts.
    
    Usage:
        store = FactStore()
        
        # Add confirmed vulnerability
        store.add_fact(
            type=FactType.VULNERABILITY,
            key="sql_injection_login",
            value="Parameter 'username' vulnerable to SQLi",
            confidence=0.95,
            evidence="sqlmap confirmed with --dbs flag",
            iteration=5
        )
        
        # Query facts
        if store.has_vulnerability("sql_injection"):
            vuln = store.get_fact("sql_injection_login")
            # Exploit it with Commitment Mode
    """
    
    def __init__(self, db_path: str | None = None):
        """
        Initialize fact store.
        
        Args:
            db_path: Path to JSON storage file
        """
        if db_path is None:
            import os
            default_base = Path(os.getenv("NUMASEC_DATA_DIR", str(Path.home() / ".numasec")))
            db_path = str(default_base / "factstore.json")
        
        self.db_path = Path(db_path).expanduser()
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        
        self.facts: dict[str, Fact] = {}  # key -> Fact
        self._load()
    
    def _load(self):
        """Load facts from disk."""
        if self.db_path.exists():
            try:
                with open(self.db_path) as f:
                    data = json.load(f)
                    for fact_dict in data.get("facts", []):
                        fact = Fact.from_dict(fact_dict)
                        self.facts[fact.key] = fact
                logger.info(f"Loaded {len(self.facts)} facts from {self.db_path}")
            except Exception as e:
                logger.error(f"Failed to load facts: {e}")
                self.facts = {}
    
    def _save(self):
        """Save facts to disk."""
        try:
            with open(self.db_path, "w") as f:
                json.dump(
                    {"facts": [f.to_dict() for f in self.facts.values()]},
                    f,
                    indent=2
                )
        except Exception as e:
            logger.error(f"Failed to save facts: {e}")
    
    def add_fact(
        self,
        type: FactType,
        key: str,
        value: str,
        confidence: float,
        evidence: str,
        iteration: int,
        tags: list[str] | None = None,
        metadata: dict[str, Any] | None = None
    ) -> Fact:
        """
        Add a confirmed fact to the store.
        
        Args:
            type: Fact type
            key: Unique semantic key
            value: The actual fact
            confidence: Must be >= 0.8 (high confidence required)
            evidence: How it was confirmed
            iteration: Current iteration number
            tags: Optional tags for categorization
            metadata: Optional additional data
            
        Returns:
            Created Fact object
        """
        # CRITICAL: Only store HIGH confidence facts
        if confidence < 0.8:
            logger.warning(
                f"Fact '{key}' rejected: confidence {confidence:.2f} < 0.8 threshold"
            )
            raise ValueError(f"Confidence {confidence:.2f} too low. Minimum: 0.8")
        
        # Check for duplicate key
        if key in self.facts:
            existing = self.facts[key]
            
            if confidence < existing.confidence:
                # Lower confidence - keep existing
                logger.info(
                    f"Fact '{key}' not updated: new confidence {confidence:.2f} "
                    f"< existing {existing.confidence:.2f}"
                )
                return existing
            elif confidence == existing.confidence:
                # Same confidence - UPDATE evidence and metadata
                logger.warning(
                    f"🔄 Fact '{key}' updated: adding new evidence "
                    f"(confidence unchanged: {confidence:.2f})"
                )
                # Append new evidence
                existing.evidence += f"\n\n[Iteration {iteration}] {evidence[:200]}"
                # Merge metadata
                if metadata:
                    existing.metadata.update(metadata)
                # Add new tags
                if tags:
                    existing.tags = list(set(existing.tags + tags))
                
                self.facts[key] = existing
                self._save()
                return existing
            else:
                # Higher confidence - will overwrite below
                logger.warning(
                    f"📈 Fact '{key}' upgrading: confidence "
                    f"{existing.confidence:.2f} → {confidence:.2f}"
                )
        
        # Create fact
        from uuid import uuid4
        fact = Fact(
            id=str(uuid4()),
            type=type,
            key=key,
            value=value,
            confidence=confidence,
            evidence=evidence,
            iteration=iteration,
            tags=tags or [],
            metadata=metadata or {}
        )
        
        self.facts[key] = fact
        self._save()
        
        logger.warning(
            f"✅ Fact stored: [{type.value}] {key} = {value[:50]}... "
            f"(confidence: {confidence:.2f})"
        )
        
        return fact
    
    def get_fact(self, key: str) -> Fact | None:
        """Get a fact by key."""
        return self.facts.get(key)
    
    def has_fact(self, key: str) -> bool:
        """Check if a fact exists."""
        return key in self.facts
    
    def get_facts_by_type(self, type: FactType) -> list[Fact]:
        """Get all facts of a specific type."""
        return [f for f in self.facts.values() if f.type == type]
    
    def has_vulnerability(self, keyword: str | None = None) -> bool:
        """
        Check if any confirmed vulnerability exists.
        
        Args:
            keyword: Optional keyword to match in key or value
        """
        vulns = self.get_facts_by_type(FactType.VULNERABILITY)
        if keyword:
            return any(
                keyword.lower() in f.key.lower() or keyword.lower() in f.value.lower()
                for f in vulns
            )
        return len(vulns) > 0
    
    def get_credentials(self) -> list[Fact]:
        """Get all confirmed credentials."""
        return self.get_facts_by_type(FactType.CREDENTIAL)
    
    def get_flag_fragments(self) -> list[Fact]:
        """Get all flag fragments (for multi-part flags)."""
        return self.get_facts_by_type(FactType.FLAG_FRAGMENT)
    
    def get_sessions(self) -> list[Fact]:
        """Get all session tokens/cookies."""
        return self.get_facts_by_type(FactType.SESSION)
    
    def search(self, query: str) -> list[Fact]:
        """
        Search facts by keyword in key, value, or tags.
        
        Args:
            query: Search query
            
        Returns:
            Matching facts sorted by confidence (high to low)
        """
        query_lower = query.lower()
        matches = []
        
        for fact in self.facts.values():
            if (
                query_lower in fact.key.lower() or
                query_lower in fact.value.lower() or
                any(query_lower in tag.lower() for tag in fact.tags)
            ):
                matches.append(fact)
        
        # Sort by confidence descending
        matches.sort(key=lambda f: f.confidence, reverse=True)
        return matches
    
    def get_context_for_prompt(self, max_facts: int = 10) -> str:
        """
        Get formatted context for LLM prompt.
        
        This injects CONFIRMED facts into the system prompt,
        ensuring the agent remembers critical information.
        
        Args:
            max_facts: Maximum facts to include (prioritize by confidence)
            
        Returns:
            Formatted string for prompt injection
        """
        if not self.facts:
            return ""
        
        # Sort by confidence (highest first)
        sorted_facts = sorted(
            self.facts.values(),
            key=lambda f: f.confidence,
            reverse=True
        )[:max_facts]
        
        lines = ["🧠 EPISTEMIC STATE (Confirmed Facts):"]
        
        # Group by type for clarity
        by_type: dict[FactType, list[Fact]] = {}
        for fact in sorted_facts:
            if fact.type not in by_type:
                by_type[fact.type] = []
            by_type[fact.type].append(fact)
        
        for fact_type, facts in by_type.items():
            lines.append(f"\n{fact_type.value.upper()}:")
            for fact in facts:
                lines.append(
                    f"  • {fact.key}: {fact.value[:100]} "
                    f"(confidence: {fact.confidence:.2f}, iter: {fact.iteration})"
                )
        
        lines.append(
            "\nℹ️ These are CONFIRMED facts (confidence ≥ 0.8). "
            "Use them to guide your strategy."
        )
        
        return "\n".join(lines)
    
    def clear(self):
        """Clear all facts (use at engagement start)."""
        self.facts.clear()
        self._save()
        logger.info("Fact store cleared")
    
    def get_stats(self) -> dict[str, Any]:
        """Get statistics about stored facts."""
        by_type = {}
        for fact_type in FactType:
            by_type[fact_type.value] = len(self.get_facts_by_type(fact_type))
        
        avg_confidence = (
            sum(f.confidence for f in self.facts.values()) / len(self.facts)
            if self.facts else 0.0
        )
        
        return {
            "total_facts": len(self.facts),
            "by_type": by_type,
            "avg_confidence": round(avg_confidence, 2),
            "has_vulnerabilities": self.has_vulnerability(),
        }
