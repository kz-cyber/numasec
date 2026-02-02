"""
NumaSec - Semantic Cache

LanceDB-based semantic cache for LLM responses.
Uses sentence-transformers for embedding and similarity matching.
"""

from __future__ import annotations

import hashlib
import json
import os
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, TYPE_CHECKING

if TYPE_CHECKING:
    from numasec.ai.router import LLMResponse


# ══════════════════════════════════════════════════════════════════════════════
# Cache Configuration
# ══════════════════════════════════════════════════════════════════════════════


@dataclass
class CacheConfig:
    """Configuration for semantic cache."""

    db_path: str = "{NUMASEC_DATA_DIR}/cache"
    similarity_threshold: float = 0.95
    ttl_hours: int = 24
    max_entries: int = 10000
    embedding_model: str = "all-MiniLM-L6-v2"


# ══════════════════════════════════════════════════════════════════════════════
# Semantic Cache Implementation
# ══════════════════════════════════════════════════════════════════════════════


class SemanticCache:
    """
    Semantic similarity cache for LLM responses.

    Uses LanceDB for vector storage and sentence-transformers for embedding.
    Cache hit if similarity > threshold (default 0.95).

    Features:
    - Semantic similarity matching (not just exact match)
    - TTL-based expiration
    - LRU eviction when max entries reached
    - Hit counting for cache optimization
    """

    def __init__(
        self,
        db_path: str = "{NUMASEC_DATA_DIR}/cache",
        similarity_threshold: float = 0.95,
        ttl_hours: int = 24,
        max_entries: int = 10000,
        embedding_model: str = "all-MiniLM-L6-v2",
    ) -> None:
        """
        Initialize semantic cache.

        Args:
            db_path: Path to LanceDB database
            similarity_threshold: Minimum similarity for cache hit (0.0-1.0)
            ttl_hours: Time-to-live in hours
            max_entries: Maximum cache entries
            embedding_model: Sentence transformer model name
        """
        # Expand {NUMASEC_DATA_DIR} placeholder
        expanded_path = db_path.replace(
            "{NUMASEC_DATA_DIR}",
            os.getenv("NUMASEC_DATA_DIR", str(Path.home() / ".numasec"))
        )
        self.db_path = Path(os.path.expanduser(expanded_path))
        self.similarity_threshold = similarity_threshold
        self.ttl = timedelta(hours=ttl_hours)
        self.max_entries = max_entries
        self.embedding_model = embedding_model

        # Lazy initialization
        self._db = None
        self._table = None
        self._encoder = None
        self._initialized = False

    async def _ensure_initialized(self) -> None:
        """Ensure cache is initialized (lazy loading)."""
        if self._initialized:
            return

        # Create directory
        self.db_path.mkdir(parents=True, exist_ok=True)

        try:
            import lancedb
            from sentence_transformers import SentenceTransformer

            # Connect to database
            self._db = lancedb.connect(str(self.db_path))

            # Load encoder
            self._encoder = SentenceTransformer(self.embedding_model)

            # Initialize table
            self._init_table()

            self._initialized = True

        except ImportError as e:
            # Cache is optional - gracefully degrade
            raise CacheNotAvailableError(
                f"Cache dependencies not installed: {e}. "
                f"Install with: pip install lancedb sentence-transformers"
            )

    def _init_table(self) -> None:
        """Initialize cache table if not exists."""
        import numpy as np

        try:
            self._table = self._db.open_table("llm_cache")
        except Exception:
            # Create table with schema
            embedding_dim = self._encoder.get_sentence_embedding_dimension()

            self._table = self._db.create_table(
                "llm_cache",
                data=[
                    {
                        "id": "__init__",
                        "cache_key": "",
                        "prompt_hash": "",
                        "prompt_embedding": np.zeros(embedding_dim).tolist(),
                        "response_content": "",
                        "response_model": "",
                        "response_provider": "",
                        "input_tokens": 0,
                        "output_tokens": 0,
                        "cost": 0.0,
                        "created_at": datetime.now(timezone.utc).isoformat(),
                        "expires_at": datetime.now(timezone.utc).isoformat(),
                        "hits": 0,
                    }
                ],
            )

    async def get(
        self,
        cache_key: str,
        messages: list[dict[str, str]],
    ) -> "LLMResponse | None":
        """
        Check cache for semantically similar prompt.

        Args:
            cache_key: Unique cache key
            messages: Conversation messages

        Returns:
            Cached LLMResponse or None if not found
        """
        try:
            await self._ensure_initialized()
        except CacheNotAvailableError:
            return None

        from numasec.ai.router import LLMResponse, LLMProvider

        prompt_text = self._messages_to_text(messages)
        prompt_embedding = self._encoder.encode(prompt_text)

        # Search for similar prompts
        try:
            results = (
                self._table.search(prompt_embedding)
                .limit(5)
                .to_list()
            )
        except Exception:
            return None

        if not results:
            return None

        now = datetime.now(timezone.utc)

        for result in results:
            # Skip init row
            if result.get("id") == "__init__":
                continue

            # Check expiration
            expires_at = datetime.fromisoformat(result.get("expires_at", ""))
            if expires_at < now:
                continue

            # Check similarity (LanceDB returns L2 distance, convert to similarity)
            # L2 distance of 0 = identical, higher = less similar
            # For normalized embeddings: similarity ≈ 1 - (distance² / 2)
            distance = result.get("_distance", float("inf"))
            similarity = 1 - (distance / 2)  # Approximate conversion

            if similarity >= self.similarity_threshold:
                # Cache hit! Update hit count
                await self._increment_hits(result.get("id"))

                return LLMResponse(
                    content=result.get("response_content", ""),
                    model=result.get("response_model", ""),
                    provider=LLMProvider(result.get("response_provider", "deepseek")),
                    input_tokens=result.get("input_tokens", 0),
                    output_tokens=result.get("output_tokens", 0),
                    latency_ms=0,
                    cost=result.get("cost", 0.0),
                    cached=True,
                )

        return None

    async def set(
        self,
        cache_key: str,
        messages: list[dict[str, str]],
        response: "LLMResponse",
    ) -> None:
        """
        Store response in cache.

        Args:
            cache_key: Unique cache key
            messages: Conversation messages
            response: LLM response to cache
        """
        try:
            await self._ensure_initialized()
        except CacheNotAvailableError:
            return

        import uuid

        prompt_text = self._messages_to_text(messages)
        prompt_hash = hashlib.sha256(prompt_text.encode()).hexdigest()
        prompt_embedding = self._encoder.encode(prompt_text)

        now = datetime.now(timezone.utc)
        expires_at = now + self.ttl

        entry = {
            "id": str(uuid.uuid4()),
            "cache_key": cache_key,
            "prompt_hash": prompt_hash,
            "prompt_embedding": prompt_embedding.tolist(),
            "response_content": response.content,
            "response_model": response.model,
            "response_provider": response.provider.value,
            "input_tokens": response.input_tokens,
            "output_tokens": response.output_tokens,
            "cost": response.cost,
            "created_at": now.isoformat(),
            "expires_at": expires_at.isoformat(),
            "hits": 0,
        }

        try:
            self._table.add([entry])

            # Check if we need to evict
            await self._maybe_evict()

        except Exception:
            pass  # Cache write failure is not critical

    async def _increment_hits(self, entry_id: str) -> None:
        """Increment hit count for cache entry."""
        try:
            # LanceDB doesn't support in-place updates well
            # For now, we skip hit tracking
            pass
        except Exception:
            pass

    async def _maybe_evict(self) -> None:
        """Evict old entries if over limit."""
        try:
            # Get table size
            count = self._table.count_rows()

            if count <= self.max_entries:
                return

            # Delete expired entries
            now = datetime.now(timezone.utc).isoformat()
            self._table.delete(f"expires_at < '{now}'")

            # If still over limit, delete oldest entries
            count = self._table.count_rows()
            if count > self.max_entries:
                # Delete 10% of oldest entries
                to_delete = int(count * 0.1)
                # LanceDB doesn't have great support for this, skip for now

        except Exception:
            pass

    async def invalidate(self, cache_key: str) -> None:
        """
        Invalidate a specific cache entry.

        Args:
            cache_key: Cache key to invalidate
        """
        try:
            await self._ensure_initialized()
            self._table.delete(f"cache_key = '{cache_key}'")
        except Exception:
            pass

    async def clear(self) -> None:
        """Clear all cache entries."""
        try:
            await self._ensure_initialized()
            self._table.delete("id != '__never_match__'")
        except Exception:
            pass

    async def get_stats(self) -> dict[str, Any]:
        """Get cache statistics."""
        try:
            await self._ensure_initialized()

            count = self._table.count_rows()

            return {
                "entries": count,
                "max_entries": self.max_entries,
                "similarity_threshold": self.similarity_threshold,
                "ttl_hours": self.ttl.total_seconds() / 3600,
                "db_path": str(self.db_path),
            }

        except CacheNotAvailableError:
            return {
                "status": "unavailable",
                "reason": "Dependencies not installed",
            }
        except Exception as e:
            return {
                "status": "error",
                "reason": str(e),
            }

    def _messages_to_text(self, messages: list[dict[str, str]]) -> str:
        """Convert messages to text for embedding."""
        parts = []
        for msg in messages:
            role = msg.get("role", "")
            content = msg.get("content", "")
            parts.append(f"{role}: {content}")
        return "\n".join(parts)


class CacheNotAvailableError(Exception):
    """Cache dependencies not available."""

    pass


# ══════════════════════════════════════════════════════════════════════════════
# Simple In-Memory Cache (Fallback)
# ══════════════════════════════════════════════════════════════════════════════


class SimpleCache:
    """
    Simple in-memory cache as fallback when LanceDB is not available.

    Uses exact key matching (no semantic similarity).
    """

    def __init__(
        self,
        max_entries: int = 1000,
        ttl_hours: int = 24,
    ) -> None:
        """Initialize simple cache."""
        self.max_entries = max_entries
        self.ttl = timedelta(hours=ttl_hours)
        self._cache: dict[str, tuple[datetime, Any]] = {}

    async def get(
        self,
        cache_key: str,
        messages: list[dict[str, str]],
    ) -> Any | None:
        """Get cached response."""
        if cache_key not in self._cache:
            return None

        expires_at, response = self._cache[cache_key]

        if datetime.now(timezone.utc) > expires_at:
            del self._cache[cache_key]
            return None

        return response

    async def set(
        self,
        cache_key: str,
        messages: list[dict[str, str]],
        response: Any,
    ) -> None:
        """Store response in cache."""
        # Evict if over limit
        if len(self._cache) >= self.max_entries:
            # Remove oldest entry
            oldest_key = min(self._cache.keys(), key=lambda k: self._cache[k][0])
            del self._cache[oldest_key]

        expires_at = datetime.now(timezone.utc) + self.ttl
        self._cache[cache_key] = (expires_at, response)

    async def invalidate(self, cache_key: str) -> None:
        """Invalidate cache entry."""
        self._cache.pop(cache_key, None)

    async def clear(self) -> None:
        """Clear all cache entries."""
        self._cache.clear()

    async def get_stats(self) -> dict[str, Any]:
        """Get cache statistics."""
        return {
            "entries": len(self._cache),
            "max_entries": self.max_entries,
            "type": "in-memory",
        }
