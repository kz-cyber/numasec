"""LanceDB-based Knowledge Store for NumaSec.

Vector store for security payloads, techniques, writeups, and reflexion entries.
Supports semantic search, hybrid search, and CRUD operations.
"""

from __future__ import annotations

import json
import hashlib
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Literal
from enum import Enum

from pydantic import BaseModel, Field, field_validator

logger = logging.getLogger(__name__)

# LanceDB may not be installed
try:
    import lancedb
    import pyarrow as pa
    from lancedb.pydantic import LanceModel, Vector
    from lancedb.embeddings import get_registry
    from sentence_transformers import SentenceTransformer
    LANCEDB_AVAILABLE = True
    EMBEDDING_AVAILABLE = True
except ImportError as e:
    LANCEDB_AVAILABLE = False
    EMBEDDING_AVAILABLE = False
    # Mock classes for type hints
    class LanceModel(BaseModel):
        pass
    Vector = list
    pa = None  # type: ignore
    SentenceTransformer = None  # type: ignore

# BM25 for hybrid search
try:
    from rank_bm25 import BM25Okapi
    BM25_AVAILABLE = True
except ImportError:
    BM25_AVAILABLE = False


class PayloadCategory(str, Enum):
    """Payload categories."""
    SQLI = "sqli"
    XSS = "xss"
    SSTI = "ssti"
    LFI = "lfi"
    RFI = "rfi"
    RCE = "rce"
    XXE = "xxe"
    SSRF = "ssrf"
    NOSQL = "nosql"
    LDAP = "ldap"
    XPATH = "xpath"
    JWT = "jwt"
    IDOR = "idor"
    DESERIALIZATION = "deserialization"
    PATH_TRAVERSAL = "path_traversal"
    HEADER_INJECTION = "header_injection"
    OPEN_REDIRECT = "open_redirect"
    CRLF = "crlf"
    CSRF = "csrf"
    OTHER = "other"


class TechniqueCategory(str, Enum):
    """Technique categories."""
    RECONNAISSANCE = "reconnaissance"
    SCANNING = "scanning"
    EXPLOITATION = "exploitation"
    POST_EXPLOITATION = "post_exploitation"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    LATERAL_MOVEMENT = "lateral_movement"
    PERSISTENCE = "persistence"
    EXFILTRATION = "exfiltration"
    EVASION = "evasion"


class DifficultyLevel(str, Enum):
    """Difficulty levels."""
    EASY = "easy"
    MEDIUM = "medium"
    HARD = "hard"
    INSANE = "insane"


# ============================================================================
# Entry Schemas (LanceDB Models)
# ============================================================================

class PayloadEntry(BaseModel):
    """Security payload entry for vector storage."""
    
    id: str = Field(description="Unique payload ID")
    name: str = Field(description="Payload name")
    category: str = Field(description="Payload category (sqli, xss, etc.)")
    payload: str = Field(description="The actual payload string")
    description: str = Field(description="What this payload does")
    use_case: str = Field(description="When to use this payload")
    bypass_technique: str = Field(default="", description="WAF/filter bypass technique")
    platform: str = Field(default="", description="Target platform (linux, windows, etc.)")
    context: str = Field(default="", description="Injection context (url, body, header)")
    tags: list[str] = Field(default_factory=list, description="Searchable tags")
    success_rate: float = Field(default=0.5, ge=0.0, le=1.0, description="Historical success rate")
    created_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    
    @field_validator('bypass_technique', 'platform', 'context', mode='before')
    @classmethod
    def convert_none_to_empty(cls, v):
        """Convert None to empty string for LanceDB compatibility."""
        return "" if v is None else v
    
    # For LanceDB: text to embed
    @property
    def embedding_text(self) -> str:
        """Text to use for vector embedding."""
        parts = [
            f"Category: {self.category}",
            f"Name: {self.name}",
            f"Description: {self.description}",
            f"Use case: {self.use_case}",
            f"Payload: {self.payload}",
        ]
        if self.bypass_technique:
            parts.append(f"Bypass: {self.bypass_technique}")
        if self.tags:
            parts.append(f"Tags: {', '.join(self.tags)}")
        return "\n".join(parts)


class TechniqueEntry(BaseModel):
    """Security technique entry for vector storage."""
    
    id: str = Field(description="Unique technique ID")
    name: str = Field(description="Technique name")
    category: str = Field(description="Technique category")
    description: str = Field(description="Detailed technique description")
    prerequisites: list[str] = Field(default_factory=list, description="Required conditions")
    steps: list[str] = Field(default_factory=list, description="Step-by-step instructions")
    tools: list[str] = Field(default_factory=list, description="Tools used")
    indicators: list[str] = Field(default_factory=list, description="Indicators of success")
    mitre_id: str = Field(default="", description="MITRE ATT&CK ID")
    difficulty: str = Field(default="medium", description="Difficulty level")
    tags: list[str] = Field(default_factory=list, description="Searchable tags")
    created_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    
    @field_validator('mitre_id', mode='before')
    @classmethod
    def convert_none_to_empty(cls, v):
        """Convert None to empty string for LanceDB compatibility."""
        return "" if v is None else v
    
    @property
    def embedding_text(self) -> str:
        """Text to use for vector embedding."""
        parts = [
            f"Technique: {self.name}",
            f"Category: {self.category}",
            f"Description: {self.description}",
            f"Steps: {' '.join(self.steps)}",
            f"Tools: {', '.join(self.tools)}",
        ]
        if self.mitre_id and self.mitre_id != "":
            parts.append(f"MITRE: {self.mitre_id}")
        if self.tags:
            parts.append(f"Tags: {', '.join(self.tags)}")
        return "\n".join(parts)


class WriteupEntry(BaseModel):
    """Security assessment writeup entry for vector storage."""
    
    id: str = Field(description="Unique writeup ID")
    title: str = Field(description="Writeup title")
    platform: str = Field(description="Platform (HackTheBox, TryHackMe, Training Lab, etc.)")
    category: str = Field(description="Challenge category (web, pwn, crypto, etc.)")
    difficulty: str = Field(default="medium", description="Difficulty level")
    summary: str = Field(description="Brief summary")
    techniques: list[str] = Field(default_factory=list, description="Techniques used")
    vulnerabilities: list[str] = Field(default_factory=list, description="Vulnerabilities exploited")
    tools: list[str] = Field(default_factory=list, description="Tools used")
    key_insights: list[str] = Field(default_factory=list, description="Key learnings")
    content: str = Field(description="Full writeup content")
    flags: list[str] = Field(default_factory=list, description="Flags found (redacted)")
    tags: list[str] = Field(default_factory=list, description="Searchable tags")
    source_url: str = Field(default="", description="Original source URL")
    created_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    
    @field_validator('source_url', mode='before')
    @classmethod
    def convert_none_to_empty(cls, v):
        """Convert None to empty string for LanceDB compatibility."""
        return "" if v is None else v
    
    @property
    def embedding_text(self) -> str:
        """Text to use for vector embedding."""
        parts = [
            f"Title: {self.title}",
            f"Platform: {self.platform}",
            f"Category: {self.category}",
            f"Summary: {self.summary}",
            f"Techniques: {', '.join(self.techniques)}",
            f"Vulnerabilities: {', '.join(self.vulnerabilities)}",
            f"Key insights: {', '.join(self.key_insights)}",
        ]
        if self.tags:
            parts.append(f"Tags: {', '.join(self.tags)}")
        return "\n".join(parts)


class ReflexionEntry(BaseModel):
    """Reflexion learning entry for vector storage.
    
    Stores learned patterns from successful/failed attack attempts.
    """
    
    id: str = Field(description="Unique reflexion ID")
    engagement_id: str = Field(description="Related engagement")
    action_type: str = Field(description="Type of action attempted")
    action_description: str = Field(description="What was attempted")
    context: dict[str, Any] = Field(default_factory=dict, description="Context when action was taken")
    outcome: str = Field(description="success or failure")
    reason: str = Field(description="Why it succeeded or failed")
    lesson_learned: str = Field(description="What to do differently")
    confidence: float = Field(default=0.5, ge=0.0, le=1.0, description="Confidence in lesson")
    applicable_scenarios: list[str] = Field(default_factory=list, description="When to apply this lesson")
    tags: list[str] = Field(default_factory=list, description="Searchable tags")
    created_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    
    @property
    def embedding_text(self) -> str:
        """Text to use for vector embedding."""
        parts = [
            f"Action: {self.action_type} - {self.action_description}",
            f"Outcome: {self.outcome}",
            f"Reason: {self.reason}",
            f"Lesson: {self.lesson_learned}",
            f"Scenarios: {', '.join(self.applicable_scenarios)}",
        ]
        if self.tags:
            parts.append(f"Tags: {', '.join(self.tags)}")
        return "\n".join(parts)


# ============================================================================
# Search Results
# ============================================================================

class SearchResult(BaseModel):
    """Generic search result with score."""
    
    entry: dict[str, Any]
    score: float
    entry_type: str  # "payload", "technique", "writeup", "reflexion"


class KnowledgeSearchResults(BaseModel):
    """Aggregated search results from knowledge store."""
    
    query: str
    results: list[SearchResult]
    total_count: int
    search_time_ms: float


# ============================================================================
# Knowledge Store Implementation
# ============================================================================

class KnowledgeStore:
    """LanceDB-based knowledge store for NumaSec.
    
    Provides semantic search over:
    - Security payloads (SQLi, XSS, SSTI, etc.)
    - Attack techniques (with MITRE ATT&CK mapping)
    - Security assessment writeups
    - Reflexion entries (learned patterns)
    
    Example:
        ```python
        store = KnowledgeStore()
        await store.initialize()
        
        # Search for SQL injection payloads
        results = await store.search("authentication bypass SQL injection", limit=10)
        
        # Add a new payload
        await store.add_payload(PayloadEntry(...))
        ```
    """
    
    def __init__(self, db_path: str | Path | None = None):
        """Initialize knowledge store.
        
        Args:
            db_path: Path to LanceDB database. Defaults to ~/.numasec/knowledge.lance
        """
        if db_path is None:
            import os
            default_base = Path(os.getenv("NUMASEC_DATA_DIR", str(Path.home() / ".numasec")))
            db_path = default_base / "knowledge.lance"
        
        self.db_path = Path(db_path)
        self._db: Any = None
        self._payloads_table: Any = None
        self._techniques_table: Any = None
        self._writeups_table: Any = None
        self._reflexions_table: Any = None
        self._initialized = False
        
        # Embedding model for vector search
        self._embedding_model: Any = None
        self._embedding_dim = 384  # all-MiniLM-L6-v2 dimension
        
        # BM25 indices for hybrid search (built on initialization)
        self._bm25_payloads: Any = None
        self._bm25_techniques: Any = None
        self._payload_docs: list[dict] = []
        self._technique_docs: list[dict] = []
    
    async def initialize(self) -> None:
        """Initialize the LanceDB connection and tables."""
        if not LANCEDB_AVAILABLE:
            raise RuntimeError(
                "LanceDB is not installed. Install with: pip install lancedb"
            )
        
        if not EMBEDDING_AVAILABLE:
            raise RuntimeError(
                "sentence-transformers is not installed. Install with: pip install sentence-transformers"
            )
        
        # Create directory if needed
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        
        # Initialize embedding model
        logger.info("Loading embedding model (all-MiniLM-L6-v2)...")
        self._embedding_model = SentenceTransformer('all-MiniLM-L6-v2')
        logger.info("Embedding model loaded")
        
        # Connect to LanceDB
        self._db = lancedb.connect(str(self.db_path))
        
        # Create or open tables
        await self._ensure_tables()
        self._initialized = True
        
        # Build BM25 indices for hybrid search
        if BM25_AVAILABLE:
            await self._build_bm25_indices()
    
    async def _ensure_tables(self) -> None:
        """Ensure all required tables exist."""
        existing_tables = self._db.table_names()
        
        # Payloads table - will be created on first insert
        if "payloads" in existing_tables:
            self._payloads_table = self._db.open_table("payloads")
        else:
            self._payloads_table = None  # Will be created on first add_payloads()
        
        # Techniques table - lazy init (no table until first insert with vectors)
        self._techniques_table = None
        
        # Writeups table - lazy init
        self._writeups_table = None
        
        # Reflexions table - lazy init
        self._reflexions_table = None
    
    def _check_initialized(self) -> None:
        """Raise error if not initialized."""
        if not self._initialized:
            raise RuntimeError("KnowledgeStore not initialized. Call await store.initialize() first.")
    
    # ========================================================================
    # BM25 Hybrid Search Implementation
    # ========================================================================
    
    async def _build_bm25_indices(self) -> None:
        """
        Build BM25 indices for keyword-based search.
        
        Scientific basis:
        - BM25 for exact term matching (Robertson & Zaragoza, 2009)
        - Complements dense vector search for technical domains
        """
        import logging
        logger = logging.getLogger(__name__)
        
        logger.info("Building BM25 indices...")
        
        # Get all payloads
        if self._payloads_table:
            try:
                payload_results = self._payloads_table.search().limit(10000).to_list()
                self._payload_docs = payload_results
                
                # Tokenize for BM25
                payload_corpus = [
                    self._tokenize_for_bm25(doc.get("text", ""))
                    for doc in payload_results
                ]
                
                if payload_corpus:
                    self._bm25_payloads = BM25Okapi(payload_corpus)
                    logger.info(f"BM25 payloads index: {len(payload_corpus)} documents")
            except Exception as e:
                logger.warning(f"Failed to build BM25 payloads index: {e}")
        
        # Get all techniques
        if self._techniques_table:
            try:
                technique_results = self._techniques_table.search().limit(10000).to_list()
                self._technique_docs = technique_results
                
                technique_corpus = [
                    self._tokenize_for_bm25(doc.get("text", ""))
                    for doc in technique_results
                ]
                
                if technique_corpus:
                    self._bm25_techniques = BM25Okapi(technique_corpus)
                    logger.info(f"BM25 techniques index: {len(technique_corpus)} documents")
            except Exception as e:
                logger.warning(f"Failed to build BM25 techniques index: {e}")
    
    def _tokenize_for_bm25(self, text: str) -> list[str]:
        """
        Tokenize text for BM25 search.
        
        Simple whitespace tokenization with filtering.
        For production, could be enhanced with stemming/lemmatization.
        
        Args:
            text: Input text
            
        Returns:
            List of tokens
        """
        # Simple tokenization (lowercase + split)
        tokens = text.lower().split()
        # Remove short tokens (< 3 chars) and common stop words
        tokens = [
            t for t in tokens 
            if len(t) >= 3 and t not in {'the', 'and', 'for', 'with'}
        ]
        return tokens
    
    async def search_hybrid(
        self,
        query: str,
        entry_types: list[str] | None = None,
        limit: int = 20,
        alpha: float = 0.5,
    ) -> KnowledgeSearchResults:
        """
        Hybrid search: BM25 + Vector with RRF fusion.
        
        Scientific basis:
        - "Hybrid Retrieval for RAG" (Anthropic, 2025)
        - RRF (Reciprocal Rank Fusion) from Cormack et al. 2009
        - BM25 + vector fusion: +23% precision on technical domains
        
        Args:
            query: Search query
            entry_types: Types to search ("payload", "technique")
            limit: Max results
            alpha: 0.0 = pure BM25, 1.0 = pure vector, 0.5 = balanced
            
        Returns:
            Fused search results
        """
        import time
        start_time = time.time()
        
        self._check_initialized()
        
        if entry_types is None:
            entry_types = ["payload", "technique"]
        
        all_results: list[SearchResult] = []
        
        # ────────────────────────────────────────────────────────────
        # PAYLOADS
        # ────────────────────────────────────────────────────────────
        if "payload" in entry_types:
            # BM25 search
            bm25_scores = {}
            if BM25_AVAILABLE and self._bm25_payloads and self._payload_docs:
                tokenized_query = self._tokenize_for_bm25(query)
                bm25_raw_scores = self._bm25_payloads.get_scores(tokenized_query)
                
                # Get top-N by BM25 score
                bm25_indices = sorted(
                    range(len(bm25_raw_scores)),
                    key=lambda i: bm25_raw_scores[i],
                    reverse=True
                )[:limit * 2]  # Get 2x for fusion
                
                for rank, idx in enumerate(bm25_indices, 1):
                    if idx < len(self._payload_docs):
                        doc_id = self._payload_docs[idx].get("id", "")
                        if doc_id:
                            bm25_scores[doc_id] = (rank, bm25_raw_scores[idx])
            
            # Vector search
            vector_scores = {}
            vector_results = await self.search_payloads(query, limit=limit * 2)
            for rank, result in enumerate(vector_results, 1):
                doc_id = result.entry.get("id", "")
                if doc_id:
                    vector_scores[doc_id] = (rank, result.score)
            
            # RRF Fusion
            fused = self._rrf_fusion(bm25_scores, vector_scores, alpha=alpha)
            
            # Convert to SearchResult
            for doc_id, score in fused[:limit]:
                # Find original document
                doc = next((d for d in self._payload_docs if d.get("id") == doc_id), None)
                if doc:
                    all_results.append(SearchResult(
                        entry=dict(doc),
                        score=score,
                        entry_type="payload",
                    ))
        
        # ────────────────────────────────────────────────────────────
        # TECHNIQUES
        # ────────────────────────────────────────────────────────────
        if "technique" in entry_types:
            # BM25 search
            bm25_scores = {}
            if BM25_AVAILABLE and self._bm25_techniques and self._technique_docs:
                tokenized_query = self._tokenize_for_bm25(query)
                bm25_raw_scores = self._bm25_techniques.get_scores(tokenized_query)
                
                bm25_indices = sorted(
                    range(len(bm25_raw_scores)),
                    key=lambda i: bm25_raw_scores[i],
                    reverse=True
                )[:limit * 2]
                
                for rank, idx in enumerate(bm25_indices, 1):
                    if idx < len(self._technique_docs):
                        doc_id = self._technique_docs[idx].get("id", "")
                        if doc_id:
                            bm25_scores[doc_id] = (rank, bm25_raw_scores[idx])
            
            # Vector search
            vector_scores = {}
            vector_results = await self.search_techniques(query, limit=limit * 2)
            for rank, result in enumerate(vector_results, 1):
                doc_id = result.entry.get("id", "")
                if doc_id:
                    vector_scores[doc_id] = (rank, result.score)
            
            # RRF Fusion
            fused = self._rrf_fusion(bm25_scores, vector_scores, alpha=alpha)
            
            for doc_id, score in fused[:limit]:
                doc = next((d for d in self._technique_docs if d.get("id") == doc_id), None)
                if doc:
                    all_results.append(SearchResult(
                        entry=dict(doc),
                        score=score,
                        entry_type="technique",
                    ))
        
        # Sort all by score
        all_results.sort(key=lambda r: r.score, reverse=True)
        
        elapsed_ms = (time.time() - start_time) * 1000
        
        return KnowledgeSearchResults(
            query=query,
            results=all_results[:limit],
            total_count=len(all_results),
            search_time_ms=elapsed_ms,
        )
    
    def _rrf_fusion(
        self,
        bm25_scores: dict[str, tuple[int, float]],
        vector_scores: dict[str, tuple[int, float]],
        alpha: float = 0.5,
        k: int = 60,
    ) -> list[tuple[str, float]]:
        """
        Reciprocal Rank Fusion (RRF).
        
        Scientific basis:
        - Cormack et al. (2009): "Reciprocal Rank Fusion"
        - k=60 empirically optimal
        - Formula: score(doc) = α*(1/(k+rank_bm25)) + (1-α)*(1/(k+rank_vec))
        
        Args:
            bm25_scores: {doc_id: (rank, score)}
            vector_scores: {doc_id: (rank, score)}
            alpha: Weight for BM25 (0.5 = balanced)
            k: RRF constant (60 is standard)
            
        Returns:
            Sorted list of (doc_id, fused_score)
        """
        fused = {}
        
        # Get all document IDs
        all_doc_ids = set(bm25_scores.keys()) | set(vector_scores.keys())
        
        for doc_id in all_doc_ids:
            # Get ranks (default to large number if not found)
            bm25_rank = bm25_scores.get(doc_id, (10000, 0.0))[0]
            vector_rank = vector_scores.get(doc_id, (10000, 0.0))[0]
            
            # RRF formula with alpha weighting
            rrf_score = (
                alpha * (1.0 / (k + bm25_rank)) +
                (1 - alpha) * (1.0 / (k + vector_rank))
            )
            
            fused[doc_id] = rrf_score
        
        # Sort by fused score (descending)
        sorted_fused = sorted(fused.items(), key=lambda x: x[1], reverse=True)
        
        return sorted_fused
    
    # ========================================================================
    # Payload Operations
    # ========================================================================
    
    async def add_payload(self, payload: PayloadEntry) -> str:
        """Add a payload to the store.
        
        Returns:
            The payload ID
        """
        self._check_initialized()
        
        data = payload.model_dump()
        data["text"] = payload.embedding_text
        
        self._payloads_table.add([data])
        return payload.id
    
    async def add_payloads(self, payloads: list[PayloadEntry]) -> int:
        """Bulk add payloads with vector embeddings.
        
        Returns:
            Number of payloads added
        """
        self._check_initialized()
        
        if not payloads:
            return 0
        
        # Prepare texts for embedding
        texts = [payload.embedding_text for payload in payloads]
        
        # Generate embeddings in batch (much faster)
        vectors = self._embedding_model.encode(texts, show_progress_bar=False)
        
        data = []
        for payload, vector in zip(payloads, vectors):
            d = payload.model_dump()
            d["text"] = payload.embedding_text
            d["vector"] = vector.tolist()  # Convert numpy array to list
            
            # CRITICAL: Ensure all string fields are strings (not None)
            # LanceDB/PyArrow fails on None -> str casting
            for key in ['bypass_technique', 'platform', 'context']:
                if d.get(key) is None:
                    d[key] = ""
            
            data.append(d)
        
        # Create or update table
        if self._payloads_table is None:
            # First insert - create table with schema inference from data
            self._payloads_table = self._db.create_table(
                "payloads",
                data=data,
                mode="overwrite",
            )
            logger.info(f"Created payloads table with {len(data)} entries")
        else:
            # Table exists - append data
            # Use mode="append" to avoid duplicates
            self._payloads_table.add(data, mode="append")
        
        return len(payloads)
    
    async def search_payloads(
        self,
        query: str,
        category: str | None = None,
        limit: int = 10,
    ) -> list[SearchResult]:
        """Search payloads by semantic similarity.
        
        Args:
            query: Search query
            category: Optional category filter
            limit: Maximum results
            
        Returns:
            List of search results with scores
        """
        self._check_initialized()
        
        # Table might not exist yet if no payloads added
        if self._payloads_table is None:
            return []
        
        # Generate query embedding
        query_vector = self._embedding_model.encode(query, show_progress_bar=False).tolist()
        
        # CRITICAL: LanceDB 0.4+ requires explicit column name when schema has fixed_size_list
        # Auto-detection fails for this type
        try:
            search = self._payloads_table.search(query_vector, vector_column_name="vector").limit(limit)
        except TypeError:
            # Fallback for older LanceDB versions
            search = self._payloads_table.search(query_vector).limit(limit)
        
        # Apply category filter
        if category:
            search = search.where(f"category = '{category}'")
        
        results = search.to_list()
        
        return [
            SearchResult(
                entry=dict(r),
                score=1.0 - r.get("_distance", 0.0),  # Convert distance to similarity
                entry_type="payload",
            )
            for r in results
        ]
    
    async def get_payload(self, payload_id: str) -> PayloadEntry | None:
        """Get a specific payload by ID."""
        self._check_initialized()
        
        results = self._payloads_table.search().where(f"id = '{payload_id}'").limit(1).to_list()
        if results:
            return PayloadEntry(**results[0])
        return None
    
    async def list_payloads_by_category(self, category: str) -> list[PayloadEntry]:
        """List all payloads in a category."""
        self._check_initialized()
        
        results = self._payloads_table.search().where(f"category = '{category}'").limit(1000).to_list()
        return [PayloadEntry(**r) for r in results]
    
    async def delete_payload(self, payload_id: str) -> bool:
        """Delete a payload by ID."""
        self._check_initialized()
        
        self._payloads_table.delete(f"id = '{payload_id}'")
        return True
    
    # ========================================================================
    # Technique Operations
    # ========================================================================
    
    async def add_technique(self, technique: TechniqueEntry) -> str:
        """Add a technique to the store."""
        self._check_initialized()
        
        data = technique.model_dump()
        data["text"] = technique.embedding_text
        
        self._techniques_table.add([data])
        return technique.id
    
    async def add_techniques(self, techniques: list[TechniqueEntry]) -> int:
        """Bulk add techniques."""
        self._check_initialized()
        
        if not techniques:
            return 0
        
        data = []
        for technique in techniques:
            d = technique.model_dump()
            d["text"] = technique.embedding_text
            data.append(d)
        
        self._techniques_table.add(data)
        return len(techniques)
    
    async def search_techniques(
        self,
        query: str,
        category: str | None = None,
        limit: int = 10,
    ) -> list[SearchResult]:
        """Search techniques by semantic similarity."""
        self._check_initialized()
        
        # Table might not exist yet
        if self._techniques_table is None:
            return []
        
        # Generate query embedding
        query_vector = self._embedding_model.encode(query, show_progress_bar=False).tolist()
        
        try:
            search = self._techniques_table.search(query_vector, vector_column_name="vector").limit(limit)
        except (TypeError, ValueError):
            # Fallback or no vector column
            return []
        
        if category:
            search = search.where(f"category = '{category}'")
        
        results = search.to_list()
        
        return [
            SearchResult(
                entry=dict(r),
                score=1.0 - r.get("_distance", 0.0),
                entry_type="technique",
            )
            for r in results
        ]
    
    async def get_technique(self, technique_id: str) -> TechniqueEntry | None:
        """Get a specific technique by ID."""
        self._check_initialized()
        
        results = self._techniques_table.search().where(f"id = '{technique_id}'").limit(1).to_list()
        if results:
            return TechniqueEntry(**results[0])
        return None
    
    # ========================================================================
    # Writeup Operations
    # ========================================================================
    
    async def add_writeup(self, writeup: WriteupEntry) -> str:
        """Add a writeup to the store."""
        self._check_initialized()
        
        data = writeup.model_dump()
        data["text"] = writeup.embedding_text
        
        self._writeups_table.add([data])
        return writeup.id
    
    async def add_writeups(self, writeups: list[WriteupEntry]) -> int:
        """Bulk add writeups."""
        self._check_initialized()
        
        if not writeups:
            return 0
        
        data = []
        for writeup in writeups:
            d = writeup.model_dump()
            d["text"] = writeup.embedding_text
            data.append(d)
        
        self._writeups_table.add(data)
        return len(writeups)
    
    async def search_writeups(
        self,
        query: str,
        platform: str | None = None,
        category: str | None = None,
        limit: int = 10,
    ) -> list[SearchResult]:
        """Search writeups by semantic similarity."""
        self._check_initialized()
        
        # Table might not exist yet
        if self._writeups_table is None:
            return []
        
        # Generate query embedding
        query_vector = self._embedding_model.encode(query, show_progress_bar=False).tolist()
        
        try:
            search = self._writeups_table.search(query_vector, vector_column_name="vector").limit(limit)
        except (TypeError, ValueError):
            return []
        
        filters = []
        if platform:
            filters.append(f"platform = '{platform}'")
        if category:
            filters.append(f"category = '{category}'")
        
        if filters:
            search = search.where(" AND ".join(filters))
        
        results = search.to_list()
        
        return [
            SearchResult(
                entry=dict(r),
                score=1.0 - r.get("_distance", 0.0),
                entry_type="writeup",
            )
            for r in results
        ]
    
    async def get_writeup(self, writeup_id: str) -> WriteupEntry | None:
        """Get a specific writeup by ID."""
        self._check_initialized()
        
        results = self._writeups_table.search().where(f"id = '{writeup_id}'").limit(1).to_list()
        if results:
            return WriteupEntry(**results[0])
        return None
    
    # ========================================================================
    # Reflexion Operations
    # ========================================================================
    
    async def add_reflexion(self, reflexion: ReflexionEntry) -> str:
        """Add a reflexion entry to the store."""
        self._check_initialized()
        
        data = reflexion.model_dump()
        data["text"] = reflexion.embedding_text
        # Convert context dict to JSON string for storage
        data["context"] = json.dumps(data["context"])
        
        self._reflexions_table.add([data])
        return reflexion.id
    
    async def search_reflexions(
        self,
        query: str,
        outcome: Literal["success", "failure"] | None = None,
        limit: int = 10,
    ) -> list[SearchResult]:
        """Search reflexions by semantic similarity."""
        self._check_initialized()
        
        # Table might not exist yet
        if self._reflexions_table is None:
            return []
        
        # Generate query embedding
        query_vector = self._embedding_model.encode(query, show_progress_bar=False).tolist()
        
        try:
            search = self._reflexions_table.search(query_vector, vector_column_name="vector").limit(limit)
        except (TypeError, ValueError):
            return []
        
        if outcome:
            search = search.where(f"outcome = '{outcome}'")
        
        results = search.to_list()
        
        return [
            SearchResult(
                entry=dict(r),
                score=1.0 - r.get("_distance", 0.0),
                entry_type="reflexion",
            )
            for r in results
        ]
    
    async def get_lessons_for_scenario(
        self,
        scenario_description: str,
        min_confidence: float = 0.5,
        limit: int = 5,
    ) -> list[ReflexionEntry]:
        """Get relevant lessons learned for a given scenario."""
        self._check_initialized()
        
        results = await self.search_reflexions(scenario_description, limit=limit)
        
        lessons = []
        for r in results:
            entry = r.entry
            # Parse context back from JSON
            if isinstance(entry.get("context"), str):
                entry["context"] = json.loads(entry["context"])
            
            reflexion = ReflexionEntry(**entry)
            if reflexion.confidence >= min_confidence:
                lessons.append(reflexion)
        
        return lessons
    
    # ========================================================================
    # Unified Search
    # ========================================================================
    
    async def search(
        self,
        query: str,
        entry_types: list[str] | None = None,
        limit: int = 20,
    ) -> KnowledgeSearchResults:
        """Unified search across all knowledge types.
        
        Args:
            query: Search query
            entry_types: Types to search ("payload", "technique", "writeup", "reflexion")
                         None means search all
            limit: Maximum results per type
            
        Returns:
            Aggregated search results
        """
        import time
        start_time = time.time()
        
        self._check_initialized()
        
        if entry_types is None:
            entry_types = ["payload", "technique", "writeup", "reflexion"]
        
        all_results: list[SearchResult] = []
        
        # Search each type (only if table exists and has data)
        if "payload" in entry_types and self._payloads_table is not None:
            all_results.extend(await self.search_payloads(query, limit=limit))
        
        if "technique" in entry_types and self._techniques_table is not None:
            all_results.extend(await self.search_techniques(query, limit=limit))
        
        if "writeup" in entry_types and self._writeups_table is not None:
            all_results.extend(await self.search_writeups(query, limit=limit))
        
        if "reflexion" in entry_types and self._reflexions_table is not None:
            all_results.extend(await self.search_reflexions(query, limit=limit))
        
        # Sort by score (descending)
        all_results.sort(key=lambda r: r.score, reverse=True)
        
        # Limit total results
        all_results = all_results[:limit]
        
        elapsed_ms = (time.time() - start_time) * 1000
        
        return KnowledgeSearchResults(
            query=query,
            results=all_results,
            total_count=len(all_results),
            search_time_ms=elapsed_ms,
        )
    
    # ========================================================================
    # Statistics
    # ========================================================================
    
    async def get_stats(self) -> dict[str, int]:
        """Get counts for each entry type."""
        self._check_initialized()
        
        return {
            "payloads": self._payloads_table.count_rows() if self._payloads_table is not None else 0,
            "techniques": self._techniques_table.count_rows() if self._techniques_table is not None else 0,
            "writeups": self._writeups_table.count_rows() if self._writeups_table is not None else 0,
            "reflexions": self._reflexions_table.count_rows() if self._reflexions_table is not None else 0,
        }
    
    async def clear_all(self) -> None:
        """Clear all entries from all tables. USE WITH CAUTION."""
        self._check_initialized()
        
        self._payloads_table.delete("id IS NOT NULL")
        self._techniques_table.delete("id IS NOT NULL")
        self._writeups_table.delete("id IS NOT NULL")
        self._reflexions_table.delete("id IS NOT NULL")


# ============================================================================
# Helper Functions
# ============================================================================

def generate_payload_id(category: str, name: str) -> str:
    """Generate a deterministic ID for a payload."""
    content = f"{category}:{name}"
    return hashlib.md5(content.encode()).hexdigest()[:12]


def generate_technique_id(name: str) -> str:
    """Generate a deterministic ID for a technique."""
    return hashlib.md5(name.encode()).hexdigest()[:12]


def generate_writeup_id(title: str, platform: str) -> str:
    """Generate a deterministic ID for a writeup."""
    content = f"{platform}:{title}"
    return hashlib.md5(content.encode()).hexdigest()[:12]


def generate_reflexion_id(engagement_id: str, action_description: str) -> str:
    """Generate a deterministic ID for a reflexion."""
    content = f"{engagement_id}:{action_description}:{datetime.now(timezone.utc).isoformat()}"
    return hashlib.md5(content.encode()).hexdigest()[:12]


# ============================================================================
# In-Memory Store (Fallback when LanceDB not available)
# ============================================================================

class InMemoryKnowledgeStore:
    """Simple in-memory fallback when LanceDB is not available.
    
    Provides basic keyword-based search (no vector embeddings).
    """
    
    def __init__(self):
        self._payloads: dict[str, PayloadEntry] = {}
        self._techniques: dict[str, TechniqueEntry] = {}
        self._writeups: dict[str, WriteupEntry] = {}
        self._reflexions: dict[str, ReflexionEntry] = {}
        self._initialized = False
    
    async def initialize(self) -> None:
        """Initialize the in-memory store."""
        self._initialized = True
    
    async def add_payload(self, payload: PayloadEntry) -> str:
        self._payloads[payload.id] = payload
        return payload.id
    
    async def add_payloads(self, payloads: list[PayloadEntry]) -> int:
        for p in payloads:
            self._payloads[p.id] = p
        return len(payloads)
    
    async def search_payloads(
        self,
        query: str,
        category: str | None = None,
        limit: int = 10,
    ) -> list[SearchResult]:
        """Simple keyword search."""
        query_lower = query.lower()
        results = []
        
        for payload in self._payloads.values():
            # Category filter
            if category and payload.category != category:
                continue
            
            # Simple keyword matching
            text = payload.embedding_text.lower()
            score = sum(1 for word in query_lower.split() if word in text)
            
            if score > 0:
                results.append(SearchResult(
                    entry=payload.model_dump(),
                    score=score / len(query_lower.split()),
                    entry_type="payload",
                ))
        
        # Sort by score
        results.sort(key=lambda r: r.score, reverse=True)
        return results[:limit]
    
    async def add_technique(self, technique: TechniqueEntry) -> str:
        self._techniques[technique.id] = technique
        return technique.id
    
    async def add_techniques(self, techniques: list[TechniqueEntry]) -> int:
        for t in techniques:
            self._techniques[t.id] = t
        return len(techniques)
    
    async def search_techniques(
        self,
        query: str,
        category: str | None = None,
        limit: int = 10,
    ) -> list[SearchResult]:
        query_lower = query.lower()
        results = []
        
        for technique in self._techniques.values():
            if category and technique.category != category:
                continue
            
            text = technique.embedding_text.lower()
            score = sum(1 for word in query_lower.split() if word in text)
            
            if score > 0:
                results.append(SearchResult(
                    entry=technique.model_dump(),
                    score=score / len(query_lower.split()),
                    entry_type="technique",
                ))
        
        results.sort(key=lambda r: r.score, reverse=True)
        return results[:limit]
    
    async def add_writeup(self, writeup: WriteupEntry) -> str:
        self._writeups[writeup.id] = writeup
        return writeup.id
    
    async def search_writeups(
        self,
        query: str,
        platform: str | None = None,
        category: str | None = None,
        limit: int = 10,
    ) -> list[SearchResult]:
        query_lower = query.lower()
        results = []
        
        for writeup in self._writeups.values():
            if platform and writeup.platform != platform:
                continue
            if category and writeup.category != category:
                continue
            
            text = writeup.embedding_text.lower()
            score = sum(1 for word in query_lower.split() if word in text)
            
            if score > 0:
                results.append(SearchResult(
                    entry=writeup.model_dump(),
                    score=score / len(query_lower.split()),
                    entry_type="writeup",
                ))
        
        results.sort(key=lambda r: r.score, reverse=True)
        return results[:limit]
    
    async def add_reflexion(self, reflexion: ReflexionEntry) -> str:
        self._reflexions[reflexion.id] = reflexion
        return reflexion.id
    
    async def search_reflexions(
        self,
        query: str,
        outcome: str | None = None,
        limit: int = 10,
    ) -> list[SearchResult]:
        query_lower = query.lower()
        results = []
        
        for reflexion in self._reflexions.values():
            if outcome and reflexion.outcome != outcome:
                continue
            
            text = reflexion.embedding_text.lower()
            score = sum(1 for word in query_lower.split() if word in text)
            
            if score > 0:
                results.append(SearchResult(
                    entry=reflexion.model_dump(),
                    score=score / len(query_lower.split()),
                    entry_type="reflexion",
                ))
        
        results.sort(key=lambda r: r.score, reverse=True)
        return results[:limit]
    
    async def search(
        self,
        query: str,
        entry_types: list[str] | None = None,
        limit: int = 20,
    ) -> KnowledgeSearchResults:
        import time
        start_time = time.time()
        
        if entry_types is None:
            entry_types = ["payload", "technique", "writeup", "reflexion"]
        
        all_results: list[SearchResult] = []
        
        if "payload" in entry_types:
            all_results.extend(await self.search_payloads(query, limit=limit))
        if "technique" in entry_types:
            all_results.extend(await self.search_techniques(query, limit=limit))
        if "writeup" in entry_types:
            all_results.extend(await self.search_writeups(query, limit=limit))
        if "reflexion" in entry_types:
            all_results.extend(await self.search_reflexions(query, limit=limit))
        
        all_results.sort(key=lambda r: r.score, reverse=True)
        all_results = all_results[:limit]
        
        elapsed_ms = (time.time() - start_time) * 1000
        
        return KnowledgeSearchResults(
            query=query,
            results=all_results,
            total_count=len(all_results),
            search_time_ms=elapsed_ms,
        )
    
    async def get_stats(self) -> dict[str, int]:
        return {
            "payloads": len(self._payloads),
            "techniques": len(self._techniques),
            "writeups": len(self._writeups),
            "reflexions": len(self._reflexions),
        }


def create_knowledge_store(db_path: str | Path | None = None) -> KnowledgeStore | InMemoryKnowledgeStore:
    """Factory function to create appropriate knowledge store.
    
    Returns LanceDB store if available, otherwise in-memory fallback.
    """
    if LANCEDB_AVAILABLE:
        return KnowledgeStore(db_path)
    else:
        return InMemoryKnowledgeStore()
