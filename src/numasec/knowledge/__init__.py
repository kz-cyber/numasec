"""Knowledge base package for NumaSec.

LanceDB vector store for payloads, techniques, and writeups.
"""

from numasec.knowledge.store import (
    KnowledgeStore,
    InMemoryKnowledgeStore,
    create_knowledge_store,
    PayloadEntry,
    TechniqueEntry,
    WriteupEntry,
    ReflexionEntry,
    SearchResult,
    KnowledgeSearchResults,
    PayloadCategory,
    TechniqueCategory,
    DifficultyLevel,
    generate_payload_id,
    generate_technique_id,
    generate_writeup_id,
    generate_reflexion_id,
    LANCEDB_AVAILABLE,
)

from numasec.knowledge.seeds import (
    ALL_PAYLOADS,
    get_payloads_by_category,
    get_all_categories,
    get_payload_count,
    get_payload_stats,
    seed_payloads,
)

__all__ = [
    # Store
    "KnowledgeStore",
    "InMemoryKnowledgeStore",
    "create_knowledge_store",
    "LANCEDB_AVAILABLE",
    # Entry Types
    "PayloadEntry",
    "TechniqueEntry",
    "WriteupEntry",
    "ReflexionEntry",
    # Search
    "SearchResult",
    "KnowledgeSearchResults",
    # Enums
    "PayloadCategory",
    "TechniqueCategory",
    "DifficultyLevel",
    # ID Generation
    "generate_payload_id",
    "generate_technique_id",
    "generate_writeup_id",
    "generate_reflexion_id",
    # Seeds
    "ALL_PAYLOADS",
    "get_payloads_by_category",
    "get_all_categories",
    "get_payload_count",
    "get_payload_stats",
    "seed_payloads",
]
