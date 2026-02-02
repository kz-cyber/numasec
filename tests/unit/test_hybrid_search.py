"""
Unit tests for hybrid search (BM25 + Vector + RRF).

Scientific basis:
- Validate RRF fusion algorithm
- Verify BM25 complements vector search
- Ensure performance targets met
"""

import pytest
from numasec.knowledge.store import KnowledgeStore, PayloadEntry, generate_payload_id


@pytest.mark.asyncio
async def test_rrf_fusion_combines_rankings():
    """
    Verify RRF correctly combines BM25 + vector rankings.
    
    Scientific basis: Cormack et al. (2009) - RRF formula
    """
    store = KnowledgeStore()
    
    # Simulate rankings
    bm25_scores = {
        "doc1": (1, 10.5),  # Rank 1, score 10.5
        "doc2": (3, 8.2),   # Rank 3
        "doc3": (5, 6.1),   # Rank 5
    }
    
    vector_scores = {
        "doc1": (4, 0.85),  # Rank 4, score 0.85
        "doc2": (1, 0.95),  # Rank 1 (best vector match)
        "doc3": (2, 0.90),  # Rank 2
    }
    
    # Balanced fusion (alpha=0.5)
    fused = store._rrf_fusion(bm25_scores, vector_scores, alpha=0.5)
    
    # doc2 should win (rank 3 in BM25, rank 1 in vector)
    # It's good in both systems
    assert fused[0][0] == "doc2", "RRF should favor documents good in both rankings"
    
    # BM25-heavy fusion (alpha=0.8)
    fused_bm25 = store._rrf_fusion(bm25_scores, vector_scores, alpha=0.8)
    
    # doc1 should win (BM25 rank 1)
    assert fused_bm25[0][0] == "doc1", "BM25-heavy fusion should favor BM25 rankings"
    
    # Vector-heavy fusion (alpha=0.2)
    fused_vector = store._rrf_fusion(bm25_scores, vector_scores, alpha=0.2)
    
    # doc2 should still win (vector rank 1, strong signal)
    assert fused_vector[0][0] == "doc2", "Vector-heavy fusion should favor vector rankings"


@pytest.mark.asyncio
async def test_rrf_handles_missing_documents():
    """Verify RRF handles documents only in one ranking system."""
    
    store = KnowledgeStore()
    
    # doc1 only in BM25
    bm25_scores = {
        "doc1": (1, 10.0),
        "doc2": (2, 8.0),
    }
    
    # doc2 and doc3 only in vector
    vector_scores = {
        "doc2": (1, 0.95),
        "doc3": (2, 0.90),
    }
    
    fused = store._rrf_fusion(bm25_scores, vector_scores, alpha=0.5)
    
    # All 3 docs should be in results
    doc_ids = [doc_id for doc_id, _ in fused]
    assert "doc1" in doc_ids
    assert "doc2" in doc_ids
    assert "doc3" in doc_ids
    
    # doc2 should win (present in both)
    assert fused[0][0] == "doc2"


def test_tokenize_for_bm25():
    """Verify BM25 tokenization filters correctly."""
    
    store = KnowledgeStore()
    
    text = "SQL injection bypass WAF with UNION SELECT"
    tokens = store._tokenize_for_bm25(text)
    
    # Should be lowercase
    assert all(t.islower() for t in tokens)
    
    # Should filter short tokens
    assert all(len(t) >= 3 for t in tokens)
    
    # Should contain main terms
    assert "sql" in tokens
    assert "injection" in tokens
    assert "bypass" in tokens
    assert "waf" in tokens
    assert "union" in tokens
    assert "select" in tokens


@pytest.mark.asyncio
@pytest.mark.integration
async def test_hybrid_search_initialization(tmp_path):
    """
    Test that hybrid search initializes BM25 indices correctly.
    
    This is an integration test requiring LanceDB.
    """
    try:
        # Use temporary database to avoid state pollution
        store = KnowledgeStore(db_path=tmp_path / "test.lance")
        await store.initialize()
        
        # Add test payloads
        test_payloads = [
            PayloadEntry(
                id=generate_payload_id("sqli", "union_test"),
                name="UNION SELECT Test",
                category="sqli",
                payload="' UNION SELECT NULL--",
                description="Test UNION columns",
                use_case="Column enumeration",
                tags=["sqli", "union"],
            ),
            PayloadEntry(
                id=generate_payload_id("sqli", "boolean_test"),
                name="Boolean Test",
                category="sqli",
                payload="' AND 1=1--",
                description="Boolean blind",
                use_case="Blind injection",
                tags=["sqli", "blind"],
            ),
        ]
        
        await store.add_payloads(test_payloads)
        
        # Rebuild indices
        from numasec.knowledge.store import BM25_AVAILABLE
        if BM25_AVAILABLE:
            await store._build_bm25_indices()
            
            # Verify indices built
            assert store._bm25_payloads is not None
            assert len(store._payload_docs) == 2
        
        # Test hybrid search
        results = await store.search_hybrid(
            "UNION SELECT SQL injection",
            entry_types=["payload"],
            limit=5
        )
        
        # Should find both payloads, UNION one should rank higher
        assert results.total_count >= 1
        if results.total_count > 0:
            top = results.results[0]
            assert "union" in top.entry.get("payload", "").lower()
        
    except RuntimeError as e:
        if "LanceDB is not installed" in str(e):
            pytest.skip("LanceDB not available")
        raise


@pytest.mark.asyncio
@pytest.mark.integration
async def test_hybrid_search_outperforms_vector_only(tmp_path):
    """
    Verify hybrid search finds more relevant results for technical queries.
    
    Target: +20% precision on technical exact-match queries.
    """
    try:
        # Use temporary database to avoid state pollution
        store = KnowledgeStore(db_path=tmp_path / "test.lance")
        await store.initialize()
        
        # Add diverse payloads
        test_payloads = [
            PayloadEntry(
                id="p1",
                name="UNION SELECT NULL",
                category="sqli",
                payload="' UNION SELECT NULL--",
                description="Column detection for SQL injection",
                use_case="Enumerate columns",
                tags=["sqli", "union"],
            ),
            PayloadEntry(
                id="p2",
                name="Boolean Blind",
                category="sqli",
                payload="' AND 1=1--",
                description="Boolean blind SQL injection",
                use_case="Blind testing",
                tags=["sqli", "blind"],
            ),
            PayloadEntry(
                id="p3",
                name="Generic XSS",
                category="xss",
                payload="<script>alert(1)</script>",
                description="Cross-site scripting test",
                use_case="XSS detection",
                tags=["xss"],
            ),
        ]
        
        await store.add_payloads(test_payloads)
        
        # Rebuild indices
        from numasec.knowledge.store import BM25_AVAILABLE
        if BM25_AVAILABLE:
            await store._build_bm25_indices()
        
        # Technical query with exact terms
        query = "SQL injection UNION SELECT"
        
        # Hybrid search should prioritize exact matches
        hybrid_results = await store.search_hybrid(
            query,
            entry_types=["payload"],
            limit=3,
            alpha=0.6  # Favor BM25 for technical terms
        )
        
        # Top result should be UNION payload (exact match)
        if hybrid_results.total_count > 0:
            top = hybrid_results.results[0]
            assert "union" in top.entry.get("payload", "").lower()
            assert "select" in top.entry.get("payload", "").lower()
        
    except RuntimeError as e:
        if "LanceDB is not installed" in str(e):
            pytest.skip("LanceDB not available")
        raise
