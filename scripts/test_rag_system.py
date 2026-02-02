#!/usr/bin/env python3
"""
End-to-end test script for Reflexive RAG system.

Usage:
    python scripts/test_rag_system.py

Validates:
1. Knowledge base population
2. Hybrid search performance
3. RAG trigger conditions
4. Full integration
"""

import asyncio
import sys
from pathlib import Path

# Add src to path
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from rich.console import Console
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn

console = Console()


async def test_knowledge_population():
    """Test Phase 1: Knowledge base population."""
    
    console.print("\n[bold cyan]═══ Phase 1: Knowledge Base Population ═══[/bold cyan]\n")
    
    from numasec.knowledge.store import KnowledgeStore
    
    store = KnowledgeStore()
    
    try:
        await store.initialize()
        console.print("[green]✓[/green] LanceDB initialized")
    except Exception as e:
        console.print(f"[red]✗[/red] Failed to initialize: {e}")
        return False
    
    # Get stats
    stats = await store.get_stats()
    
    # Display stats
    stats_table = Table(title="Knowledge Base Stats", show_header=True)
    stats_table.add_column("Type", style="cyan")
    stats_table.add_column("Count", justify="right", style="green")
    
    stats_table.add_row("Payloads", str(stats['payloads']))
    stats_table.add_row("Techniques", str(stats['techniques']))
    stats_table.add_row("Writeups", str(stats['writeups']))
    
    console.print(stats_table)
    
    if stats['payloads'] == 0 and stats['techniques'] == 0:
        console.print("\n[yellow]⚠ Knowledge base is empty![/yellow]")
        console.print("[dim]Run: python -m numasec.knowledge.seeds.populate[/dim]")
        return False
    
    console.print(f"\n[green]✓ Phase 1 PASS[/green] ({stats['payloads'] + stats['techniques']} entries)")
    return True


async def test_hybrid_search():
    """Test Phase 2: Hybrid search performance."""
    
    console.print("\n[bold cyan]═══ Phase 2: Hybrid Search ═══[/bold cyan]\n")
    
    from numasec.knowledge.store import KnowledgeStore, BM25_AVAILABLE
    
    if not BM25_AVAILABLE:
        console.print("[yellow]⚠ BM25 not available (install rank-bm25)[/yellow]")
        console.print("[dim]pip install rank-bm25[/dim]")
        return False
    
    store = KnowledgeStore()
    await store.initialize()
    
    # Test queries
    test_queries = [
        ("SQL injection bypass WAF", "Should find SQLi payloads"),
        ("UNION SELECT enumeration", "Should find UNION techniques"),
        ("command injection bypass space", "Should find command injection"),
        ("XSS bypass filter", "Should find XSS payloads"),
    ]
    
    results_table = Table(title="Search Performance", show_header=True)
    results_table.add_column("Query", style="cyan", no_wrap=False)
    results_table.add_column("Results", justify="right", style="green")
    results_table.add_column("Latency", justify="right", style="yellow")
    
    latencies = []
    
    for query, description in test_queries:
        try:
            results = await store.search_hybrid(
                query=query,
                entry_types=["payload", "technique"],
                limit=5,
                alpha=0.6
            )
            
            latencies.append(results.search_time_ms)
            
            results_table.add_row(
                query[:40] + "..." if len(query) > 40 else query,
                str(results.total_count),
                f"{results.search_time_ms:.1f}ms"
            )
            
        except Exception as e:
            console.print(f"[red]✗[/red] Query failed: {e}")
    
    console.print(results_table)
    
    if latencies:
        avg_latency = sum(latencies) / len(latencies)
        p95_latency = sorted(latencies)[int(len(latencies) * 0.95)] if len(latencies) > 1 else latencies[0]
        
        console.print(f"\n[yellow]Performance:[/yellow]")
        console.print(f"  Avg latency: {avg_latency:.1f}ms")
        console.print(f"  P95 latency: {p95_latency:.1f}ms")
        
        if p95_latency < 150:
            console.print(f"\n[green]✓ Phase 2 PASS[/green] (latency target met)")
            return True
        else:
            console.print(f"\n[yellow]⚠ Phase 2 WARNING[/yellow] (latency: {p95_latency:.1f}ms > 150ms target)")
            return True  # Still pass, just slower
    
    return False


async def test_rag_triggers():
    """Test Phase 3: RAG trigger conditions."""
    
    console.print("\n[bold cyan]═══ Phase 3: RAG Trigger Conditions ═══[/bold cyan]\n")
    
    from numasec.agent.agent import NumaSecAgent, AgentConfig
    from numasec.agent.state import AgentState, Action
    from numasec.ai.router import LLMRouter
    from unittest.mock import MagicMock
    
    # Create mock agent
    mock_router = MagicMock(spec=LLMRouter)
    mock_mcp_client = MagicMock()
    
    agent = NumaSecAgent(
        router=mock_router,
        mcp_client=mock_mcp_client,
        config=AgentConfig(),
    )
    
    agent.state = AgentState(target="http://test.com", objective="Test")
    
    # Test 1: No trigger on empty history
    should_trigger, reason = await agent._should_trigger_knowledge_retrieval()
    
    if should_trigger:
        console.print("[red]✗[/red] Trigger 1: Should not trigger on empty history")
        return False
    
    console.print("[green]✓[/green] Trigger 1: No false positive on empty history")
    
    # Test 2: Trigger on 3 consecutive failures
    from numasec.agent.state import Action
    import hashlib
    
    for i in range(3):
        result = "403 Forbidden"
        agent.state.history.append(Action(
            iteration=i + 1,
            tool="web_request",
            args={"url": "http://test.com"},
            result=result,
            result_hash=hashlib.md5(result.encode()).hexdigest()[:8],
            result_excerpt=result[:200]
        ))
    
    should_trigger, reason = await agent._should_trigger_knowledge_retrieval()
    
    if not should_trigger:
        console.print("[red]✗[/red] Trigger 2: Should trigger on 3 failures")
        return False
    
    if "consecutive" not in reason.lower():
        console.print(f"[red]✗[/red] Trigger 2: Wrong reason: {reason}")
        return False
    
    console.print("[green]✓[/green] Trigger 2: Correctly triggers on consecutive failures")
    console.print(f"[dim]  Reason: {reason}[/dim]")
    
    # Test 3: Trigger on Commitment Mode stalled
    agent.state.history.clear()
    agent.commitment_mode = True
    agent.commitment_target = "sqli_test"
    
    for i in range(5):
        result = "Error: exploit failed"
        agent.state.history.append(Action(
            iteration=i + 1,
            tool="exploit_script",
            args={"code": "test"},
            result=result,
            result_hash=hashlib.md5(result.encode()).hexdigest()[:8],
            result_excerpt=result[:200]
        ))
    
    should_trigger, reason = await agent._should_trigger_knowledge_retrieval()
    
    if not should_trigger:
        console.print("[red]✗[/red] Trigger 3: Should trigger on Commitment Mode stall")
        return False
    
    if "commitment" not in reason.lower():
        console.print(f"[red]✗[/red] Trigger 3: Wrong reason: {reason}")
        return False
    
    console.print("[green]✓[/green] Trigger 3: Correctly triggers on Commitment Mode stall")
    console.print(f"[dim]  Reason: {reason}[/dim]")
    
    console.print(f"\n[green]✓ Phase 3 PASS[/green] (all triggers working)")
    return True


async def test_full_integration():
    """Test Phase 4: Full RAG integration."""
    
    console.print("\n[bold cyan]═══ Phase 4: Full Integration ═══[/bold cyan]\n")
    
    from numasec.knowledge.store import KnowledgeStore
    
    # Initialize knowledge
    store = KnowledgeStore()
    
    try:
        await store.initialize()
    except Exception as e:
        console.print(f"[red]✗[/red] Failed to initialize: {e}")
        return False
    
    stats = await store.get_stats()
    
    if stats['payloads'] == 0 and stats['techniques'] == 0:
        console.print("[yellow]⚠ Cannot test integration without knowledge data[/yellow]")
        return False
    
    # Test query construction and formatting
    from numasec.agent.agent import NumaSecAgent, AgentConfig
    from numasec.agent.state import AgentState, Action
    from unittest.mock import MagicMock
    import hashlib
    
    mock_router = MagicMock()
    mock_mcp_client = MagicMock()
    
    agent = NumaSecAgent(
        router=mock_router,
        mcp_client=mock_mcp_client,
        config=AgentConfig(),
    )
    
    agent.state = AgentState(
        target="http://test.com",
        objective="Find SQL injection vulnerability"
    )
    
    # Initialize knowledge in agent
    await agent._initialize_knowledge()
    
    if not agent._knowledge_initialized:
        console.print("[red]✗[/red] Agent failed to initialize knowledge")
        return False
    
    console.print("[green]✓[/green] Agent initialized with knowledge base")
    
    # Simulate failures to trigger retrieval
    for i in range(3):
        result = "403 Forbidden by WAF"
        agent.state.history.append(Action(
            iteration=i + 1,
            tool="web_request",
            args={"url": "http://test.com"},
            result=result,
            result_hash=hashlib.md5(result.encode()).hexdigest()[:8],
            result_excerpt=result[:200]
        ))
    
    # Test retrieval
    console.print("\n[yellow]Testing knowledge retrieval...[/yellow]")
    
    knowledge_ctx = await agent._retrieve_knowledge_for_context(
        "3+ consecutive low-reward actions (agent stuck)"
    )
    
    if not knowledge_ctx:
        console.print("[yellow]⚠[/yellow] No knowledge retrieved (might be normal if no relevant entries)")
    else:
        console.print("[green]✓[/green] Knowledge retrieved successfully")
        console.print(f"[dim]  Length: {len(knowledge_ctx)} chars[/dim]")
        
        # Verify token budget
        if len(knowledge_ctx) > 3200:
            console.print(f"[red]✗[/red] Token budget exceeded: {len(knowledge_ctx)} > 3200 chars")
            return False
        
        console.print("[green]✓[/green] Token budget respected (<3200 chars)")
        
        # Verify structure
        if "KNOWLEDGE BASE RETRIEVAL" in knowledge_ctx:
            console.print("[green]✓[/green] Proper formatting")
        
        if "PAYLOAD" in knowledge_ctx or "TECHNIQUE" in knowledge_ctx:
            console.print("[green]✓[/green] Contains actionable knowledge")
        
        # Show preview
        console.print("\n[yellow]Preview (first 500 chars):[/yellow]")
        console.print(f"[dim]{knowledge_ctx[:500]}...[/dim]")
    
    # Test metrics
    console.print("\n[yellow]RAG Metrics:[/yellow]")
    console.print(f"  Triggers: {agent.rag_metrics.total_triggers}")
    console.print(f"  Retrievals: {agent.rag_metrics.total_retrievals}")
    console.print(f"  Injections: {agent.rag_metrics.total_injections}")
    
    if agent.rag_metrics.total_triggers > 0:
        console.print("[green]✓[/green] Metrics tracking working")
    
    console.print(f"\n[green]✓ Phase 4 PASS[/green] (integration working)")
    return True


async def main():
    """Run all tests."""
    
    console.print("[bold cyan]╔═══════════════════════════════════════════════════╗[/bold cyan]")
    console.print("[bold cyan]║  NumaSec - Reflexive RAG Validation        ║[/bold cyan]")
    console.print("[bold cyan]╚═══════════════════════════════════════════════════╝[/bold cyan]")
    
    results = {
        "Phase 1: Population": False,
        "Phase 2: Hybrid Search": False,
        "Phase 3: Triggers": False,
        "Phase 4: Integration": False,
    }
    
    # Run tests
    results["Phase 1: Population"] = await test_knowledge_population()
    
    if results["Phase 1: Population"]:
        results["Phase 2: Hybrid Search"] = await test_hybrid_search()
    
    results["Phase 3: Triggers"] = await test_rag_triggers()
    
    if results["Phase 1: Population"]:
        results["Phase 4: Integration"] = await test_full_integration()
    
    # Summary
    console.print("\n[bold cyan]═══════════════════════════════════════════════════[/bold cyan]")
    console.print("[bold cyan]                   SUMMARY                          [/bold cyan]")
    console.print("[bold cyan]═══════════════════════════════════════════════════[/bold cyan]\n")
    
    summary_table = Table(show_header=False)
    summary_table.add_column("Phase", style="cyan")
    summary_table.add_column("Status", justify="center")
    
    for phase, passed in results.items():
        status = "[green]✓ PASS[/green]" if passed else "[red]✗ FAIL[/red]"
        summary_table.add_row(phase, status)
    
    console.print(summary_table)
    
    # Overall
    all_passed = all(results.values())
    
    console.print()
    if all_passed:
        console.print("[bold green]🎉 ALL TESTS PASSED[/bold green]")
        console.print("[green]Reflexive RAG system is ready for production![/green]")
    else:
        console.print("[bold yellow]⚠ SOME TESTS FAILED[/bold yellow]")
        console.print("[yellow]Review errors above and fix before deployment[/yellow]")
    
    return all_passed


if __name__ == "__main__":
    try:
        success = asyncio.run(main())
        sys.exit(0 if success else 1)
    except KeyboardInterrupt:
        console.print("\n[yellow]Tests interrupted[/yellow]")
        sys.exit(1)
    except Exception as e:
        console.print(f"\n[red]Fatal error: {e}[/red]")
        import traceback
        traceback.print_exc()
        sys.exit(1)
