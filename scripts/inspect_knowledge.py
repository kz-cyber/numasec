#!/usr/bin/env python3
"""
Inspect knowledge base contents.

Usage:
    python scripts/inspect_knowledge.py [query]

Examples:
    python scripts/inspect_knowledge.py "SQL injection"
    python scripts/inspect_knowledge.py "command bypass"
"""

import asyncio
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from rich.console import Console
from rich.table import Table
from rich.panel import Panel

console = Console()


async def main():
    """Main function."""
    
    from numasec.knowledge.store import KnowledgeStore
    
    # Get query from args
    query = " ".join(sys.argv[1:]) if len(sys.argv) > 1 else None
    
    console.print("[bold cyan]NumaSec Knowledge Base Inspector[/bold cyan]\n")
    
    # Initialize
    store = KnowledgeStore()
    
    try:
        await store.initialize()
    except Exception as e:
        console.print(f"[red]Error: {e}[/red]")
        return
    
    # Get stats
    stats = await store.get_stats()
    
    console.print("[yellow]Knowledge Base Statistics:[/yellow]")
    console.print(f"  Payloads:   {stats['payloads']}")
    console.print(f"  Techniques: {stats['techniques']}")
    console.print(f"  Writeups:   {stats['writeups']}")
    console.print(f"  Reflexions: {stats['reflexions']}")
    console.print()
    
    if stats['payloads'] == 0 and stats['techniques'] == 0:
        console.print("[yellow]Knowledge base is empty![/yellow]")
        console.print("Run: python -m numasec.knowledge.seeds.populate")
        return
    
    # If query provided, search
    if query:
        console.print(f"[cyan]Searching for: '{query}'[/cyan]\n")
        
        results = await store.search_hybrid(
            query=query,
            entry_types=["payload", "technique"],
            limit=10,
            alpha=0.6
        )
        
        console.print(f"[green]Found {results.total_count} results in {results.search_time_ms:.1f}ms[/green]\n")
        
        # Display results
        for i, result in enumerate(results.results[:5], 1):
            entry = result.entry
            
            if result.entry_type == "payload":
                title = f"{i}. PAYLOAD: {entry.get('name', 'Unknown')}"
                content_lines = [
                    f"[yellow]Score:[/yellow] {result.score:.3f}",
                    f"[yellow]Category:[/yellow] {entry.get('category', 'Unknown')}",
                    f"[yellow]Payload:[/yellow] {entry.get('payload', '')[:200]}",
                ]
                if entry.get('use_case'):
                    content_lines.append(f"[yellow]Use:[/yellow] {entry.get('use_case')}")
                
                panel = Panel(
                    "\n".join(content_lines),
                    title=title,
                    border_style="cyan"
                )
                console.print(panel)
            
            elif result.entry_type == "technique":
                title = f"{i}. TECHNIQUE: {entry.get('name', 'Unknown')}"
                content_lines = [
                    f"[yellow]Score:[/yellow] {result.score:.3f}",
                    f"[yellow]Category:[/yellow] {entry.get('category', 'Unknown')}",
                    f"[yellow]Description:[/yellow] {entry.get('description', '')[:150]}",
                ]
                
                steps = entry.get('steps', [])
                if steps:
                    content_lines.append(f"[yellow]Steps:[/yellow]")
                    for j, step in enumerate(steps[:3], 1):
                        content_lines.append(f"  {j}. {step[:80]}")
                
                panel = Panel(
                    "\n".join(content_lines),
                    title=title,
                    border_style="green"
                )
                console.print(panel)
    
    else:
        # No query - show samples
        console.print("[yellow]Sample Payloads:[/yellow]\n")
        
        # Get first 5 payloads
        sample_results = await store.search("injection", entry_types=["payload"], limit=5)
        
        for i, result in enumerate(sample_results.results, 1):
            entry = result.entry
            console.print(f"{i}. {entry.get('name', 'Unknown')}")
            console.print(f"   Category: {entry.get('category', 'Unknown')}")
            console.print(f"   Payload: {entry.get('payload', '')[:80]}...")
            console.print()
        
        console.print("\n[dim]Usage: python scripts/inspect_knowledge.py \"your search query\"[/dim]")


if __name__ == "__main__":
    asyncio.run(main())
