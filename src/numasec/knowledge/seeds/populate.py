"""
Knowledge base population script.

Parses markdown files from knowledge/ directory and populates LanceDB.

Usage:
    python -m numasec.knowledge.seeds.populate
    
Scientific basis:
- Domain-specific knowledge extraction
- Vector embedding for semantic search
- Hybrid indexing (BM25 + dense vectors)
"""

import asyncio
from pathlib import Path
import logging
import argparse

# Check for harvester dependencies
try:
    import aiohttp
    import aiofiles
    HARVESTER_AVAILABLE = True
except ImportError:
    HARVESTER_AVAILABLE = False

from rich.console import Console
from rich.progress import track
from rich.table import Table

from numasec.knowledge.store import KnowledgeStore
from numasec.knowledge.seeds.parsers import PayloadParser, TechniqueParser

console = Console()
logger = logging.getLogger(__name__)


async def populate_payloads(store: KnowledgeStore, knowledge_dir: Path) -> int:
    """
    Populate payloads from knowledge/payloads/*.md
    
    Args:
        store: Knowledge store instance
        knowledge_dir: Path to knowledge directory
        
    Returns:
        Number of payloads inserted
    """
    payloads_dir = knowledge_dir / "payloads"
    if not payloads_dir.exists():
        console.print(f"[yellow]Payloads directory not found: {payloads_dir}[/yellow]")
        return 0
    
    all_payloads = []
    
    md_files = list(payloads_dir.glob("*.md"))
    
    if not md_files:
        console.print("[yellow]No markdown files found in payloads/[/yellow]")
        return 0
    
    for md_file in track(
        md_files,
        description="[cyan]Parsing payload files..."
    ):
        try:
            payloads = PayloadParser.parse_file(md_file)
            all_payloads.extend(payloads)
            console.print(f"  ✓ {md_file.name}: {len(payloads)} payloads")
        except Exception as e:
            console.print(f"  ✗ {md_file.name}: {e}", style="red")
    
    # Bulk insert
    if all_payloads:
        count = await store.add_payloads(all_payloads)
        console.print(f"[green]✓ Inserted {count} payloads[/green]")
        return count
    
    return 0


async def populate_techniques(store: KnowledgeStore, knowledge_dir: Path) -> int:
    """
    Populate techniques from knowledge/*_cheatsheet.md
    
    Args:
        store: Knowledge store instance
        knowledge_dir: Path to knowledge directory
        
    Returns:
        Number of techniques inserted
    """
    all_techniques = []
    
    cheatsheet_files = list(knowledge_dir.glob("*_cheatsheet.md"))
    
    if not cheatsheet_files:
        console.print("[yellow]No cheatsheet files found[/yellow]")
        return 0
    
    for md_file in track(
        cheatsheet_files,
        description="[cyan]Parsing technique files..."
    ):
        try:
            techniques = TechniqueParser.parse_file(md_file)
            all_techniques.extend(techniques)
            console.print(f"  ✓ {md_file.name}: {len(techniques)} techniques")
        except Exception as e:
            console.print(f"  ✗ {md_file.name}: {e}", style="red")
    
    # Bulk insert
    if all_techniques:
        count = await store.add_techniques(all_techniques)
        console.print(f"[green]✓ Inserted {count} techniques[/green]")
        return count
    
    return 0


async def populate_web_payloads(store: KnowledgeStore, knowledge_dir: Path) -> int:
    """
    Populate web-specific payloads from knowledge/web/*.md
    
    Args:
        store: Knowledge store instance
        knowledge_dir: Path to knowledge directory
        
    Returns:
        Number of payloads inserted
    """
    web_dir = knowledge_dir / "web"
    if not web_dir.exists():
        return 0
    
    all_payloads = []
    
    payload_files = list(web_dir.glob("payloads_*.md"))
    
    if not payload_files:
        return 0
    
    for md_file in track(
        payload_files,
        description="[cyan]Parsing web payloads..."
    ):
        try:
            payloads = PayloadParser.parse_file(md_file)
            all_payloads.extend(payloads)
            console.print(f"  ✓ {md_file.name}: {len(payloads)} payloads")
        except Exception as e:
            console.print(f"  ✗ {md_file.name}: {e}", style="red")
    
    if all_payloads:
        count = await store.add_payloads(all_payloads)
        console.print(f"[green]✓ Inserted {count} web payloads[/green]")
        return count
    
    return 0


async def harvest_elite_sources(store: KnowledgeStore, max_payloads: int = 1000) -> int:
    """
    Harvest payloads from elite sources using the new PayloadHarvester.
    
    Args:
        store: Knowledge store instance
        max_payloads: Maximum payloads to harvest (to prevent explosion)
        
    Returns:
        Number of payloads harvested and inserted
    """
    if not HARVESTER_AVAILABLE:
        console.print("[yellow]⚠️ Harvester dependencies not available[/yellow]")
        console.print("[dim]Install with: pip install aiohttp aiofiles[/dim]")
        return 0
    
    try:
        console.print("[cyan]🚀 Starting automated payload harvesting...[/cyan]")
        
        from numasec.knowledge.harvester import PayloadHarvester
        from numasec.knowledge.seeds.advanced_payloads import ALL_ADVANCED_PAYLOADS
        
        total_inserted = 0
        
        # First, add our curated advanced payloads
        console.print("[cyan]📦 Adding advanced security payloads...[/cyan]")
        try:
            advanced_count = await store.add_payloads(ALL_ADVANCED_PAYLOADS)
            total_inserted += advanced_count
            console.print(f"[green]✅ Added {advanced_count} advanced payloads[/green]")
        except Exception as e:
            console.print(f"[yellow]⚠️ Failed to add advanced payloads: {e}[/yellow]"))
        
        # Then harvest from real-world sources
        async with PayloadHarvester() as harvester:
            harvested_entries = await harvester.harvest_all_sources(
                include_variants=True,
                max_payloads_per_source=max_payloads // 4  # Distribute across sources
            )
            
            if harvested_entries:
                # Limit total to prevent explosion
                if len(harvested_entries) > max_payloads:
                    console.print(f"[yellow]⚠️ Limiting harvested payloads to {max_payloads}[/yellow]")
                    harvested_entries = harvested_entries[:max_payloads]
                
                # Insert in batches
                batch_size = 100
                for i in range(0, len(harvested_entries), batch_size):
                    batch = harvested_entries[i:i+batch_size]
                    try:
                        count = await store.add_payloads(batch)
                        total_inserted += count
                        console.print(f"[green]✅ Batch {i//batch_size + 1}: {count} payloads[/green]")
                    except Exception as e:
                        console.print(f"[yellow]⚠️ Batch {i//batch_size + 1} failed: {e}[/yellow]")
                        continue
                
                # Print harvesting stats
                stats = harvester.get_stats()
                console.print(f"[cyan]📊 Harvesting Stats:[/cyan]")
                for source, count in stats.get('by_source', {}).items():
                    console.print(f"  {source}: {count}")
                for category, count in stats.get('by_category', {}).items():
                    console.print(f"  {category}: {count}")
                
                console.print(f"[bold green]🎯 Harvested {total_inserted} total payloads from elite sources![/bold green]")
            else:
                console.print("[yellow]⚠️ No payloads harvested from automated sources[/yellow]")
                
        return total_inserted
        
    except Exception as e:
        console.print(f"[red]❌ Automated harvesting failed: {e}[/red]")
        import traceback
        console.print(f"[dim]{traceback.format_exc()}[/dim]")
        console.print("[yellow]Continuing with manual seed files only...[/yellow]")
        return 0


async def main():
    """Main population script."""
    
    # Parse command line arguments
    parser = argparse.ArgumentParser(description="Populate NumaSec Knowledge Base")
    parser.add_argument(
        "--harvest-all", 
        action="store_true", 
        help="Enable automated harvesting from elite sources (5000+ payloads)"
    )
    parser.add_argument(
        "--max-payloads",
        type=int,
        default=1000,
        help="Maximum payloads to harvest (default: 1000)"
    )
    
    args = parser.parse_args()
    
    console.print("[bold cyan]═══════════════════════════════════════[/bold cyan]")
    console.print("[bold cyan]  NumaSec Knowledge Base Population  [/bold cyan]")
    console.print("[bold cyan]═══════════════════════════════════════[/bold cyan]")
    console.print()
    
    if args.harvest_all:
        console.print("[bold yellow]🚀 ELITE HARVESTING MODE ENABLED[/bold yellow]")
        console.print(f"[dim]Max payloads: {args.max_payloads}[/dim]")
        console.print()
    
    # Initialize store
    console.print("[yellow]Initializing LanceDB...[/yellow]")
    store = KnowledgeStore()
    
    try:
        await store.initialize()
        console.print("[green]✓ LanceDB initialized[/green]\n")
    except Exception as e:
        console.print(f"[red]✗ Failed to initialize LanceDB: {e}[/red]")
        console.print("[yellow]Make sure lancedb is installed: pip install lancedb[/yellow]")
        return
    
    # Get knowledge directory using centralized path resolution
    from numasec.knowledge.paths import get_knowledge_dir
    try:
        knowledge_dir = get_knowledge_dir()
    except RuntimeError as e:
        console.print(f"[red]Knowledge directory not found: {e}[/red]")
        console.print("[yellow]Expected structure:[/yellow]")
        console.print("  src/numasec/knowledge_data/")
        console.print("    payloads/")
        console.print("    web/")
        console.print("    *_cheatsheet.md")
        return
    
    console.print(f"[dim]Knowledge directory: {knowledge_dir}[/dim]\n")
    
    # Populate
    total_payloads = 0
    total_techniques = 0
    
    try:
        # Traditional seed file parsing
        total_payloads += await populate_payloads(store, knowledge_dir)
        total_payloads += await populate_web_payloads(store, knowledge_dir)
        total_techniques += await populate_techniques(store, knowledge_dir)
        
        # Elite source harvesting (if enabled)
        if args.harvest_all:
            console.print()
            console.print("[bold yellow]🌟 ACTIVATING ELITE SOURCE HARVESTING[/bold yellow]")
            console.print("[dim]Harvesting from: HackerOne, CVE/ExploitDB, PortSwigger, OWASP, Security Research[/dim]")
            console.print()
            
            harvested_count = await harvest_elite_sources(store, args.max_payloads)
            total_payloads += harvested_count
            
            console.print()
            if harvested_count > 0:
                console.print(f"[bold green]🎯 HARVEST COMPLETE: +{harvested_count} elite payloads added![/bold green]")
            else:
                console.print("[yellow]⚠️ Harvesting failed, continuing with seed files only[/yellow]")
                
    except Exception as e:
        console.print(f"[red]Error during population: {e}[/red]")
        import traceback
        traceback.print_exc()
        return
    
    # Show stats
    console.print()
    console.print("[bold green]═══════════════════════════════════════[/bold green]")
    console.print("[bold green]       POPULATION COMPLETE[/bold green]")
    console.print("[bold green]═══════════════════════════════════════[/bold green]")
    console.print()
    
    stats = await store.get_stats()
    
    # Create stats table
    stats_table = Table(title="Knowledge Base Statistics", show_header=True)
    stats_table.add_column("Type", style="cyan")
    stats_table.add_column("Count", justify="right", style="green")
    
    stats_table.add_row("Payloads", str(stats['payloads']))
    stats_table.add_row("Techniques", str(stats['techniques']))
    stats_table.add_row("Writeups", str(stats['writeups']))
    stats_table.add_row("Reflexions", str(stats['reflexions']))
    
    console.print(stats_table)
    console.print()
    
    # Test search if we have data
    if stats['payloads'] > 0:
        console.print("[cyan]Testing semantic search...[/cyan]")
        try:
            # Test payload search specifically
            results = await store.search_payloads("SQL injection bypass", limit=3)
            console.print(f"  Query: 'SQL injection bypass'")
            console.print(f"  Results: {len(results)}")
            
            if results:
                console.print(f"\n[green]Top result:[/green]")
                top = results[0]
                console.print(f"  Name: {top.entry.get('name', 'Unknown')[:60]}")
                console.print(f"  Category: {top.entry.get('category', 'Unknown')}")
                console.print(f"  Score: {top.score:.3f}")
                console.print(f"\n[bold green]✓ Semantic search working![/bold green]")
        except Exception as e:
            console.print(f"[red]Search test failed: {e}[/red]")
            import traceback
            console.print(f"[dim]{traceback.format_exc()}[/dim]")
    
    console.print()
    console.print("[bold green]✓ Knowledge base ready![/bold green]")
    console.print()
    console.print("[dim]Next steps:[/dim]")
    console.print("[dim]  1. Run agent with RAG enabled[/dim]")
    console.print("[dim]  2. Monitor knowledge retrieval triggers[/dim]")
    console.print("[dim]  3. Validate performance improvement[/dim]")


if __name__ == "__main__":
    asyncio.run(main())
