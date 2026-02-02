"""
RAG performance metrics for monitoring and optimization.

Tracks:
- Trigger frequency and reasons
- Retrieval latency
- Knowledge usage patterns
- Impact on agent success rate

Scientific basis:
- Observability for AI systems (Anthropic, 2025)
- Metrics-driven optimization
"""

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Dict, List
import json
from pathlib import Path
import logging

logger = logging.getLogger(__name__)


@dataclass
class RAGMetrics:
    """
    Metrics for Reflexive RAG system.
    
    Tracks all aspects of knowledge retrieval to enable:
    - Performance monitoring
    - A/B testing (with/without RAG)
    - Knowledge quality assessment
    - Cost-benefit analysis
    """
    
    # Trigger metrics
    total_triggers: int = 0
    trigger_reasons: Dict[str, int] = field(default_factory=dict)
    
    # Retrieval metrics
    total_retrievals: int = 0
    successful_retrievals: int = 0
    failed_retrievals: int = 0
    avg_retrieval_time_ms: float = 0.0
    
    # Injection metrics
    total_injections: int = 0
    knowledge_used: Dict[str, int] = field(default_factory=dict)  # entry_id -> usage_count
    
    # Impact metrics
    iterations_after_rag: List[int] = field(default_factory=list)
    success_after_rag: int = 0
    failures_after_rag: int = 0
    
    # Session info
    session_start: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    
    def record_trigger(self, reason: str):
        """
        Record a trigger event.
        
        Args:
            reason: Why knowledge retrieval was triggered
        """
        self.total_triggers += 1
        self.trigger_reasons[reason] = self.trigger_reasons.get(reason, 0) + 1
        logger.info(f"🔍 RAG trigger: {reason}")
    
    def record_retrieval(self, success: bool, time_ms: float, entry_count: int):
        """
        Record a retrieval event.
        
        Args:
            success: Whether retrieval returned results
            time_ms: Retrieval latency
            entry_count: Number of entries retrieved
        """
        self.total_retrievals += 1
        
        if success:
            self.successful_retrievals += 1
        else:
            self.failed_retrievals += 1
        
        # Update running average
        if self.total_retrievals == 1:
            self.avg_retrieval_time_ms = time_ms
        else:
            self.avg_retrieval_time_ms = (
                (self.avg_retrieval_time_ms * (self.total_retrievals - 1) + time_ms) /
                self.total_retrievals
            )
        
        logger.debug(
            f"Retrieval: success={success}, time={time_ms:.1f}ms, "
            f"entries={entry_count}"
        )
    
    def record_injection(self, entry_ids: List[str]):
        """
        Record knowledge injection into context.
        
        Args:
            entry_ids: IDs of knowledge entries injected
        """
        self.total_injections += 1
        
        for entry_id in entry_ids:
            self.knowledge_used[entry_id] = self.knowledge_used.get(entry_id, 0) + 1
    
    def record_outcome_after_rag(self, iterations_to_success: int | None):
        """
        Record outcome after RAG injection.
        
        Args:
            iterations_to_success: Number of iterations until success (None if failed)
        """
        if iterations_to_success is not None:
            self.success_after_rag += 1
            self.iterations_after_rag.append(iterations_to_success)
        else:
            self.failures_after_rag += 1
    
    def get_summary(self) -> Dict:
        """
        Get metrics summary.
        
        Returns:
            Dictionary with aggregated metrics
        """
        total_outcomes = self.success_after_rag + self.failures_after_rag
        
        return {
            "triggers": {
                "total": self.total_triggers,
                "by_reason": self.trigger_reasons,
            },
            "retrievals": {
                "total": self.total_retrievals,
                "successful": self.successful_retrievals,
                "failed": self.failed_retrievals,
                "success_rate": (
                    f"{self.successful_retrievals / self.total_retrievals * 100:.1f}%"
                    if self.total_retrievals > 0 else "N/A"
                ),
                "avg_time_ms": round(self.avg_retrieval_time_ms, 2),
            },
            "injections": {
                "total": self.total_injections,
                "top_used": sorted(
                    self.knowledge_used.items(),
                    key=lambda x: x[1],
                    reverse=True
                )[:10],
            },
            "impact": {
                "success_rate": (
                    f"{self.success_after_rag / total_outcomes * 100:.1f}%"
                    if total_outcomes > 0 else "N/A"
                ),
                "avg_iterations_to_success": (
                    round(sum(self.iterations_after_rag) / len(self.iterations_after_rag), 1)
                    if self.iterations_after_rag else 0
                ),
                "total_outcomes": total_outcomes,
            },
        }
    
    def save_to_file(self, filepath: Path):
        """
        Save metrics to JSON file.
        
        Args:
            filepath: Output file path
        """
        summary = self.get_summary()
        summary["session_start"] = self.session_start
        summary["session_end"] = datetime.now(timezone.utc).isoformat()
        
        filepath.parent.mkdir(parents=True, exist_ok=True)
        
        try:
            with open(filepath, "w") as f:
                json.dump(summary, f, indent=2)
            logger.info(f"RAG metrics saved to {filepath}")
        except Exception as e:
            logger.error(f"Failed to save RAG metrics: {e}")
    
    def print_summary(self):
        """Print metrics summary to console."""
        from rich.console import Console
        from rich.table import Table
        
        console = Console()
        
        console.print("\n[bold cyan]═══════════════════════════════════════[/bold cyan]")
        console.print("[bold cyan]      Reflexive RAG Metrics             [/bold cyan]")
        console.print("[bold cyan]═══════════════════════════════════════[/bold cyan]\n")
        
        summary = self.get_summary()
        
        # Triggers table
        if self.trigger_reasons:
            trigger_table = Table(title="Trigger Statistics", show_header=True)
            trigger_table.add_column("Reason", style="cyan", no_wrap=False)
            trigger_table.add_column("Count", justify="right", style="green")
            
            for reason, count in sorted(
                self.trigger_reasons.items(),
                key=lambda x: x[1],
                reverse=True
            ):
                trigger_table.add_row(reason, str(count))
            
            console.print(trigger_table)
            console.print()
        
        # Performance metrics
        console.print("[yellow]Retrieval Performance:[/yellow]")
        console.print(f"  Total retrievals: {self.total_retrievals}")
        console.print(f"  Success rate: {summary['retrievals']['success_rate']}")
        console.print(f"  Avg latency: {self.avg_retrieval_time_ms:.1f}ms")
        console.print()
        
        # Impact metrics
        console.print("[yellow]Impact on Agent Performance:[/yellow]")
        console.print(f"  Success rate after RAG: {summary['impact']['success_rate']}")
        console.print(f"  Avg iterations to success: {summary['impact']['avg_iterations_to_success']}")
        console.print(f"  Total outcomes tracked: {summary['impact']['total_outcomes']}")
        console.print()
        
        # Top used knowledge
        if self.knowledge_used:
            console.print("[yellow]Most Used Knowledge Entries:[/yellow]")
            for entry_id, count in list(summary['injections']['top_used'])[:5]:
                console.print(f"  {entry_id}: {count} times")
        
        console.print()
