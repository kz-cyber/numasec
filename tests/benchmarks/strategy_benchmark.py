"""
Performance Benchmark: Progressive Strategy vs Unified Adaptive Strategy

SCIENTIFIC VALIDATION (January 2026)

This benchmark demonstrates the performance improvements of the Unified Adaptive Strategy
over the original Progressive Strategy system.
"""

import time
import asyncio
from typing import Dict, List, Any
from dataclasses import dataclass
from pathlib import Path

# Import both strategies
from numasec.agent.progressive_strategy import StrategyEscalation  # Old
from numasec.agent.unified_adaptive_strategy import UnifiedAdaptiveStrategy  # New


@dataclass
class BenchmarkResult:
    """Results from strategy benchmark."""
    strategy_name: str
    iterations_to_success: int
    tool_calls_made: int
    successful_tool_calls: int
    failed_tool_calls: int
    blocked_tools: int  # Tools blocked by strategy
    time_elapsed_ms: float
    
    @property
    def success_rate(self) -> float:
        """Tool selection success rate."""
        total = self.successful_tool_calls + self.failed_tool_calls
        return self.successful_tool_calls / max(total, 1)
    
    @property
    def efficiency(self) -> float:
        """Iterations per successful tool call."""
        return self.iterations_to_success / max(self.successful_tool_calls, 1)


class StrategyBenchmark:
    """Benchmark both strategies on simulated CTF scenarios."""
    
    def __init__(self):
        """Initialize benchmark scenarios."""
        # Test scenarios based on real CTF challenges
        self.scenarios = [
            {
                "name": "picoCTF Cookie Auth Bypass",
                "target": "http://jupiter.challenges.picoctf.org:12345",
                "objective": "Extract flag via authentication bypass",
                "recon_results": {
                    "status_code": 200,
                    "body": "Login form detected. Admin panel referenced.",
                    "cookies": ["sessionid=abc123"],
                    "forms": ["login"],
                    "hints": ["Check for simple auth bypass"]
                },
                "optimal_sequence": [
                    ("web_request", {"headers": {"Cookie": "admin=true"}}, True),  # Immediate success
                ],
                "optimal_iterations": 1
            },
            {
                "name": "SQL Injection Login Bypass",
                "target": "http://ctf.example.com/login",
                "objective": "Bypass login via SQL injection",
                "recon_results": {
                    "status_code": 200,
                    "body": "MySQL database detected. Login form with username/password.",
                    "technology": "PHP/MySQL",
                    "forms": ["login"],
                    "parameters": ["username", "password"]
                },
                "optimal_sequence": [
                    ("web_request", {"data": {"username": "admin", "password": "password"}}, False),
                    ("web_request", {"data": {"username": "admin' OR 1=1--", "password": "x"}}, True),
                ],
                "optimal_iterations": 2
            },
            {
                "name": "Directory Traversal Challenge", 
                "target": "http://ctf.example.com/files",
                "objective": "Extract flag via directory traversal",
                "recon_results": {
                    "status_code": 200,
                    "body": "File browser application. Parameter: file",
                    "parameters": ["file"],
                    "hints": ["Files stored in /var/www/html"]
                },
                "optimal_sequence": [
                    ("web_request", {"params": {"file": "index.php"}}, False),
                    ("web_request", {"params": {"file": "../../etc/passwd"}}, False),
                    ("web_ffuf", {"target": "{target}", "wordlist": "common"}, True),
                    ("web_request", {"params": {"file": "../../../../flag.txt"}}, True),
                ],
                "optimal_iterations": 4
            }
        ]
    
    async def run_benchmark(self) -> Dict[str, List[BenchmarkResult]]:
        """
        Run benchmark comparing both strategies.
        
        Returns:
            Dictionary mapping scenario names to [progressive_result, adaptive_result]
        """
        results = {}
        
        print("🔬 STRATEGY BENCHMARK - Progressive vs Adaptive")
        print("=" * 60)
        
        for scenario in self.scenarios:
            print(f"\n📋 Scenario: {scenario['name']}")
            print("-" * 40)
            
            # Test Progressive Strategy
            progressive_result = await self._test_progressive_strategy(scenario)
            
            # Test Adaptive Strategy  
            adaptive_result = await self._test_adaptive_strategy(scenario)
            
            results[scenario['name']] = [progressive_result, adaptive_result]
            
            # Print comparison
            self._print_comparison(progressive_result, adaptive_result, scenario['optimal_iterations'])
        
        # Print overall summary
        self._print_summary(results)
        
        return results
    
    async def _test_progressive_strategy(self, scenario: Dict) -> BenchmarkResult:
        """Test Progressive Strategy on scenario."""
        start_time = time.time()
        
        strategy = StrategyEscalation()
        
        iterations = 0
        successful_tools = 0
        failed_tools = 0
        blocked_tools = 0
        
        # Simulate tool execution following Progressive Strategy rules
        for iteration in range(1, 51):  # Max 50 iterations
            iterations = iteration
            
            # Get current strategy level
            current_strategy = strategy.get_current_strategy(iteration)
            
            # Determine optimal tool for this iteration
            optimal_tools = self._get_optimal_tools_for_iteration(scenario, iteration)
            
            tool_selected = None
            for tool in optimal_tools:
                # Check if tool is allowed
                allowed, reason = strategy.validate_tool_use(tool, iteration)
                if allowed:
                    tool_selected = tool
                    break
                else:
                    blocked_tools += 1
            
            if not tool_selected:
                # Use first allowed tool from current level
                allowed_tools = current_strategy.get("allowed_tools", [])
                if allowed_tools and allowed_tools[0] != "*":
                    tool_selected = allowed_tools[0]
                else:
                    tool_selected = "web_request"  # Fallback
            
            # Simulate tool execution
            success = self._simulate_tool_execution(scenario, tool_selected, iteration)
            
            if success:
                successful_tools += 1
                # Check if we achieved the objective
                if self._check_objective_achieved(scenario, tool_selected, iteration):
                    break
            else:
                failed_tools += 1
        
        elapsed_ms = (time.time() - start_time) * 1000
        
        return BenchmarkResult(
            strategy_name="Progressive Strategy",
            iterations_to_success=iterations,
            tool_calls_made=successful_tools + failed_tools,
            successful_tool_calls=successful_tools,
            failed_tool_calls=failed_tools,
            blocked_tools=blocked_tools,
            time_elapsed_ms=elapsed_ms
        )
    
    async def _test_adaptive_strategy(self, scenario: Dict) -> BenchmarkResult:
        """Test Unified Adaptive Strategy on scenario."""
        start_time = time.time()
        
        strategy = UnifiedAdaptiveStrategy()
        
        # Initialize strategy with scenario
        await strategy.initialize_engagement(
            target=scenario["target"],
            objective=scenario["objective"],
            initial_recon=scenario["recon_results"]
        )
        
        iterations = 0
        successful_tools = 0
        failed_tools = 0
        blocked_tools = 0
        recent_results = []
        
        # Simulate tool execution following Adaptive Strategy
        for iteration in range(1, 51):  # Max 50 iterations
            iterations = iteration
            
            # Get tool recommendation
            recommendation = await strategy.get_next_tool_recommendation(recent_results, iteration)
            
            if not recommendation:
                break  # Strategy believes objective is achieved
            
            tool, args, reasoning = recommendation
            
            # Simulate tool execution
            success = self._simulate_tool_execution(scenario, tool, iteration)
            result = "Success: Found flag picoCTF{test}" if success else "Failed: No result"
            
            # Update strategy
            await strategy.update_from_result(tool, args, result, success, iteration)
            
            recent_results.append({
                "tool": tool,
                "success": success,
                "result": result,
                "iteration": iteration
            })
            
            # Keep recent results manageable
            if len(recent_results) > 5:
                recent_results = recent_results[-5:]
            
            if success:
                successful_tools += 1
                # Check if objective achieved
                if self._check_objective_achieved(scenario, tool, iteration):
                    break
            else:
                failed_tools += 1
        
        elapsed_ms = (time.time() - start_time) * 1000
        
        return BenchmarkResult(
            strategy_name="Unified Adaptive Strategy",
            iterations_to_success=iterations,
            tool_calls_made=successful_tools + failed_tools,
            successful_tool_calls=successful_tools,
            failed_tool_calls=failed_tools,
            blocked_tools=blocked_tools,  # Adaptive doesn't block tools arbitrarily
            time_elapsed_ms=elapsed_ms
        )
    
    def _get_optimal_tools_for_iteration(self, scenario: Dict, iteration: int) -> List[str]:
        """Get optimal tools for current iteration of scenario."""
        optimal_sequence = scenario["optimal_sequence"]
        
        if iteration <= len(optimal_sequence):
            return [optimal_sequence[iteration - 1][0]]
        else:
            # Return generally useful tools
            return ["web_request", "web_ffuf", "web_sqlmap"]
    
    def _simulate_tool_execution(self, scenario: Dict, tool: str, iteration: int) -> bool:
        """Simulate tool execution and determine success."""
        optimal_sequence = scenario["optimal_sequence"]
        
        # Check if this tool is part of the optimal sequence
        for seq_iteration, (optimal_tool, args, expected_success) in enumerate(optimal_sequence, 1):
            if iteration == seq_iteration and tool == optimal_tool:
                return expected_success
        
        # For non-optimal tools, lower success probability
        if tool in ["web_request", "recon_scan"]:
            return iteration <= 3  # Basic tools work early
        elif tool in ["web_ffuf", "web_nuclei"]:
            return iteration >= 5 and iteration <= 15  # Discovery tools work mid-game
        elif tool in ["web_sqlmap", "exploit_script"]:
            return iteration >= 10  # Advanced tools work later
        
        return False  # Unknown tools generally fail
    
    def _check_objective_achieved(self, scenario: Dict, tool: str, iteration: int) -> bool:
        """Check if scenario objective has been achieved."""
        # Check if we hit the exact optimal solution
        optimal_iterations = scenario["optimal_iterations"]
        optimal_sequence = scenario["optimal_sequence"]
        
        if iteration == optimal_iterations:
            # Check if we executed the winning tool
            if iteration <= len(optimal_sequence):
                winning_tool, _, success = optimal_sequence[iteration - 1]
                return tool == winning_tool and success
        
        return False
    
    def _print_comparison(self, progressive: BenchmarkResult, adaptive: BenchmarkResult, optimal: int):
        """Print comparison of results."""
        print(f"Progressive Strategy:")
        print(f"  Iterations: {progressive.iterations_to_success} (optimal: {optimal})")
        print(f"  Success Rate: {progressive.success_rate:.2%}")
        print(f"  Blocked Tools: {progressive.blocked_tools}")
        print(f"  Efficiency: {progressive.efficiency:.1f} iterations/success")
        
        print(f"\nAdaptive Strategy:")
        print(f"  Iterations: {adaptive.iterations_to_success} (optimal: {optimal})")
        print(f"  Success Rate: {adaptive.success_rate:.2%}")
        print(f"  Blocked Tools: {adaptive.blocked_tools}")
        print(f"  Efficiency: {adaptive.efficiency:.1f} iterations/success")
        
        # Calculate improvements
        iteration_improvement = (
            (progressive.iterations_to_success - adaptive.iterations_to_success) /
            max(progressive.iterations_to_success, 1) * 100
        )
        
        success_improvement = (
            (adaptive.success_rate - progressive.success_rate) * 100
        )
        
        print(f"\n🚀 Improvements:")
        print(f"  Iterations: {iteration_improvement:+.1f}%")
        print(f"  Success Rate: {success_improvement:+.1f}%")
        print(f"  Blocked Tools: {progressive.blocked_tools - adaptive.blocked_tools:+d}")
    
    def _print_summary(self, results: Dict[str, List[BenchmarkResult]]):
        """Print overall benchmark summary."""
        print("\n" + "=" * 60)
        print("🏆 BENCHMARK SUMMARY")
        print("=" * 60)
        
        progressive_total = 0
        adaptive_total = 0
        progressive_blocked = 0
        adaptive_blocked = 0
        
        for scenario_name, (progressive, adaptive) in results.items():
            progressive_total += progressive.iterations_to_success
            adaptive_total += adaptive.iterations_to_success
            progressive_blocked += progressive.blocked_tools
            adaptive_blocked += adaptive.blocked_tools
        
        total_improvement = (
            (progressive_total - adaptive_total) / max(progressive_total, 1) * 100
        )
        
        print(f"Overall Iteration Reduction: {total_improvement:.1f}%")
        print(f"Blocked Tools Eliminated: {progressive_blocked - adaptive_blocked}")
        
        if total_improvement > 30:
            print("\n✅ VALIDATION: Adaptive Strategy significantly outperforms Progressive Strategy")
            print("   Recommendation: DEPLOY immediately")
        elif total_improvement > 10:
            print("\n🟡 VALIDATION: Adaptive Strategy shows improvement")
            print("   Recommendation: A/B test in production")
        else:
            print("\n🔴 VALIDATION: No significant improvement")
            print("   Recommendation: Further optimization needed")


# Run benchmark if executed directly
async def main():
    benchmark = StrategyBenchmark()
    results = await benchmark.run_benchmark()
    
    print(f"\n📊 Raw Results:")
    for scenario, (prog, adapt) in results.items():
        print(f"{scenario}: {prog.iterations_to_success} → {adapt.iterations_to_success}")


if __name__ == "__main__":
    asyncio.run(main())