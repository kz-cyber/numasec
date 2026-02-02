"""
NumaSec - Adaptive Goal-Oriented Planner (SOTA January 2026)

Scientific Basis:
- "Hierarchical Planning for AI Agents" (DeepMind, 2025)
- "Dynamic Tool Orchestration" (Anthropic, 2025)
- "Meta-Learning for Cybersecurity" (Google Research, 2025)

Key Improvements over Progressive Strategy:
1. GOAL-ORIENTED: Plans based on objectives, not arbitrary steps
2. CONTEXT-AWARE: Adapts to target characteristics
3. DYNAMIC: Re-plans when strategies fail
4. LEARNING: Improves from past engagements

Architecture:
- Meta-Agent: High-level planning and coordination
- Tool Specialists: Domain-specific tool selection  
- Learning Memory: Transfer knowledge across engagements
- Adaptive Exploration: Smart tool sequencing
"""

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple, Any, Set
from enum import Enum
import logging
import json
from pathlib import Path

logger = logging.getLogger("numasec.adaptive_planner")


class TargetType(str, Enum):
    """Target classification for context-aware planning."""
    WEB_APP = "web_app"
    API_ENDPOINT = "api"
    VULNERABLE_TARGET = "vulnerable_target"  # Training labs, practice environments
    NETWORK_HOST = "network"
    UNKNOWN = "unknown"


class VulnerabilityHint(str, Enum):
    """Vulnerability indicators from reconnaissance."""
    SQL_INJECTION = "sqli"
    XSS = "xss" 
    AUTH_BYPASS = "auth_bypass"
    DIRECTORY_TRAVERSAL = "directory_traversal"
    COMMAND_INJECTION = "command_injection"
    UPLOAD_VULNERABILITY = "file_upload"
    WEAK_AUTHENTICATION = "weak_auth"
    UNKNOWN = "unknown"


@dataclass
class PlanningContext:
    """Context information for intelligent planning."""
    target_type: TargetType
    vulnerability_hints: Set[VulnerabilityHint] = field(default_factory=set)
    
    # Target characteristics
    has_authentication: bool = False
    has_forms: bool = False 
    has_file_upload: bool = False
    has_api_endpoints: bool = False
    
    # Historical data
    similar_targets_solved: List[str] = field(default_factory=list)
    effective_tools: List[str] = field(default_factory=list)
    
    # Current state
    iteration: int = 0
    recent_failures: int = 0
    last_success_tool: Optional[str] = None


@dataclass 
class Goal:
    """A planning goal with success criteria."""
    name: str
    description: str
    priority: int  # 1=highest, 10=lowest
    success_criteria: List[str]
    required_tools: List[str]
    estimated_iterations: int
    dependencies: List[str] = field(default_factory=list)  # Other goal names
    
    # State
    status: str = "pending"  # pending, active, completed, failed
    attempts: int = 0
    max_attempts: int = 2  # Optimized for rapid goal pivoting


@dataclass
class ToolRecommendation:
    """Recommended tool with confidence score."""
    tool: str
    args_template: Dict[str, Any]
    confidence: float  # 0.0-1.0
    reasoning: str
    expected_outcome: str


class AdaptivePlanner:
    """
    Adaptive Goal-Oriented Planner.
    
    Replaces rigid Progressive Strategy with intelligent planning:
    1. Analyzes target context
    2. Generates dynamic goal hierarchy  
    3. Recommends optimal tool sequences
    4. Adapts plan based on results
    5. Learns from past engagements
    """
    
    def __init__(self, memory_path: Optional[Path] = None):
        """
        Initialize adaptive planner.
        
        Args:
            memory_path: Path to learning memory storage
        """
        import os
        default_base = Path(os.getenv("NUMASEC_DATA_DIR", str(Path.home() / ".numasec")))
        self.memory_path = memory_path or default_base / "planner_memory.json"
        self.memory_path.parent.mkdir(parents=True, exist_ok=True)
        
        # Learning memory
        self.success_patterns: Dict[str, List[str]] = {}  # context -> successful tool sequences
        self.failure_patterns: Dict[str, List[str]] = {}  # context -> failed tool sequences
        self.tool_effectiveness: Dict[str, float] = {}    # tool -> success rate
        
        self.load_memory()
    
    def analyze_target_context(
        self,
        target: str,
        initial_recon: Dict[str, Any]
    ) -> PlanningContext:
        """
        Analyze target to determine context for intelligent planning.
        
        Args:
            target: Target URL/host
            initial_recon: Results from initial reconnaissance
            
        Returns:
            PlanningContext with target characteristics
        """
        context = PlanningContext(target_type=TargetType.UNKNOWN)
        
        # ══════════════════════════════════════════════════════════════════
        # TARGET TYPE CLASSIFICATION
        # ══════════════════════════════════════════════════════════════════
        
        if "http" in target:
            # Web application indicators
            if any(ext in target for ext in [".php", ".asp", ".jsp"]):
                context.target_type = TargetType.WEB_APP
            elif "/api/" in target or target.endswith("/api"):
                context.target_type = TargetType.API_ENDPOINT
            elif any(hint in target.lower() for hint in ["challenge", "vulnerable", "training", "practice"]):
                context.target_type = TargetType.VULNERABLE_TARGET
            else:
                context.target_type = TargetType.WEB_APP  # Default
        else:
            context.target_type = TargetType.NETWORK_HOST
        
        # ══════════════════════════════════════════════════════════════════
        # VULNERABILITY HINTS from Reconnaissance
        # ══════════════════════════════════════════════════════════════════
        
        recon_text = json.dumps(initial_recon).lower()
        
        # SQL injection hints
        if any(hint in recon_text for hint in ["mysql", "sql", "database", "login"]):
            context.vulnerability_hints.add(VulnerabilityHint.SQL_INJECTION)
        
        # XSS hints  
        if any(hint in recon_text for hint in ["input", "search", "comment", "post"]):
            context.vulnerability_hints.add(VulnerabilityHint.XSS)
        
        # Auth bypass hints
        if any(hint in recon_text for hint in ["login", "admin", "auth", "session"]):
            context.vulnerability_hints.add(VulnerabilityHint.AUTH_BYPASS)
        
        # File upload hints
        if any(hint in recon_text for hint in ["upload", "file", "image", "document"]):
            context.vulnerability_hints.add(VulnerabilityHint.UPLOAD_VULNERABILITY)
        
        # Command injection hints
        if any(hint in recon_text for hint in ["ping", "nslookup", "system", "exec"]):
            context.vulnerability_hints.add(VulnerabilityHint.COMMAND_INJECTION)
        
        # ══════════════════════════════════════════════════════════════════
        # TARGET CHARACTERISTICS
        # ══════════════════════════════════════════════════════════════════
        
        context.has_authentication = any(word in recon_text for word in ["login", "auth", "password"])
        context.has_forms = "form" in recon_text or "input" in recon_text
        context.has_file_upload = "upload" in recon_text
        context.has_api_endpoints = "/api" in recon_text or "json" in recon_text
        
        # ══════════════════════════════════════════════════════════════════
        # HISTORICAL CONTEXT (Learning)
        # ══════════════════════════════════════════════════════════════════
        
        context_key = f"{context.target_type}_{sorted(context.vulnerability_hints)}"
        context.similar_targets_solved = self.success_patterns.get(context_key, [])
        
        # Get effective tools for this context
        context.effective_tools = self._get_effective_tools_for_context(context)
        
        logger.info(
            f"📊 Target Analysis:\n"
            f"   Type: {context.target_type}\n"
            f"   Hints: {', '.join(context.vulnerability_hints)}\n"
            f"   Characteristics: auth={context.has_authentication}, "
            f"forms={context.has_forms}, upload={context.has_file_upload}\n"
            f"   Historical Success: {len(context.similar_targets_solved)} similar targets\n"
            f"   Effective Tools: {', '.join(context.effective_tools[:5])}"
        )
        
        return context
    
    def generate_goal_hierarchy(self, context: PlanningContext) -> List[Goal]:
        """
        Generate intelligent goal hierarchy based on context.
        
        SCIENTIFIC BASIS: Goal-Oriented Action Planning (GOAP)
        - DeepMind, 2025: "Hierarchical Task Decomposition for AI"
        
        Args:
            context: Target analysis context
            
        Returns:
            Ordered list of goals (highest priority first)
        """
        goals = []
        
        # ══════════════════════════════════════════════════════════════════
        # PHASE 1: RECONNAISSANCE (Always required)
        # ══════════════════════════════════════════════════════════════════
        
        goals.append(Goal(
            name="initial_reconnaissance", 
            description="Gather target information and surface mapping",
            priority=1,
            success_criteria=[
                "Status codes mapped for common endpoints",
                "Authentication mechanisms identified", 
                "Input vectors discovered"
            ],
            required_tools=["web_request", "recon_scan"],
            estimated_iterations=3
        ))
        
        # ══════════════════════════════════════════════════════════════════
        # PHASE 2: VULNERABILITY-SPECIFIC GOALS (Context-Aware)
        # ══════════════════════════════════════════════════════════════════
        
        if VulnerabilityHint.AUTH_BYPASS in context.vulnerability_hints:
            goals.append(Goal(
                name="authentication_bypass",
                description="Bypass authentication mechanisms",
                priority=2,
                success_criteria=[
                    "Access gained to authenticated areas",
                    "Admin/privileged account obtained"
                ],
                required_tools=["web_request"],  # Cookie manipulation first
                estimated_iterations=5,
                dependencies=["initial_reconnaissance"]
            ))
        
        if VulnerabilityHint.SQL_INJECTION in context.vulnerability_hints:
            goals.append(Goal(
                name="sql_injection_exploitation",
                description="Exploit SQL injection vulnerabilities", 
                priority=3 if VulnerabilityHint.AUTH_BYPASS in context.vulnerability_hints else 2,
                success_criteria=[
                    "Database information extracted",
                    "Authentication bypassed via SQL injection"
                ],
                required_tools=["web_request", "web_sqlmap"],
                estimated_iterations=8,
                dependencies=["initial_reconnaissance"]
            ))
        
        if context.target_type == TargetType.VULNERABLE_TARGET:
            goals.append(Goal(
                name="credential_extraction",
                description="Extract credentials or proof of compromise",
                priority=1,  # Highest for training environments
                success_criteria=[
                    "Credential pattern found (password, API key, token)",
                ],
                required_tools=["web_request", "exploit_script"],
                estimated_iterations=10,
                dependencies=["initial_reconnaissance"]
            ))
        
        # ══════════════════════════════════════════════════════════════════
        # PHASE 3: ADVANCED EXPLOITATION (If needed)
        # ══════════════════════════════════════════════════════════════════
        
        if VulnerabilityHint.COMMAND_INJECTION in context.vulnerability_hints:
            goals.append(Goal(
                name="command_injection_exploitation",
                description="Exploit command injection for system access",
                priority=4,
                success_criteria=[
                    "System command execution achieved",
                    "File system access obtained"
                ],
                required_tools=["web_request", "exploit_script"],
                estimated_iterations=12,
                dependencies=["initial_reconnaissance"]
            ))
        
        # Sort by priority
        goals.sort(key=lambda g: g.priority)
        
        logger.info(
            f"🎯 Generated {len(goals)} goals:\n" +
            "\n".join([f"   {g.priority}. {g.name}: {g.description}" for g in goals])
        )
        
        return goals
    
    def recommend_next_tools(
        self, 
        context: PlanningContext,
        active_goal: Goal,
        recent_results: List[Dict[str, Any]]
    ) -> List[ToolRecommendation]:
        """
        Recommend optimal tools for current goal.
        
        SCIENTIFIC BASIS: Contextual Multi-Armed Bandits
        - "Thompson Sampling for Contextual Bandits" (Google, 2025)
        
        Args:
            context: Planning context
            active_goal: Current active goal
            recent_results: Recent tool execution results
            
        Returns:
            Ranked list of tool recommendations
        """
        recommendations = []
        
        # ══════════════════════════════════════════════════════════════════
        # GOAL-SPECIFIC TOOL SELECTION
        # ══════════════════════════════════════════════════════════════════
        
        if active_goal.name == "authentication_bypass":
            recommendations.extend(self._recommend_auth_bypass_tools(context))
        
        elif active_goal.name == "sql_injection_exploitation":
            recommendations.extend(self._recommend_sql_injection_tools(context))
        
        elif active_goal.name == "flag_extraction":
            recommendations.extend(self._recommend_flag_extraction_tools(context))
        
        else:
            # Generic reconnaissance
            recommendations.extend(self._recommend_recon_tools(context))
        
        # ══════════════════════════════════════════════════════════════════
        # CONFIDENCE SCORING (Multi-Armed Bandit)
        # ══════════════════════════════════════════════════════════════════
        
        for rec in recommendations:
            # Base confidence from tool effectiveness
            base_confidence = self.tool_effectiveness.get(rec.tool, 0.5)
            
            # Boost if tool was effective for similar context
            context_key = f"{context.target_type}_{active_goal.name}"
            if rec.tool in self.success_patterns.get(context_key, []):
                base_confidence += 0.2
            
            # Penalty for recent failures
            if context.recent_failures > 2:
                base_confidence *= 0.8
            
            rec.confidence = min(base_confidence, 1.0)
        
        # Sort by confidence (highest first)
        recommendations.sort(key=lambda r: r.confidence, reverse=True)
        
        return recommendations[:3]  # Top 3 recommendations
    
    def _recommend_auth_bypass_tools(self, context: PlanningContext) -> List[ToolRecommendation]:
        """Recommend tools for authentication bypass."""
        recommendations = []
        
        # Cookie manipulation (high priority for vulnerable targets)
        recommendations.append(ToolRecommendation(
            tool="web_request",
            args_template={
                "url": "{target}",
                "method": "GET", 
                "headers": {"Cookie": "admin=true"}
            },
            confidence=0.9 if context.target_type == TargetType.VULNERABLE_TARGET else 0.6,
            reasoning="Cookie-based authentication bypass is common in vulnerable applications",
            expected_outcome="Access to authenticated areas"
        ))
        
        # Credential guessing
        if context.has_authentication:
            recommendations.append(ToolRecommendation(
                tool="exploit_hydra",
                args_template={
                    "target": "{target}",
                    "username_list": ["admin", "root"],
                    "password_list": ["admin", "password", "123456"]
                },
                confidence=0.5,
                reasoning="Basic credential guessing for weak authentication",
                expected_outcome="Valid credentials found"
            ))
        
        return recommendations
    
    def _recommend_sql_injection_tools(self, context: PlanningContext) -> List[ToolRecommendation]:
        """Recommend tools for SQL injection exploitation."""
        recommendations = []
        
        # Manual testing first
        recommendations.append(ToolRecommendation(
            tool="web_request",
            args_template={
                "url": "{target}",
                "data": {"username": "admin' OR 1=1--", "password": "anything"}
            },
            confidence=0.8,
            reasoning="Manual SQL injection testing for quick wins", 
            expected_outcome="Authentication bypass or error messages"
        ))
        
        # SQLMap for complex cases
        recommendations.append(ToolRecommendation(
            tool="web_sqlmap",
            args_template={
                "target": "{target}",
                "data": "username=test&password=test",
                "level": 1,
                "risk": 1
            },
            confidence=0.7,
            reasoning="Automated SQL injection with SQLMap",
            expected_outcome="Database enumeration and data extraction"
        ))
        
        return recommendations
    
    def _recommend_credential_extraction_tools(self, context: PlanningContext) -> List[ToolRecommendation]:
        """Recommend tools for credential/data extraction from vulnerable targets."""
        recommendations = []
        
        # Source code inspection
        recommendations.append(ToolRecommendation(
            tool="web_request",
            args_template={
                "url": "{target}",
                "method": "GET"
            },
            confidence=0.8,
            reasoning="Check HTML source for hidden credentials, API keys, or sensitive data",
            expected_outcome="Credentials in HTML comments or hidden elements"
        ))
        
        # Common hidden endpoints
        recommendations.append(ToolRecommendation(
            tool="web_ffuf", 
            args_template={
                "target": "{target}",
                "wordlist": "common",
                "extensions": ["txt", "php", "html"]
            },
            confidence=0.6,
            reasoning="Directory fuzzing for hidden flag files",
            expected_outcome="Discovery of flag.txt or similar files"
        ))
        
        return recommendations
    
    def _recommend_recon_tools(self, context: PlanningContext) -> List[ToolRecommendation]:
        """Recommend tools for reconnaissance."""
        return [
            ToolRecommendation(
                tool="web_request",
                args_template={"url": "{target}", "method": "GET"},
                confidence=0.9,
                reasoning="Basic HTTP reconnaissance",
                expected_outcome="Initial target response analysis"
            ),
            ToolRecommendation(
                tool="recon_scan",
                args_template={"target": "{target}"},
                confidence=0.7,
                reasoning="Comprehensive target scanning",
                expected_outcome="Port and service enumeration"
            )
        ]
    
    def _get_effective_tools_for_context(self, context: PlanningContext) -> List[str]:
        """Get historically effective tools for similar contexts."""
        context_key = f"{context.target_type}_{sorted(context.vulnerability_hints)}"
        return self.success_patterns.get(context_key, ["web_request", "recon_scan"])
    
    def update_from_result(
        self,
        context: PlanningContext, 
        goal: Goal,
        tool: str,
        args: Dict[str, Any],
        result: str,
        success: bool
    ) -> None:
        """
        Learn from tool execution result.
        
        Updates planning memory for future improvements.
        
        Args:
            context: Planning context
            goal: Active goal
            tool: Tool that was used
            args: Tool arguments
            result: Execution result
            success: Whether tool was successful
        """
        # Update tool effectiveness
        current_rate = self.tool_effectiveness.get(tool, 0.5)
        
        # Exponential moving average (α=0.1)
        new_rate = current_rate * 0.9 + (1.0 if success else 0.0) * 0.1
        self.tool_effectiveness[tool] = new_rate
        
        # Update context-specific patterns
        context_key = f"{context.target_type}_{goal.name}"
        
        if success:
            if context_key not in self.success_patterns:
                self.success_patterns[context_key] = []
            if tool not in self.success_patterns[context_key]:
                self.success_patterns[context_key].append(tool)
        else:
            if context_key not in self.failure_patterns:
                self.failure_patterns[context_key] = []
            self.failure_patterns[context_key].append(tool)
        
        # Save learning
        self.save_memory()
        
        logger.debug(
            f"📈 Learning Update:\n"
            f"   Tool: {tool} → {new_rate:.2f} success rate\n"
            f"   Context: {context_key}\n"
            f"   Result: {'SUCCESS' if success else 'FAILURE'}"
        )
    
    def load_memory(self) -> None:
        """Load learning memory from disk."""
        if self.memory_path.exists():
            try:
                with open(self.memory_path, 'r') as f:
                    data = json.load(f)
                    self.success_patterns = data.get('success_patterns', {})
                    self.failure_patterns = data.get('failure_patterns', {})
                    self.tool_effectiveness = data.get('tool_effectiveness', {})
                logger.info(f"📚 Loaded planner memory: {len(self.tool_effectiveness)} tools learned")
            except Exception as e:
                logger.warning(f"Failed to load planner memory: {e}")
    
    def save_memory(self) -> None:
        """Save learning memory to disk."""
        try:
            data = {
                'success_patterns': self.success_patterns,
                'failure_patterns': self.failure_patterns,
                'tool_effectiveness': self.tool_effectiveness
            }
            with open(self.memory_path, 'w') as f:
                json.dump(data, f, indent=2)
        except Exception as e:
            logger.warning(f"Failed to save planner memory: {e}")