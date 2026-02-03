"""
NumaSec - Batch Suggester

SOTA 2026: Proactive batching suggestions to LLM for parallel execution.

Problem: LLMs naturally call 1 tool at a time unless explicitly prompted.
Solution: Inject batch suggestions into prompts when patterns detected.

Scientific Basis:
- Prompt Engineering (OpenAI, 2023): Structure prompts for desired behavior
- Few-Shot Learning (Brown et al., 2020): Show examples to guide behavior
- Contextual Priming (Google DeepMind, 2025): Prime LLM with batch patterns
"""

import re
from typing import Optional


class BatchSuggester:
    """
    Intelligently suggests tool batches to LLM for parallel execution.
    
    Patterns detected:
    1. "reconnaissance" / "recon" / "scan" → Suggest nmap+httpx+whatweb
    2. "enumerate" / "discover" → Suggest subdomain+dns+httpx
    3. New target mentioned → Suggest comprehensive recon batch
    
    Output: Injected system message priming LLM to use parallel calls.
    """
    
    def detect_recon_intent(self, user_input: str, context: dict) -> Optional[str]:
        """
        Detect if user is requesting reconnaissance.
        
        Args:
            user_input: User's request
            context: Agent context (target, previous actions)
            
        Returns:
            Batch suggestion prompt if pattern detected, else None
        """
        user_lower = user_input.lower()
        
        # Pattern 1: Explicit recon request
        recon_keywords = [
            "reconnaissance", "recon", "scan", "enumerate",
            "discover", "map", "fingerprint", "probe"
        ]
        
        if any(keyword in user_lower for keyword in recon_keywords):
            # Check if target is new (no previous recon actions)
            previous_recon = context.get("previous_recon_count", 0)
            
            if previous_recon == 0:
                # NEW TARGET - Suggest comprehensive batch
                return self._generate_comprehensive_recon_batch()
        
        # Pattern 2: New target mentioned with port
        if re.search(r'(localhost|127\.0\.0\.1|\d+\.\d+\.\d+\.\d+):\d+', user_input):
            return self._generate_web_recon_batch()
        
        # Pattern 3: Domain/subdomain enumeration
        if any(kw in user_lower for kw in ["subdomain", "dns", "domain"]):
            return self._generate_domain_enum_batch()
        
        return None
    
    def _generate_comprehensive_recon_batch(self) -> str:
        """Generate prompt for comprehensive reconnaissance batch."""
        return """
🎯 BATCH OPTIMIZATION OPPORTUNITY DETECTED

The user requested RECONNAISSANCE on a new target.

⚡ PARALLEL EXECUTION STRATEGY:
Instead of calling tools one-by-one, you can call MULTIPLE independent reconnaissance tools in ONE response for 50% faster execution.

RECOMMENDED BATCH (call these together):
```
recon_nmap       - Port scanning
recon_httpx      - HTTP probing  
recon_whatweb    - Technology fingerprinting
```

HOW TO USE PARALLEL TOOLS:
Simply return multiple tool_calls in your response. The system will execute them simultaneously.

Example response structure:
{
  "tool_calls": [
    {"name": "recon_nmap", "arguments": {...}},
    {"name": "recon_httpx", "arguments": {...}},
    {"name": "recon_whatweb", "arguments": {...}}
  ]
}

⏱️ PERFORMANCE IMPACT:
- Sequential: 10-15 seconds (one tool at a time)
- Parallel: 5-7 seconds (all tools simultaneously)

💡 Use parallel batching when tools are INDEPENDENT (don't need each other's results).
"""
    
    def _generate_web_recon_batch(self) -> str:
        """Generate prompt for web application reconnaissance."""
        return """
🎯 WEB APPLICATION RECONNAISSANCE DETECTED

⚡ PARALLEL BATCH SUGGESTION:
For web targets, these tools can run simultaneously:

```
recon_httpx      - Check if web service is alive
recon_whatweb    - Identify technologies (server, framework, CMS)
```

After this batch completes, you can proceed with:
- web_request (if httpx confirms service is up)
- web_crawl (to map endpoints)
- web_nuclei (vulnerability scanning)

Call the first batch together in ONE response for 2x faster execution.
"""
    
    def _generate_domain_enum_batch(self) -> str:
        """Generate prompt for domain enumeration."""
        return """
🎯 DOMAIN ENUMERATION DETECTED

⚡ PARALLEL BATCH SUGGESTION:
```
recon_subdomain  - Passive subdomain discovery
recon_dns        - DNS records enumeration
```

These tools are independent and can run simultaneously.
Call them together for faster results.
"""
    
    def should_inject_batch_hint(
        self,
        iteration: int,
        last_tool: Optional[str],
        context: dict
    ) -> Optional[str]:
        """
        Decide if we should inject batch hint based on current state.
        
        Inject when:
        - Early in engagement (iteration < 3)
        - Just completed first recon tool
        - Haven't seen parallel execution yet
        
        Returns:
            Hint message or None
        """
        # Only inject in early iterations (don't spam)
        if iteration > 3:
            return None
        
        # Check if we just did a recon tool
        if last_tool and last_tool.startswith("recon_"):
            parallel_count = context.get("parallel_batches_used", 0)
            
            if parallel_count == 0:
                # User hasn't used parallel yet - give hint
                return """
💡 PERFORMANCE TIP: You just used a reconnaissance tool. Consider calling MULTIPLE recon tools in your next response (if they're independent) for parallel execution. Example:

Instead of:
  Call recon_httpx → wait → call recon_whatweb → wait

Do:
  Call recon_httpx AND recon_whatweb together → both run in parallel

This is 2x faster and already supported by the system.
"""
        
        return None
