"""AI Layer package for NumaSec.

Multi-provider LLM router with semantic caching and reflexion memory.
"""

from numasec.ai.router import (
    LLMRouter,
    LLMProvider,
    TaskComplexity,
    LLMResponse,
    LLMRouterError,
    LLMMetrics,
    PROVIDER_CONFIGS,
)
from numasec.ai.cache import (
    SemanticCache,
    SimpleCache,
    CacheNotAvailableError,
)
from numasec.ai.prompts import (
    SYSTEM_PROMPT,
    get_prompt,
    get_system_prompt,
    list_prompts,
    PROMPTS,
)

__all__ = [
    # Router
    "LLMRouter",
    "LLMProvider",
    "TaskComplexity",
    "LLMResponse",
    "LLMRouterError",
    "LLMMetrics",
    "PROVIDER_CONFIGS",
    # Cache
    "SemanticCache",
    "SimpleCache",
    "CacheNotAvailableError",
    # Prompts
    "SYSTEM_PROMPT",
    "get_prompt",
    "get_system_prompt",
    "list_prompts",
    "PROMPTS",
]
