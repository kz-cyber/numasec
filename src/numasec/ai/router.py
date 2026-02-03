"""
NumaSec - LLM Router

Multi-provider LLM routing with fallback, caching, and cost optimization.
Supports Claude, DeepSeek, OpenAI, and Local (Ollama) providers.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import os
import time
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, TYPE_CHECKING, AsyncGenerator

import httpx

logger = logging.getLogger("numasec.router")

if TYPE_CHECKING:
    from numasec.ai.cache import SemanticCache


# ══════════════════════════════════════════════════════════════════════════════
# Enums and Types
# ══════════════════════════════════════════════════════════════════════════════


class LLMProvider(str, Enum):
    """Supported LLM providers."""

    CLAUDE = "claude"
    DEEPSEEK = "deepseek"
    OPENAI = "openai"
    LOCAL = "local"


class TaskComplexity(str, Enum):
    """Task complexity for model selection."""

    SIMPLE = "simple"  # Encoding, formatting, simple lookups
    STANDARD = "standard"  # Analysis, suggestions, explanations
    COMPLEX = "complex"  # CVSS calculation, executive summaries, attack chains


# ══════════════════════════════════════════════════════════════════════════════
# Data Classes
# ══════════════════════════════════════════════════════════════════════════════


@dataclass
class ProviderConfig:
    """Configuration for an LLM provider."""

    name: LLMProvider
    base_url: str
    api_key_env: str
    models: dict[TaskComplexity, str]
    cost_per_1k_input: float
    cost_per_1k_output: float
    max_tokens: int = 4096
    timeout: int = 60
    supports_tools: bool = True
    supports_vision: bool = False

    def get_api_key(self) -> str | None:
        """Get API key from environment."""
        if not self.api_key_env:
            return None
        return os.environ.get(self.api_key_env)

    def get_model(self, task: TaskComplexity) -> str:
        """Get appropriate model for task complexity."""
        return self.models.get(task, self.models[TaskComplexity.STANDARD])


@dataclass
class LLMResponse:
    """Response from LLM provider."""

    content: str
    model: str
    provider: LLMProvider
    input_tokens: int
    output_tokens: int
    latency_ms: float
    cost: float
    tool_calls: list[dict[str, Any]] = field(default_factory=list)
    reasoning_content: str | None = None  # DeepSeek R1 thinking mode
    cached: bool = False
    raw_response: dict[str, Any] | None = None

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "content": self.content,
            "model": self.model,
            "provider": self.provider.value,
            "input_tokens": self.input_tokens,
            "output_tokens": self.output_tokens,
            "latency_ms": self.latency_ms,
            "cost": self.cost,
            "tool_calls": self.tool_calls,
            "cached": self.cached,
        }


@dataclass
class StreamChunk:
    """
    Single chunk from streaming LLM response.
    
    SOTA 2026: Unified streaming format across all providers.
    Handles content, reasoning (R1), and tool calls incrementally.
    """
    content_delta: str | None = None  # Text content chunk
    reasoning_delta: str | None = None  # DeepSeek R1 thinking chunk
    tool_call_delta: dict | None = None  # Partial tool call (id, name, arguments chunk)
    finish_reason: str | None = None  # "stop", "tool_calls", "length"
    provider: LLMProvider | None = None
    model: str | None = None


@dataclass
class LLMMetrics:
    """Metrics for LLM usage tracking."""

    total_requests: int = 0
    cache_hits: int = 0
    cache_misses: int = 0
    total_input_tokens: int = 0
    total_output_tokens: int = 0
    total_cost: float = 0.0
    provider_successes: dict[str, int] = field(default_factory=dict)
    provider_failures: dict[str, int] = field(default_factory=dict)
    latency_sum_ms: float = 0.0

    def record_success(
        self, provider: LLMProvider, response: LLMResponse
    ) -> None:
        """Record successful request."""
        self.total_requests += 1
        self.total_input_tokens += response.input_tokens
        self.total_output_tokens += response.output_tokens
        self.total_cost += response.cost
        self.latency_sum_ms += response.latency_ms

        key = provider.value
        self.provider_successes[key] = self.provider_successes.get(key, 0) + 1

    def record_failure(self, provider: LLMProvider, error: str) -> None:
        """Record failed request."""
        key = provider.value
        self.provider_failures[key] = self.provider_failures.get(key, 0) + 1

    def record_cache_hit(self) -> None:
        """Record cache hit."""
        self.cache_hits += 1

    def record_cache_miss(self) -> None:
        """Record cache miss."""
        self.cache_misses += 1

    @property
    def average_latency_ms(self) -> float:
        """Get average latency."""
        if self.total_requests == 0:
            return 0.0
        return self.latency_sum_ms / self.total_requests

    @property
    def cache_hit_rate(self) -> float:
        """Get cache hit rate."""
        total = self.cache_hits + self.cache_misses
        if total == 0:
            return 0.0
        return self.cache_hits / total

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "total_requests": self.total_requests,
            "cache_hits": self.cache_hits,
            "cache_misses": self.cache_misses,
            "cache_hit_rate": f"{self.cache_hit_rate:.2%}",
            "total_input_tokens": self.total_input_tokens,
            "total_output_tokens": self.total_output_tokens,
            "total_cost": f"${self.total_cost:.4f}",
            "average_latency_ms": f"{self.average_latency_ms:.1f}",
            "provider_successes": self.provider_successes,
            "provider_failures": self.provider_failures,
        }


class LLMRouterError(Exception):
    """Error from LLM router."""

    pass


# ══════════════════════════════════════════════════════════════════════════════
# Provider Configurations
# ══════════════════════════════════════════════════════════════════════════════

PROVIDER_CONFIGS: dict[LLMProvider, ProviderConfig] = {
    LLMProvider.CLAUDE: ProviderConfig(
        name=LLMProvider.CLAUDE,
        base_url="https://api.anthropic.com/v1",
        api_key_env="ANTHROPIC_API_KEY",
        models={
            TaskComplexity.COMPLEX: "claude-sonnet-4-20250514",
            TaskComplexity.STANDARD: "claude-sonnet-4-20250514",
            TaskComplexity.SIMPLE: "claude-haiku-3-20240307",
        },
        cost_per_1k_input=0.003,
        cost_per_1k_output=0.015,
        max_tokens=8192,
        timeout=120,
        supports_tools=True,
        supports_vision=True,
    ),
    LLMProvider.DEEPSEEK: ProviderConfig(
        name=LLMProvider.DEEPSEEK,
        base_url="https://api.deepseek.com/v1",
        api_key_env="DEEPSEEK_API_KEY",
        models={
            TaskComplexity.COMPLEX: "deepseek-reasoner",
            TaskComplexity.STANDARD: "deepseek-chat",
            TaskComplexity.SIMPLE: "deepseek-chat",
        },
        cost_per_1k_input=0.00014,
        cost_per_1k_output=0.00028,
        max_tokens=8192,
        timeout=180,
        supports_tools=True,
        supports_vision=False,
    ),
    LLMProvider.OPENAI: ProviderConfig(
        name=LLMProvider.OPENAI,
        base_url="https://api.openai.com/v1",
        api_key_env="OPENAI_API_KEY",
        models={
            TaskComplexity.COMPLEX: "gpt-4o",
            TaskComplexity.STANDARD: "gpt-4o-mini",
            TaskComplexity.SIMPLE: "gpt-4o-mini",
        },
        cost_per_1k_input=0.005,
        cost_per_1k_output=0.015,
        max_tokens=4096,
        timeout=60,
        supports_tools=True,
        supports_vision=True,
    ),
    LLMProvider.LOCAL: ProviderConfig(
        name=LLMProvider.LOCAL,
        base_url="http://localhost:11434/v1",  # Ollama
        api_key_env="",
        models={
            TaskComplexity.COMPLEX: "llama3.3:70b",
            TaskComplexity.STANDARD: "llama3.3:70b",
            TaskComplexity.SIMPLE: "llama3.2:3b",
        },
        cost_per_1k_input=0.0,
        cost_per_1k_output=0.0,
        max_tokens=4096,
        timeout=180,
        supports_tools=True,
        supports_vision=False,
    ),
}


# ══════════════════════════════════════════════════════════════════════════════
# LLM Router
# ══════════════════════════════════════════════════════════════════════════════


class LLMRouter:
    """
    Intelligent LLM routing with fallback, caching, and cost optimization.

    Features:
    - Multi-provider support (Claude, DeepSeek, OpenAI, Local)
    - Automatic fallback on failure
    - Task complexity classification for model selection
    - Semantic caching for cost reduction
    - Cost and latency tracking
    """

    def __init__(
        self,
        primary: LLMProvider = LLMProvider.DEEPSEEK,
        fallback: LLMProvider | None = LLMProvider.CLAUDE,
        local_fallback: LLMProvider | None = LLMProvider.LOCAL,
        cache: "SemanticCache | None" = None,
    ) -> None:
        """
        Initialize LLM router.

        Args:
            primary: Primary LLM provider
            fallback: Fallback provider on primary failure
            local_fallback: Local fallback (Ollama) for offline use
            cache: Semantic cache instance
        """
        self.primary = PROVIDER_CONFIGS[primary]
        self.fallback = PROVIDER_CONFIGS[fallback] if fallback else None
        self.local_fallback = PROVIDER_CONFIGS[local_fallback] if local_fallback else None
        self.cache = cache
        self.metrics = LLMMetrics()

        # HTTP client
        self._client: httpx.AsyncClient | None = None

    async def _get_client(self) -> httpx.AsyncClient:
        """Get or create HTTP client."""
        if self._client is None:
            self._client = httpx.AsyncClient(timeout=180.0)
        return self._client

    async def close(self) -> None:
        """Close HTTP client."""
        if self._client:
            await self._client.aclose()
            self._client = None

    async def complete(
        self,
        messages: list[dict[str, str]],
        task: TaskComplexity = TaskComplexity.STANDARD,
        tools: list[dict[str, Any]] | None = None,
        require_tools: bool = False,
        system_prompt: str | None = None,
        cache_key: str | None = None,
        max_retries: int = 3,
    ) -> LLMResponse:
        """
        Route request to appropriate LLM with fallback.

        Flow:
        1. Check semantic cache
        2. Try primary provider
        3. On failure, try fallback
        4. On failure, try local
        5. Cache successful response

        Args:
            messages: Conversation messages
            task: Task complexity for model selection
            tools: Tool definitions for function calling
            require_tools: Require tool use in response
            system_prompt: System prompt to prepend
            cache_key: Key for caching (None to disable)
            max_retries: Max retries per provider

        Returns:
            LLMResponse with content and metadata

        Raises:
            LLMRouterError: If all providers fail
        """
        # Check cache first
        if self.cache and cache_key:
            cached = await self.cache.get(cache_key, messages)
            if cached:
                self.metrics.record_cache_hit()
                cached.cached = True
                return cached

        self.metrics.record_cache_miss()

        # Build provider list
        providers = [self.primary]
        if self.fallback:
            providers.append(self.fallback)
        if self.local_fallback:
            providers.append(self.local_fallback)

        last_error: Exception | None = None

        for provider in providers:
            # Skip if no API key (except local)
            if provider.name != LLMProvider.LOCAL and not provider.get_api_key():
                logger.warning(f"Skipping {provider.name.value}: No API key")
                continue

            logger.info(f"Trying provider: {provider.name.value}")

            for attempt in range(max_retries):
                try:
                    response = await self._call_provider(
                        provider=provider,
                        messages=messages,
                        task=task,
                        tools=tools,
                        require_tools=require_tools,
                        system_prompt=system_prompt,
                    )

                    # Cache successful response
                    if self.cache and cache_key:
                        await self.cache.set(cache_key, messages, response)

                    self.metrics.record_success(provider.name, response)
                    logger.info(f"Success with {provider.name.value}")
                    return response

                except Exception as e:
                    last_error = e
                    self.metrics.record_failure(provider.name, str(e))
                    logger.error(f"Provider {provider.name.value} attempt {attempt+1}/{max_retries} failed: {e}")

                    # Retry with exponential backoff
                    if attempt < max_retries - 1:
                        await asyncio.sleep(2 ** attempt)
                    continue

        raise LLMRouterError(f"All providers failed. Last error: {last_error}")

    async def stream(
        self,
        messages: list[dict[str, str]],
        task: TaskComplexity = TaskComplexity.STANDARD,
        tools: list[dict[str, Any]] | None = None,
        system_prompt: str | None = None,
    ) -> AsyncGenerator[StreamChunk, None]:
        """
        Stream LLM response with real-time token delivery.
        
        SOTA 2026: True streaming eliminates perceived latency.
        First token arrives in <500ms vs 8-15s for complete().
        
        Supports:
        - Content streaming (text tokens)
        - Reasoning streaming (DeepSeek R1 thinking)
        - Tool call streaming (buffered until complete)
        
        Args:
            messages: Conversation messages
            task: Task complexity for model selection
            tools: Tool definitions for function calling
            system_prompt: System prompt to prepend
            
        Yields:
            StreamChunk with incremental content/reasoning/tool_calls
        """
        # Build provider list (no cache for streaming)
        providers = [self.primary]
        if self.fallback:
            providers.append(self.fallback)
        if self.local_fallback:
            providers.append(self.local_fallback)
        
        last_error: Exception | None = None
        
        for provider in providers:
            # Skip if no API key (except local)
            if provider.name != LLMProvider.LOCAL and not provider.get_api_key():
                logger.warning(f"Skipping {provider.name.value}: No API key")
                continue
            
            logger.info(f"Streaming with provider: {provider.name.value}")
            
            try:
                async for chunk in self._stream_provider(
                    provider=provider,
                    messages=messages,
                    task=task,
                    tools=tools,
                    system_prompt=system_prompt,
                ):
                    yield chunk
                
                # Success - don't try other providers
                return
                
            except Exception as e:
                last_error = e
                self.metrics.record_failure(provider.name, str(e))
                logger.error(f"Streaming failed with {provider.name.value}: {e}")
                continue
        
        # All providers failed - yield error chunk
        yield StreamChunk(
            content_delta=f"[ERROR] All providers failed: {last_error}",
            finish_reason="error"
        )

    async def _stream_provider(
        self,
        provider: ProviderConfig,
        messages: list[dict[str, str]],
        task: TaskComplexity,
        tools: list[dict[str, Any]] | None = None,
        system_prompt: str | None = None,
    ) -> AsyncGenerator[StreamChunk, None]:
        """Stream from a specific provider."""
        if provider.name == LLMProvider.CLAUDE:
            async for chunk in self._stream_anthropic(provider, messages, task, tools, system_prompt):
                yield chunk
        else:
            # OpenAI-compatible API (DeepSeek, OpenAI, Local/Ollama)
            async for chunk in self._stream_openai_compatible(provider, messages, task, tools, system_prompt):
                yield chunk

    async def _stream_openai_compatible(
        self,
        provider: ProviderConfig,
        messages: list[dict[str, str]],
        task: TaskComplexity,
        tools: list[dict[str, Any]] | None = None,
        system_prompt: str | None = None,
    ) -> AsyncGenerator[StreamChunk, None]:
        """
        Stream from OpenAI-compatible API (DeepSeek, OpenAI, Ollama).
        
        All use identical SSE format with data: {json} lines.
        """
        client = await self._get_client()
        model = provider.get_model(task)
        
        headers = {"Content-Type": "application/json"}
        api_key = provider.get_api_key()
        if api_key:
            headers["Authorization"] = f"Bearer {api_key}"
        
        # Build messages with system prompt
        all_messages = []
        if system_prompt:
            all_messages.append({"role": "system", "content": system_prompt})
        
        for msg in messages:
            sanitized = {"role": msg.get("role", "user")}
            if sanitized["role"] == "tool":
                sanitized["role"] = "user"
                tool_id = msg.get("tool_call_id", "unknown")
                sanitized["content"] = f"[Tool Result for {tool_id}]: {msg.get('content', '')}"
            else:
                sanitized["content"] = msg.get("content") or ""
            if sanitized["content"] or sanitized["role"] == "assistant":
                all_messages.append(sanitized)
        
        payload: dict[str, Any] = {
            "model": model,
            "messages": all_messages,
            "max_tokens": provider.max_tokens,
            "stream": True,
        }
        
        if tools:
            payload["tools"] = self._convert_tools_to_openai(tools)
        
        # Tool call accumulator (streamed in pieces)
        tool_calls_buffer: dict[int, dict] = {}
        
        async with client.stream(
            "POST",
            f"{provider.base_url}/chat/completions",
            headers=headers,
            json=payload,
            timeout=provider.timeout,
        ) as response:
            response.raise_for_status()
            
            async for line in response.aiter_lines():
                if not line or line == "data: [DONE]":
                    continue
                
                if not line.startswith("data: "):
                    continue
                
                try:
                    data = json.loads(line[6:])
                except json.JSONDecodeError:
                    continue
                
                choice = data.get("choices", [{}])[0]
                delta = choice.get("delta", {})
                finish = choice.get("finish_reason")
                
                # Content chunk
                content_delta = delta.get("content")
                
                # Reasoning chunk (DeepSeek R1)
                reasoning_delta = delta.get("reasoning_content")
                
                # Tool call chunk (accumulate until complete)
                if delta.get("tool_calls"):
                    for tc in delta["tool_calls"]:
                        idx = tc.get("index", 0)
                        if idx not in tool_calls_buffer:
                            tool_calls_buffer[idx] = {
                                "id": tc.get("id", ""),
                                "name": "",
                                "arguments": ""
                            }
                        if tc.get("id"):
                            tool_calls_buffer[idx]["id"] = tc["id"]
                        if tc.get("function", {}).get("name"):
                            tool_calls_buffer[idx]["name"] = tc["function"]["name"]
                        if tc.get("function", {}).get("arguments"):
                            tool_calls_buffer[idx]["arguments"] += tc["function"]["arguments"]
                
                # Yield chunk if we have content or reasoning
                if content_delta or reasoning_delta or finish:
                    yield StreamChunk(
                        content_delta=content_delta,
                        reasoning_delta=reasoning_delta,
                        finish_reason=finish,
                        provider=provider.name,
                        model=model,
                    )
        
        # Yield accumulated tool calls at the end
        if tool_calls_buffer:
            for idx in sorted(tool_calls_buffer.keys()):
                tc = tool_calls_buffer[idx]
                try:
                    args = json.loads(tc["arguments"]) if tc["arguments"] else {}
                except json.JSONDecodeError:
                    args = {}
                yield StreamChunk(
                    tool_call_delta={
                        "id": tc["id"],
                        "name": tc["name"],
                        "arguments": args,
                    },
                    provider=provider.name,
                    model=model,
                )

    async def _stream_anthropic(
        self,
        provider: ProviderConfig,
        messages: list[dict[str, str]],
        task: TaskComplexity,
        tools: list[dict[str, Any]] | None = None,
        system_prompt: str | None = None,
    ) -> AsyncGenerator[StreamChunk, None]:
        """
        Stream from Anthropic Claude API.
        
        Claude uses slightly different SSE format:
        - event: content_block_delta
        - data: {"type": "content_block_delta", "delta": {"text": "..."}}
        """
        client = await self._get_client()
        model = provider.get_model(task)
        
        headers = {
            "Content-Type": "application/json",
            "x-api-key": provider.get_api_key() or "",
            "anthropic-version": "2023-06-01",
        }
        
        payload: dict[str, Any] = {
            "model": model,
            "max_tokens": provider.max_tokens,
            "messages": messages,
            "stream": True,
        }
        
        if system_prompt:
            payload["system"] = system_prompt
        
        if tools:
            payload["tools"] = self._convert_tools_to_anthropic(tools)
        
        # Tool call accumulator
        current_tool_use: dict | None = None
        
        async with client.stream(
            "POST",
            f"{provider.base_url}/messages",
            headers=headers,
            json=payload,
            timeout=provider.timeout,
        ) as response:
            response.raise_for_status()
            
            async for line in response.aiter_lines():
                if not line:
                    continue
                
                # Claude uses "event: type\ndata: {json}" format
                if line.startswith("event:"):
                    continue  # We parse the data line
                
                if not line.startswith("data: "):
                    continue
                
                try:
                    data = json.loads(line[6:])
                except json.JSONDecodeError:
                    continue
                
                event_type = data.get("type", "")
                
                if event_type == "content_block_start":
                    block = data.get("content_block", {})
                    if block.get("type") == "tool_use":
                        current_tool_use = {
                            "id": block.get("id", ""),
                            "name": block.get("name", ""),
                            "arguments": ""
                        }
                
                elif event_type == "content_block_delta":
                    delta = data.get("delta", {})
                    
                    if delta.get("type") == "text_delta":
                        yield StreamChunk(
                            content_delta=delta.get("text"),
                            provider=provider.name,
                            model=model,
                        )
                    
                    elif delta.get("type") == "input_json_delta" and current_tool_use:
                        current_tool_use["arguments"] += delta.get("partial_json", "")
                
                elif event_type == "content_block_stop":
                    if current_tool_use:
                        try:
                            args = json.loads(current_tool_use["arguments"]) if current_tool_use["arguments"] else {}
                        except json.JSONDecodeError:
                            args = {}
                        yield StreamChunk(
                            tool_call_delta={
                                "id": current_tool_use["id"],
                                "name": current_tool_use["name"],
                                "arguments": args,
                            },
                            provider=provider.name,
                            model=model,
                        )
                        current_tool_use = None
                
                elif event_type == "message_stop":
                    yield StreamChunk(
                        finish_reason="stop",
                        provider=provider.name,
                        model=model,
                    )

    async def _call_provider(
        self,
        provider: ProviderConfig,
        messages: list[dict[str, str]],
        task: TaskComplexity,
        tools: list[dict[str, Any]] | None = None,
        require_tools: bool = False,
        system_prompt: str | None = None,
    ) -> LLMResponse:
        """Call a specific LLM provider."""
        start_time = time.perf_counter()

        if provider.name == LLMProvider.CLAUDE:
            response = await self._call_anthropic(
                provider, messages, task, tools, system_prompt
            )
        else:
            # OpenAI-compatible API (DeepSeek, OpenAI, Local)
            response = await self._call_openai_compatible(
                provider, messages, task, tools, system_prompt
            )

        latency_ms = (time.perf_counter() - start_time) * 1000
        response.latency_ms = latency_ms

        return response

    async def _call_anthropic(
        self,
        provider: ProviderConfig,
        messages: list[dict[str, str]],
        task: TaskComplexity,
        tools: list[dict[str, Any]] | None = None,
        system_prompt: str | None = None,
    ) -> LLMResponse:
        """Call Anthropic Claude API."""
        client = await self._get_client()
        model = provider.get_model(task)

        # Prepare request
        headers = {
            "Content-Type": "application/json",
            "x-api-key": provider.get_api_key() or "",
            "anthropic-version": "2023-06-01",
        }

        # Build payload
        payload: dict[str, Any] = {
            "model": model,
            "max_tokens": provider.max_tokens,
            "messages": messages,
        }

        if system_prompt:
            payload["system"] = system_prompt

        if tools:
            payload["tools"] = self._convert_tools_to_anthropic(tools)

        # Call API
        response = await client.post(
            f"{provider.base_url}/messages",
            headers=headers,
            json=payload,
            timeout=provider.timeout,
        )
        
        # Log error response body for debugging
        if response.status_code >= 400:
            logger.error(f"Anthropic API Error: {response.text[:500]}")
        
        response.raise_for_status()
        data = response.json()

        # Parse response
        content = ""
        tool_calls = []

        for block in data.get("content", []):
            if block["type"] == "text":
                content += block["text"]
            elif block["type"] == "tool_use":
                tool_calls.append({
                    "id": block["id"],
                    "name": block["name"],
                    "arguments": block["input"],
                })

        # Calculate cost
        input_tokens = data.get("usage", {}).get("input_tokens", 0)
        output_tokens = data.get("usage", {}).get("output_tokens", 0)
        cost = (
            (input_tokens / 1000) * provider.cost_per_1k_input
            + (output_tokens / 1000) * provider.cost_per_1k_output
        )

        return LLMResponse(
            content=content,
            model=model,
            provider=provider.name,
            input_tokens=input_tokens,
            output_tokens=output_tokens,
            latency_ms=0,  # Will be set by caller
            cost=cost,
            tool_calls=tool_calls,
            raw_response=data,
        )

    async def _call_openai_compatible(
        self,
        provider: ProviderConfig,
        messages: list[dict[str, str]],
        task: TaskComplexity,
        tools: list[dict[str, Any]] | None = None,
        system_prompt: str | None = None,
    ) -> LLMResponse:
        """Call OpenAI-compatible API (OpenAI, DeepSeek, Ollama)."""
        client = await self._get_client()
        model = provider.get_model(task)

        # Prepare request
        headers = {
            "Content-Type": "application/json",
        }

        api_key = provider.get_api_key()
        if api_key:
            headers["Authorization"] = f"Bearer {api_key}"

        # Build messages with system prompt
        all_messages = []
        if system_prompt:
            all_messages.append({"role": "system", "content": system_prompt})
        
        # Sanitize messages for OpenAI-compatible APIs
        for msg in messages:
            sanitized = {"role": msg.get("role", "user")}
            
            # DeepSeek doesn't support "tool" role, convert to "user" with context
            if sanitized["role"] == "tool":
                sanitized["role"] = "user"
                tool_id = msg.get("tool_call_id", "unknown")
                sanitized["content"] = f"[Tool Result for {tool_id}]: {msg.get('content', '')}"
            else:
                sanitized["content"] = msg.get("content") or ""
            
            # Skip messages with empty content (except for assistant with tool_calls)
            if not sanitized["content"] and sanitized["role"] != "assistant":
                continue
                
            all_messages.append(sanitized)

        # Build payload
        payload: dict[str, Any] = {
            "model": model,
            "messages": all_messages,
            "max_tokens": provider.max_tokens,
        }
        
        logger.debug(f"Payload messages count: {len(all_messages)}")

        if tools:
            payload["tools"] = self._convert_tools_to_openai(tools)
            logger.debug(f"Tools count: {len(payload['tools'])}")

        # Call API
        response = await client.post(
            f"{provider.base_url}/chat/completions",
            headers=headers,
            json=payload,
            timeout=provider.timeout,
        )
        
        # Log error response body for debugging
        if response.status_code >= 400:
            logger.error(f"API Error Response: {response.text[:500]}")
        
        response.raise_for_status()
        data = response.json()

        # Parse response
        choice = data.get("choices", [{}])[0]
        message = choice.get("message", {})
        content = message.get("content", "") or ""
        
        # Extract DeepSeek R1 reasoning (thinking mode)
        reasoning_content = message.get("reasoning_content")

        tool_calls = []
        for tc in message.get("tool_calls", []):
            tool_calls.append({
                "id": tc.get("id"),
                "name": tc.get("function", {}).get("name"),
                "arguments": json.loads(tc.get("function", {}).get("arguments", "{}")),
            })

        # Calculate cost
        usage = data.get("usage", {})
        input_tokens = usage.get("prompt_tokens", 0)
        output_tokens = usage.get("completion_tokens", 0)
        cost = (
            (input_tokens / 1000) * provider.cost_per_1k_input
            + (output_tokens / 1000) * provider.cost_per_1k_output
        )

        return LLMResponse(
            content=content,
            model=model,
            provider=provider.name,
            input_tokens=input_tokens,
            output_tokens=output_tokens,
            latency_ms=0,  # Will be set by caller
            cost=cost,
            tool_calls=tool_calls,
            reasoning_content=reasoning_content,  # R1 thinking
            raw_response=data,
        )

    def _convert_tools_to_anthropic(
        self, tools: list[dict[str, Any]]
    ) -> list[dict[str, Any]]:
        """Convert tools to Anthropic format."""
        anthropic_tools = []
        for tool in tools:
            anthropic_tools.append({
                "name": tool.get("name"),
                "description": tool.get("description", ""),
                "input_schema": tool.get("inputSchema", tool.get("parameters", {})),
            })
        return anthropic_tools

    def _convert_tools_to_openai(
        self, tools: list[dict[str, Any]]
    ) -> list[dict[str, Any]]:
        """Convert tools to OpenAI format."""
        openai_tools = []
        for tool in tools:
            openai_tools.append({
                "type": "function",
                "function": {
                    "name": tool.get("name"),
                    "description": tool.get("description", ""),
                    "parameters": tool.get("inputSchema", tool.get("parameters", {})),
                },
            })
        return openai_tools

    def classify_task(self, prompt: str) -> TaskComplexity:
        """
        Classify task complexity based on prompt content.

        Args:
            prompt: The prompt text

        Returns:
            TaskComplexity enum value
        """
        complex_indicators = [
            "cvss",
            "attack chain",
            "executive summary",
            "remediation",
            "risk analysis",
            "business impact",
            "compliance",
            "strategic",
            "calculate score",
            "full report",
        ]
        simple_indicators = [
            "decode",
            "encode",
            "hash",
            "convert",
            "format",
            "base64",
            "url encode",
            "hex",
        ]

        prompt_lower = prompt.lower()

        if any(ind in prompt_lower for ind in complex_indicators):
            return TaskComplexity.COMPLEX
        if any(ind in prompt_lower for ind in simple_indicators):
            return TaskComplexity.SIMPLE
        return TaskComplexity.STANDARD

    def get_cache_key(self, messages: list[dict[str, str]]) -> str:
        """Generate cache key from messages."""
        content = json.dumps(messages, sort_keys=True)
        return hashlib.sha256(content.encode()).hexdigest()[:16]

    def get_metrics(self) -> dict[str, Any]:
        """Get router metrics."""
        return self.metrics.to_dict()

    async def simple_complete(
        self,
        prompt: str,
        task: TaskComplexity | None = None,
        cache: bool = True,
    ) -> str:
        """
        Simple completion with just a prompt string.

        Args:
            prompt: The prompt text
            task: Task complexity (auto-detect if None)
            cache: Whether to use caching

        Returns:
            Response content string
        """
        if task is None:
            task = self.classify_task(prompt)

        messages = [{"role": "user", "content": prompt}]
        cache_key = self.get_cache_key(messages) if cache else None

        response = await self.complete(
            messages=messages,
            task=task,
            cache_key=cache_key,
        )

        return response.content
