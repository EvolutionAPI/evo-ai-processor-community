"""LLM model identifier normalization for provider routing — EVO-1684.

Lives outside ``src.services`` so it can be imported (and unit-tested) without
pulling in the ADK / google-adk / langgraph dependency chain.
"""

from __future__ import annotations

from typing import Optional, Tuple


OPENROUTER_API_BASE = "https://openrouter.ai/api/v1"


def normalize_model_for_provider(
    model: str, provider: Optional[str]
) -> Tuple[str, dict]:
    """Normalize a model identifier for the configured LLM provider.

    For ``provider="openrouter"``, prepend ``openrouter/`` so LiteLLM routes
    the call to OpenRouter instead of the underlying vendor (otherwise an
    OpenRouter API key gets sent to OpenAI/Anthropic/etc. and is rejected —
    see EVO-1684). The vendor segment is preserved verbatim; when the model
    has no vendor at all we default to ``openai`` (the most common path via
    OpenRouter). Idempotent for already-prefixed values.

    Returns ``(normalized_model, extra_litellm_kwargs)``.
    """
    if provider != "openrouter":
        return model, {}

    extra_kwargs = {"api_base": OPENROUTER_API_BASE}

    if not model:
        return model, extra_kwargs

    if model.startswith("openrouter/"):
        return model, extra_kwargs

    if "/" in model:
        return f"openrouter/{model}", extra_kwargs

    # Bare model name (e.g. "gpt-4.1") — assume OpenAI vendor on OpenRouter.
    return f"openrouter/openai/{model}", extra_kwargs
