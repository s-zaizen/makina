"""Runtime feature flags via OpenFeature.

Single env-driven flag for now: ``public_mode`` — when set, the ML
service refuses ``/train`` calls because the deployment ships a frozen
GBDT and there is nothing meaningful to retrain.

We use OpenFeature (CNCF spec) rather than a bare ``os.environ`` lookup
because the flag set is expected to grow and OpenFeature gives us a
clean swap point to a remote provider (Flipt, Unleash, GrowthBook, …)
without rewriting callers. The default provider is in-memory, populated
from environment variables at startup.
"""

from __future__ import annotations

import os

from openfeature import api
from openfeature.provider.in_memory_provider import InMemoryFlag, InMemoryProvider

_FLAG_PUBLIC_MODE = "public_mode"


def _truthy(value: str | None) -> bool:
    return (value or "").lower() in {"1", "true", "yes", "on"}


def setup_flags() -> None:
    """Wire the OpenFeature default provider with values resolved from
    the environment. Idempotent — calling twice replaces the provider."""
    public_mode = _truthy(os.environ.get("MAKINA_PUBLIC_MODE"))
    api.set_provider(
        InMemoryProvider(
            {
                _FLAG_PUBLIC_MODE: InMemoryFlag(
                    default_variant="enabled" if public_mode else "disabled",
                    variants={"enabled": True, "disabled": False},
                ),
            }
        )
    )


def is_public_mode() -> bool:
    """True when learning-loop writes are disabled in this deployment."""
    return api.get_client().get_boolean_value(_FLAG_PUBLIC_MODE, False)
