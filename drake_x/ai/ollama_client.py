"""Tiny async client for a local Ollama instance.

We only need two endpoints:

- ``GET  /api/tags``      → check the runtime is reachable
- ``POST /api/generate``  → ask the model for a single completion

We deliberately do not stream tokens. The orchestrator wants a single string
back, and not streaming makes graceful-fallback easier.
"""

from __future__ import annotations

import json
from typing import Any

import httpx

from ..exceptions import AIUnavailableError
from ..logging import get_logger

log = get_logger("ollama")


class OllamaClient:
    """Minimal Ollama HTTP wrapper. Local-only by design."""

    def __init__(self, *, base_url: str, model: str, timeout: float = 180.0) -> None:
        self.base_url = base_url.rstrip("/")
        self.model = model
        self.timeout = timeout

    async def is_available(self) -> bool:
        try:
            async with httpx.AsyncClient(timeout=5.0) as client:
                resp = await client.get(f"{self.base_url}/api/tags")
                return resp.status_code == 200
        except (httpx.HTTPError, OSError) as exc:
            log.debug("Ollama not reachable at %s: %s", self.base_url, exc)
            return False

    async def generate(self, prompt: str, *, system: str | None = None) -> str:
        body: dict[str, Any] = {
            "model": self.model,
            "prompt": prompt,
            "stream": False,
            "options": {
                "temperature": 0.2,
                "num_ctx": 2048,
                "num_predict": 256,
            },
        }
        if system:
            body["system"] = system

        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                resp = await client.post(f"{self.base_url}/api/generate", json=body)
        except (httpx.HTTPError, OSError) as exc:
            raise AIUnavailableError(f"failed to reach Ollama at {self.base_url}: {exc}") from exc

        if resp.status_code != 200:
            raise AIUnavailableError(
                f"Ollama returned HTTP {resp.status_code}: {resp.text[:200]}"
            )

        try:
            data = resp.json()
        except json.JSONDecodeError as exc:
            raise AIUnavailableError(f"Ollama returned non-JSON body: {exc}") from exc

        return str(data.get("response", "")).strip()
