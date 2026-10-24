"""Shared data shapes. Changing these requires an all-hands issue + PR."""
from __future__ import annotations

from dataclasses import dataclass
from typing import TypedDict


@dataclass(frozen=True)
class Evidence:
    """One citable fact. `id` is what the LLM must cite, e.g. 'CVE-2099-0002:kev'."""

    id: str
    cve_id: str | None
    kind: str  # score | kev | epss | fix | desc | asset | cwe
    text: str
    source: str = ""  # url or table name


class Answer(TypedDict):
    answer: str
    citations: list[str]  # Evidence.id values actually used
    refused: bool
