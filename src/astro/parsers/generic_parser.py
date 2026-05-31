"""Generic fallback parser — no structured parsing."""
from typing import Any

from astro.parsers.base import BaseParser


class GenericParser(BaseParser):
    def parse(self, raw_output: dict[str, Any], params: dict[str, Any]) -> dict[str, Any] | None:
        return None
