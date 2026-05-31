"""Abstract base class for all output parsers."""
from abc import ABC, abstractmethod
from typing import Any


class BaseParser(ABC):
    @abstractmethod
    def parse(self, raw_output: dict[str, Any], params: dict[str, Any]) -> dict[str, Any] | None:
        """Parse raw tool output into structured data. Return None on failure."""
        ...
