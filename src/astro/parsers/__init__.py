"""Parsers package — structured output parsers for Kali tools."""
from astro.parsers.base import BaseParser
from astro.parsers.generic_parser import GenericParser
from astro.parsers.nmap_parser import NmapStructuredParser
from astro.parsers.sqlmap_parser import SqlmapStructuredParser
from astro.parsers.wpscan_parser import WpscanStructuredParser

__all__ = [
    "BaseParser",
    "GenericParser",
    "NmapStructuredParser",
    "SqlmapStructuredParser",
    "WpscanStructuredParser",
]
