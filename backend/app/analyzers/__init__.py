"""Analyzer interface and implementations for AIPAM.

This package defines the pluggable analyzer contract (BaseAnalyzer)
and adapter implementations wrapping existing backends.
"""

from .base import BaseAnalyzer

__all__ = ["BaseAnalyzer"]
