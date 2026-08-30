"""slopquat — catch AI-hallucinated package names before they reach your lockfile."""

from .detector import detect, Detector, Finding, Report
from .corpus import IMPORT_TO_DIST, POPULAR_PYTHON, POPULAR_NPM

__version__ = "0.1.0"
__all__ = ["detect", "Detector", "Finding", "Report", "IMPORT_TO_DIST",
           "POPULAR_PYTHON", "POPULAR_NPM", "__version__"]