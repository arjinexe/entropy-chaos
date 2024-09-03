"""Active discovery for Entropy — find endpoints without a spec file."""
from .crawler import ActiveCrawler, DiscoveryResult

__all__ = ["ActiveCrawler", "DiscoveryResult"]
