"""Compatibility re-export of shared URL feature utilities."""

from app.ml.url_features import URL_FEATURE_NAMES, extract_url_features, parse_canonical_url

__all__ = ["URL_FEATURE_NAMES", "extract_url_features", "parse_canonical_url"]
