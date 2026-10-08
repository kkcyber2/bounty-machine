"""Program-scope import and matching."""

from .importer import ScopeImporter
from .matcher import (
    host_matches,
    normalize_target,
    resolve_scope,
    target_matches_pattern,
    technique_prohibited,
    url_matches,
)

__all__ = [
    "ScopeImporter",
    "host_matches",
    "normalize_target",
    "resolve_scope",
    "target_matches_pattern",
    "technique_prohibited",
    "url_matches",
]
