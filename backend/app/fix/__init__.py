"""Patch suggester. Importing the package registers every bug type that has patches."""

from app.fix import rule_patches  # noqa: F401  (adds the rule layer's bug types to PLANNERS)
