"""YAML-backed configuration helpers for the services layer."""

from __future__ import annotations

from functools import lru_cache
from pathlib import Path
from typing import Any

import yaml


ROOT_DIR = Path(__file__).resolve().parents[2]


@lru_cache(maxsize=None)
def load_yaml_config(relative_path: str) -> dict[str, Any]:
    """Load a YAML document from the repository root and cache the result."""
    config_path = ROOT_DIR / relative_path
    with config_path.open("r", encoding="utf-8") as handle:
        loaded = yaml.safe_load(handle) or {}
    if not isinstance(loaded, dict):
        raise ValueError(f"Config at {config_path} must deserialize to a mapping.")
    return loaded


def load_profile(profile_name: str = "default") -> dict[str, Any]:
    """Return a policy profile by name from the shared policy config."""
    profiles = load_yaml_config("config/policy_profiles.yaml").get("profiles", {})
    if profile_name not in profiles:
        raise KeyError(f"Unknown policy profile: {profile_name}")
    profile = profiles[profile_name]
    if not isinstance(profile, dict):
        raise ValueError(f"Policy profile {profile_name} must be a mapping.")
    return profile
