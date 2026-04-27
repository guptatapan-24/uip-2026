"""Environment configuration and logging setup for the API gateway."""

from __future__ import annotations

import logging
import os
import sys
from typing import Optional


class APIConfig:
    """Configuration from environment variables."""

    # API Settings
    HOST: str = os.getenv("API_HOST", "0.0.0.0")
    PORT: int = int(os.getenv("API_PORT", "8000"))
    ENV: str = os.getenv("API_ENV", "production")
    DEBUG: bool = ENV == "development"

    # CORS
    CORS_ORIGINS: str = os.getenv(
        "CORS_ORIGINS", "http://localhost:3000,http://localhost:5173"
    )

    # Logging
    LOG_LEVEL: str = os.getenv("API_LOG_LEVEL", "INFO")
    LOG_FORMAT: str = os.getenv(
        "API_LOG_FORMAT",
        "%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    )

    # Policy profiles
    DEFAULT_POLICY_PROFILE: str = os.getenv("DEFAULT_POLICY_PROFILE", "default")

    # Feature flags
    ENABLE_SEMANTIC_VALIDATION: bool = os.getenv(
        "ENABLE_SEMANTIC_VALIDATION", "true"
    ).lower() in ("true", "1", "yes")
    ENABLE_DETERMINISTIC_VALIDATION: bool = os.getenv(
        "ENABLE_DETERMINISTIC_VALIDATION", "true"
    ).lower() in ("true", "1", "yes")

    # Timeouts
    EXTRACTION_TIMEOUT_SEC: float = float(
        os.getenv("EXTRACTION_TIMEOUT_SEC", "30.0")
    )
    VALIDATION_TIMEOUT_SEC: float = float(
        os.getenv("VALIDATION_TIMEOUT_SEC", "60.0")
    )
    DECISION_TIMEOUT_SEC: float = float(os.getenv("DECISION_TIMEOUT_SEC", "10.0"))

    @classmethod
    def get_cors_origins(cls) -> list[str]:
        """Parse CORS origins from environment variable."""
        return [origin.strip() for origin in cls.CORS_ORIGINS.split(",")]


def setup_logging(config: APIConfig = APIConfig) -> None:
    """
    Configure structured logging for the application.

    Args:
        config: APIConfig instance with logging settings
    """
    # Configure root logger
    root_logger = logging.getLogger()
    root_logger.setLevel(getattr(logging, config.LOG_LEVEL))

    # Remove existing handlers
    for handler in root_logger.handlers[:]:
        root_logger.removeHandler(handler)

    # Console handler with formatting
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(getattr(logging, config.LOG_LEVEL))

    formatter = logging.Formatter(config.LOG_FORMAT)
    console_handler.setFormatter(formatter)

    root_logger.addHandler(console_handler)

    # Log startup configuration
    logger = logging.getLogger(__name__)
    logger.info(f"Logging configured at level {config.LOG_LEVEL}")
    logger.info(f"API environment: {config.ENV}")
    logger.info(f"Deterministic validation: {'ENABLED' if config.ENABLE_DETERMINISTIC_VALIDATION else 'DISABLED'}")
    logger.info(f"Semantic validation: {'ENABLED' if config.ENABLE_SEMANTIC_VALIDATION else 'DISABLED'}")


def validate_config(config: APIConfig = APIConfig) -> list[str]:
    """
    Validate configuration settings.

    Args:
        config: APIConfig instance to validate

    Returns:
        List of validation errors (empty if valid)
    """
    errors = []

    # Validate port
    if not (1 <= config.PORT <= 65535):
        errors.append(f"Invalid port {config.PORT}: must be 1-65535")

    # Validate log level
    valid_levels = ["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"]
    if config.LOG_LEVEL not in valid_levels:
        errors.append(f"Invalid log level {config.LOG_LEVEL}: must be in {valid_levels}")

    # Validate policy profile exists
    try:
        from services.common.config import load_profile
        load_profile(config.DEFAULT_POLICY_PROFILE)
    except KeyError:
        errors.append(f"Policy profile not found: {config.DEFAULT_POLICY_PROFILE}")
    except Exception as e:
        errors.append(f"Error loading policy profile: {e}")

    # Validate timeouts
    if config.EXTRACTION_TIMEOUT_SEC <= 0:
        errors.append("EXTRACTION_TIMEOUT_SEC must be positive")
    if config.VALIDATION_TIMEOUT_SEC <= 0:
        errors.append("VALIDATION_TIMEOUT_SEC must be positive")
    if config.DECISION_TIMEOUT_SEC <= 0:
        errors.append("DECISION_TIMEOUT_SEC must be positive")

    return errors


# Singleton config instance
_config = None


def get_config() -> APIConfig:
    """Get the application config instance."""
    global _config
    if _config is None:
        _config = APIConfig()
        # Validate and log
        errors = validate_config(_config)
        if errors:
            logger = logging.getLogger(__name__)
            for error in errors:
                logger.error(f"Config error: {error}")
        setup_logging(_config)
    return _config
