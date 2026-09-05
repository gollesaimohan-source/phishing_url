"""Configuration for the ScamShield application."""

import os
from pathlib import Path

try:
    from dotenv import load_dotenv
except ImportError:  # pragma: no cover - dependency may not be installed yet.
    load_dotenv = None

PROJECT_ROOT = Path(__file__).resolve().parent.parent
ENV_PATH = PROJECT_ROOT / ".env"

if load_dotenv is not None:
    load_dotenv(ENV_PATH)
else:
    if ENV_PATH.exists():
        for line in ENV_PATH.read_text(encoding="utf-8").splitlines():
            stripped = line.strip()
            if not stripped or stripped.startswith("#") or "=" not in stripped:
                continue
            key, value = stripped.split("=", 1)
            os.environ.setdefault(key.strip(), value.strip())


_INSECURE_SECRET_KEY = "scamshield-demo-secret"
_INSECURE_JWT_SECRET_KEY = "scamshield-development-jwt-secret"


class Config:
    """Default application configuration loaded from environment variables."""

    PROJECT_ROOT = PROJECT_ROOT
    SECRET_KEY = os.environ.get(
        "SECRET_KEY",
        os.environ.get("SCAMSHIELD_SECRET_KEY", _INSECURE_SECRET_KEY),
    )
    DEBUG = os.environ.get(
        "DEBUG",
        os.environ.get("FLASK_DEBUG", "false"),
    ).lower() in {"1", "true", "yes"}
    MONGODB_URI = os.environ.get("MONGODB_URI", "")
    DATABASE_NAME = os.environ.get("DATABASE_NAME", "scamshield")
    DATABASE_BACKEND = "mongodb"
    MONGODB_TIMEOUT_MS = int(os.environ.get("MONGODB_TIMEOUT_MS", "5000"))
    MONGODB_STRICT = os.environ.get("MONGODB_STRICT", "false").lower() in {
        "1",
        "true",
        "yes",
    }
    MAX_CONTENT_LENGTH = 16 * 1024 * 1024
    JWT_SECRET_KEY = os.environ.get(
        "JWT_SECRET_KEY",
        os.environ.get("SECRET_KEY", _INSECURE_JWT_SECRET_KEY),
    )
    JWT_EXPIRATION_MINUTES = int(os.environ.get("JWT_EXPIRATION_MINUTES", "60"))
    JWT_REFRESH_EXPIRATION_DAYS = int(
        os.environ.get("JWT_REFRESH_EXPIRATION_DAYS", "30")
    )
    BCRYPT_ROUNDS = int(os.environ.get("BCRYPT_ROUNDS", "12"))
    LOGIN_MAX_FAILED_ATTEMPTS = int(os.environ.get("LOGIN_MAX_FAILED_ATTEMPTS", "5"))
    LOGIN_RATE_LIMIT_WINDOW_MINUTES = int(
        os.environ.get("LOGIN_RATE_LIMIT_WINDOW_MINUTES", "15")
    )
    API_RATE_LIMIT_MAX_REQUESTS = int(
        os.environ.get("API_RATE_LIMIT_MAX_REQUESTS", "30")
    )
    API_RATE_LIMIT_WINDOW_SECONDS = int(
        os.environ.get("API_RATE_LIMIT_WINDOW_SECONDS", "60")
    )
    PASSWORD_RESET_TOKEN_EXPIRATION_MINUTES = int(
        os.environ.get("PASSWORD_RESET_TOKEN_EXPIRATION_MINUTES", "30")
    )
    SMTP_HOST = os.environ.get("SMTP_HOST", "")
    SMTP_PORT = int(os.environ.get("SMTP_PORT", "587"))
    SMTP_USERNAME = os.environ.get("SMTP_USERNAME", "")
    SMTP_PASSWORD = os.environ.get("SMTP_PASSWORD", "")
    SMTP_FROM = os.environ.get("SMTP_FROM", "no-reply@scamshield.local")
    FRONTEND_BASE_URL = os.environ.get("FRONTEND_BASE_URL", "http://127.0.0.1:5000")
    GOOGLE_FACT_CHECK_API_KEY = os.environ.get("GOOGLE_FACT_CHECK_API_KEY", "")
    SIGHTENGINE_API_USER = os.environ.get("SIGHTENGINE_API_USER", "")
    SIGHTENGINE_API_SECRET = os.environ.get("SIGHTENGINE_API_SECRET", "")
    LEGACY_SQLITE_PATH = os.environ.get(
        "SCAMSHIELD_DATABASE_PATH",
        str(PROJECT_ROOT / "scamshield.db"),
    )
    _CORS_ORIGINS = os.environ.get(
        "CORS_ORIGINS",
        os.environ.get("SCAMSHIELD_CORS_ORIGINS", "*"),
    )
    CORS_ORIGINS = (
        [origin.strip() for origin in _CORS_ORIGINS.split(",") if origin.strip()]
        if "," in _CORS_ORIGINS
        else _CORS_ORIGINS
    )
    DEMO_EMAIL = os.environ.get("SCAMSHIELD_DEMO_EMAIL", "demo@scamshield.com")
    DEMO_PASSWORD = os.environ.get("SCAMSHIELD_DEMO_PASSWORD", "scamshield123")
    JSON_SORT_KEYS = False

    @classmethod
    def validate(cls) -> list[str]:
        """Return a list of production-readiness warnings for the current config.

        Raises RuntimeError if the app is about to run in a non-debug
        environment with secrets that still have their insecure defaults,
        since that combination is unsafe to deploy.
        """
        warnings: list[str] = []
        # Prefer explicit environment variables for secrets. If the modern
        # `SECRET_KEY` or `JWT_SECRET_KEY` env vars are not explicitly set by
        # the process (for example they only come from a local `.env` file),
        # treat the configuration as insecure. This makes validation
        # deterministic for tests and avoids the situation where a repository
        # `.env` file masks missing production secrets.
        dotenv_values: dict[str, str] = {}
        try:
            if ENV_PATH.exists():
                for line in ENV_PATH.read_text(encoding="utf-8").splitlines():
                    stripped = line.strip()
                    if not stripped or stripped.startswith("#") or "=" not in stripped:
                        continue
                    key, value = stripped.split("=", 1)
                    dotenv_values[key.strip()] = value.strip()
        except Exception:
            # If we cannot read the .env file for any reason, fall back to
            # normal environment checks — do not fail validation because of IO.
            dotenv_values = {}

        def _is_explicit_env(key: str) -> bool:
            """Return True if an env var was explicitly provided (not only from .env)."""
            val = os.environ.get(key)
            if val is None:
                return False
            # If the value matches the one in the repository `.env`, consider
            # it a fallback rather than an explicit production secret.
            if key in dotenv_values and dotenv_values[key] == val:
                return False
            return True

        if not _is_explicit_env("SECRET_KEY"):
            warnings.append(
                "SECRET_KEY is using the insecure built-in default or local .env fallback. "
                "Set the SECRET_KEY environment variable."
            )
        if not _is_explicit_env("JWT_SECRET_KEY"):
            warnings.append(
                "JWT_SECRET_KEY is using the insecure built-in default or local .env fallback. "
                "Set the JWT_SECRET_KEY environment variable."
            )
        if cls.CORS_ORIGINS == "*":
            warnings.append(
                "CORS_ORIGINS is set to '*'. Restrict this to known frontend "
                "origins before deploying to production."
            )

        secret_warnings = [
            w for w in warnings if w.startswith(("SECRET_KEY", "JWT_SECRET_KEY"))
        ]
        if not cls.DEBUG and secret_warnings:
            raise RuntimeError(
                "Refusing to start with insecure configuration outside DEBUG "
                "mode:\n- " + "\n- ".join(secret_warnings)
            )
        return warnings
