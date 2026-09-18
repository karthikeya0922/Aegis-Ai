"""Central configuration for the Aegis Inspector.

Every threshold, timeout and feature flag is declared here and sourced from the
environment. Nothing in the codebase is allowed to hardcode a tunable value --
see docs/AEGIS_PROBLEM_STATEMENT.md section 11.
"""

from __future__ import annotations

from functools import lru_cache
from pathlib import Path

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

BACKEND_ROOT = Path(__file__).resolve().parent.parent
CONFIG_DIR = BACKEND_ROOT / "config"
EVAL_DIR = BACKEND_ROOT / "eval"


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=(".env", "../.env"),
        env_file_encoding="utf-8",
        extra="ignore",
        case_sensitive=False,
    )

    # ---- Service identity -------------------------------------------------
    service_name: str = "aegis-inspector"
    version: str = "0.1.0"
    environment: str = Field(default="development")

    # ---- Storage ----------------------------------------------------------
    database_url: str = Field(default="sqlite:///./aegis.db", alias="DATABASE_URL")

    # ---- Policy -----------------------------------------------------------
    aegis_mode: str = Field(default="sanitize", alias="AEGIS_MODE")
    policy_profile: str = Field(default="default", alias="AEGIS_POLICY_PROFILE")

    # Secrets are never rehydrated. This flag exists so the value is explicit
    # in configuration rather than implicit in code, but the egress path
    # ignores a `true` value -- see spec section 3.
    secret_rehydration: bool = Field(default=False, alias="AEGIS_SECRET_REHYDRATION")
    pii_rehydration: bool = Field(default=True, alias="AEGIS_PII_REHYDRATION")

    # ---- Detection thresholds --------------------------------------------
    injection_threshold: float = Field(default=0.75, alias="AEGIS_INJECTION_THRESHOLD")
    pii_min_confidence: float = Field(default=0.50, alias="AEGIS_PII_MIN_CONFIDENCE")
    entropy_threshold: float = Field(default=4.0, alias="AEGIS_ENTROPY_THRESHOLD")
    entropy_min_length: int = Field(default=20, alias="AEGIS_ENTROPY_MIN_LENGTH")

    # ---- Grounded verification -------------------------------------------
    grounding_review_below: float = Field(default=0.75, alias="AEGIS_GROUNDING_REVIEW_BELOW")
    grounding_replace_below: float = Field(default=0.50, alias="AEGIS_GROUNDING_REPLACE_BELOW")
    grounding_fallback_text: str = Field(
        default="I cannot verify this claim against the supplied documentation.",
        alias="AEGIS_GROUNDING_FALLBACK_TEXT",
    )

    # ---- Models -----------------------------------------------------------
    embedding_model: str = Field(default="all-MiniLM-L6-v2", alias="AEGIS_EMBEDDING_MODEL")
    embedding_dim: int = Field(default=384, alias="AEGIS_EMBEDDING_DIM")
    nli_model: str = Field(
        default="cross-encoder/nli-deberta-v3-small", alias="AEGIS_NLI_MODEL"
    )
    spacy_model: str = Field(default="en_core_web_lg", alias="AEGIS_SPACY_MODEL")
    warm_models_on_startup: bool = Field(default=False, alias="AEGIS_WARM_MODELS")

    # ---- Vault ------------------------------------------------------------
    vault_ttl_seconds: int = Field(default=300, alias="AEGIS_VAULT_TTL_SECONDS")

    # ---- Cache hints ------------------------------------------------------
    # A request that contained personal data is not cacheable by default,
    # even after sanitisation. See config/routing.yaml.
    cache_allow_pii: bool = Field(default=False, alias="AEGIS_CACHE_ALLOW_PII")

    # ---- Privacy of our own audit log ------------------------------------
    user_hash_salt: str = Field(default="dev-salt-change-me", alias="AEGIS_USER_HASH_SALT")
    audit_retention_days: int = Field(default=30, alias="AEGIS_AUDIT_RETENTION_DAYS")

    # ---- Human oversight --------------------------------------------------
    override_token_ttl_seconds: int = Field(
        default=900, alias="AEGIS_OVERRIDE_TOKEN_TTL_SECONDS"
    )

    # ---- Transport limits -------------------------------------------------
    max_request_bytes: int = Field(default=256_000, alias="AEGIS_MAX_REQUEST_BYTES")
    cors_origins: str = Field(default="http://localhost:3000", alias="AEGIS_CORS_ORIGINS")
    # Per-tenant token bucket, in-process. 0 disables. See app/hardening.py.
    rate_limit_per_minute: int = Field(default=600, alias="AEGIS_RATE_LIMIT_PER_MINUTE")
    rate_limit_burst: int = Field(default=60, alias="AEGIS_RATE_LIMIT_BURST")
    # Bounded wait for the Gateway; work on the threadpool is not cancelled. 0 disables.
    request_timeout_seconds: float = Field(default=20.0, alias="AEGIS_REQUEST_TIMEOUT_SECONDS")

    # ---- Operator auth (shared secrets; RBAC lives in the Gateway) ----------
    reviewer_token: str | None = Field(default=None, alias="AEGIS_REVIEWER_TOKEN")
    admin_token: str | None = Field(default=None, alias="AEGIS_ADMIN_TOKEN")

    # ---- Retention scheduler ----------------------------------------------
    purge_interval_hours: float = Field(default=6.0, alias="AEGIS_PURGE_INTERVAL_HOURS")

    @field_validator("aegis_mode")
    @classmethod
    def _validate_mode(cls, v: str) -> str:
        allowed = {"allow", "sanitize", "warn", "block", "strict"}
        if v.lower() not in allowed:
            raise ValueError(f"AEGIS_MODE must be one of {sorted(allowed)}")
        return v.lower()

    @property
    def cors_origin_list(self) -> list[str]:
        return [o.strip() for o in self.cors_origins.split(",") if o.strip()]

    @property
    def policies_path(self) -> Path:
        return CONFIG_DIR / "policies.yaml"

    @property
    def secret_patterns_path(self) -> Path:
        return CONFIG_DIR / "secret_patterns.yaml"

    @property
    def injection_rules_path(self) -> Path:
        return CONFIG_DIR / "injection_rules.yaml"

    @property
    def routing_path(self) -> Path:
        return CONFIG_DIR / "routing.yaml"


@lru_cache
def get_settings() -> Settings:
    return Settings()


settings = get_settings()
