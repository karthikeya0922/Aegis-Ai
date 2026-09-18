# Aegis Inspector
#
# Two-stage by dependency weight, not by build artifact: the base image serves
# the full contract with no model downloads (Phases 0-8), and the `ml` stage
# adds Presidio, spaCy and sentence-transformers with the weights baked in.
#
# Baking the models into the image is deliberate -- a cold model download
# during a live demo is the most likely way this service embarrasses us.
#
#   docker build --target base -t aegis-inspector:base .
#   docker build --target ml   -t aegis-inspector:ml   .

FROM python:3.11-slim AS base

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /srv

RUN apt-get update \
 && apt-get install -y --no-install-recommends curl \
 && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app ./app
COPY config ./config
COPY alembic.ini .
COPY migrations ./migrations

# Run unprivileged. The SQLite default lives under /srv/data; mount a volume
# there or point DATABASE_URL at Postgres.
RUN mkdir -p /srv/data
ENV DATABASE_URL=sqlite:////srv/data/aegis.db

# Run unprivileged.
RUN useradd --system --uid 10001 aegis && chown -R aegis:aegis /srv
USER aegis

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=3s --start-period=10s --retries=3 \
  CMD curl -fsS http://localhost:8000/api/health || exit 1

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]


# --------------------------------------------------------------------------
FROM base AS ml

USER root

COPY requirements-ml.txt .
RUN pip install --no-cache-dir -r requirements-ml.txt \
 && python -m spacy download en_core_web_lg

# Pre-fetch transformer weights into the image layer: the embedding model
# (semantic cache, fairness harness) and the NLI cross-encoder (grounding).
# Without the second one grounding reports SKIPPED -- never a faked score --
# but a demo that shows SKIPPED is a demo that forgot this line.
ARG AEGIS_EMBEDDING_MODEL=all-MiniLM-L6-v2
ARG AEGIS_NLI_MODEL=cross-encoder/nli-deberta-v3-small
RUN python - <<'PY'
import os
from sentence_transformers import CrossEncoder, SentenceTransformer
SentenceTransformer(os.environ.get("AEGIS_EMBEDDING_MODEL", "all-MiniLM-L6-v2"))
CrossEncoder(os.environ.get("AEGIS_NLI_MODEL", "cross-encoder/nli-deberta-v3-small"))
PY

COPY eval ./eval

RUN chown -R aegis:aegis /srv
USER aegis

ENV AEGIS_WARM_MODELS=true

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
