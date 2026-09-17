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

# Pre-fetch transformer weights into the image layer.
RUN python - <<'PY'
from sentence_transformers import SentenceTransformer
SentenceTransformer("all-MiniLM-L6-v2")
PY

COPY eval ./eval

RUN chown -R aegis:aegis /srv
USER aegis

ENV AEGIS_WARM_MODELS=true

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
