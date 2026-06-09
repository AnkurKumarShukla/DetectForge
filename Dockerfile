# ── Stage 1: dependency builder ───────────────────────────────────────────────
# Resolves and installs all production packages into an isolated venv.
# This stage is discarded; only the built .venv is carried forward.
FROM python:3.13-slim AS builder

COPY --from=ghcr.io/astral-sh/uv:latest /uv /usr/local/bin/uv

WORKDIR /app

# Layer-cache: reinstall only when dependency manifest changes
COPY pyproject.toml uv.lock ./
RUN uv sync --frozen --no-dev

# ── Stage 2: production runtime ───────────────────────────────────────────────
FROM python:3.13-slim

LABEL org.opencontainers.image.title="DetectForge" \
      org.opencontainers.image.description="Autonomous Detection Engineering Platform — Splunk Agentic Ops Hackathon 2026" \
      org.opencontainers.image.version="0.1.0"

WORKDIR /app

# Bring in the pre-resolved venv — no uv, no compiler, no package index needed
COPY --from=builder /app/.venv /app/.venv

# Application source (excludes .venv, data/, .env — see .dockerignore)
COPY api/       api/
COPY core/      core/
COPY db/        db/
COPY features/  features/
COPY scheduler/ scheduler/
COPY dashboard/ dashboard/
COPY scripts/   scripts/
# knowledge/ contains the 46 MB ATT&CK JSON + industry profiles + SPL seeds.
# Baking it in means the container starts fully offline with no download delay.
COPY knowledge/ knowledge/

# Persistent volume mount-point for SQLite database
RUN mkdir -p /data

ENV PATH="/app/.venv/bin:$PATH" \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    DATABASE_URL="sqlite:////data/detectforge.db"

EXPOSE 8077

HEALTHCHECK --interval=30s --timeout=10s --start-period=15s --retries=3 \
    CMD python -c \
      "import urllib.request; urllib.request.urlopen('http://localhost:8077/health')" \
      || exit 1

CMD ["uvicorn", "api.main:app", "--host", "0.0.0.0", "--port", "8077"]
