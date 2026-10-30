# Build Stage using official Python 3.12 slim
FROM python:3.12-slim AS builder

WORKDIR /build

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1

# Install uv for fast dependency resolution
COPY --from=ghcr.io/astral-sh/uv:0.5.24 /uv /bin/uv

# Copy project definition and contracts
COPY pyproject.toml README.md ./
COPY packages/ packages/
COPY apps/api/ apps/api/

# Install dependencies into virtual environment
RUN uv venv /app/.venv && \
    uv pip install --no-cache -e ".[dev]"

# Runtime Stage
FROM python:3.12-slim AS runner

WORKDIR /app

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PATH="/app/.venv/bin:$PATH"

# Create unprivileged system user
RUN groupadd -g 10001 cyberduel && \
    useradd -u 10001 -g cyberduel -s /bin/bash -m cyberduel

# Copy virtualenv and code from builder
COPY --from=builder /app/.venv /app/.venv
COPY --chown=cyberduel:cyberduel . /app/

RUN chmod +x /app/apps/api/entrypoint.sh

USER cyberduel

EXPOSE 8000

HEALTHCHECK --interval=15s --timeout=5s --start-period=10s --retries=3 \
  CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8000/health/live')" || exit 1

ENTRYPOINT ["/app/apps/api/entrypoint.sh"]

