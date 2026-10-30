FROM python:3.12-slim

WORKDIR /app

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

# Create dedicated unprivileged lab user
RUN groupadd -g 20001 labworker && \
    useradd -u 20001 -g labworker -s /bin/sh -m labworker

COPY --from=ghcr.io/astral-sh/uv:0.5.24 /uv /bin/uv

COPY pyproject.toml README.md ./
COPY packages/ packages/
COPY services/ services/

RUN uv venv /app/.venv && \
    /app/.venv/bin/python -m ensurepip || true && \
    uv pip install --no-cache -e "."

ENV PATH="/app/.venv/bin:$PATH"

USER labworker

CMD ["python", "services/lab-worker/app/worker.py"]

