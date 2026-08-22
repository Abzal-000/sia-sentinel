# ============================================================
# SIA Sentinel - Production Docker Image (Linux)
# ============================================================

FROM python:3.11-slim AS builder

WORKDIR /app

RUN apt-get update && apt-get install -y \
    gcc \
    && rm -rf /var/lib/apt/lists/*

COPY requirements-docker.txt .

RUN python -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r requirements-docker.txt

# ============================================================
# Production stage
# ============================================================

FROM python:3.11-slim AS production

WORKDIR /app

RUN apt-get update && apt-get install -y \
    curl \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /opt/venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

COPY sia/ ./sia/
COPY sentinel/ ./sentinel/
COPY dashboard/ ./dashboard/
COPY policies/ ./policies/
# scripts/ нужен в образе: scripts/anchor_checkpoint.py гоняется кроном
# ЧЕРЕЗ docker compose exec (блокер 2 мини-аудита: крон падал, файла не было)
COPY scripts/ ./scripts/

RUN useradd -m -u 1000 siauser && \
    chown -R siauser:siauser /app

USER siauser

RUN mkdir -p logs evidence data

EXPOSE 8000 8501

HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:8000/health || exit 1

CMD ["uvicorn", "sentinel.api:app", "--host", "0.0.0.0", "--port", "8000"]
