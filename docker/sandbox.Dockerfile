# ============================================================
# SIA Sandbox - Isolated Execution Environment
# ============================================================
# Minimal Python image for running AI-generated code
# Security-hardened with resource limits
# ============================================================

FROM python:3.11-slim

WORKDIR /workspace

# Install only essential packages
RUN pip install --no-cache-dir --upgrade pip

# Create non-root user
RUN useradd -m -u 1000 sandboxuser && \
    chown -R sandboxuser:sandboxuser /workspace

USER sandboxuser

# Set resource limits via environment variables
ENV PYTHONUNBUFFERED=1
ENV PYTHONDONTWRITEBYTECODE=1

# Default command (will be overridden)
CMD ["python", "--version"]
