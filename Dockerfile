# Purple Team GRC - Multi-stage Docker Build
# Supports API server, worker, and scanner containers

# =============================================================================
# Stage 1: Base Image
# =============================================================================
FROM python:3.11-slim AS base

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    postgresql-client \
    nmap \
    curl \
    git \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Create application directory
WORKDIR /app

# Copy project structure
COPY bin/ /app/bin/
COPY lib/ /app/lib/
COPY scanners/ /app/scanners/
COPY utilities/ /app/utilities/
COPY config/ /app/config/
COPY requirements.txt /app/

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Create data directories
RUN mkdir -p /app/data/evidence /app/data/results /app/data/logs \
    /app/data/reports /app/data/archives /app/tools

# Set environment variables
ENV PYTHONUNBUFFERED=1
ENV PURPLE_TEAM_HOME=/app

# =============================================================================
# Stage 2: API Server
# =============================================================================
FROM base AS api

# Expose API port
EXPOSE 8443

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=40s --retries=3 \
    CMD curl -f http://localhost:8443/health || exit 1

# Run API server
CMD ["python", "/app/bin/start-server.py", "--host", "0.0.0.0", "--port", "8443"]

# =============================================================================
# Stage 3: Worker (Scheduler + Background Tasks)
# =============================================================================
FROM base AS worker

# Run background worker
CMD ["python", "/app/bin/run-worker.py"]

# =============================================================================
# Stage 4: Scanner (For running scans in container)
# =============================================================================
FROM base AS scanner

# Interactive scan mode
CMD ["python", "/app/bin/purple-launcher", "--non-interactive"]
