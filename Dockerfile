# Stage 1: Build Web Frontend
FROM node:22-alpine AS frontend-builder
WORKDIR /app/web
COPY web/package*.json ./
RUN npm ci
COPY web/ ./
RUN npm run build

# Stage 2: Hardened Python Runtime
FROM python:3.12-slim AS runtime

# Security hardening: Prevent bytecode generation issues and ensure unbuffered output
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PORT=8000 \
    HOST=0.0.0.0

WORKDIR /app

# Install security updates and curl for healthcheck
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Create unprivileged application user
RUN groupadd -g 10001 taintwatch && \
    useradd -u 10001 -g taintwatch -s /bin/bash -m taintwatch

# Copy python dependencies definition
COPY pyproject.toml README.md ./
COPY src/ src/

# Install taintwatch with server extras
RUN pip install --no-cache-dir -e ".[server]"

# Copy built frontend assets from Stage 1
COPY --from=frontend-builder /app/web/dist /app/web/dist

# Set ownership to unprivileged user
RUN chown -R taintwatch:taintwatch /app

USER taintwatch

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:8000/api/health || exit 1

ENTRYPOINT ["python", "-m", "taintwatch.server"]
CMD ["--host", "0.0.0.0", "--port", "8000"]
