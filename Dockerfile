# Stage 1: Build & dependency resolver
FROM python:3.11-slim AS builder

WORKDIR /app

# Install uv for rapid, secure, and reproducible dependency installation
RUN pip install --no-cache-dir uv

# Copy project definition files
COPY pyproject.toml uv.lock ./

# Install dependencies into system packages
RUN uv pip install --system --no-cache -r pyproject.toml

# Stage 2: Final minimal runner image
FROM python:3.11-slim AS runner

WORKDIR /app

# Create a system user and group with explicit non-root UID/GID
RUN groupadd -g 10001 appgroup && \
    useradd -u 10001 -g appgroup -m -s /bin/bash appuser

# Copy installed dependencies from the builder stage
COPY --from=builder /usr/local/lib/python3.11/site-packages /usr/local/lib/python3.11/site-packages
COPY --from=builder /usr/local/bin /usr/local/bin

# Copy application source code
COPY main.py schemas.py ./

# Ensure ownership is assigned to the non-root user
RUN chown -R appuser:appgroup /app

# Switch to the non-root user
USER appuser

EXPOSE 8000

ENV PYTHONUNBUFFERED=1

# Run the FastAPI server via uvicorn
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]
