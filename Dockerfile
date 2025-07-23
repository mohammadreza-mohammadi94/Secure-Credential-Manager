# --- Stage 1: The Builder ---
# This stage installs dependencies, including build-time tools.
FROM python:3.11-slim AS builder

WORKDIR /app

# Install build-time system dependencies
RUN apt-get update && apt-get install -y \
    gcc \
    g++ \
    && rm -rf /var/lib/apt/lists/*

# Install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt


# --- Stage 2: The Final Image ---
# This stage is clean and only contains the runtime environment.
FROM python:3.11-slim

WORKDIR /app

# Install runtime-only system dependencies (like curl for the healthcheck)
RUN apt-get update && apt-get install -y curl && rm -rf /var/lib/apt/lists/*

# Copy the installed Python packages from the builder stage
COPY --from=builder /usr/local/lib/python3.11/site-packages /usr/local/lib/python3.11/site-packages
COPY --from=builder /usr/local/bin /usr/local/bin

# --- CHANGE: Copy all .py files from the root directory ---
COPY *.py ./

# Create and switch to a non-root user
RUN groupadd -r appuser && useradd -r -g appuser appuser
RUN chown -R appuser:appuser /app
USER appuser

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:8501/_stcore/health || exit 1

# Expose port and run the application
EXPOSE 8501
CMD ["streamlit", "run", "main.py"]