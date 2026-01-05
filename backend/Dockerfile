FROM python:3.11-slim

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

# Install system dependencies including Zeek and Suricata.
# Zeek is installed from the official OBS repository for Debian 12.
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        ca-certificates \
        curl \
        gnupg \
        build-essential && \
    echo 'deb http://download.opensuse.org/repositories/security:/zeek/Debian_12/ /' > /etc/apt/sources.list.d/security:zeek.list && \
    curl -fsSL https://download.opensuse.org/repositories/security:zeek/Debian_12/Release.key | \
        gpg --dearmor > /etc/apt/trusted.gpg.d/security_zeek.gpg && \
    apt-get update && \
    apt-get install -y --no-install-recommends \
        zeek \
        suricata && \
    rm -rf /var/lib/apt/lists/*
# Ensure Zeek binary is discoverable via PATH for shutil.which("zeek")
RUN ln -s /opt/zeek/bin/zeek /usr/local/bin/zeek || true



WORKDIR /app

# Copy backend source
COPY app ./app

# Install Python dependencies directly (runtime-only)
RUN pip install --upgrade pip && \
    pip install \
        fastapi \
        uvicorn \
        sqlmodel \
        celery \
        redis \
        httpx \
        python-multipart \
        scapy

# Default runtime configuration (can be overridden by docker-compose)
ENV FILE_STORAGE_PATH=/data/storage \
    DATABASE_URL=sqlite:////data/aipam.db \
    REDIS_URL=redis://redis:6379/0 \
    LLM_ENDPOINT=http://ollama:11434/v1/chat/completions \
    LLM_MODEL_NAME=llama3.1:8b

VOLUME ["/data"]

EXPOSE 8000

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]

