FROM python:3.11-slim

ARG CAPA_VERSION=9.3.1

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    AIPAM_CAPA_RULES_DIR=/opt/aipam/rules/capa \
    AIPAM_CAPA_SIGNATURES_DIR=/opt/aipam/signatures/capa

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
    suricata \
    suricata-update && \
    rm -rf /var/lib/apt/lists/*

# Ensure Zeek binary is discoverable via PATH for shutil.which("zeek")
RUN ln -s /opt/zeek/bin/zeek /usr/local/bin/zeek || true

# Download Suricata rules (ET Open ruleset)
RUN suricata-update --no-test && \
    suricata-update update-sources && \
    suricata-update enable-source et/open || true



WORKDIR /app

# Copy backend source
COPY app ./app

# Create 'backend' package alias so "from backend.app.X" imports work
# (code uses absolute imports like "from backend.app.models.job import Job")
COPY __init__.py ./backend/__init__.py
RUN ln -s /app/app /app/backend/app

ENV PYTHONPATH=/app

# Install Python dependencies from requirements.txt
COPY requirements.txt ./requirements.txt
RUN pip install --upgrade pip && \
    pip install -r requirements.txt && \
    pip install "flare-capa==${CAPA_VERSION}" && \
    mkdir -p "${AIPAM_CAPA_RULES_DIR}" "${AIPAM_CAPA_SIGNATURES_DIR}" /opt/aipam/rules/suricata && \
    curl -fsSL "https://github.com/mandiant/capa-rules/archive/refs/tags/v${CAPA_VERSION}.tar.gz" | \
      tar -xz -C "${AIPAM_CAPA_RULES_DIR}" --strip-components=1 && \
    for sig in 1_flare_msvc_rtf_32_64.sig 2_flare_msvc_atlmfc_32_64.sig 3_flare_common_libs.sig; do \
      curl -fsSL "https://raw.githubusercontent.com/mandiant/capa/v${CAPA_VERSION}/sigs/${sig}" \
        -o "${AIPAM_CAPA_SIGNATURES_DIR}/${sig}"; \
    done

# Default runtime configuration (can be overridden by docker-compose)
ENV FILE_STORAGE_PATH=/data/storage \
    DATABASE_URL=sqlite:////data/aipam.db \
    REDIS_URL=redis://redis:6379/0 \
    LLM_ENDPOINT=http://ollama:11434/v1/chat/completions \
    LLM_MODEL_NAME=llama3.1:8b

VOLUME ["/data"]

EXPOSE 8000

CMD ["uvicorn", "app.main_v2:create_app", "--factory", "--host", "0.0.0.0", "--port", "8000"]

