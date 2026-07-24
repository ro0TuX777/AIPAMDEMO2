# AIPAM V2 Application Container
# Backend only — API server and Celery worker share this image.
# Frontend is served by a separate nginx container (frontend/Dockerfile).
#
# Build: docker build -t aipam-app:latest -f deploy/Dockerfile.app .
# Usage (API):    docker run ... aipam-app:latest uvicorn backend.app.main_v2:create_app --factory --host 0.0.0.0 --port 8000
# Usage (Worker): docker run ... aipam-app:latest celery -A backend.app.worker worker --loglevel=info

FROM python:3.12-slim

ARG CAPA_VERSION=9.3.1

ENV AIPAM_CAPA_RULES_DIR=/opt/aipam/rules/capa \
    AIPAM_CAPA_SIGNATURES_DIR=/opt/aipam/signatures/capa

WORKDIR /app

# System deps: curl for healthcheck, gnupg/ca-certs for Zeek repo,
# zeek + suricata for the pipeline stages, tshark + tcpdump for the Streams
# forensics endpoints (follow-stream transcript, per-packet hexdump, carving).
# Preseed wireshark-common so the tshark install stays non-interactive; setuid
# is unnecessary since we only read PCAP files, never capture live traffic.
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    curl \
    gnupg \
    && echo 'deb http://download.opensuse.org/repositories/security:/zeek/Debian_12/ /' \
       > /etc/apt/sources.list.d/security:zeek.list \
    && curl -fsSL https://download.opensuse.org/repositories/security:zeek/Debian_12/Release.key \
       | gpg --dearmor > /etc/apt/trusted.gpg.d/security_zeek.gpg \
    && apt-get update \
    && echo "wireshark-common wireshark-common/install-setuid boolean false" | debconf-set-selections \
    && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
       zeek \
       suricata \
       suricata-update \
       tshark \
       tcpdump \
    && rm -rf /var/lib/apt/lists/*

# Ensure zeek is on PATH
RUN ln -sf /opt/zeek/bin/zeek /usr/local/bin/zeek 2>/dev/null || true

# Download Suricata rules (ET Open ruleset)
RUN suricata-update --no-test \
    && suricata-update update-sources \
    && suricata-update enable-source et/open || true

# Python dependencies
COPY backend/requirements.txt /tmp/requirements.txt
RUN pip install --no-cache-dir -r /tmp/requirements.txt \
    && pip install --no-cache-dir "flare-capa==${CAPA_VERSION}" \
    && mkdir -p "${AIPAM_CAPA_RULES_DIR}" "${AIPAM_CAPA_SIGNATURES_DIR}" \
    && curl -fsSL "https://github.com/mandiant/capa-rules/archive/refs/tags/v${CAPA_VERSION}.tar.gz" \
       | tar -xz -C "${AIPAM_CAPA_RULES_DIR}" --strip-components=1 \
    && for sig in 1_flare_msvc_rtf_32_64.sig 2_flare_msvc_atlmfc_32_64.sig 3_flare_common_libs.sig; do \
         curl -fsSL "https://raw.githubusercontent.com/mandiant/capa/v${CAPA_VERSION}/sigs/${sig}" \
           -o "${AIPAM_CAPA_SIGNATURES_DIR}/${sig}"; \
       done \
    && rm /tmp/requirements.txt

# Copy backend as a proper Python package (imports use "backend.app.*")
COPY backend/ /app/backend/

# Alembic config at repo root (env.py references backend.app.*)
COPY alembic.ini /app/alembic.ini

# Create required directories
RUN mkdir -p /data /jobs /uploads /opt/aipam/logs /opt/aipam/sensor-config /opt/aipam/rules/suricata /import-queue

# Non-root user for API; worker overrides to root for Docker socket access
RUN groupadd -r aipam && useradd -r -g aipam -d /app aipam \
    && chown -R aipam:aipam /app /data /jobs /uploads /opt/aipam /import-queue

# Default environment
ENV PYTHONPATH=/app \
    PYTHONUNBUFFERED=1

EXPOSE 8000

# Health check (for API mode — worker has no HTTP port)
HEALTHCHECK --interval=30s --timeout=10s --start-period=15s --retries=3 \
    CMD curl -sf http://localhost:8000/api/v1/health || exit 1

# Default command — API server (override in docker-compose for worker)
CMD ["uvicorn", "backend.app.main_v2:create_app", "--factory", "--host", "0.0.0.0", "--port", "8000"]

