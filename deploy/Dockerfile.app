# AIPAM Application Container
# Combines React frontend + FastAPI backend in a single container
# Build: docker build -t aipam-app:latest -f deploy/Dockerfile.app .

FROM node:20-slim AS frontend-builder

WORKDIR /app/frontend
COPY frontend/package*.json ./
RUN npm ci
COPY frontend/ ./
RUN npm run build

# ============================================
FROM python:3.11-slim AS backend

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    nginx \
    supervisor \
    && rm -rf /var/lib/apt/lists/*

# Install Python dependencies
COPY backend/requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

# Copy backend code
COPY backend/app ./app

# Copy built frontend from builder stage
COPY --from=frontend-builder /app/frontend/dist /app/static

# Create nginx config for serving frontend + proxying API
RUN cat > /etc/nginx/sites-available/default << 'EOF'
server {
    listen 80;
    server_name _;
    
    # Serve frontend static files
    location / {
        root /app/static;
        try_files $uri $uri/ /index.html;
    }
    
    # Proxy API requests to FastAPI
    location /api/ {
        proxy_pass http://127.0.0.1:8000/api/;
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_read_timeout 300s;
        proxy_connect_timeout 75s;
    }
    
    # WebSocket support for real-time updates
    location /ws {
        proxy_pass http://127.0.0.1:8000/ws;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host $host;
    }
}
EOF

# Create supervisord config
RUN cat > /etc/supervisor/conf.d/aipam.conf << 'EOF'
[supervisord]
nodaemon=true
logfile=/var/log/supervisor/supervisord.log
pidfile=/var/run/supervisord.pid

[program:nginx]
command=/usr/sbin/nginx -g "daemon off;"
autostart=true
autorestart=true
stdout_logfile=/var/log/nginx/access.log
stderr_logfile=/var/log/nginx/error.log

[program:fastapi]
command=uvicorn app.main:app --host 127.0.0.1 --port 8000
directory=/app
autostart=true
autorestart=true
stdout_logfile=/var/log/fastapi.log
stderr_logfile=/var/log/fastapi_error.log
environment=OLLAMA_HOST="http://ollama:11434"
EOF

# Create log directories
RUN mkdir -p /var/log/supervisor /var/log/nginx

# Create data directory for SQLite
RUN mkdir -p /app/data
VOLUME /app/data

EXPOSE 80

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD curl -f http://localhost/api/health || exit 1

CMD ["/usr/bin/supervisord", "-c", "/etc/supervisor/supervisord.conf"]

