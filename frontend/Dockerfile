# Build stage: compile the React/Vite frontend
FROM node:20-alpine AS build

WORKDIR /app

COPY package*.json ./
RUN npm install

COPY . .

# In containerized/prod mode, the frontend talks to the backend via Nginx at
# the same origin, using a relative API base.
ENV VITE_API_BASE_URL=/api/v1

# API token baked into the frontend build for authenticated requests
ARG VITE_API_TOKEN
ENV VITE_API_TOKEN=${VITE_API_TOKEN}

RUN npm run build

# Runtime stage: serve static assets with Nginx
FROM nginx:1.27-alpine

COPY --from=build /app/dist /usr/share/nginx/html
COPY nginx.conf /etc/nginx/nginx.conf

# Entrypoint writes /usr/share/nginx/html/runtime-config.js from
# $AIPAM_API_TOKEN at container start — see frontend/docker-entrypoint.sh.
COPY docker-entrypoint.sh /docker-entrypoint.sh
RUN chmod +x /docker-entrypoint.sh

EXPOSE 80

ENTRYPOINT ["/docker-entrypoint.sh"]

