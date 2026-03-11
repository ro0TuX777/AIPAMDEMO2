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

EXPOSE 80

CMD ["nginx", "-g", "daemon off;"]

