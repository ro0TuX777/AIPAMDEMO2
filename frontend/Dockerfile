# Build stage: compile the React/Vite frontend
FROM node:20-alpine AS build

WORKDIR /app

COPY package*.json ./
RUN npm install

COPY . .

# In containerized/prod mode, the frontend talks to the backend via Nginx at
# the same origin, using a relative API base.
ENV VITE_API_BASE_URL=/api/v1

RUN npm run build

# Runtime stage: serve static assets with Nginx
FROM nginx:1.27-alpine

COPY --from=build /app/dist /usr/share/nginx/html
COPY nginx.conf /etc/nginx/nginx.conf

EXPOSE 80

CMD ["nginx", "-g", "daemon off;"]

