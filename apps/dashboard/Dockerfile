# Multi-stage production build for CyberDuel Command Center Dashboard
# Stage 1: Build React/Vite SPA
FROM node:20-alpine AS builder

WORKDIR /app

# Cache package dependencies
COPY package*.json ./
RUN npm ci

# Copy source and build
COPY . .
RUN npm run build

# Stage 2: Serve static distribution via lightweight NGINX
FROM nginx:alpine AS runner

WORKDIR /usr/share/nginx/html

# Clean default assets and copy production build
RUN rm -rf ./*
COPY --from=builder /app/dist /usr/share/nginx/html
COPY nginx.conf /etc/nginx/templates/default.conf.template
COPY nginx.conf /etc/nginx/conf.d/default.conf

EXPOSE 80

HEALTHCHECK --interval=15s --timeout=5s --start-period=5s --retries=3 \
  CMD wget --quiet --tries=1 --spider http://localhost:${PORT:-80}/health/live || exit 1

CMD ["nginx", "-g", "daemon off;"]

