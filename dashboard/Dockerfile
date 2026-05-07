FROM node:22-alpine
WORKDIR /app

RUN apk add --no-cache python3

COPY dashboard/package*.json ./
RUN npm ci

COPY dashboard/ ./
COPY scripts/ ./scripts/

ENV NODE_ENV=production
ENV SCRIPTS_DIR=/app/scripts
EXPOSE 8501

RUN npm run build
CMD ["npm", "start"]
