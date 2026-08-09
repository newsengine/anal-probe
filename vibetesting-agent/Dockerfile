# VibeTesting Agent — Node host (Railway / Fly / any Docker)
FROM node:22-bookworm-slim AS build
WORKDIR /app
RUN apt-get update && apt-get install -y python3 make g++ && rm -rf /var/lib/apt/lists/*

# Parent scanner
COPY package.json package-lock.json* tsconfig.json ./
COPY src ./src
COPY scripts ./scripts
RUN npm ci || npm install
RUN npm run build

# Hosted app
WORKDIR /app/vibetesting-agent
COPY vibetesting-agent/package.json vibetesting-agent/package-lock.json* ./
RUN npm ci || npm install
COPY vibetesting-agent ./
RUN npm run build

FROM node:22-bookworm-slim
WORKDIR /app
ENV NODE_ENV=production
ENV DATABASE_PATH=/data/vta.db
RUN apt-get update && apt-get install -y python3 make g++ && rm -rf /var/lib/apt/lists/*
COPY --from=build /app /app
RUN mkdir -p /data
WORKDIR /app/vibetesting-agent
EXPOSE 3000
CMD ["npm", "run", "start"]
