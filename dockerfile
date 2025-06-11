FROM node:20-slim

WORKDIR /usr/src/app

# RUN npm install -g npm@11.3.0

# Instalar OpenSSL explícitamente
RUN apt-get update -y && apt-get install -y openssl procps && rm -rf /var/lib/apt/lists/*

# Configurar npm para usar un mirror alternativo
RUN npm config set registry https://registry.npmjs.org/ && \
npm config set fetch-timeout 600000 && \
npm config set fetch-retries 5 && \
npm config set fetch-retry-mintimeout 10000 && \
npm config set fetch-retry-maxtimeout 120000 && \
npm config set maxsockets 5


COPY package*.json ./


RUN npm ci --only=production --no-audit --no-fund --prefer-offline || \
    npm install --only=production --no-audit --no-fund
# RUN npm install 

COPY . .

EXPOSE 3002