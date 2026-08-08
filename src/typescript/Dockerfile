# Stage 1: build TypeScript to JavaScript
FROM node:20-alpine AS builder
WORKDIR /app
COPY package.json tsconfig.json ./
RUN npm install
COPY src ./src
RUN npm run build

# Stage 2: production deps only
FROM node:20-alpine AS deps
WORKDIR /app
COPY package.json .
RUN npm install --production

# Stage 3: distroless Node.js runtime
FROM gcr.io/distroless/nodejs20-debian12:nonroot
WORKDIR /app
COPY --from=deps /app/node_modules ./node_modules
COPY --from=builder /app/dist ./dist
EXPOSE 9003
CMD ["dist/app_fixed.js"]
