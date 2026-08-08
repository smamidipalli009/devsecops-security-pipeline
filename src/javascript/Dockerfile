# Stage 1: install dependencies
FROM node:20-alpine AS builder
WORKDIR /app
COPY package.json .
RUN npm install --production

# Stage 2: distroless Node.js runtime
FROM gcr.io/distroless/nodejs20-debian12:nonroot
WORKDIR /app
COPY --from=builder /app/node_modules ./node_modules
COPY app_fixed.js .
EXPOSE 9002
CMD ["app_fixed.js"]
