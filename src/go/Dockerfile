# Stage 1: build
FROM golang:1.21-alpine AS builder
RUN apk add --no-cache gcc musl-dev sqlite-dev
WORKDIR /app
COPY go.mod .
COPY main_fixed.go .
RUN go mod tidy
RUN go mod download
RUN CGO_ENABLED=1 GOOS=linux go build -o server main_fixed.go
# Verify binary was created
RUN ls -la /app/server && /app/server --help || true

# Stage 2: alpine slim (not distroless) — has musl libc needed by CGO
FROM alpine:3.19
RUN apk add --no-cache sqlite-libs
WORKDIR /app
COPY --from=builder /app/server .
RUN ls -la /app/server
EXPOSE 9001
ENTRYPOINT ["/app/server"]
