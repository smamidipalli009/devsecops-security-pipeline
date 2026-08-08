# Stage 1: build static binary
FROM golang:1.21-alpine AS builder
RUN apk add --no-cache gcc musl-dev sqlite-dev
WORKDIR /app
COPY go.mod .
RUN go mod download
COPY main_fixed.go .
RUN CGO_ENABLED=1 GOOS=linux go build -o server main_fixed.go

# Stage 2: distroless static runtime
FROM gcr.io/distroless/base-debian12:nonroot
WORKDIR /app
COPY --from=builder /app/server .
EXPOSE 9001
ENTRYPOINT ["/app/server"]
