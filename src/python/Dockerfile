# Stage 1: install dependencies
FROM python:3.12-slim AS builder
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir --target=/app/deps -r requirements.txt

# Stage 2: minimal distroless runtime — no shell, no package manager
FROM gcr.io/distroless/python3-debian12:nonroot
WORKDIR /app
COPY --from=builder /app/deps /app/deps
COPY app_fixed.py /app/app.py
ENV PYTHONPATH=/app/deps
EXPOSE 5000
ENTRYPOINT ["python", "app.py"]
