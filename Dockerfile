# Build a simple FastAPI app image
FROM python:3.11-slim

# System deps (faster DNS & whois needs whois lib sometimes, but python-whois is pure python; keep slim)
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy dependency list first for better caching
COPY requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r /app/requirements.txt

# Copy app code
COPY backend /app/backend
COPY web /app/web

# Expose app
EXPOSE 8080

# Run uvicorn
CMD ["uvicorn", "backend.main:app", "--host", "0.0.0.0", "--port", "8080"]
