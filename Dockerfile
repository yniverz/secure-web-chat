# Use a small Python base image
FROM python:3.11-slim

# System deps (only if wheels need compiling; safe to include)
RUN apt-get update && apt-get install -y --no-install-recommends build-essential \
    && rm -rf /var/lib/apt/lists/*

# Put the application code in /opt/app
WORKDIR /opt/app

# Install deps first for better Docker layer caching
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy the rest of your code
COPY . .

# Create a dedicated runtime directory for files the server creates (chat.db, etc.)
# This keeps code (read-only) separate from data (read/write) and is easy to persist via a volume.
RUN useradd -m appuser && mkdir -p /data && chown -R appuser:appuser /opt/app /data
USER appuser

# The Python app binds to 8000 internally (as you said)
EXPOSE 8000

# Run the app; cwd is /data so runtime files are created there
WORKDIR /data
CMD ["python", "/opt/app/server.py"]
