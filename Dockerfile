# Use a small Python base image
FROM python:3.11-slim

# System deps (only if wheels need compiling; safe to include)
RUN apt-get update && apt-get install -y --no-install-recommends \
        build-essential \
        openssl \
        curl \
    gosu \
    && rm -rf /var/lib/apt/lists/*

# Put the application code in /opt/app
WORKDIR /opt/app

# Install deps first for better Docker layer caching
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy the rest of your code
COPY . .

# Add a small entrypoint to wire persistent data in /data to the app working dir
COPY docker-entrypoint.sh /opt/app/docker-entrypoint.sh
RUN chmod +x /opt/app/docker-entrypoint.sh

# Create a dedicated runtime directory for files the server creates (chat.db, etc.)
# This keeps code (read-only) separate from data (read/write) and is easy to persist via a volume.
RUN useradd -m appuser && mkdir -p /data && chown -R appuser:appuser /opt/app /data
USER root

# The Python app binds to 8000 internally
EXPOSE 8000

# Keep working dir at /opt/app so static/ paths resolve; persist DB via symlink to /data
ENTRYPOINT ["/opt/app/docker-entrypoint.sh"]
CMD ["python", "/opt/app/server.py"]
