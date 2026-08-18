# Use a slim Python 3.11 base image
FROM python:3.11-slim

# Prevent Python from writing pyc files to disc
ENV PYTHONDONTWRITEBYTECODE=1
# Prevent Python from buffering stdout and stderr
ENV PYTHONUNBUFFERED=1

# Install system dependencies required for psycopg2 and health checks
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        libpq-dev \
        gcc \
        curl \
    && rm -rf /var/lib/apt/lists/*

# Create a non-root user and group
RUN groupadd -r appgroup && useradd -r -g appgroup -m -d /home/appuser appuser

# Set working directory
WORKDIR /app

# Copy requirements and install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy the entire application source code
COPY . .

# Ensure the application directory is owned by the non-root user
RUN chown -R appuser:appgroup /app

# Set PYTHONPATH to include the project root
ENV PYTHONPATH=/app

# Expose the service port
EXPOSE 8080

# Switch to the non-root user
USER appuser

# Define the command to run the application
CMD ["python", "cmd/audit-service/main.py"]
