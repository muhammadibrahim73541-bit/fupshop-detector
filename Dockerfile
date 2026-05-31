# Use Python 3.11 (compatible with our packages)
FROM python:3.11-slim

# Install system dependencies for compilation
RUN apt-get update && apt-get install -y \
    gcc \
    g++ \
    && rm -rf /var/lib/apt/lists/*

# Create user
RUN useradd -m -u 1000 user
USER user
ENV PATH="/home/user/.local/bin:$PATH"

WORKDIR /app

# Copy requirements first (for caching)
COPY --chown=user ./requirements.txt requirements.txt
RUN pip install --no-cache-dir --upgrade -r requirements.txt

# Copy all code
COPY --chown=user . /app

# Hugging Face requires port 7860
CMD ["gunicorn", "app.app:app", "--bind", "0.0.0.0:7860", "--workers", "1", "--timeout", "60"]
