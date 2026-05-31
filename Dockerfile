FROM python:3.11-slim

# Install system dependencies
RUN apt-get update && apt-get install -y \
    gcc \
    g++ \
    git \
    && rm -rf /var/lib/apt/lists/*

# Create user (HF requirement)
RUN useradd -m -u 1000 user
USER user
ENV PATH="/home/user/.local/bin:$PATH"
ENV HOME="/home/user"

WORKDIR /app

# Copy requirements first (for caching)
COPY --chown=user ./requirements.txt requirements.txt
RUN pip install --no-cache-dir --upgrade -r requirements.txt

# Copy all code
COPY --chown=user . /app

# HF Spaces requires port 7860
EXPOSE 7860

# Start with gunicorn
CMD ["gunicorn", "app.app:app", "--bind", "0.0.0.0:7860", "--workers", "1", "--timeout", "120", "--keep-alive", "5"]
