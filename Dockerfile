FROM python:3.11-slim

WORKDIR /app

# System dependencies for wappalyzer/playwright and general builds
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    curl \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.docker.txt ./
RUN pip install --no-cache-dir -r requirements.docker.txt

# Optional: install playwright chromium for wappalyzer
# RUN playwright install --with-deps chromium

COPY . .

EXPOSE 5003

CMD ["streamlit", "run", "app.py", \
     "--server.port=5003", \
     "--server.address=0.0.0.0", \
     "--server.headless=true", \
     "--browser.gatherUsageStats=false"]
