FROM python:3.11-slim

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    curl \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

RUN mkdir -p /app/data

ENV FLASK_ENV=production
ENV DATA_DIR=/app/data

EXPOSE 5001

CMD ["gunicorn", "--config", "gunicorn.conf.py", "api:app"]
