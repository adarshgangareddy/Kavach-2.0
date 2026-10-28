# Demo Flask app that reports attack attempts to Kavach.
# Build from the repository root, so the telemetry file can be copied in:
#   docker build -f demo/monitored-app/Dockerfile -t kavach-demo-shop .
FROM python:3.11-slim-bookworm

ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PIP_NO_CACHE_DIR=1 PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /app
COPY demo/monitored-app/requirements.txt ./
RUN pip install -r requirements.txt
COPY telemetry/kavach_telemetry.py demo/monitored-app/app.py ./
COPY demo/monitored-app/files ./files

RUN useradd --uid 10002 shop
USER shop

EXPOSE 5000
CMD ["gunicorn", "--bind", "0.0.0.0:5000", "--workers", "2", "app:app"]
