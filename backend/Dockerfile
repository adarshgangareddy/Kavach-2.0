# Kavach API: FastAPI + the taint detector, Bandit and Semgrep.
FROM python:3.11-slim-bookworm

ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PIP_NO_CACHE_DIR=1 PIP_DISABLE_PIP_VERSION_CHECK=1

# git: GitHub-link scans clone the repository.
# apt over HTTPS: plain-HTTP package downloads are tampered with or dropped on some networks.
RUN sed -i 's|http://deb.debian.org|https://deb.debian.org|g' /etc/apt/sources.list.d/debian.sources \
    && apt-get update \
    && apt-get install -y --no-install-recommends git \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY pyproject.toml ./
COPY app ./app
RUN pip install . bandit

# Semgrep gets its own virtualenv: it pins opentelemetry versions that conflict with FastAPI.
# Build with --build-arg WITH_SEMGREP=false for a smaller image without it.
ARG WITH_SEMGREP=true
RUN if [ "$WITH_SEMGREP" = "true" ]; then \
        python -m venv /opt/semgrep \
        && /opt/semgrep/bin/pip install semgrep \
        && ln -s /opt/semgrep/bin/semgrep /usr/local/bin/semgrep; \
    fi

COPY sentinel-rules.toml sentinel-model.json ./

# Run as an unprivileged user; scan data lives in the /data volume.
RUN useradd --create-home --uid 10001 kavach && mkdir -p /data && chown kavach:kavach /data
USER kavach

ENV SENTINEL_DATA=/data \
    SENTINEL_RULES=/app/sentinel-rules.toml \
    SENTINEL_MODEL=/app/sentinel-model.json

EXPOSE 8000
HEALTHCHECK --interval=10s --timeout=3s --start-period=10s --retries=5 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/health')"
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
