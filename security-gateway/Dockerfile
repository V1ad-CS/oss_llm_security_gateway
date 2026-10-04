FROM golang:1.24-alpine AS gitleaks-builder
ARG GITLEAKS_VERSION=v8.30.1
# Статический бинарник: собирается на musl (alpine), а запускается на glibc (debian slim).
ENV CGO_ENABLED=0
RUN go install github.com/zricethezav/gitleaks/v8@${GITLEAKS_VERSION}

FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

COPY --from=gitleaks-builder /go/bin/gitleaks /usr/local/bin/gitleaks
COPY requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r /app/requirements.txt

COPY app.py guardrail_rules.py /app/
COPY policy.yaml /app/policy.yaml

RUN gitleaks version \
    && python -m py_compile /app/app.py \
    && python -c "import app; print('security-gateway import smoke test: OK')" \
    && useradd --system --uid 10001 --no-create-home --shell /usr/sbin/nologin gateway

USER gateway

EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=5s --start-period=30s --retries=3 \
    CMD ["python", "-c", "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8080/healthz', timeout=3)"]
CMD ["uvicorn", "app:app", "--host", "0.0.0.0", "--port", "8080"]
