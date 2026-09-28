FROM golang:1.24-alpine AS gitleaks-builder
ARG GITLEAKS_VERSION=v8.30.1
RUN go install github.com/zricethezav/gitleaks/v8@${GITLEAKS_VERSION}

FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

COPY --from=gitleaks-builder /go/bin/gitleaks /usr/local/bin/gitleaks
COPY requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r /app/requirements.txt

COPY app.py /app/app.py
COPY policy.yaml /app/policy.yaml

RUN python -m py_compile /app/app.py && python -c "import app; print('security-gateway import smoke test: OK')"

EXPOSE 8080
CMD ["uvicorn", "app:app", "--host", "0.0.0.0", "--port", "8080"]
