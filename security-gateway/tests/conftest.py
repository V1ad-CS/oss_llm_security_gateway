import os
import sys
from pathlib import Path

GATEWAY_DIR = Path(__file__).resolve().parents[1]

# app.py читает policy.yaml при импорте; по умолчанию путь /app/policy.yaml (внутри контейнера).
os.environ.setdefault("POLICY_FILE", str(GATEWAY_DIR / "policy.yaml"))
sys.path.insert(0, str(GATEWAY_DIR))


def pytest_configure(config):
    config.addinivalue_line("markers", "real_gitleaks: needs the gitleaks binary on PATH")
