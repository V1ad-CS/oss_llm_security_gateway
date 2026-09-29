import hashlib
import io
import json
import logging
import os
import re
import subprocess
import tempfile
import uuid
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any

import clamd
import httpx
import yaml
from fastapi import FastAPI, File, HTTPException, Request, UploadFile
from fastapi.concurrency import run_in_threadpool
from fastapi.responses import JSONResponse, Response, StreamingResponse
from presidio_analyzer import Pattern, PatternRecognizer
from pydantic import BaseModel, Field

try:
    from natasha import Doc, NewsEmbedding, NewsNERTagger, Segmenter
    NATASHA_AVAILABLE = True
except Exception:
    NATASHA_AVAILABLE = False


def env_flag(name: str, default: bool) -> bool:
    """Parse a boolean env var; unknown values fall back to the (safe) default."""
    value = os.getenv(name, "").strip().lower()
    if value in {"1", "true", "yes", "on"}:
        return True
    if value in {"0", "false", "no", "off"}:
        return False
    return default


APP_NAME = "oss-llm-security-gateway"
MAX_TEXT_CHARS = int(os.getenv("MAX_TEXT_CHARS", "500000"))
MAX_FILE_BYTES = int(os.getenv("MAX_FILE_BYTES", str(25 * 1024 * 1024)))
TIKA_URL = os.getenv("TIKA_URL", "http://tika:9998").rstrip("/")
CLAMAV_HOST = os.getenv("CLAMAV_HOST", "clamav")
CLAMAV_PORT = int(os.getenv("CLAMAV_PORT", "3310"))
CLAMAV_TIMEOUT = float(os.getenv("CLAMAV_TIMEOUT", "60"))
FAIL_CLOSED = env_flag("FAIL_CLOSED", True)
POLICY_FILE = os.getenv("POLICY_FILE", "/app/policy.yaml")
LITELLM_BASE_URL = os.getenv("LITELLM_BASE_URL", "http://host.docker.internal:4000").rstrip("/")
UPSTREAM_TIMEOUT = float(os.getenv("UPSTREAM_TIMEOUT", "600"))

logging.basicConfig(
    level=os.getenv("LOG_LEVEL", "INFO").strip().upper() or "INFO",
    format="%(asctime)s %(levelname)s %(name)s %(message)s",
)
log = logging.getLogger(APP_NAME)


class TextRequest(BaseModel):
    text: str = Field(min_length=1)
    source: str = "message"


class Finding(BaseModel):
    category: str
    detector: str
    score: float = 1.0
    count: int = 1


class ScanResult(BaseModel):
    request_id: str
    action: str
    categories: list[str]
    findings: list[Finding]
    content_sha256: str


def load_policy() -> dict[str, Any]:
    with open(POLICY_FILE, "r", encoding="utf-8") as f:
        return yaml.safe_load(f) or {}


POLICY = load_policy()


def policy_list(key: str, default: list[str] | None = None) -> list[str]:
    """
    Список из policy.yaml. Пустой ключ в YAML (`protected_terms:` без элементов)
    даёт None — трактуем его как пустой список, а не падаем на каждом запросе.
    """
    value = POLICY.get(key)
    if value is None:
        return list(default or [])
    if isinstance(value, (str, bytes)):
        value = [value]
    return [str(x) for x in value if x is not None and str(x).strip()]


def policy_number(key: str, default: float) -> float:
    value = POLICY.get(key)
    return float(value) if value is not None else default


# ---------- PII validation ----------

def only_digits(value: str) -> str:
    return re.sub(r"\D", "", value)


def valid_luhn(value: str) -> bool:
    digits = [int(x) for x in only_digits(value)]
    if not 13 <= len(digits) <= 19:
        return False
    total = 0
    parity = len(digits) % 2
    for i, d in enumerate(digits):
        if i % 2 == parity:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return total % 10 == 0


def valid_card(value: str) -> bool:
    # Платёжные карты (Мир, Visa, Mastercard, Maestro, Amex, JCB, UnionPay...)
    # начинаются с 2-6. Без этой проверки миллисекундные Unix-таймстемпы
    # (13 цифр, начинаются с 1) в ~10% случаев проходят Luhn и блокируются как карта.
    digits = only_digits(value)
    return bool(digits) and digits[0] in "23456" and valid_luhn(digits)


def valid_inn(value: str) -> bool:
    s = only_digits(value)
    if len(s) == 10:
        k = [2, 4, 10, 3, 5, 9, 4, 6, 8]
        check = sum(int(s[i]) * k[i] for i in range(9)) % 11 % 10
        return check == int(s[9])
    if len(s) == 12:
        k11 = [7, 2, 4, 10, 3, 5, 9, 4, 6, 8]
        k12 = [3, 7, 2, 4, 10, 3, 5, 9, 4, 6, 8]
        c11 = sum(int(s[i]) * k11[i] for i in range(10)) % 11 % 10
        c12 = sum(int(s[i]) * k12[i] for i in range(11)) % 11 % 10
        return c11 == int(s[10]) and c12 == int(s[11])
    return False


def valid_snils(value: str) -> bool:
    s = only_digits(value)
    if len(s) != 11:
        return False
    base = int(s[:9])
    if base < 1001998:
        # Для старых номеров алгоритм проверки отличался; считаем формат подозрительным.
        return True
    checksum = sum(int(s[i]) * (9 - i) for i in range(9))
    if checksum < 100:
        expected = checksum
    elif checksum in (100, 101):
        expected = 0
    else:
        expected = checksum % 101
        if expected == 100:
            expected = 0
    return expected == int(s[9:])


PRESIDIO_RECOGNIZERS = {
    "EMAIL": PatternRecognizer(
        supported_entity="EMAIL",
        patterns=[Pattern(
            name="email",
            regex=r"(?i)\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b",
            score=0.85,
        )],
    ),
    "RU_PHONE": PatternRecognizer(
        supported_entity="RU_PHONE",
        patterns=[Pattern(
            name="ru_phone",
            regex=r"(?<!\d)(?:\+7|8)(?:(?:\s|\(|\)|-)*\d){10}(?!\d)",
            score=0.85,
        )],
    ),
    "RU_PASSPORT": PatternRecognizer(
        supported_entity="RU_PASSPORT",
        patterns=[Pattern(
            name="ru_passport",
            regex=r"(?<!\d)\d{2}\s?\d{2}\s?\d{6}(?!\d)",
            score=0.90,
        )],
        context=["паспорт", "серия", "номер паспорта", "passport"],
    ),
    "RU_SNILS": PatternRecognizer(
        supported_entity="RU_SNILS",
        patterns=[Pattern(
            name="ru_snils",
            regex=r"(?<!\d)\d{3}[- ]?\d{3}[- ]?\d{3}[ -]?\d{2}(?!\d)",
            score=0.90,
        )],
        context=["снилс", "страховой номер"],
    ),
    "RU_INN": PatternRecognizer(
        supported_entity="RU_INN",
        patterns=[Pattern(
            name="ru_inn",
            regex=r"(?<!\d)(?:\d{10}|\d{12})(?!\d)",
            score=0.90,
        )],
        context=["инн"],
    ),
    "BANK_CARD": PatternRecognizer(
        supported_entity="BANK_CARD",
        patterns=[Pattern(
            name="bank_card",
            regex=r"(?<!\d)(?:\d[ -]?){13,19}(?!\d)",
            score=0.90,
        )],
        context=["карта", "card", "номер карты"],
    ),
}

HARD_PII = {"RU_PASSPORT", "RU_SNILS", "RU_INN", "BANK_CARD"}

# PatternRecognizer.analyze() без AnalyzerEngine НЕ применяет context-слова,
# поэтому контекст проверяем сами. Паспорт не имеет контрольной суммы: без
# контекста под шаблон попадает любое 10-значное число (таймстемпы, ID, телефоны).
CONTEXT_REQUIRED = {"RU_PASSPORT"}
CONTEXT_WINDOW_CHARS = 64

PII_VALIDATORS = {
    "BANK_CARD": valid_card,
    "RU_INN": valid_inn,
    "RU_SNILS": valid_snils,
}


def has_context(text_lower: str, start: int, end: int, words: list[str]) -> bool:
    window = text_lower[max(0, start - CONTEXT_WINDOW_CHARS):end + CONTEXT_WINDOW_CHARS]
    return any(w.lower() in window for w in words)


def scan_pii(text: str) -> list[Finding]:
    findings: list[Finding] = []
    text_lower = text.lower()
    for entity, recognizer in PRESIDIO_RECOGNIZERS.items():
        raw_results = recognizer.analyze(text=text, entities=[entity])
        accepted = []
        max_score = 0.0

        for result in raw_results:
            value = text[result.start:result.end]
            validator = PII_VALIDATORS.get(entity)
            if validator and not validator(value):
                continue
            if entity in CONTEXT_REQUIRED and not has_context(
                text_lower, result.start, result.end, recognizer.context or []
            ):
                continue
            accepted.append(result)
            max_score = max(max_score, float(result.score))

        if accepted:
            score = max(0.99 if entity in HARD_PII else 0.85, max_score)
            findings.append(
                Finding(category="PII", detector=f"PRESIDIO:{entity}", score=score, count=len(accepted))
            )

    if POLICY.get("block_person_names", False):
        try:
            if not NATASHA_AVAILABLE:
                raise RuntimeError("natasha is not installed")
            segmenter = app.state.segmenter
            ner_tagger = app.state.ner_tagger
            doc = Doc(text[:100000])
            doc.segment(segmenter)
            doc.tag_ner(ner_tagger)
            count = sum(1 for span in doc.spans if span.type == "PER")
            if count:
                findings.append(Finding(category="PII", detector="PERSON_NAME", score=0.75, count=count))
        except Exception as exc:
            log.warning("Natasha failed: %s", type(exc).__name__)
            if FAIL_CLOSED:
                findings.append(Finding(category="SECURITY_SERVICE_UNAVAILABLE", detector="NATASHA", score=1.0))
    return findings


# ---------- Secret detection (Gitleaks) ----------

def scan_gitleaks(text: str) -> list[Finding]:
    # mkstemp возвращает открытый дескриптор: его нужно закрыть, иначе каждый
    # запрос "утекает" один fd и сервис со временем падает с "Too many open files".
    fd, report_path = tempfile.mkstemp(prefix="gitleaks-", suffix=".json")
    os.close(fd)
    report = Path(report_path)
    try:
        proc = subprocess.run(
            [
                "gitleaks", "stdin",
                "--redact",
                "--report-format", "json",
                "--report-path", str(report),
                "--exit-code", "0",
                "--no-banner",
            ],
            input=text.encode("utf-8", errors="ignore"),
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
            timeout=20,
            check=False,
        )
        if proc.returncode != 0:
            raise RuntimeError(f"gitleaks rc={proc.returncode}")
        if not report.exists() or report.stat().st_size == 0:
            return []
        data = json.loads(report.read_text(encoding="utf-8") or "[]")
        counts: dict[str, int] = {}
        for item in data:
            rule = str(item.get("RuleID") or item.get("Description") or "SECRET")
            counts[rule] = counts.get(rule, 0) + 1
        return [
            Finding(category="SECRET", detector=f"GITLEAKS:{rule}", score=1.0, count=count)
            for rule, count in counts.items()
        ]
    except Exception as exc:
        log.warning("Gitleaks failed: %s", type(exc).__name__)
        if FAIL_CLOSED:
            return [Finding(category="SECURITY_SERVICE_UNAVAILABLE", detector="GITLEAKS", score=1.0)]
        return []
    finally:
        try:
            report.unlink(missing_ok=True)
        except Exception:
            pass


# ---------- Prompt injection / jailbreak heuristic layer ----------

INJECTION_PATTERNS = [
    ("IGNORE_INSTRUCTIONS_EN", re.compile(r"(?i)\b(ignore|disregard|forget)\b.{0,60}\b(previous|prior|above|system|developer)\b.{0,40}\b(instructions?|prompts?|messages?)\b", re.S)),
    ("REVEAL_SYSTEM_EN", re.compile(r"(?i)\b(reveal|show|print|repeat|expose)\b.{0,50}\b(system|developer)\b.{0,30}\b(prompts?|instructions?|messages?)\b", re.S)),
    ("IGNORE_INSTRUCTIONS_RU", re.compile(r"(?i)\b((?:про)?игнорируй(?:те)?|забудь(?:те)?|отмени(?:те)?)\b.{0,80}\b(предыдущ|системн|инструкц|правил|сообщен)", re.S)),
    ("REVEAL_SYSTEM_RU", re.compile(r"(?i)\b(покажи|выведи|раскрой|напечатай)(?:те)?\b.{0,60}\b(системн|скрыт)\w*\b.{0,40}\b(промпт|инструкц|сообщен|правил)", re.S)),
    ("JAILBREAK_TERMS", re.compile(r"(?i)\b(jailbreak|DAN mode|developer mode|режим DAN|джейлбрейк)\b")),
    ("TOOL_EXFIL", re.compile(r"(?i)\b(send|upload|exfiltrat\w*|отправь(?:те)?|загрузи(?:те)?|передай(?:те)?)\b.{0,80}\b(secret|credential|token|password|парол|токен|ключ|секрет)", re.S)),
]


def scan_prompt_injection(text: str) -> list[Finding]:
    hits = []
    for name, pattern in INJECTION_PATTERNS:
        count = len(pattern.findall(text))
        if count:
            hits.append(Finding(category="PROMPT_INJECTION", detector=name, score=0.9, count=count))
    return hits


# ---------- Commercial secret rules ----------

def scan_trade_secret(text: str) -> list[Finding]:
    low = text.lower()
    findings: list[Finding] = []

    marking_hits = {x.lower() for x in policy_list("blocked_markings") if x.lower() in low}
    if marking_hits:
        findings.append(
            Finding(category="TRADE_SECRET", detector="DOCUMENT_MARKING", score=1.0, count=len(marking_hits))
        )

    protected_hits = {x.lower() for x in policy_list("protected_terms") if x.lower() in low}
    if protected_hits:
        findings.append(
            Finding(category="TRADE_SECRET", detector="PROTECTED_TERM", score=1.0, count=len(protected_hits))
        )

    terms = {x.lower() for x in policy_list("commercial_terms") if x.lower() in low}
    # min_hits = 0 раньше означало "блокировать любой текст" (0 >= 0).
    min_hits = max(1, int(policy_number("commercial_terms_min_hits", 2)))
    if len(terms) >= min_hits:
        findings.append(
            Finding(category="TRADE_SECRET", detector="COMMERCIAL_TERMS", score=0.85, count=len(terms))
        )

    return findings


# ---------- Policy ----------

DEFAULT_BLOCK_CATEGORIES = [
    "PII", "SECRET", "TRADE_SECRET", "PROMPT_INJECTION",
    "MALWARE", "UNSUPPORTED_FILE", "SECURITY_SERVICE_UNAVAILABLE",
]


def decide(findings: list[Finding]) -> str:
    if not findings:
        return "ALLOW"

    blocked = set(policy_list("block_categories", DEFAULT_BLOCK_CATEGORIES))
    threshold = policy_number("pii_score_threshold", 0.8)

    for f in findings:
        if f.category not in blocked:
            continue
        if f.category == "PII":
            if f.detector == "PERSON_NAME":
                # ФИО блокируется только явным включением block_person_names;
                # порог к нему не применяем, иначе score 0.75 < 0.80 и флаг не работал бы.
                if not POLICY.get("block_person_names", False):
                    continue
            elif f.score < threshold:
                continue
        return "BLOCK"
    return "ALLOW"


def scan_text_impl(text: str, source: str = "message") -> ScanResult:
    if len(text) > MAX_TEXT_CHARS:
        finding = Finding(category="POLICY", detector="TEXT_TOO_LARGE", score=1.0)
        findings = [finding]
        action = "BLOCK"
    else:
        findings = []
        findings += scan_pii(text)
        findings += scan_gitleaks(text)
        findings += scan_trade_secret(text)
        findings += scan_prompt_injection(text)
        action = decide(findings)

    digest = hashlib.sha256(text.encode("utf-8", errors="ignore")).hexdigest()
    request_id = str(uuid.uuid4())

    # Не логируем исходный текст и найденные секретные значения.
    log.info(
        "scan request_id=%s source=%r action=%s sha256=%s categories=%s",
        request_id,
        source[:200],
        action,
        digest,
        sorted({x.category for x in findings}),
    )
    return ScanResult(
        request_id=request_id,
        action=action,
        categories=sorted({x.category for x in findings}),
        findings=findings,
        content_sha256=digest,
    )


@asynccontextmanager
async def lifespan(app: FastAPI):
    if NATASHA_AVAILABLE and POLICY.get("block_person_names", False):
        emb = NewsEmbedding()
        app.state.segmenter = Segmenter()
        app.state.ner_tagger = NewsNERTagger(emb)
    yield


app = FastAPI(title=APP_NAME, version="0.2.0", lifespan=lifespan)


@app.get("/healthz")
def healthz() -> dict[str, str]:
    return {"status": "ok"}


@app.post("/v1/scan/text", response_model=ScanResult)
def scan_text(req: TextRequest) -> ScanResult:
    return scan_text_impl(req.text, req.source)


# ---------- File scanning ----------

BLOCKED_MIME_PREFIXES = (
    "application/x-dosexec",
    "application/x-executable",
    "application/x-sharedlib",
    "application/x-elf",
    "application/x-mach-o",
    "application/x-msdownload",
    "application/x-ms-installer",
    "application/x-msi",
    "application/vnd.microsoft.portable-executable",
    "application/java-vm",
    "application/x-sh",
)
BLOCKED_ARCHIVE_MIMES = {
    "application/zip",
    "application/x-zip-compressed",
    "application/java-archive",
    "application/vnd.android.package-archive",
    "application/x-7z-compressed",
    "application/x-rar-compressed",
    "application/vnd.rar",
    "application/x-tar",
    "application/gzip",
    "application/x-gzip",
    "application/x-bzip",
    "application/x-bzip2",
    "application/x-xz",
    "application/x-lzma",
    "application/x-lz4",
    "application/x-lzip",
    "application/zstd",
    "application/x-compress",
    "application/x-cpio",
    "application/x-archive",
    "application/x-iso9660-image",
    "application/x-apple-diskimage",
    "application/vnd.ms-cab-compressed",
    "application/x-rpm",
    "application/x-debian-package",
    # Зашифрованные документы нельзя проверить на DLP.
    "application/x-tika-ooxml-protected",
}


def is_blocked_mime(mime: str) -> bool:
    # Tika может вернуть параметры: "application/x-msdownload; format=pe32".
    base = mime.split(";", 1)[0].strip().lower()
    return base.startswith(BLOCKED_MIME_PREFIXES) or base in BLOCKED_ARCHIVE_MIMES


def clamav_scan(data: bytes) -> list[Finding]:
    try:
        # Таймаут 15 с не хватало на файлы в 25 МБ -> ложный SECURITY_SERVICE_UNAVAILABLE.
        cd = clamd.ClamdNetworkSocket(host=CLAMAV_HOST, port=CLAMAV_PORT, timeout=CLAMAV_TIMEOUT)
        result = cd.instream(io.BytesIO(data))
        status, signature = (result or {}).get("stream", ("ERROR", ""))
        if status == "FOUND":
            return [Finding(category="MALWARE", detector=f"CLAMAV:{signature or 'FOUND'}", score=1.0)]
        if status != "OK":
            raise RuntimeError(f"clamav status={status}")
        return []
    except Exception as exc:
        log.warning("ClamAV failed: %s", type(exc).__name__)
        if FAIL_CLOSED:
            return [Finding(category="SECURITY_SERVICE_UNAVAILABLE", detector="CLAMAV", score=1.0)]
        return []


def safe_filename(filename: str | None) -> str:
    # HTTP-заголовки httpx кодирует в ASCII: имя "договор.pdf" роняло detect
    # с UnicodeEncodeError. Для детекта Tika важно только расширение.
    name = re.sub(r"[^A-Za-z0-9._-]", "_", Path(filename or "").name)
    return name or "upload.bin"


async def tika_detect(data: bytes, filename: str) -> str:
    headers = {"Content-Disposition": f'attachment; filename="{safe_filename(filename)}"'}
    async with httpx.AsyncClient(timeout=30) as client:
        # Tika 3.x: PUT /detect/stream; в Tika 4.x эндпоинт переименован в PUT /detect.
        for path in ("/detect/stream", "/detect"):
            r = await client.put(f"{TIKA_URL}{path}", content=data, headers=headers)
            if r.status_code != 404:
                break
        r.raise_for_status()
        return r.text.strip().lower()


async def tika_extract(data: bytes, mime: str) -> str:
    # Без X-Tika-Skip-Embedded: текст вложенных объектов (Excel внутри Word,
    # вложения PDF) тоже должен проходить DLP, иначе это обход проверки.
    headers = {
        "Content-Type": mime or "application/octet-stream",
        "Accept": "text/plain",
    }
    async with httpx.AsyncClient(timeout=120) as client:
        r = await client.put(f"{TIKA_URL}/tika", content=data, headers=headers)
        r.raise_for_status()
        return r.text


def _file_result(action: str, findings: list[Finding], digest: str) -> ScanResult:
    result = ScanResult(
        request_id=str(uuid.uuid4()),
        action=action,
        categories=sorted({x.category for x in findings}),
        findings=findings,
        content_sha256=digest,
    )
    log.info(
        "scan request_id=%s source='file' action=%s sha256=%s categories=%s",
        result.request_id, result.action, digest, result.categories,
    )
    return result


@app.post("/v1/scan/file", response_model=ScanResult)
async def scan_file(file: UploadFile = File(...)) -> ScanResult:
    data = await file.read(MAX_FILE_BYTES + 1)
    if len(data) > MAX_FILE_BYTES:
        digest = hashlib.sha256(data[:MAX_FILE_BYTES]).hexdigest()
        return _file_result(
            "BLOCK", [Finding(category="POLICY", detector="FILE_TOO_LARGE", score=1.0)], digest
        )

    digest = hashlib.sha256(data).hexdigest()
    # Сокет ClamAV блокирующий: выполняем в threadpool, чтобы не останавливать event loop.
    malware_findings = await run_in_threadpool(clamav_scan, data)
    if decide(malware_findings) == "BLOCK":
        return _file_result("BLOCK", malware_findings, digest)

    try:
        mime = await tika_detect(data, file.filename or "upload.bin")
    except Exception as exc:
        log.warning("Tika detect failed: %s", type(exc).__name__)
        findings = [Finding(category="SECURITY_SERVICE_UNAVAILABLE", detector="TIKA_DETECT", score=1.0)]
        return _file_result("BLOCK" if FAIL_CLOSED else "ALLOW", findings, digest)

    if is_blocked_mime(mime):
        findings = [Finding(category="UNSUPPORTED_FILE", detector=f"MIME:{mime}", score=1.0)]
        return _file_result("BLOCK", findings, digest)

    try:
        text = await tika_extract(data, mime)
    except httpx.HTTPStatusError as exc:
        # 422 — Tika не может разобрать файл (например, зашифрованный PDF):
        # содержимое не проверить, значит пропускать его нельзя.
        if exc.response.status_code == 422:
            findings = [Finding(category="UNSUPPORTED_FILE", detector="TIKA_UNPROCESSABLE", score=1.0)]
            return _file_result("BLOCK", findings, digest)
        log.warning("Tika extract failed: HTTP %s", exc.response.status_code)
        findings = [Finding(category="SECURITY_SERVICE_UNAVAILABLE", detector="TIKA_EXTRACT", score=1.0)]
        return _file_result("BLOCK" if FAIL_CLOSED else "ALLOW", findings, digest)
    except Exception as exc:
        log.warning("Tika extract failed: %s", type(exc).__name__)
        findings = [Finding(category="SECURITY_SERVICE_UNAVAILABLE", detector="TIKA_EXTRACT", score=1.0)]
        return _file_result("BLOCK" if FAIL_CLOSED else "ALLOW", findings, digest)

    result = await run_in_threadpool(scan_text_impl, text, f"file:{mime}")
    # Хеш ответа для файла должен относиться к исходному файлу, а не к извлечённому тексту.
    result.content_sha256 = digest
    return result


# ---------- OpenAI-compatible gateway -> LiteLLM ----------

HOP_BY_HOP_HEADERS = {
    "host",
    "content-length",
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailers",
    "transfer-encoding",
    "upgrade",
}
# content-type выставляет сам httpx (json=body), accept-encoding задаём явно ниже.
DROP_REQUEST_HEADERS = HOP_BY_HOP_HEADERS | {"accept-encoding", "content-type"}
# httpx уже распаковал тело ответа, поэтому Content-Encoding клиенту передавать нельзя.
DROP_RESPONSE_HEADERS = HOP_BY_HOP_HEADERS | {"content-encoding"}


def _forward_headers(request: Request) -> dict[str, str]:
    """Forward auth and relevant headers, but never Host/content-length."""
    headers = {
        k: v
        for k, v in request.headers.items()
        if k.lower() not in DROP_REQUEST_HEADERS
    }
    # Просим upstream отвечать без сжатия: иначе тело (уже распакованное httpx)
    # уходило бы клиенту с заголовком Content-Encoding: gzip и не читалось.
    headers["accept-encoding"] = "identity"
    return headers


def _response_headers(headers: httpx.Headers) -> dict[str, str]:
    return {
        k: v
        for k, v in headers.items()
        if k.lower() not in DROP_RESPONSE_HEADERS
    }


def _upstream_client(timeout: float) -> httpx.AsyncClient:
    return httpx.AsyncClient(timeout=httpx.Timeout(timeout))


# Ключи с бинарными данными (base64 аудио/файлы), а не текстом.
_BINARY_KEYS = {"file_data", "input_audio"}
# Служебные ключи с короткими enum-значениями, не несущими пользовательский контент.
_STRUCTURAL_KEYS = {"model", "role", "type", "id", "call_id", "tool_call_id", "status", "detail"}
_DATA_URL = re.compile(r"data:[\w.+-]+/[\w.+-]+(?:;[\w.+-]+=[\w.+-]+)*;base64,[A-Za-z0-9+/=\s]*")


def _extract_openai_text(payload: Any) -> str:
    """
    Extract all text that is about to be sent upstream.

    Walks the whole JSON body instead of a fixed set of fields, so nothing that
    reaches the model is skipped: messages, tool_calls arguments, tool results,
    Responses API `instructions`, `function_call_output`, tool definitions, etc.
    Base64 data URLs (images/files) are skipped: they are not text.
    """
    chunks: list[str] = []
    stack: list[tuple[str | None, Any]] = [(None, payload)]
    while stack:
        key, node = stack.pop()
        if key in _BINARY_KEYS:
            continue
        if isinstance(node, str):
            if key in _STRUCTURAL_KEYS or not node.strip() or _DATA_URL.fullmatch(node):
                continue
            chunks.append(node)
        elif isinstance(node, dict):
            stack.extend(reversed([(str(k), v) for k, v in node.items()]))
        elif isinstance(node, list):
            stack.extend(reversed([(key, v) for v in node]))
    return "\n\n".join(chunks)


def _blocked_response(result: ScanResult) -> JSONResponse:
    # Do not return matched secret values.
    return JSONResponse(
        status_code=403,
        content={
            "error": {
                "message": (
                    "Запрос заблокирован политикой информационной безопасности. "
                    "Удалите или обезличьте защищённую информацию."
                ),
                "type": "security_policy_block",
                "categories": result.categories,
                "request_id": result.request_id,
            }
        },
    )


@app.get("/v1/models")
async def gateway_models(request: Request):
    """Open WebUI model discovery -> LiteLLM."""
    url = f"{LITELLM_BASE_URL}/v1/models"
    try:
        async with _upstream_client(30) as client:
            r = await client.get(
                url,
                headers=_forward_headers(request),
                params=dict(request.query_params),
            )
        return Response(
            content=r.content,
            status_code=r.status_code,
            headers=_response_headers(r.headers),
            media_type=r.headers.get("content-type"),
        )
    except Exception as exc:
        log.error("LiteLLM /models unavailable: %s", type(exc).__name__)
        raise HTTPException(status_code=502, detail="Upstream LiteLLM unavailable")


async def _proxy_json_to_litellm(request: Request, upstream_path: str):
    try:
        body = await request.json()
    except Exception:
        raise HTTPException(status_code=400, detail="Expected JSON request body")
    if not isinstance(body, dict):
        raise HTTPException(status_code=400, detail="Expected JSON object in request body")

    text = _extract_openai_text(body)
    if text.strip():
        # Presidio + gitleaks — синхронные и медленные: в threadpool, чтобы не
        # замораживать event loop (и все параллельные стримы) на время проверки.
        result = await run_in_threadpool(scan_text_impl, text, f"gateway:{upstream_path}")
        if result.action == "BLOCK":
            return _blocked_response(result)

    url = f"{LITELLM_BASE_URL}{upstream_path}"
    headers = _forward_headers(request)
    params = dict(request.query_params)

    # Preserve LiteLLM/OpenAI streaming semantics.
    if body.get("stream") is True:
        client = _upstream_client(UPSTREAM_TIMEOUT)
        try:
            upstream_request = client.build_request(
                request.method, url, headers=headers, params=params, json=body
            )
            r = await client.send(upstream_request, stream=True)
        except Exception as exc:
            await client.aclose()
            log.error("LiteLLM streaming call failed: %s", type(exc).__name__)
            raise HTTPException(status_code=502, detail="Upstream LiteLLM unavailable")

        if r.status_code >= 400:
            # Ошибку upstream отдаём с её реальным HTTP-статусом, а не как 200 + SSE.
            try:
                error_body = await r.aread()
            finally:
                await r.aclose()
                await client.aclose()
            return Response(
                content=error_body,
                status_code=r.status_code,
                headers=_response_headers(r.headers),
                media_type=r.headers.get("content-type"),
            )

        async def stream_upstream():
            try:
                async for chunk in r.aiter_bytes():
                    yield chunk
            except Exception as exc:
                log.error("LiteLLM streaming call failed: %s", type(exc).__name__)
                yield b'data: {"error":{"message":"Upstream LiteLLM unavailable","type":"upstream_error"}}\n\n'
            finally:
                await r.aclose()
                await client.aclose()

        headers_out = _response_headers(r.headers)
        headers_out["cache-control"] = "no-cache"
        return StreamingResponse(
            stream_upstream(),
            status_code=r.status_code,
            headers=headers_out,
            media_type=r.headers.get("content-type", "text/event-stream"),
        )

    try:
        async with _upstream_client(UPSTREAM_TIMEOUT) as client:
            r = await client.request(
                request.method,
                url,
                headers=headers,
                params=params,
                json=body,
            )
        return Response(
            content=r.content,
            status_code=r.status_code,
            headers=_response_headers(r.headers),
            media_type=r.headers.get("content-type"),
        )
    except Exception as exc:
        log.error("LiteLLM call failed: %s", type(exc).__name__)
        raise HTTPException(status_code=502, detail="Upstream LiteLLM unavailable")


@app.post("/v1/chat/completions")
async def gateway_chat_completions(request: Request):
    return await _proxy_json_to_litellm(request, "/v1/chat/completions")


@app.post("/v1/responses")
async def gateway_responses(request: Request):
    return await _proxy_json_to_litellm(request, "/v1/responses")
