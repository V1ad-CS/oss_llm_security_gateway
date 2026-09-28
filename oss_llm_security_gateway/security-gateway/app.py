import hashlib
import io
import json
import logging
import os
import re
import subprocess
import tempfile
import uuid
from pathlib import Path
from typing import Any

import clamd
import httpx
import yaml
from fastapi import FastAPI, File, HTTPException, UploadFile, Request
from pydantic import BaseModel, Field
from fastapi.responses import JSONResponse, Response, StreamingResponse
from presidio_analyzer import Pattern, PatternRecognizer

try:
    from natasha import Doc, NewsEmbedding, NewsNERTagger, Segmenter
    NATASHA_AVAILABLE = True
except Exception:
    NATASHA_AVAILABLE = False

APP_NAME = "oss-llm-security-gateway"
MAX_TEXT_CHARS = int(os.getenv("MAX_TEXT_CHARS", "500000"))
MAX_FILE_BYTES = int(os.getenv("MAX_FILE_BYTES", str(25 * 1024 * 1024)))
TIKA_URL = os.getenv("TIKA_URL", "http://tika:9998").rstrip("/")
CLAMAV_HOST = os.getenv("CLAMAV_HOST", "clamav")
CLAMAV_PORT = int(os.getenv("CLAMAV_PORT", "3310"))
FAIL_CLOSED = os.getenv("FAIL_CLOSED", "true").lower() == "true"
POLICY_FILE = os.getenv("POLICY_FILE", "/app/policy.yaml")
LITELLM_BASE_URL = os.getenv("LITELLM_BASE_URL", "http://host.docker.internal:4000").rstrip("/")
UPSTREAM_TIMEOUT = float(os.getenv("UPSTREAM_TIMEOUT", "600"))

logging.basicConfig(
    level=os.getenv("LOG_LEVEL", "INFO"),
    format="%(asctime)s %(levelname)s %(name)s %(message)s",
)
log = logging.getLogger(APP_NAME)

app = FastAPI(title=APP_NAME, version="0.1.0")


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
        context=["паспорт", "серия", "номер паспорта"],
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


def scan_pii(text: str) -> list[Finding]:
    findings: list[Finding] = []
    for entity, recognizer in PRESIDIO_RECOGNIZERS.items():
        raw_results = recognizer.analyze(text=text, entities=[entity])
        accepted = []
        max_score = 0.0

        for result in raw_results:
            value = text[result.start:result.end]
            if entity == "BANK_CARD" and not valid_luhn(value):
                continue
            if entity == "RU_INN" and not valid_inn(value):
                continue
            if entity == "RU_SNILS" and not valid_snils(value):
                continue
            accepted.append(result)
            max_score = max(max_score, float(result.score))

        if accepted:
            score = max(0.99 if entity in HARD_PII else 0.85, max_score)
            findings.append(
                Finding(category="PII", detector=f"PRESIDIO:{entity}", score=score, count=len(accepted))
            )

    if POLICY.get("block_person_names", False) and NATASHA_AVAILABLE:
        try:
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
    report = Path(tempfile.mkstemp(prefix="gitleaks-", suffix=".json")[1])
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
    ("IGNORE_INSTRUCTIONS_EN", re.compile(r"(?i)\b(ignore|disregard|forget)\b.{0,60}\b(previous|prior|above|system|developer)\b.{0,40}\b(instructions?|prompt|message)\b", re.S)),
    ("REVEAL_SYSTEM_EN", re.compile(r"(?i)\b(reveal|show|print|repeat|expose)\b.{0,50}\b(system|developer)\b.{0,30}\b(prompt|instructions?|message)\b", re.S)),
    ("IGNORE_INSTRUCTIONS_RU", re.compile(r"(?i)\b(игнорируй|забудь|отмени)\b.{0,80}\b(предыдущ|системн|инструкц|правил|сообщен)", re.S)),
    ("REVEAL_SYSTEM_RU", re.compile(r"(?i)\b(покажи|выведи|раскрой|напечатай)\b.{0,60}\b(системн|скрыт)\w*\b.{0,40}\b(промпт|инструкц|сообщен|правил)", re.S)),
    ("JAILBREAK_TERMS", re.compile(r"(?i)\b(jailbreak|DAN mode|developer mode|режим DAN|джейлбрейк)\b")),
    ("TOOL_EXFIL", re.compile(r"(?i)\b(send|upload|exfiltrat|отправь|загрузи|передай)\b.{0,80}\b(secret|credential|token|password|парол|токен|ключ|секрет)", re.S)),
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

    marking_hits = [
        x for x in POLICY.get("blocked_markings", [])
        if str(x).lower() in low
    ]
    if marking_hits:
        findings.append(
            Finding(category="TRADE_SECRET", detector="DOCUMENT_MARKING", score=1.0, count=len(marking_hits))
        )

    protected_hits = [
        x for x in POLICY.get("protected_terms", [])
        if str(x).lower() in low
    ]
    if protected_hits:
        findings.append(
            Finding(category="TRADE_SECRET", detector="PROTECTED_TERM", score=1.0, count=len(protected_hits))
        )

    terms = [
        x for x in POLICY.get("commercial_terms", [])
        if str(x).lower() in low
    ]
    min_hits = int(POLICY.get("commercial_terms_min_hits", 2))
    if len(set(map(str.lower, terms))) >= min_hits:
        findings.append(
            Finding(category="TRADE_SECRET", detector="COMMERCIAL_TERMS", score=0.85, count=len(set(terms)))
        )

    return findings


# ---------- Policy ----------

def decide(findings: list[Finding]) -> str:
    if not findings:
        return "ALLOW"

    blocked = set(POLICY.get("block_categories", [
        "PII", "SECRET", "TRADE_SECRET", "PROMPT_INJECTION",
        "MALWARE", "UNSUPPORTED_FILE", "SECURITY_SERVICE_UNAVAILABLE"
    ]))

    for f in findings:
        if f.category not in blocked:
            continue
        if f.category == "PII":
            if f.detector == "PERSON_NAME" and not POLICY.get("block_person_names", False):
                continue
            threshold = float(POLICY.get("pii_score_threshold", 0.8))
            if f.score < threshold:
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
        "scan request_id=%s source=%s action=%s sha256=%s categories=%s",
        request_id,
        source,
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


@app.on_event("startup")
def startup() -> None:
    if NATASHA_AVAILABLE and POLICY.get("block_person_names", False):
        emb = NewsEmbedding()
        app.state.segmenter = Segmenter()
        app.state.ner_tagger = NewsNERTagger(emb)


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
    "application/x-sh",
    "application/x-msdownload",
)
BLOCKED_ARCHIVE_MIMES = {
    "application/x-7z-compressed",
    "application/x-rar-compressed",
    "application/vnd.rar",
    "application/x-tar",
    "application/gzip",
    "application/x-gzip",
}


def clamav_scan(data: bytes) -> list[Finding]:
    try:
        cd = clamd.ClamdNetworkSocket(host=CLAMAV_HOST, port=CLAMAV_PORT, timeout=15)
        result = cd.instream(io.BytesIO(data))
        status = result.get("stream", ("ERROR", ""))[0]
        signature = result.get("stream", ("", ""))[1]
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


async def tika_detect(data: bytes, filename: str) -> str:
    headers = {"Content-Disposition": f'attachment; filename="{filename}"'}
    async with httpx.AsyncClient(timeout=30) as client:
        r = await client.put(f"{TIKA_URL}/detect/stream", content=data, headers=headers)
        r.raise_for_status()
        return r.text.strip().lower()


async def tika_extract(data: bytes, mime: str) -> str:
    headers = {
        "Content-Type": mime or "application/octet-stream",
        "Accept": "text/plain",
        "X-Tika-Skip-Embedded": "true",
    }
    async with httpx.AsyncClient(timeout=60) as client:
        r = await client.put(f"{TIKA_URL}/tika", content=data, headers=headers)
        r.raise_for_status()
        return r.text


@app.post("/v1/scan/file", response_model=ScanResult)
async def scan_file(file: UploadFile = File(...)) -> ScanResult:
    data = await file.read(MAX_FILE_BYTES + 1)
    if len(data) > MAX_FILE_BYTES:
        digest = hashlib.sha256(data[:MAX_FILE_BYTES]).hexdigest()
        return ScanResult(
            request_id=str(uuid.uuid4()),
            action="BLOCK",
            categories=["POLICY"],
            findings=[Finding(category="POLICY", detector="FILE_TOO_LARGE", score=1.0)],
            content_sha256=digest,
        )

    digest = hashlib.sha256(data).hexdigest()
    malware_findings = clamav_scan(data)
    if decide(malware_findings) == "BLOCK":
        return ScanResult(
            request_id=str(uuid.uuid4()),
            action="BLOCK",
            categories=sorted({x.category for x in malware_findings}),
            findings=malware_findings,
            content_sha256=digest,
        )

    try:
        mime = await tika_detect(data, file.filename or "upload.bin")
    except Exception as exc:
        log.warning("Tika detect failed: %s", type(exc).__name__)
        findings = [Finding(category="SECURITY_SERVICE_UNAVAILABLE", detector="TIKA_DETECT", score=1.0)]
        return ScanResult(
            request_id=str(uuid.uuid4()),
            action="BLOCK" if FAIL_CLOSED else "ALLOW",
            categories=sorted({x.category for x in findings}),
            findings=findings,
            content_sha256=digest,
        )

    if mime.startswith(BLOCKED_MIME_PREFIXES) or mime in BLOCKED_ARCHIVE_MIMES:
        findings = [Finding(category="UNSUPPORTED_FILE", detector=f"MIME:{mime}", score=1.0)]
        return ScanResult(
            request_id=str(uuid.uuid4()),
            action="BLOCK",
            categories=["UNSUPPORTED_FILE"],
            findings=findings,
            content_sha256=digest,
        )

    try:
        text = await tika_extract(data, mime)
    except Exception as exc:
        log.warning("Tika extract failed: %s", type(exc).__name__)
        findings = [Finding(category="SECURITY_SERVICE_UNAVAILABLE", detector="TIKA_EXTRACT", score=1.0)]
        return ScanResult(
            request_id=str(uuid.uuid4()),
            action="BLOCK" if FAIL_CLOSED else "ALLOW",
            categories=sorted({x.category for x in findings}),
            findings=findings,
            content_sha256=digest,
        )

    result = scan_text_impl(text, source=f"file:{mime}")
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


def _forward_headers(request: Request) -> dict[str, str]:
    """Forward auth and relevant headers, but never Host/content-length."""
    return {
        k: v
        for k, v in request.headers.items()
        if k.lower() not in HOP_BY_HOP_HEADERS
    }


def _response_headers(headers: httpx.Headers) -> dict[str, str]:
    return {
        k: v
        for k, v in headers.items()
        if k.lower() not in HOP_BY_HOP_HEADERS
    }


def _extract_openai_text(payload: dict[str, Any]) -> str:
    """
    Extract text that is about to be sent upstream.
    Covers classic Chat Completions and the common Responses API input forms.
    """
    chunks: list[str] = []

    for msg in payload.get("messages") or []:
        if not isinstance(msg, dict):
            continue
        role = str(msg.get("role", "unknown"))
        content = msg.get("content")

        if isinstance(content, str):
            chunks.append(f"[{role}]\n{content}")
        elif isinstance(content, list):
            for part in content:
                if not isinstance(part, dict):
                    continue
                if isinstance(part.get("text"), str):
                    chunks.append(f"[{role}]\n{part['text']}")
                elif isinstance(part.get("content"), str):
                    chunks.append(f"[{role}]\n{part['content']}")

    # Responses API compatibility.
    inp = payload.get("input")
    if isinstance(inp, str):
        chunks.append(f"[input]\n{inp}")
    elif isinstance(inp, list):
        for item in inp:
            if isinstance(item, str):
                chunks.append(f"[input]\n{item}")
            elif isinstance(item, dict):
                content = item.get("content")
                if isinstance(content, str):
                    chunks.append(f"[input]\n{content}")
                elif isinstance(content, list):
                    for part in content:
                        if isinstance(part, dict) and isinstance(part.get("text"), str):
                            chunks.append(f"[input]\n{part['text']}")

    # Tool definitions may themselves contain untrusted text/instructions.
    tools = payload.get("tools")
    if tools:
        try:
            chunks.append("[tools]\n" + json.dumps(tools, ensure_ascii=False))
        except Exception:
            pass

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
        async with httpx.AsyncClient(timeout=30) as client:
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

    text = _extract_openai_text(body)
    if text.strip():
        result = scan_text_impl(text, source=f"gateway:{upstream_path}")
        if result.action == "BLOCK":
            return _blocked_response(result)

    url = f"{LITELLM_BASE_URL}{upstream_path}"
    headers = _forward_headers(request)
    params = dict(request.query_params)

    # Preserve LiteLLM/OpenAI streaming semantics.
    if body.get("stream") is True:
        async def stream_upstream():
            try:
                async with httpx.AsyncClient(timeout=httpx.Timeout(UPSTREAM_TIMEOUT)) as client:
                    async with client.stream(
                        request.method,
                        url,
                        headers=headers,
                        params=params,
                        json=body,
                    ) as r:
                        if r.status_code >= 400:
                            error_body = await r.aread()
                            yield error_body
                            return
                        async for chunk in r.aiter_raw():
                            yield chunk
            except Exception as exc:
                log.error("LiteLLM streaming call failed: %s", type(exc).__name__)
                yield b'data: {"error":{"message":"Upstream LiteLLM unavailable","type":"upstream_error"}}\n\n'

        return StreamingResponse(
            stream_upstream(),
            media_type="text/event-stream",
            headers={"Cache-Control": "no-cache"},
        )

    try:
        async with httpx.AsyncClient(timeout=httpx.Timeout(UPSTREAM_TIMEOUT)) as client:
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
