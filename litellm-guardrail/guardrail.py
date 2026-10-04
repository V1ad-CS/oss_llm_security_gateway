# ============================================================
# LiteLLM custom code guardrail (guardrail: custom_code, mode: pre_call).
#
# Runs inside LiteLLM's RestrictedPython sandbox:
# - no imports; names must not start with "_";
# - no any()/all()/enumerate()/min()/max()/sum() builtins;
# - primitives take the TEXT first: regex_match(text, pattern),
#   regex_find_all(text, pattern). Swapping the arguments turns the
#   user's message into a regex (guardrail silently off + ReDoS).
# ============================================================

# Longest accepted user message, in characters (LLM10).
MAX_USER_MESSAGE_CHARS = 30000

# Detected types listed here are logged via flag() instead of blocking.
# Example: FLAG_ONLY_TYPES = ["DANGEROUS_SQL", "DANGEROUS_SHELL_EXECUTION"]
FLAG_ONLY_TYPES = []

# Which message roles each rule group inspects. Assistant messages are
# never inspected: they are the model's own earlier answers, and scanning
# them would block the whole chat after the model once printed e.g. SQL.
DLP_ROLES = ["system", "developer", "user", "tool", "function"]
INJECTION_ROLES = ["user", "tool", "function"]
ACTION_ROLES = ["user"]


# ============================================================
# LLM02:2025 - Sensitive Information Disclosure (PII, secrets)
# Applied to every non-assistant message.
# ============================================================

DLP_RULES = [
    # Email ("_" is allowed in the local part; git@host SSH URLs are not emails)
    ("PII_EMAIL",
     r"(?i)\b(?!git@)[\w.%+-]+@[\w-]+(?:\.[\w-]+)*\.[a-zа-яё]{2,}\b"),

    # Russian phone numbers: +7 (999) 123-45-67, 8 999 123 45 67
    ("PII_PHONE",
     r"(?<!\d)(?:\+7|8)[\s()\-]*\d{3}[\s()\-]*\d{3}[\s\-]*\d{2}[\s\-]*\d{2}(?!\d)"),

    # International phone numbers starting with "+"
    ("PII_PHONE",
     r"(?<![\w+])\+\d[\d\s()\-]{8,18}\d(?!\d)"),

    # Russian passport next to a context word:
    # "паспорт 4510 123456", "серия 4510 № 123456", "номер паспорта: 4510123456"
    ("PII_PASSPORT",
     r"(?i)(?:паспорт|passport|серия)[^\d]{0,40}?"
     r"(?<!\d)\d{2}\s?\d{2}\s*(?:№|#|номер|no\.?|number)?\s*[:.]?\s*\d{6}(?!\d)"),

    # Explicitly labelled full name: "ФИО: Иванов Иван", "ФИО сотрудника Петров И.И."
    ("PII_FULL_NAME",
     r"(?<![А-Яа-яЁё])(?:[Фф][Ии][Оо]|Ф\.\s?И\.\s?О\.?)(?![А-Яа-яЁё])"
     r"(?:\s+[а-яё]+){0,2}\s*[:\-–—]?\s*"
     r"[А-ЯЁA-Z][а-яёa-z]+(?:-[А-ЯЁA-Z][а-яёa-z]+)?\s+[А-ЯЁA-Z](?:[а-яёa-z]+|\.)"),

    # key = value credentials, incl. quoted/JSON/env forms:
    # password: "...", "api_key": "...", DB_PASSWORD=..., пароль: ...
    ("SECRET_OR_CREDENTIAL",
     r"(?i)(?<![a-z0-9])(?:api[_ -]?key|apikey|access[_ -]?token|refresh[_ -]?token|"
     r"auth[_ -]?token|client[_ -]?secret|secret[_ -]?key|private[_ -]?key|"
     r"password|passwd|pwd|пароль)[\"']?\s*(?:[:=]|=>)\s*[\"']?"
     r"[A-Za-z0-9_\-./+=!@#$%^&~]{8,}"),

    # Authorization headers
    ("SECRET_OR_CREDENTIAL",
     r"(?i)\bauthorization\b[\"']?\s*[:=]\s*[\"']?(?:bearer|basic|token)\s+[A-Za-z0-9._~+/=-]{8,}"),
    ("SECRET_OR_CREDENTIAL",
     r"(?i)\bbearer\s+[A-Za-z0-9._~+/-]{20,}=*"),

    # Well-known token formats: OpenAI/Anthropic/LiteLLM sk-, GitHub, GitLab,
    # Google AIza, AWS, Slack, Yandex Cloud
    ("SECRET_OR_CREDENTIAL",
     r"(?<![A-Za-z0-9])(?:sk-(?=[A-Za-z0-9_-]*\d)[A-Za-z0-9_-]{20,}|"
     r"gh[pousr]_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{40,}|glpat-[A-Za-z0-9_-]{20,}|"
     r"AIza[0-9A-Za-z_-]{35}|(?:AKIA|ASIA)[0-9A-Z]{16}|xox[abposr]-[A-Za-z0-9-]{10,}|"
     r"AQVN[A-Za-z0-9_-]{35,38}|t1\.[A-Za-z0-9_-]+=*\.[A-Za-z0-9_-]{86}=*)"),

    # JWT
    ("SECRET_OR_CREDENTIAL",
     r"\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}"),

    # PEM private keys
    ("SECRET_OR_CREDENTIAL",
     r"-----BEGIN (?:[A-Z0-9]+ )*PRIVATE KEY-----"),

    # Telegram bot token
    ("SECRET_OR_CREDENTIAL",
     r"(?<!\d)\d{8,10}:AA[A-Za-z0-9_-]{33}(?![A-Za-z0-9_-])"),

    # Connection strings with an embedded password
    ("SECRET_OR_CREDENTIAL",
     r"(?i)\b(?:postgres(?:ql)?|mysql|mariadb|mongodb(?:\+srv)?|redis|amqps?|mssql)://"
     r"[^\s:/@]+:[^\s@/]{3,}@"),
]

# Rules whose matches are confirmed by a checksum (see is_valid).
VALIDATED_DLP_RULES = [
    # Bank card: 13-19 digits, prefix 2-6, Luhn
    ("PII_BANK_CARD", r"(?<!\d)(?:\d[ -]?){12,18}\d(?!\d)", "card"),
    # SNILS: checksum
    ("PII_SNILS", r"(?<!\d)\d{3}[- ]?\d{3}[- ]?\d{3}[- ]?\d{2}(?!\d)", "snils"),
    # INN after the word "ИНН": checksum
    ("PII_INN", r"(?i)(?<![а-яёa-z])инн(?![а-яёa-z])[^\d\n]{0,25}(\d{10}|\d{12})(?!\d)", "inn"),
]


# ============================================================
# LLM01 / LLM07 - Prompt injection, jailbreak, system prompt leakage,
# exfiltration. Applied to user messages and tool results (indirect
# injection), not to the operator's system prompt.
# ============================================================

INJECTION_RULES = [
    ("PROMPT_INJECTION",
     r"(?is)\b(?:ignore|disregard|forget|override|bypass)\b.{0,60}?"
     r"\b(?:previous|prior|above|earlier|preceding|system|developer|original)\b.{0,40}?"
     r"\b(?:instructions?|prompts?|rules?|polic(?:y|ies)|guidelines?|directives?)\b"),
    ("PROMPT_INJECTION",
     r"(?i)\b(?:ignore|disregard)\s+(?:all|any)\s+(?:of\s+)?(?:your\s+|the\s+|my\s+)?"
     r"(?:previous\s+|prior\s+)?(?:instructions|guidelines|directives)\b"),
    ("PROMPT_INJECTION",
     r"(?i)\b(?:new\s+instructions\s*:|your\s+new\s+instructions\s+are|new\s+system\s+prompt|"
     r"(?:replace|override)\s+(?:the|your)\s+system\s+prompt|ignore\s+all\s+previous|"
     r"forget\s+all\s+previous|forget\s+everything\s+(?:above|before))"),
    ("PROMPT_INJECTION",
     r"(?is)(?<![а-яё])(?:проигнорируй|игнорируй|игнорировать|забудь|забыть|отмени|"
     r"не\s+учитывай|не\s+обращай\s+внимания\s+на|пренебреги)\w*.{0,60}?"
     r"(?<![а-яё])(?:предыдущ|прошл|ранее|выше|вышеизложенн|системн|исходн|первоначальн|изначальн)\w*"
     r".{0,40}?(?<![а-яё])(?:инструкци|указани|правил|промпт|ограничени|настройк|директив)"),
    ("PROMPT_INJECTION",
     r"(?i)(?<![а-яё])(?:проигнорируй|игнорируй|забудь|отмени)\w*\s+(?:все|всё|любые)\s+"
     r"(?:свои\s+|твои\s+|эти\s+)?(?:инструкци|указани|ограничени)"),
    ("PROMPT_INJECTION",
     r"(?i)(?<![а-яё])(?:нов(?:ые|ая)\s+инструкци[ия]\s*:|новый\s+системный\s+промпт|"
     r"(?:замени|перезапиши)\w*\s+системн\w*\s+промпт)"),

    ("JAILBREAK_ATTEMPT",
     r"(?i)\b(?:jailbreak\w*|dan\s+mode|do\s+anything\s+now|unrestricted\s+mode|"
     r"(?:disable|bypass|turn\s+off)\s+(?:your\s+|all\s+)?(?:safety(?:\s+(?:filters?|guidelines|"
     r"restrictions))?|guardrails|content\s+filters?|moderation))\b"),
    ("JAILBREAK_ATTEMPT",
     r"(?is)\b(?:act\s+as|simulate|pretend|you\s+are\s+now|you\s+will\s+now)\b.{0,40}?"
     r"\bdeveloper\s+mode\b|\bdeveloper\s+mode\s+output\b"),
    ("JAILBREAK_ATTEMPT",
     r"(?i)\b(?:you\s+(?:have|are\s+under|operate\s+with)\s+no\s+(?:restrictions|rules|limits|filters|guidelines)|"
     r"(?:respond|answer|reply|act|operate|behave)\w*\s+without\s+(?:any\s+)?"
     r"(?:restrictions|filters|limitations|censorship|guidelines|rules))\b"),
    ("JAILBREAK_ATTEMPT",
     r"(?i)(?:джейлбрейк|режим\w*\s+(?:dan|дан|без\s+ограничений)|"
     r"(?:отключи|сними|убери|выключи|обойди)\w*\s+(?:все\s+)?(?:свои|твои)\s+"
     r"(?:ограничени|фильтр|цензур|правил|модераци)|обойди\w*\s+(?:фильтр|цензур|модераци)|"
     r"(?:отвечай|действуй|веди\s+себя|работай)\w*\s+без\s+(?:каких-либо\s+|любых\s+)?"
     r"(?:ограничений|фильтров|цензуры|правил))"),

    ("ROLE_OVERRIDE",
     r"(?is)\b(?:you\s+are\s+now|from\s+now\s+on\s+you\s+are|pretend\s+(?:that\s+)?you\s+are|"
     r"act\s+as|switch\s+to)\b.{0,30}?\b(?:unrestricted|unfiltered|uncensored|jailbroken|"
     r"(?:admin|administrator|root|superuser|system|developer|god|sudo)\s+"
     r"(?:mode|access|privileges?|rights|level))\b"),
    ("ROLE_OVERRIDE",
     r"(?is)(?:ты\s+теперь|теперь\s+ты|с\s+этого\s+момента\s+ты|притворись|"
     r"представь\w*,?\s+что\s+ты|переключись\s+в)(?![а-яё]).{0,30}?"
     r"(?:режим\w*\s+(?:администратора|админа|root|суперпользователя|без\s+ограничений)|"
     r"без\s+(?:ограничений|цензуры|фильтров))"),

    ("SYSTEM_PROMPT_EXTRACTION",
     r"(?i)\b(?:show|print|reveal|display|repeat|output|dump|leak)\b\s+(?:me\s+)?"
     r"(?:your\s+|the\s+)?(?:full\s+|entire\s+|exact\s+|original\s+|initial\s+|hidden\s+|secret\s+)?"
     r"(?:system|developer|hidden|initial|internal|original|secret)\s+"
     r"(?:prompt|instructions?|message|rules)\b"),
    ("SYSTEM_PROMPT_EXTRACTION",
     r"(?i)\b(?:tell\s+me|give\s+me|what\s+(?:is|are|was|were))\s+your\s+"
     r"(?:full\s+|exact\s+|original\s+|initial\s+)?(?:system|developer|hidden|initial|internal|secret)\s+"
     r"(?:prompt|instructions?|message|rules)\b"),
    ("SYSTEM_PROMPT_EXTRACTION",
     r"(?is)\b(?:repeat|print|output|copy)\b.{0,30}?\b(?:everything|all\s+(?:the\s+)?(?:text|words)|"
     r"the\s+(?:text|words))\b.{0,20}?\babove\b"),
    ("SYSTEM_PROMPT_EXTRACTION",
     r"(?is)\b(?:what\s+are|what\s+were|show\s+me|tell\s+me|list)\b.{0,50}?"
     r"\byour\s+(?:hidden|internal|secret|original|initial)\s+(?:instructions|rules|guidelines|policies)\b"),
    ("SYSTEM_PROMPT_EXTRACTION",
     r"(?i)(?<![а-яё])(?:покажи|выведи|раскрой|повтори|напечатай|скажи|назови|перечисли)\w*\s+"
     r"(?:мне\s+)?(?:свой\s+|свои\s+|твой\s+|твои\s+|весь\s+|полный\s+)?"
     r"(?:системн|скрыт|внутренн|исходн|секретн)\w*\s+(?:промпт|инструкци|указани|правил|сообщени)"),

    ("DATA_EXFILTRATION",
     r"(?is)\b(?:send|upload|post|forward|transmit|exfiltrat\w*|leak)\b.{0,80}?"
     r"\b(?:secrets?|credentials?|passwords?(?!\s+reset)|tokens?|api\s+keys?|private\s+data|"
     r"confidential\s+data|user\s+data|customer\s+data|personal\s+data)\b.{0,80}?"
     r"\b(?:url|webhook|server|endpoint|e-?mail|external|https?)\b"),
    ("DATA_EXFILTRATION",
     r"(?is)(?<![а-яё])(?:отправь|перешли|загрузи|слей|выгрузи)\w*.{0,80}?"
     r"(?:секрет|ключ|токен|парол|учётн|учетн|персональн\w*\s+данн|клиентск\w*\s+баз)\w*.{0,80}?"
     r"(?:url|вебхук|webhook|сервер|внешн|http)"),

    ("OBFUSCATED_INSTRUCTION",
     r"(?is)\b(?:decode|base64|rot13|hex\s+decode|from\s+base64)\b.{0,100}?"
     r"\b(?:instructions?|prompts?|commands?|payloads?)\b"),
    ("OBFUSCATED_INSTRUCTION",
     r"(?is)(?<![а-яё])(?:декодируй|расшифруй)\w*.{0,100}?(?:инструкци|команд|промпт)"),
]


# ============================================================
# LLM05 / LLM06 / LLM10 - dangerous actions requested by the user.
# Applied to user messages only (tool results such as fetched HTML
# routinely contain <script>, SQL, localhost URLs).
# ============================================================

ACTION_RULES = [
    ("DANGEROUS_SHELL_EXECUTION",
     r"(?is)\b(?:execute|run|invoke|launch)\b.{0,40}?\b(?:shell|bash|powershell|cmd|terminal|commands?)\b"),

    ("DANGEROUS_SHELL_COMMAND",
     r"(?i)(?<![\w-])(?:rm\s+-(?:[a-z]*r[a-z]*f|[a-z]*f[a-z]*r)[a-z]*\b|del\s+/[sqf]\b|format\s+[a-z]:|"
     r"shutdown\s+[-/]|mkfs\.|chmod\s+(?:-r\s+)?777\b|dd\s+if=\S+\s+of=/dev/(?:sd|nvme|hd|xvd)|"
     r":\(\)\s*\{\s*:\|:&\s*\};:)"),

    ("DANGEROUS_SQL",
     r"(?im)\b(?:drop\s+(?:table|database|schema)|truncate\s+table|alter\s+table|"
     r"delete\s+from\s+[\w.\"`\[\]]+\s*(?:;|$|where\b))"),

    ("SCRIPT_INJECTION",
     r"(?i)(?:<script\b|\bjavascript\s*:|\bon(?:error|load)\s*=|\bdocument\.cookie\b)"),

    ("SSRF_INTERNAL_RESOURCE",
     r"(?i)\bhttps?://(?:127\.\d{1,3}\.\d{1,3}\.\d{1,3}|localhost\b|0\.0\.0\.0|\[::1?\]|"
     r"169\.254\.\d{1,3}\.\d{1,3}|10\.\d{1,3}\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}|"
     r"172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|0x7f[0-9a-f]*\b|2130706433\b)"),

    ("CLOUD_METADATA_ACCESS",
     r"(?i)(?:169\.254\.169\.254|metadata\.google\.internal|\binstance\s+metadata\b|"
     r"\bcloud\s+metadata\s+endpoint\b|100\.100\.100\.200|fd00:ec2::254)"),

    ("HIGH_IMPACT_ACTION",
     r"(?is)\b(?:delete|remove|erase|destroy|wipe|purge)\b.{0,50}?\b(?:all|every|entire)\b.{0,40}?"
     r"\b(?:files?|databases?|records?|e-?mails?|messages?|repositor(?:y|ies)|accounts?|users?|backups?)\b"),

    ("PRIVILEGE_ESCALATION_REQUEST",
     r"(?is)\b(?:grant|give|assign|enable)\b.{0,30}?"
     r"\b(?:admin|administrator|root|superuser|sudo|full\s+access|all\s+permissions)\b"),

    ("UNBOUNDED_CONSUMPTION",
     r"(?is)\b(?:repeat|generate|write|output|print|list)\b.{0,40}?"
     r"\b(?:forever|indefinitely|endlessly|infinitely|without\s+stopping|non-?stop|"
     r"(?:millions|billions)\s+of\s+(?:times|words|lines|tokens|characters|pages)|"
     r"an?\s+(?:million|billion)\s+(?:times|words|lines|tokens|characters|pages))\b"),
]


# ============================================================
# Helpers
# ============================================================

def only_digits(value):
    digits = ""
    for ch in value:
        if ch in "0123456789":
            digits += ch
    return digits


def luhn_ok(digits):
    total = 0
    double = False
    i = len(digits) - 1
    while i >= 0:
        d = int(digits[i])
        if double:
            d = d * 2
            if d > 9:
                d = d - 9
        total += d
        double = not double
        i -= 1
    return total % 10 == 0


def inn_ok(digits):
    if len(digits) == 10:
        weights = [2, 4, 10, 3, 5, 9, 4, 6, 8]
        check = 0
        for i in range(9):
            check += int(digits[i]) * weights[i]
        return check % 11 % 10 == int(digits[9])
    if len(digits) == 12:
        weights11 = [7, 2, 4, 10, 3, 5, 9, 4, 6, 8]
        weights12 = [3, 7, 2, 4, 10, 3, 5, 9, 4, 6, 8]
        c11 = 0
        c12 = 0
        for i in range(10):
            c11 += int(digits[i]) * weights11[i]
        for i in range(11):
            c12 += int(digits[i]) * weights12[i]
        return c11 % 11 % 10 == int(digits[10]) and c12 % 11 % 10 == int(digits[11])
    return False


def snils_ok(digits):
    if len(digits) != 11:
        return False
    if int(digits[:9]) < 1001998:
        # The checksum is defined only for numbers above 001-001-998.
        return True
    checksum = 0
    for i in range(9):
        checksum += int(digits[i]) * (9 - i)
    if checksum < 100:
        expected = checksum
    elif checksum < 102:
        expected = 0
    else:
        expected = checksum % 101
        if expected == 100:
            expected = 0
    return expected == int(digits[9:])


def is_valid(kind, value):
    digits = only_digits(value)
    if kind == "card":
        return 13 <= len(digits) <= 19 and digits[0] in "23456" and luhn_ok(digits)
    if kind == "snils":
        return snils_ok(digits)
    if kind == "inn":
        return inn_ok(digits)
    return True


def message_text(message):
    content = message.get("content")
    if isinstance(content, str):
        return content
    parts = []
    if isinstance(content, list):
        for part in content:
            if isinstance(part, str):
                parts.append(part)
            elif isinstance(part, dict):
                value = part.get("text")
                if not isinstance(value, str):
                    value = part.get("content")
                if isinstance(value, str):
                    parts.append(value)
    return "\n".join(parts)


def collect_texts(inputs):
    """Split request texts by role: dlp / injection / action groups + latest user message."""
    groups = {"dlp": [], "injection": [], "action": [], "last_user": ""}
    messages = inputs.get("structured_messages")
    if isinstance(messages, list) and len(messages) > 0:
        for message in messages:
            if not isinstance(message, dict):
                continue
            role = str(message.get("role") or "user").lower()
            text = message_text(message)
            if not text:
                continue
            if role in DLP_ROLES:
                groups["dlp"].append(text)
            if role in INJECTION_ROLES:
                groups["injection"].append(text)
            if role in ACTION_ROLES:
                groups["action"].append(text)
                groups["last_user"] = text
        return groups

    # No roles available (e.g. non-chat endpoints): treat every text as user input.
    for text in inputs.get("texts") or []:
        if isinstance(text, str) and text:
            groups["dlp"].append(text)
            groups["injection"].append(text)
            groups["action"].append(text)
            groups["last_user"] = text
    return groups


def matches_any_text(texts, pattern):
    for text in texts:
        if regex_match(text, pattern):
            return True
    return False


def add_type(detected, name):
    if name not in detected:
        detected.append(name)


def check_rules(detected, rules, texts):
    for name, pattern in rules:
        if name not in detected and matches_any_text(texts, pattern):
            detected.append(name)


# ============================================================
# Entry point
# ============================================================

def apply_guardrail(inputs, request_data, input_type):
    if input_type != "request":
        return allow()

    groups = collect_texts(inputs)
    detected = []

    check_rules(detected, DLP_RULES, groups["dlp"])
    for name, pattern, kind in VALIDATED_DLP_RULES:
        if name in detected:
            continue
        for text in groups["dlp"]:
            found = False
            for value in regex_find_all(text, pattern):
                if is_valid(kind, value):
                    found = True
                    break
            if found:
                add_type(detected, name)
                break

    check_rules(detected, INJECTION_RULES, groups["injection"])
    check_rules(detected, ACTION_RULES, groups["action"])

    if len(groups["last_user"]) > MAX_USER_MESSAGE_CHARS:
        add_type(detected, "EXCESSIVE_INPUT_SIZE")

    if len(detected) == 0:
        return allow()

    reason = (
        "Message blocked by security guardrail. "
        "Detected security risk(s): "
        + ", ".join(detected)
        + ". Remove sensitive data or unsafe instructions and try again."
    )
    blocking = [name for name in detected if name not in FLAG_ONLY_TYPES]
    if len(blocking) == 0:
        return flag("Security guardrail flagged: " + ", ".join(detected), {"detected_types": detected})
    return block(reason, {"detected_types": detected})
