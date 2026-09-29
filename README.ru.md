# OSS LLM Security Gateway — MVP

Схема:

Open WebUI -> Global Filter -> Security Gateway -> LiteLLM -> Gemini/другая модель

Security Gateway не отправляет проверяемые данные во внешние SaaS.

## Что проверяется

- PII через Presidio custom recognizers: российский паспорт (только рядом со словом «паспорт»/«серия»), СНИЛС, ИНН, телефон, email, банковская карта; для ИНН/СНИЛС/карт добавлена checksum-проверка.
- ФИО через Natasha (опционально включается в policy.yaml).
- API keys / tokens / credentials через Gitleaks.
- Явные признаки коммерческой тайны через policy.yaml.
- Базовые prompt-injection / jailbreak признаки на русском и английском.
- Файлы: ClamAV -> MIME detection/extraction через Apache Tika -> тот же DLP scan.
- Fail-closed: если критический защитный сервис недоступен, запрос блокируется.

## Запуск

Из корня репозитория (там, где лежит docker-compose.security.yml):

    cp .env.example .env        # необязательно: LITELLM_BASE_URL и др.
    docker compose -f docker-compose.security.yml up -d --build

Проверка:

    curl http://localhost:8080/healthz

Gateway опубликован только на 127.0.0.1:8080 (порт меняется через `GATEWAY_PORT` в `.env`).

При первом запуске ClamAV несколько минут скачивает базы сигнатур; пока контейнер
`clamav` не стал `healthy`, проверка файлов возвращает BLOCK
(`SECURITY_SERVICE_UNAVAILABLE`, fail-closed). Чат это не затрагивает.

policy.yaml монтируется в контейнер: после правки достаточно

    docker compose -f docker-compose.security.yml restart security-gateway

Тесты:

    cd security-gateway
    pip install -r requirements-dev.txt
    python -m pytest

Текст:

    curl -X POST http://localhost:8080/v1/scan/text \
      -H 'Content-Type: application/json' \
      -d '{"text":"мой email user@example.org","source":"manual-test"}'

Файл:

    curl -X POST http://localhost:8080/v1/scan/file \
      -F 'file=@./document.pdf'

## Open WebUI

1. Admin Panel -> Functions -> Create New Function.
2. Вставить содержимое openwebui_filter.py.
3. Включить Active и Global.
4. В Valves указать адрес gateway, доступный из контейнера Open WebUI.

Фильтр выполняет:
- inlet(): проверяет свежий текст пользователя;
- request(): повторно проверяет весь payload прямо перед моделью.
  На этом этапе Open WebUI уже добавил RAG chunks/tool context.

## Важно про raw upload

Open WebUI request()-фильтр защищает от утечки содержимого файла в модель,
потому что сканирует извлечённые RAG chunks перед provider call.

Но raw binary файла при стандартной загрузке Open WebUI не проходит через
этот gateway. Если требуется полноценный quarantine до хранения/индексации,
маршрут загрузки файла необходимо отправлять сначала на /v1/scan/file.
После ALLOW файл можно отдавать штатному upload endpoint Open WebUI.

## Production hardening

Перед production:
- закрепить версии Docker images/dependencies по digest;
- включить mTLS между Open WebUI, gateway и LiteLLM;
- не публиковать gateway/Tika/ClamAV в Интернет;
- добавить auth между сервисами;
- хранить только security metadata/hash, не исходные prompts;
- настроить свои protected_terms;
- добавить YARA;
- добавить локальный multilingual classifier для prompt injection;
- добавить отдельный semantic classifier коммерческой тайны;
- нагрузочно протестировать timeout/cache;
- добавить unit/regression tests на реальные корпоративные примеры.


## Gitleaks build note

Gitleaks v8.30.1 repository lives at `github.com/gitleaks/gitleaks`, but its Go module path is still `github.com/zricethezav/gitleaks/v8`. The Dockerfile therefore pins v8.30.1 and installs using the module path declared in `go.mod`.


## Fix v2 — Presidio regex

Исправлено двойное экранирование regex в custom recognizers.
В Python raw-строке должно быть `\d`, `\s`, `\b`, а не двойной literal backslash.
Также дефис в классе RU_PHONE перенесён в безопасную позицию/экранирован.

После обновления пересоберите:

    docker compose -f docker-compose.security.yml down
    docker compose -f docker-compose.security.yml build --no-cache
    docker compose -f docker-compose.security.yml up -d


## v4: использовать как настоящий gateway

Целевая цепочка:

    Open WebUI -> Security Gateway :8080 -> LiteLLM :4000 -> Gemini

Security Gateway теперь реализует:
- GET /v1/models
- POST /v1/chat/completions
- POST /v1/responses

Перед пересылкой Chat/Responses body проходит локальный DLP/firewall.
При BLOCK LiteLLM вообще не вызывается; клиент получает HTTP 403.

### Если LiteLLM слушает Windows host:4000

По умолчанию compose использует:

    LITELLM_BASE_URL=http://host.docker.internal:4000

### Если LiteLLM — Docker service в той же сети

Задайте:

    LITELLM_BASE_URL=http://litellm:4000

и убедитесь, что оба контейнера подключены к одной Docker network.

### Open WebUI

В Settings -> Admin -> Connections -> OpenAI-compatible connection:

    URL: http://host.docker.internal:8080/v1

если Open WebUI находится в другом Docker compose на той же Windows-машине.

API Key: тот же LiteLLM virtual key. Gateway пересылает Authorization header в LiteLLM.

Если Open WebUI находится в одной Docker network с gateway:

    URL: http://security-gateway:8080/v1

После настройки удалите/отключите прямое соединение Open WebUI -> LiteLLM,
иначе пользователь сможет выбрать старое соединение и обойти DLP.

### Проверка с Windows host

    Invoke-RestMethod http://127.0.0.1:8080/healthz

Проверка model discovery (если LiteLLM требует key):

    $headers = @{ Authorization = "Bearer <LITELLM_KEY>" }
    Invoke-RestMethod -Headers $headers http://127.0.0.1:8080/v1/models
