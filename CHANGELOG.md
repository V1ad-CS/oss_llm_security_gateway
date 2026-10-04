# Changelog

## 0.3.0 — правила LiteLLM guardrail в gateway

Gateway применяет те же регулярные правила, что и `litellm-guardrail/guardrail.py`, и реагирует
на текстовые запросы (`/v1/scan/text`, чат, `/v1/scan/messages`) так же, как guardrail.

- Таблицы правил скопированы дословно в `security-gateway/guardrail_rules.py`; тест
  `test_rule_tables_match_guardrail` падает при расхождении с guardrail.
- Новые категории: `UNSAFE_ACTION` (shell, SQL, XSS, SSRF, метаданные облака, массовое удаление,
  повышение прав) и `UNBOUNDED_CONSUMPTION` («повторяй бесконечно», сообщение пользователя длиннее
  `max_user_message_chars`, по умолчанию 30 000 символов). Обе добавлены в `block_categories`.
- `PROMPT_INJECTION` теперь определяется правилами guardrail (рус./англ.): jailbreak, смена роли,
  извлечение системного промпта, эксфильтрация, инструкции в base64. Старые 6 шаблонов удалены:
  «developer mode» больше не срабатывает на вопросы про Android, а эксфильтрация требует адресата
  («отправь пароль на сервер»), поэтому «send a password reset email» не блокируется.
- Дополнительные ПДн и секреты поверх Presidio и Gitleaks: ФИО с пометкой «ФИО», международные
  телефоны, форматы паспорта «серия 4510 № 123456», `пароль: ...`, заголовки Authorization,
  строки подключения к БД, токены Telegram и Яндекс Облака. То, что уже нашли Presidio или
  Gitleaks, повторно не выводится.
- Учёт ролей сообщений, как в guardrail: ПДн и секреты — во всех ролях (включая assistant),
  prompt injection — в сообщениях user и tool, опасные действия и размер — только user.
  Ответ модели с SQL в истории больше не блокирует диалог, фраза «не раскрывай системный
  промпт» в системном промпте не блокирует запросы.
- `flag_only_types` в `policy.yaml` — аналог `FLAG_ONLY_TYPES`: тип фиксируется, но не блокирует.
- Новый метод `POST /v1/scan/messages` (диалог с ролями); фильтр Open WebUI в `request()`
  использует его вместо склеенного текста.
- Текст файлов из `/v1/scan/file` проверяется как результат инструмента: SQL и `<script>`
  в документах и выгрузках не блокируются, prompt injection — блокируется.
- `git@github.com:org/repo.git` больше не считается email.
- Общий корпус атак и обычных запросов `litellm-guardrail/corpus.py` прогоняется в тестах
  обоих уровней.

## 0.2.0 — исправление ошибок

Каждое исправление покрыто тестом в `security-gateway/tests/test_app.py`.

### Запуск по README

- **Файла `docker-compose.security.yml` не было** (был `docker-compose.yml` во вложенной папке),
  поэтому все команды из README (`docker compose -f docker-compose.security.yml ...`) падали.
  Структура репозитория приведена к описанной в README.
- **Не было `.env.example`**, упомянутого в README. Добавлен; compose теперь берёт из `.env`
  `LITELLM_BASE_URL`, `FAIL_CLOSED`, `UPSTREAM_TIMEOUT`, лимиты, `LOG_LEVEL`, `GATEWAY_PORT`.
- **`host.docker.internal` не резолвился на Linux** (Docker Engine): gateway не видел LiteLLM
  на хосте. Добавлено `extra_hosts: host.docker.internal:host-gateway`.
- README был с потерянной Markdown-разметкой (диаграммы и команды склеивались в абзацы),
  PowerShell-пример переносил строки через `\` вместо обратной кавычки.

### Прокси OpenAI API

- **Обход DLP**: не проверялись `instructions` (Responses API), `function_call_output`,
  аргументы `tool_calls` ассистента, legacy `functions`. Теперь проверяется всё текстовое
  содержимое тела запроса, кроме base64-картинок/файлов.
- **Сжатые ответы ломались**: httpx распаковывал gzip, а заголовок `Content-Encoding: gzip`
  уходил клиенту → `incorrect header check`. Upstream теперь запрашивается без сжатия,
  `Content-Encoding` не проксируется.
- **Стриминг терял статус ошибки**: при `stream=true` неверный ключ LiteLLM (401) отдавался
  клиенту как `200 text/event-stream`. Теперь возвращается реальный статус и тело ошибки;
  недоступный upstream — `502`.
- **JSON-массив в теле → 500** (`AttributeError`). Теперь `400`.
- **Блокировка event loop**: синхронные Presidio/gitleaks/ClamAV выполнялись прямо в async-
  обработчиках и замораживали все параллельные запросы и стримы. Вынесены в threadpool.

### Детекторы

- **Утечка файловых дескрипторов** в gitleaks: `tempfile.mkstemp()` открывал fd, который
  никогда не закрывался → со временем `Too many open files`.
- **`block_person_names: true` не работал**: находки Natasha имели score 0.75, а порог
  `pii_score_threshold` 0.80 — ФИО никогда не блокировались.
- **Natasha недоступна при `block_person_names: true`** — проверка молча пропускалась;
  теперь при `FAIL_CLOSED` запрос блокируется.
- **Паспорт: context-слова игнорировались** (`PatternRecognizer.analyze()` без
  `AnalyzerEngine` их не применяет), и любое 10-значное число (Unix-время, ID заказа)
  блокировалось как паспорт. Теперь паспорт требует рядом слово `паспорт`/`серия`/`passport`.
- **Банковская карта**: миллисекундные таймстемпы (13 цифр) в ~10% случаев проходили Luhn.
  Добавлена проверка первой цифры карты (2–6).
- **Prompt injection**: стем `exfiltrat\b` никогда не совпадал (после него всегда буква);
  не ловились `prompts`/`messages` и формы «проигнорируйте», «покажите».
- **Пустой список в `policy.yaml`** (`protected_terms:` без элементов → `None`) ронял каждый
  запрос с `TypeError`. `commercial_terms_min_hits: 0` блокировал любой текст.
- **`FAIL_CLOSED=1`/`yes` включали fail-open** (сравнение только с `"true"`). Теперь
  понимаются `1/true/yes/on` и `0/false/no/off`, любое другое значение — безопасное `true`.
- `LOG_LEVEL=info` (в нижнем регистре) ронял запуск.
- В `policy.yaml` добавлены английские грифы и термины из примера README.

### Сканирование файлов

- **Сканирование файлов не работало вообще**: образ `apache/tika:latest-full` теперь
  указывает на Tika 4.x, где `PUT /detect/stream` переименован в `PUT /detect` (404) →
  любой файл блокировался как `SECURITY_SERVICE_UNAVAILABLE`. Tika закреплён на 3.3.1.0,
  а код понимает оба варианта API (проверено на Tika 3.3.1 и 4.0.0).
- **Исполняемые файлы Linux проходили**: современные ELF (PIE, например `/bin/ls`) Tika
  определяет как `application/x-sharedlib`, которого не было в списке блокировки.
- **Русское имя файла** (`договор.pdf`) → `UnicodeEncodeError` в заголовке к Tika →
  файл блокировался как «сервис недоступен». Имя нормализуется до ASCII с сохранением расширения.
- **ZIP не блокировался** (как и bzip2/xz/zstd/cab/iso/jar/apk), хотя README обещает
  блокировку архивов. MIME с параметрами (`application/x-msdownload; format=pe32`,
  `...rar-compressed; version=5`) не совпадал со списком. Зашифрованные Office-документы
  блокируются; файлы, которые Tika не может разобрать (HTTP 422), — тоже.
- **`X-Tika-Skip-Embedded: true`** пропускал текст вложенных объектов (Excel внутри Word,
  вложения PDF) мимо DLP.
- Таймаут ClamAV 15 с был мал для файлов в 25 МБ → ложный `SECURITY_SERVICE_UNAVAILABLE`.

### Docker

- Gitleaks собирается статически (`CGO_ENABLED=0`) — бинарник с alpine запускается на debian.
- Контейнер gateway работает не от root, добавлен `HEALTHCHECK`.
- Версии Python-зависимостей зафиксированы; `@app.on_event` (deprecated) заменён на `lifespan`.
- `policy.yaml` монтируется в контейнер — после правки достаточно `restart`, без пересборки.
- Сигнатуры ClamAV хранятся в volume и не скачиваются заново при каждом перезапуске.
