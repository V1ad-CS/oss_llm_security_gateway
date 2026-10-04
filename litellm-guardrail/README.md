# LiteLLM custom code guardrail

`guardrail.py` — гуардрейл для LiteLLM (`guardrail: custom_code`), проверяющий запросы до
отправки в модель: ПДн (LLM02), секреты, prompt injection / jailbreak (LLM01),
извлечение системного промпта (LLM07), опасные действия (LLM05/LLM06) и размер ввода (LLM10).

Это дополнительный слой к security-gateway, а не его замена: гуардрейл работает на
регулярных выражениях внутри LiteLLM, без gitleaks, Presidio и проверки файлов.

Те же правила применяет и security-gateway: таблицы скопированы в
`security-gateway/guardrail_rules.py`. **При изменении правил обновите оба файла** —
тест gateway `test_rule_tables_match_guardrail` проверяет, что они совпадают.
Общий корпус атак и обычных запросов (`corpus.py`) прогоняется в тестах обоих уровней.

## Подключение

В UI LiteLLM (*Guardrails → Add → Custom Code*) вставьте содержимое `guardrail.py`,
режим **pre_call**. Или в `config.yaml`:

```yaml
guardrails:
  - guardrail_name: security-guardrail
    litellm_params:
      guardrail: custom_code
      mode: pre_call
      default_on: true
      custom_code: |
        # содержимое guardrail.py с отступом
```

Заблокированный запрос в режиме `pre_call` возвращает HTTP 200, а причина блокировки
приходит текстом ответа ассистента (так LiteLLM обрабатывает блок до вызова модели).

## Что проверяется в каких сообщениях

| Группа правил | Роли |
|---|---|
| ПДн и секреты | system, developer, user, tool |
| Prompt injection, jailbreak, системный промпт, эксфильтрация | user, tool |
| Shell, SQL, XSS, SSRF, опасные действия, размер | user |

Ответы модели (assistant) не проверяются: это её собственный вывод, и иначе один ответ
с SQL-запросом блокировал бы весь дальнейший чат. Если в системном промпте есть
контакты (email, телефон), добавьте в `litellm_params` гуардрейла
`skip_system_message_in_guardrail: true`.

Заблокированное сообщение остаётся в истории чата Open WebUI и будет блокировать
следующие запросы, пока его не удалить или не отредактировать.

## Настройка

- `FLAG_ONLY_TYPES` — категории, которые только логируются (`flag`), а не блокируют.
  Например, `["DANGEROUS_SQL", "DANGEROUS_SHELL_EXECUTION", "SSRF_INTERNAL_RESOURCE"]`,
  если пользователи — разработчики и вопросы про SQL, консоль и `localhost` для них норма.
- `MAX_USER_MESSAGE_CHARS` — предельная длина последнего сообщения пользователя.

## Ограничения песочницы LiteLLM

- Сигнатура примитивов — **сначала текст, потом шаблон**: `regex_match(text, pattern)`,
  `regex_find_all(text, pattern)`.
- Ошибка в регулярном выражении не падает, а молча отключает правило — поэтому шаблоны
  проверяются тестами.
- Нельзя: `import`, имена с `_` в начале, `any/all/enumerate/min/max/sum`.

## Тесты

Тесты загружают `guardrail.py` в настоящую песочницу LiteLLM:

```bash
pip install "litellm[proxy]" pytest
python -m pytest litellm-guardrail
```
