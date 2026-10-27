# Аудит конфигурации Azure Firewall

`azfw_audit.py` получает конфигурацию Azure Firewall, находит изменения относительно
утверждённого эталона и отклонения от стандарта безопасности, а затем формирует отчёт
в форматах Markdown, HTML и JSON. **Конфигурация в Azure не изменяется.**

```text
Azure Resource Manager ──GET──► снимок (JSON) ──┬─► изменения относительно эталона
                                                ├─► отклонения от standard.yaml
                                                └─► отчёт .md / .html / .json
```

Пример отчёта на демонстрационных данных: [examples/report.md](examples/report.md).

## Только чтение

- Скрипт отправляет в Azure только GET-запросы. Сессия HTTP построена на
  `ReadOnlyAdapter`: любой POST, PUT, PATCH или DELETE блокируется до отправки, даже если
  его вызовет ошибочный код (это покрыто тестом). POST-операции, которые лишь читают
  данные (`learnedIPPrefixes`, `listIdpsSignatures`), тоже не используются.
- Токен Azure AD отправляется только на адрес Resource Manager. Чужой `nextLink`
  отклоняется.
- Учётной записи достаточно встроенной роли **Reader** («Читатель») на подписку или
  группы ресурсов с брандмауэрами, политиками и IP-группами. Если базовая политика
  лежит в другой подписке, на ту подписку тоже нужна роль Reader.

## Что собирается

| Данные | API | Для чего |
|---|---|---|
| Azure Firewall (`Microsoft.Network/azureFirewalls`), включая классические правила | 2024-05-01 | SKU, Threat Intelligence, DNS proxy, зоны, IP-адреса, классические правила |
| Firewall Policy и цепочка базовых политик (`basePolicy`) | 2024-05-01 | Настройки политики, IDPS, TLS-инспекция, исключения Threat Intelligence |
| Группы коллекций правил (`ruleCollectionGroups`) | 2024-05-01 | Правила сетевые, правил приложений и DNAT |
| IP-группы, на которые ссылаются правила | 2024-05-01 | Изменения состава групп; адрес `0.0.0.0/0` внутри группы тоже считается «любым» |
| Параметры диагностики брандмауэров | 2021-05-01-preview | Отправляются ли журналы |
| Журнал действий Azure (Activity Log), по желанию | 2015-04-01 | Кто и когда менял брандмауэры, политики, IP-группы и параметры диагностики |

## Установка

Нужен Python 3.9 или новее.

```bash
cd azure-firewall-audit
python -m venv .venv && . .venv/bin/activate
pip install -r requirements.txt
```

## Вход в Azure

Используется `DefaultAzureCredential` из `azure-identity`. Он по очереди пробует:

- переменные окружения сервисного принципала: `AZURE_TENANT_ID`, `AZURE_CLIENT_ID` и
  `AZURE_CLIENT_SECRET` (или `AZURE_CLIENT_CERTIFICATE_PATH`);
- workload identity, например OIDC в GitHub Actions;
- управляемое удостоверение (managed identity) виртуальной машины, Azure Automation и т. п.;
- `az login`, Azure PowerShell, Azure Developer CLI.

Подписку можно передать через `-s`, переменную `AZURE_SUBSCRIPTION_ID` или
`--all-subscriptions`.

Для национальных облаков укажите `--arm-endpoint` (например,
`https://management.chinacloudapi.cn`) и переменную `AZURE_AUTHORITY_HOST`.

## Порядок работы

**1. Эталон.** Соберите снимок утверждённой конфигурации, проверьте отчёт по нему и
сохраните файл в git или другом защищённом хранилище:

```bash
python azfw_audit.py collect -s <subscription-id> -o baselines/azfw-baseline.json
python azfw_audit.py report -c baselines/azfw-baseline.json -o baselines/azfw-baseline.html
```

**2. Регулярная проверка.** Скрипт собирает новый снимок, сравнивает его с эталоном,
проверяет по стандарту и сохраняет снимок и отчёты в каталог:

```bash
python azfw_audit.py run -s <subscription-id> \
    --baseline baselines/azfw-baseline.json \
    --output-dir reports \
    --fail-on high --fail-on-drift
```

В каталоге появятся файлы `azfw-snapshot-<время>.json` и `azfw-report-<время>.{md,html,json}`.
Журнал действий по умолчанию читается с даты эталона (не более чем за 90 дней), чтобы
в отчёте было видно, кто вносил изменения.

**3. После согласованного изменения** замените эталон новым снимком из `reports/`.

Отчёт по уже сохранённым снимкам строится без обращения к Azure:

```bash
python azfw_audit.py report -c examples/current.snapshot.json -b examples/baseline.snapshot.json -o report.html
```

## Команды

| Команда | Что делает |
|---|---|
| `collect -o FILE` | Сохраняет снимок конфигурации |
| `report -c FILE [-b FILE] [-o FILE \| --output-dir DIR]` | Строит отчёт по снимкам; без `-o` выводит Markdown в stdout |
| `run --output-dir DIR` | Выполняет `collect` и `report` за один запуск |

Параметры сбора (`collect`, `run`):

| Параметр | Значение |
|---|---|
| `-s`, `--subscription` | Подписка; можно указать несколько раз |
| `--all-subscriptions` | Все доступные подписки в состоянии Enabled |
| `-g`, `--resource-group` | Только одна группа ресурсов |
| `-f`, `--firewall` | Только брандмауэры с этими именами |
| `--all-policies` | Также политики, не привязанные к найденным брандмауэрам |
| `--no-diagnostics` | Не читать параметры диагностики |
| `--activity-days N` | Глубина чтения журнала действий в днях; `0` отключает чтение |
| `--arm-endpoint`, `--api-version`, `--timeout` | Адрес Resource Manager, версия API `Microsoft.Network`, тайм-аут запроса |

Параметры отчёта (`report`, `run`):

| Параметр | Значение |
|---|---|
| `-b`, `--baseline` | Эталонный снимок |
| `--standard` | Файл стандарта; по умолчанию `standard.yaml` рядом со скриптом |
| `--format` | `md`, `html`, `json` или список через запятую |
| `--fail-on LEVEL` | Код выхода 2, если есть отклонения уровня `info`/`low`/`medium`/`high`/`critical` или выше |
| `--fail-on-drift` | Код выхода 2, если конфигурация отличается от эталона |

Коды выхода:

| Код | Значение |
|---|---|
| 0 | Проверка завершена, пороги не превышены |
| 1 | Ошибка: нет доступа к Azure AD, неверные параметры, повреждённый снимок |
| 2 | Сработал `--fail-on` или `--fail-on-drift` |
| 3 | Отчёт сформирован, но часть конфигурации прочитать не удалось (например, 403 на базовую политику) |

## Что считается изменением

Снимок раскладывается на объекты: брандмауэры, политики, группы коллекций, коллекции,
правила, IP-группы и параметры диагностики. Объекты сопоставляются по ARM ID и именам,
поэтому в отчёте видно, какое именно правило добавлено, удалено, переименовано или
изменено. Для изменённых объектов показываются конкретные поля, например
`destinationPorts — добавлено: 1434`.

Ложных изменений скрипт не показывает. Не учитываются:

- `etag`, `provisioningState`, `size`, `changeNumber`;
- обратные ссылки, которые Azure ведёт сам: список брандмауэров и дочерних политик в
  политике, `ipGroups` в брандмауэре;
- порядок адресов, портов и других списков, а также регистр ARM ID;
- разница между пустым значением и отсутствующим полем.

Если объект не удалось прочитать (ошибка 403, сбой сети), он попадает в раздел
«Не сравнивались», а не в «Удалено». Ответ 404 означает, что объекта нет, и такой объект
считается удалённым.

## Проверки

| Проверка | Уровень | Что ищет |
|---|---|---|
| `AZFW-ANY-ANY` | критический / высокий / низкий | Разрешающее сетевое правило «любой источник → любое назначение»: критический уровень при всех портах, низкий — только для ICMP |
| `AZFW-SENSITIVE-PORT` | высокий | `sensitive_ports` (SSH, RDP, SMB, СУБД, WinRM…) открыты для любого источника сетевым правилом или DNAT, включая порт после трансляции |
| `AZFW-APP-ANY-FQDN` | высокий | Правило приложений с `targetFqdns: "*"` |
| `AZFW-STATE` | высокий | Брандмауэр, политика или группа правил не в состоянии `Succeeded` |
| `AZFW-TI` | средний / высокий | Режим Threat Intelligence слабее `threat_intel_mode` (с учётом базовых политик) |
| `AZFW-IDPS` | средний / высокий | Premium: режим IDPS слабее `idps_mode` |
| `AZFW-DNS-PROXY` | средний | Сетевые правила используют FQDN, а DNS proxy выключен (или он требуется `require_dns_proxy`) |
| `AZFW-LOGS` | средний | Журналы никуда не отправляются или не включены категории из `required_log_categories` |
| `AZFW-ANY-PORT` | средний | Разрешены все порты или диапазон шире `max_port_range` |
| `AZFW-DNAT-PUBLIC` | средний | DNAT для любого источника на порт вне `public_dnat_allowed_ports` |
| `AZFW-APP-BROAD-FQDN` | средний | Шаблоны вроде `*.com` — целая доменная зона верхнего уровня |
| `AZFW-SKU` | средний | SKU ниже `minimum_sku_tier` |
| `AZFW-PROP` | средний | Свойство отличается от значения в `expected_properties` |
| `AZFW-CLASSIC` | низкий | Классические правила вместо Firewall Policy |
| `AZFW-ANY-PROTO` | низкий | Протокол `Any` |
| `AZFW-TI-ALLOWLIST`, `AZFW-IDPS-BYPASS` | низкий | Исключения Threat Intelligence, отключённые сигнатуры IDPS и правила обхода IDPS |
| `AZFW-DUPLICATE` | низкий | Правила с одинаковыми условиями и действием в одной политике или одном брандмауэре |
| `AZFW-TLS`, `AZFW-ZONES` | низкий | Нет TLS-инспекции или зон доступности (если требуются стандартом) |
| `AZFW-EMPTY`, `AZFW-NO-DESC` | инфо | Пустые коллекции и группы; правила без описания (если требуется) |

## Стандарт и исключения

Требования задаются в [`standard.yaml`](standard.yaml); для каждого параметра там есть
комментарий. Помимо готовых проверок, можно потребовать любое значение свойства:

```yaml
expected_properties:
  firewall:
    properties.sku.tier: "Premium"
  firewall_policy:
    properties.dnsSettings.enableProxy: true
```

Согласованные отклонения оформляются исключениями. Поле `reason` обязательно, `expires`
задавать не обязательно. Отклонения, подпадающие под исключение, выводятся в отдельном
разделе отчёта. В отчёте также отмечаются просроченные исключения и исключения, которые
ни с чем не совпали:

```yaml
exceptions:
  - check: AZFW-SENSITIVE-PORT
    object: "rg-hub-network/fwpol-hub-prod/rcg-workloads/dnat-published/rdp-jumphost"
    reason: "Временный доступ подрядчика, CHG-1050"
    expires: 2026-11-30
```

## Запуск по расписанию

GitHub Actions с OIDC-входом (сервисному принципалу нужна только роль Reader):

```yaml
name: azure-firewall-audit
on:
  schedule: [{cron: "17 5 * * *"}]
  workflow_dispatch:
permissions:
  id-token: write
  contents: read
jobs:
  audit:
    runs-on: ubuntu-latest
    env:
      AZURE_SUBSCRIPTION_ID: ${{ secrets.AZURE_SUBSCRIPTION_ID }}
    steps:
      - uses: actions/checkout@v4
      - uses: azure/login@v2
        with:
          client-id: ${{ secrets.AZURE_CLIENT_ID }}
          tenant-id: ${{ secrets.AZURE_TENANT_ID }}
          subscription-id: ${{ secrets.AZURE_SUBSCRIPTION_ID }}
      - run: pip install -r azure-firewall-audit/requirements.txt
      - run: >
          python azure-firewall-audit/azfw_audit.py run
          --baseline azure-firewall-audit/baselines/azfw-baseline.json
          --output-dir reports --fail-on high --fail-on-drift
      - uses: actions/upload-artifact@v4
        if: always()
        with: {name: azfw-report, path: reports/}
```

Вместо GitHub Actions подойдут cron, Azure Automation или Azure DevOps: достаточно
запустить `run` под учётной записью с ролью Reader и сохранять каталог с отчётами.

## Ограничения

- Затенение правил коллекциями с более высоким приоритетом не анализируется; ищутся
  только точные дубликаты.
- Сервисные теги и FQDN-теги не раскрываются: `Internet` или `AzureCloud` не считаются
  «любым адресом». Список таких обозначений задаётся параметром `any_address_tokens`.
- Черновики политик (`firewallPolicyDrafts`) и маршрутизация Virtual WAN не читаются.
- В журнале действий Azure события хранятся 90 дней.
- Снимки и отчёты содержат внутренние адреса и топологию сети. Храните их с тем же
  уровнем защиты, что и саму конфигурацию.

## Тесты

```bash
pip install -r requirements-dev.txt
python -m pytest
```

Тесты не обращаются к Azure: ответы Resource Manager подменяет заглушка, у которой есть
только метод `get`.
