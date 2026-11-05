# Нарушения стандарта ИБ

Какие настройки и правила Azure Firewall и NSG нарушают стандарт информационной безопасности.

- **Сформирован:** 2026-11-05 09:57:26 UTC
- **Снимок конфигурации:** 2026-10-27 08:00:00 UTC; подписки: 00000000-0000-0000-0000-000000000000
- **Стандарт:** standard.yaml
- **Режим:** только чтение — конфигурация Azure не изменялась

## Итог

Нарушений стандарта ИБ: 13 (критический: 1, высокий: 4, средний: 6, низкий: 1, инфо: 1).

| Уровень | Нарушений |
|---|---|
| Критический | 1 |
| Высокий | 4 |
| Средний | 6 |
| Низкий | 1 |
| Инфо | 1 |

| Показатель | Значение |
|---|---|
| Брандмауэры | 2 |
| Политики | 2 |
| IP-группы | 1 |
| NSG | 2 |
| Принятые исключения | 0 |
| Ошибки получения данных | 0 |

## Нарушения стандарта

| Уровень | Проверка | Объект | Описание |
|---|---|---|---|
| Критический | AZFW-ANY-ANY | rg-hub-network/fwpol-hub-prod/rcg-workloads/net-allow-workloads/temp-any-any | Правило «любой → любой». Любой источник → любое назначение; протоколы: ANY; порты: \* |
| Высокий | NSG-SENSITIVE-PORT | rg-app/nsg-snet-web/allow-rdp-temp | NSG открывает административный или чувствительный порт для Интернета. Из Интернета доступны порты 3389; источник \*, протокол Tcp, приоритет 120 |
| Высокий | AZFW-APP-ANY-FQDN | rg-dmz/fw-legacy-dmz/classic-application/app-dmz/any-web | Правило приложения разрешает любой FQDN. targetFqdns содержит «\*»; источники: 10.50.0.0/24 |
| Высокий | AZFW-SENSITIVE-PORT | rg-dmz/fw-legacy-dmz/classic-nat/nat-dmz/ssh-admin | Административный или чувствительный порт открыт для любого источника. Публикация для любого источника, порты 22: 198.51.100.20:22 → 10.50.0.10:22 |
| Высокий | AZFW-SENSITIVE-PORT | rg-hub-network/fwpol-hub-prod/rcg-workloads/dnat-published/rdp-jumphost | Административный или чувствительный порт открыт для любого источника. Публикация для любого источника, порты 3389: 203.0.113.10:3389 → 10.1.3.4:3389 |
| Средний | NSG-PUBLIC-PORT | rg-app/nsg-snet-web/allow-https-in | NSG открывает для Интернета порт вне списка разрешённых. Из Интернета доступны порты 8443; источник Internet, протокол Tcp, приоритет 100 |
| Средний | AZFW-DNS-PROXY | rg-dmz/fw-legacy-dmz | DNS proxy выключен. FQDN используются в сетевых правилах: rg-dmz/fw-legacy-dmz/classic-network/net-dmz/smtp-relay |
| Средний | AZFW-LOGS | rg-dmz/fw-legacy-dmz | Журналирование настроено не полностью. Журналы брандмауэра никуда не отправляются: нет параметров диагностики с включёнными журналами |
| Средний | AZFW-TI | rg-dmz/fw-legacy-dmz | Режим Threat Intelligence слабее требуемого. Режим Alert, стандарт требует Deny |
| Средний | AZFW-IDPS | rg-hub-network/fw-hub-weu | Режим IDPS слабее требуемого. Режим IDPS Alert (политика rg-hub-network/fwpol-hub-prod), стандарт требует Deny |
| Средний | AZFW-TI | rg-hub-network/fw-hub-weu | Режим Threat Intelligence слабее требуемого. Режим Alert (политика rg-hub-network/fwpol-hub-prod), стандарт требует Deny |
| Низкий | AZFW-CLASSIC | rg-dmz/fw-legacy-dmz | Классические правила вместо Firewall Policy. Классических правил: 4 |
| Инфо | NSG-UNUSED | rg-app/nsg-snet-db | NSG не привязана ни к подсети, ни к сетевому интерфейсу. Нет привязанных подсетей и сетевых интерфейсов |

### Рекомендации

| Проверка | Что не так | Что сделать |
|---|---|---|
| AZFW-ANY-ANY | Правило «любой → любой» | Ограничьте источники, назначения, порты и протоколы минимально необходимыми. |
| AZFW-APP-ANY-FQDN | Правило приложения разрешает любой FQDN | Замените «\*» перечнем FQDN, FQDN-тегов или веб-категорий. |
| AZFW-CLASSIC | Классические правила вместо Firewall Policy | Перенесите правила в Azure Firewall Policy: классические правила не поддерживают наследование политик и функции Premium. |
| AZFW-DNS-PROXY | DNS proxy выключен | Включите DNS proxy (dnsSettings.enableProxy) и укажите брандмауэр DNS-сервером виртуальных сетей: без этого FQDN в сетевых правилах разрешаются ненадёжно. |
| AZFW-IDPS | Режим IDPS слабее требуемого | Включите IDPS в режиме «Alert and deny» в политике уровня Premium. |
| AZFW-LOGS | Журналирование настроено не полностью | Создайте параметр диагностики, отправляющий журналы брандмауэра (рекомендуются структурированные журналы AZFW\*) в Log Analytics или SIEM. |
| AZFW-SENSITIVE-PORT | Административный или чувствительный порт открыт для любого источника | Ограничьте источники доверенными адресами; для RDP/SSH используйте Azure Bastion, JIT или VPN вместо публикации портов. |
| AZFW-TI | Режим Threat Intelligence слабее требуемого | Установите в политике режим Threat Intelligence «Alert and deny» (Deny). |
| NSG-PUBLIC-PORT | NSG открывает для Интернета порт вне списка разрешённых | Ограничьте источники правила или добавьте порт в nsg\_public\_allowed\_ports, если публикация согласована. |
| NSG-SENSITIVE-PORT | NSG открывает административный или чувствительный порт для Интернета | Ограничьте источник доверенными адресами; для RDP/SSH используйте Azure Bastion, JIT-доступ Defender for Cloud или VPN. |
| NSG-UNUSED | NSG не привязана ни к подсети, ни к сетевому интерфейсу | Привяжите NSG к нужной подсети или удалите её; проверьте, не осталась ли подсеть без защиты. |

## Инвентаризация

| Брандмауэр | Регион | SKU | Правила из | Threat Intel | IDPS | DNS proxy | Зоны | Частный IP | Правил | Журналы | Состояние |
|---|---|---|---|---|---|---|---|---|---|---|---|
| rg-dmz/fw-legacy-dmz | westeurope | AZFW\_VNet / Standard | классические правила | Alert | — | выкл | — | 10.50.1.4 | 4 | нет | Succeeded |
| rg-hub-network/fw-hub-weu | westeurope | AZFW\_VNet / Premium | rg-hub-network/fwpol-hub-prod | Alert | Alert | вкл | 1, 2, 3 | 10.0.1.4 | 11 | да | Succeeded |

| Политика | SKU | Базовая политика | Брандмауэров | Групп коллекций | Правил | Threat Intel | IDPS |
|---|---|---|---|---|---|---|---|
| rg-hub-network/fwpol-hub-prod | Premium | rg-security/fwpol-base-global | 1 | 2 | 10 | Alert | Alert |
| rg-security/fwpol-base-global | Premium | — | 0 | 1 | 1 | Alert | — |

| NSG | Регион | Правил | Подсети | Сетевых интерфейсов | Правил с доступом из Интернета | Состояние |
|---|---|---|---|---|---|---|
| rg-app/nsg-snet-db | westeurope | 3 | — | 0 | 0 | Succeeded |
| rg-app/nsg-snet-web | westeurope | 4 | rg-app/vnet-app/snet-web | 0 | 2 | Succeeded |

azfw-audit 1.2.0: данные получены только GET-запросами к Azure Resource Manager; конфигурация не изменялась.
