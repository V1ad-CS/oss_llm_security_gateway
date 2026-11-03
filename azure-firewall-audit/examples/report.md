# Отчёт аудита Azure Firewall и NSG

- **Сформирован:** 2026-11-03 10:21:12 UTC
- **Снимок конфигурации:** 2026-10-27 08:00:00 UTC; подписки: 00000000-0000-0000-0000-000000000000
- **Эталон (baseline):** 2026-10-01 08:00:00 UTC
- **Стандарт:** standard.yaml
- **Режим:** только чтение — конфигурация Azure не изменялась

## Итог

Отклонений от стандарта: 13 (критический: 1, высокий: 4, средний: 6, низкий: 1, инфо: 1). Изменений относительно эталона: 11.

| Уровень | Отклонений |
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
| Изменения: добавлено / удалено / изменено / переименовано | 3 / 1 / 6 / 1 |
| Принятые исключения | 0 |
| Ошибки получения данных | 0 |

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

## Изменения относительно эталона

Эталон: 2026-10-01 08:00:00 UTC, текущий снимок: 2026-10-27 08:00:00 UTC.

| Объект | Изменение | Тип | Подробности |
|---|---|---|---|
| rg-app/nsg-snet-db | Изменено | NSG | subnets — удалено: rg-app/vnet-app/snet-db |
| rg-app/nsg-snet-web/allow-https-in | Изменено | Правило NSG | destinationPortRanges — добавлено: 8443 |
| rg-app/nsg-snet-web/allow-rdp-temp | Добавлено | Правило NSG | Inbound Allow Tcp \* → \* : 3389, приоритет 120 |
| rg-hub-network/fw-hub-weu | Изменено | Брандмауэр | tags.changeTicket: CHG-1001 → CHG-1042 |
| rg-hub-network/fwpol-hub-prod | Изменено | Политика | intrusionDetection.mode: Deny → Alert |
| rg-hub-network/fwpol-hub-prod | Изменено | Политика | threatIntelMode: Deny → Alert |
| rg-hub-network/fwpol-hub-prod/rcg-workloads/app-allow-saas/github-com | Переименовано | Правило | было: rg-hub-network/fwpol-hub-prod/rcg-workloads/app-allow-saas/github; Https:443 10.1.0.0/16 → \*.github.com, github.com |
| rg-hub-network/fwpol-hub-prod/rcg-workloads/dnat-published/rdp-jumphost | Добавлено | Правило | TCP \* → 203.0.113.10 : 3389 ⇒ 10.1.3.4:3389 |
| rg-hub-network/fwpol-hub-prod/rcg-workloads/net-allow-workloads/legacy-ftp | Удалено | Правило | TCP 10.1.1.0/24 → 192.0.2.50 : 21 |
| rg-hub-network/fwpol-hub-prod/rcg-workloads/net-allow-workloads/temp-any-any | Добавлено | Правило | Any \* → \* : \* |
| rg-hub-network/fwpol-hub-prod/rcg-workloads/net-allow-workloads/web-to-sql | Изменено | Правило | destinationPorts — добавлено: 1434 |
| rg-hub-network/ipg-spokes | Изменено | IP-группа | ipAddresses — добавлено: 10.3.0.0/16 |

## Журнал действий Azure

Операции изменения брандмауэров, политик, IP-групп, NSG и диагностики с 2026-10-01 08:00:00 UTC по 2026-10-27 08:00:00 UTC.

| Время | Кто | Операция | Ресурс | Статус |
|---|---|---|---|---|
| 2026-10-14 16:02:11 UTC | netadmin@example.com | ipGroups/write | rg-hub-network/ipGroups/ipg-spokes | Succeeded |
| 2026-10-20 21:47:03 UTC | contractor@example.com | firewallPolicies/ruleCollectionGroups/write | rg-hub-network/firewallPolicies/fwpol-hub-prod/ruleCollectionGroups/rcg-workloads | Succeeded |
| 2026-10-20 21:55:40 UTC | contractor@example.com | firewallPolicies/write | rg-hub-network/firewallPolicies/fwpol-hub-prod | Succeeded |
| 2026-10-20 22:03:52 UTC | contractor@example.com | networkSecurityGroups/securityRules/write | rg-app/networkSecurityGroups/nsg-snet-web/securityRules/allow-rdp-temp | Succeeded |
| 2026-10-21 07:12:19 UTC | netadmin@example.com | azureFirewalls/write | rg-hub-network/azureFirewalls/fw-hub-weu | Succeeded |
| 2026-10-23 11:40:07 UTC | app-deploy@example.com | virtualNetworks/subnets/write | rg-app/virtualNetworks/vnet-app/subnets/snet-db | Succeeded |

## Отклонения от стандарта

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

azfw-audit 1.1.0: данные получены только GET-запросами к Azure Resource Manager; конфигурация не изменялась.
