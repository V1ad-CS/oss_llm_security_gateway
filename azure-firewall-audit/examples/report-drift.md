# Отличия от эталона

Чем текущая конфигурация Azure Firewall и NSG отличается от утверждённого эталона: всё, что изменено и ещё не согласовано заменой эталона.

- **Сформирован:** 2026-11-05 09:57:26 UTC
- **Снимок конфигурации:** 2026-10-27 08:00:00 UTC; подписки: 00000000-0000-0000-0000-000000000000
- **Эталон (baseline):** 2026-10-01 08:00:00 UTC
- **Режим:** только чтение — конфигурация Azure не изменялась

## Итог

Отличий от эталона (2026-10-01 08:00:00 UTC): 11. Согласованные изменения внесите в эталон, несогласованные — откатите.

| Показатель | Значение |
|---|---|
| Добавлено | 3 |
| Удалено | 1 |
| Изменено | 6 |
| Переименовано | 1 |
| Не сравнивались | 0 |
| Ошибки получения данных | 0 |

## Изменения

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

Кто и когда менял брандмауэры, политики, IP-группы, NSG, подсети и диагностику: с 2026-10-01 08:00:00 UTC по 2026-10-27 08:00:00 UTC.

| Время | Кто | Операция | Ресурс | Статус |
|---|---|---|---|---|
| 2026-10-14 16:02:11 UTC | netadmin@example.com | ipGroups/write | rg-hub-network/ipGroups/ipg-spokes | Succeeded |
| 2026-10-20 21:47:03 UTC | contractor@example.com | firewallPolicies/ruleCollectionGroups/write | rg-hub-network/firewallPolicies/fwpol-hub-prod/ruleCollectionGroups/rcg-workloads | Succeeded |
| 2026-10-20 21:55:40 UTC | contractor@example.com | firewallPolicies/write | rg-hub-network/firewallPolicies/fwpol-hub-prod | Succeeded |
| 2026-10-20 22:03:52 UTC | contractor@example.com | networkSecurityGroups/securityRules/write | rg-app/networkSecurityGroups/nsg-snet-web/securityRules/allow-rdp-temp | Succeeded |
| 2026-10-21 07:12:19 UTC | netadmin@example.com | azureFirewalls/write | rg-hub-network/azureFirewalls/fw-hub-weu | Succeeded |
| 2026-10-22 10:31:44 UTC | app-deploy@example.com | networkSecurityGroups/securityRules/write | rg-app/networkSecurityGroups/nsg-snet-web/securityRules/allow-https-in | Succeeded |
| 2026-10-23 11:40:07 UTC | app-deploy@example.com | virtualNetworks/subnets/write | rg-app/virtualNetworks/vnet-app/subnets/snet-db | Succeeded |

azfw-audit 1.2.0: данные получены только GET-запросами к Azure Resource Manager; конфигурация не изменялась.
