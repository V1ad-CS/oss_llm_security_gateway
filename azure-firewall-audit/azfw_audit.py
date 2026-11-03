#!/usr/bin/env python3
"""
Read-only audit of Azure Firewall and Network Security Group configuration.

Reads Azure Firewall resources, their Firewall Policies (with base policies and
rule collection groups), referenced IP Groups, diagnostic settings, Network
Security Groups with their rules and associations and, optionally, Activity Log
entries through Azure Resource Manager, then

  * compares the snapshot with an approved baseline snapshot (drift),
  * checks it against the security standard in standard.yaml (deviations),
  * writes a report in Markdown, HTML and/or JSON.

Nothing in Azure is changed: the HTTP session refuses every method except GET
(see ReadOnlyAdapter), and the identity only needs the built-in Reader role.

    python azfw_audit.py collect -s <subscription> -o baseline.json
    python azfw_audit.py run -s <subscription> --baseline baseline.json --output-dir reports
    python azfw_audit.py report --current snapshot.json --baseline baseline.json -o report.html

See README.md for details.
"""

from __future__ import annotations

import argparse
import copy
import datetime as dt
import fnmatch
import hashlib
import html
import ipaddress
import json
import logging
import math
import os
import re
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Iterable, Iterator
from urllib.parse import urlparse

import requests
import yaml
from requests.adapters import HTTPAdapter

TOOL_NAME = "azfw-audit"
TOOL_VERSION = "1.1.0"
SNAPSHOT_SCHEMA_VERSION = 1

DEFAULT_ARM_ENDPOINT = "https://management.azure.com"
NETWORK_API_VERSION = "2024-05-01"
DIAGNOSTICS_API_VERSION = "2021-05-01-preview"
ACTIVITY_LOG_API_VERSION = "2015-04-01"
SUBSCRIPTIONS_API_VERSION = "2022-12-01"
ACTIVITY_LOG_MAX_DAYS = 90  # Activity Log retention

EXIT_OK = 0
EXIT_ERROR = 1
EXIT_ATTENTION = 2  # findings or drift reached the --fail-on thresholds
EXIT_INCOMPLETE = 3  # report written, but part of the configuration could not be read

SEVERITIES = ("info", "low", "medium", "high", "critical")
SEVERITY_RANK = {name: rank for rank, name in enumerate(SEVERITIES)}
SEVERITY_TITLES = {
    "critical": "Критический",
    "high": "Высокий",
    "medium": "Средний",
    "low": "Низкий",
    "info": "Инфо",
}
MODE_RANK = {"off": 0, "alert": 1, "deny": 2}  # Threat Intelligence and IDPS modes
SKU_RANK = {"basic": 0, "standard": 1, "premium": 2}

# Classic rules live on the firewall itself instead of a Firewall Policy.
CLASSIC_COLLECTIONS = (
    ("network", "networkRuleCollections"),
    ("application", "applicationRuleCollections"),
    ("nat", "natRuleCollections"),
)
POLICY_RULE_KINDS = {"NetworkRule": "network", "ApplicationRule": "application", "NatRule": "nat"}

# Ignored when comparing snapshots: they change on every update (etag, size,
# changeNumber) or describe a deployment rather than the configuration.
VOLATILE_KEYS = frozenset({"etag", "provisioningState", "size", "changeNumber"})
# Back-references maintained by Azure; the same fact is compared on the other side.
BACKREF_KEYS = {
    "firewall": ("ipGroups",),
    "firewall_policy": ("ruleCollectionGroups", "firewalls", "childPolicies"),
    "ip_group": ("firewalls", "firewallPolicies"),
}
LOG_DESTINATIONS = ("workspaceId", "storageAccountId", "eventHubAuthorizationRuleId", "marketplacePartnerId")
DIAGNOSTICS_SUFFIX = "/providers/microsoft.insights/diagnosticsettings"

# NSG rules accept one value or a list for the same field; both are merged into the list.
NSG_SINGLE_TO_LIST = (
    ("sourceAddressPrefix", "sourceAddressPrefixes"),
    ("destinationAddressPrefix", "destinationAddressPrefixes"),
    ("sourcePortRange", "sourcePortRanges"),
    ("destinationPortRange", "destinationPortRanges"),
)
NSG_ASG_KEYS = ("sourceApplicationSecurityGroups", "destinationApplicationSecurityGroups")
NSG_PORTLESS_PROTOCOLS = frozenset({"icmp", "esp", "ah"})

# Entity kinds by where they are discovered; a failed listing blinds only its own kinds.
FIREWALL_KINDS = ("firewall", "firewall_policy", "rule_collection_group", "rule_collection", "rule", "ip_group", "diagnostic_setting")
NSG_KINDS = ("network_security_group", "security_rule")

# Snapshot sections that can be switched off (--no-diagnostics, --no-nsg) or are
# missing in snapshots of older versions, and the entity kinds read from them.
OPTIONAL_SECTIONS = {
    "diagnostic_settings": ("параметры диагностики", ("diagnostic_setting",)),
    "network_security_groups": ("NSG", NSG_KINDS),
}

ACTIVITY_OPERATION_PREFIXES = (
    "microsoft.network/azurefirewalls/",
    "microsoft.network/firewallpolicies/",
    "microsoft.network/ipgroups/",
    "microsoft.network/networksecuritygroups/",
    "microsoft.network/virtualnetworks/subnets/",  # attaching or detaching an NSG is a subnet write
    "microsoft.insights/diagnosticsettings/",
)
ACTIVITY_OPERATION_SUFFIXES = ("/write", "/delete", "/deploy/action")

DEFAULT_STANDARD: dict[str, Any] = {
    "minimum_sku_tier": "Standard",
    "threat_intel_mode": "Deny",
    "idps_mode": "Deny",
    "require_tls_inspection": False,
    "require_dns_proxy": False,
    "require_diagnostic_settings": True,
    "required_log_categories": [],
    "require_availability_zones": False,
    "require_rule_description": False,
    "max_port_range": 1000,
    "sensitive_ports": [
        20, 21, 22, 23, 135, 137, 138, 139, 445, 1433, 1521, 2375, 2376,
        3306, 3389, 5432, 5900, 5985, 5986, 6379, 9200, 11211, 27017,
    ],
    "public_dnat_allowed_ports": [80, 443],
    "any_address_tokens": ["*", "0.0.0.0/0", "0.0.0.0-255.255.255.255", "::/0"],
    "nsg_public_sources": ["*", "0.0.0.0/0", "::/0", "Internet"],
    "nsg_public_allowed_ports": [80, 443],
    "require_nsg_association": True,
    "expected_properties": {"firewall": {}, "firewall_policy": {}, "network_security_group": {}},
    "exceptions": [],
}

# check id -> (title, recommendation)
CHECKS = {
    "AZFW-STATE": (
        "Ресурс не в состоянии Succeeded",
        "Выясните причину сбоя в журнале действий Azure и повторно примените конфигурацию "
        "из эталонного шаблона (IaC).",
    ),
    "AZFW-SKU": (
        "Уровень SKU ниже требуемого",
        "Перейдите на требуемый уровень SKU; IDPS и TLS-инспекция доступны только в Premium.",
    ),
    "AZFW-TI": (
        "Режим Threat Intelligence слабее требуемого",
        "Установите в политике режим Threat Intelligence «Alert and deny» (Deny).",
    ),
    "AZFW-TI-ALLOWLIST": (
        "Есть исключения из Threat Intelligence",
        "Проверьте обоснованность каждого исключения и удалите неактуальные.",
    ),
    "AZFW-IDPS": (
        "Режим IDPS слабее требуемого",
        "Включите IDPS в режиме «Alert and deny» в политике уровня Premium.",
    ),
    "AZFW-IDPS-BYPASS": (
        "IDPS частично отключён",
        "Проверьте обоснованность отключённых сигнатур и правил обхода IDPS.",
    ),
    "AZFW-TLS": (
        "TLS-инспекция не настроена",
        "Укажите в политике Premium промежуточный сертификат ЦС из Key Vault и включите "
        "terminateTLS в правилах приложений.",
    ),
    "AZFW-DNS-PROXY": (
        "DNS proxy выключен",
        "Включите DNS proxy (dnsSettings.enableProxy) и укажите брандмауэр DNS-сервером "
        "виртуальных сетей: без этого FQDN в сетевых правилах разрешаются ненадёжно.",
    ),
    "AZFW-LOGS": (
        "Журналирование настроено не полностью",
        "Создайте параметр диагностики, отправляющий журналы брандмауэра (рекомендуются "
        "структурированные журналы AZFW*) в Log Analytics или SIEM.",
    ),
    "AZFW-ZONES": (
        "Брандмауэр не размещён в зонах доступности",
        "Разверните брандмауэр в нескольких зонах доступности (требует пересоздания).",
    ),
    "AZFW-CLASSIC": (
        "Классические правила вместо Firewall Policy",
        "Перенесите правила в Azure Firewall Policy: классические правила не поддерживают "
        "наследование политик и функции Premium.",
    ),
    "AZFW-PROP": (
        "Параметр отличается от стандарта",
        "Приведите параметр к значению из стандарта или оформите исключение.",
    ),
    "AZFW-ANY-ANY": (
        "Правило «любой → любой»",
        "Ограничьте источники, назначения, порты и протоколы минимально необходимыми.",
    ),
    "AZFW-ANY-PORT": (
        "Разрешены все порты или слишком широкий диапазон",
        "Укажите только порты, которые нужны приложению.",
    ),
    "AZFW-ANY-PROTO": (
        "Разрешён любой протокол (Any)",
        "Укажите конкретные протоколы: TCP, UDP или ICMP.",
    ),
    "AZFW-SENSITIVE-PORT": (
        "Административный или чувствительный порт открыт для любого источника",
        "Ограничьте источники доверенными адресами; для RDP/SSH используйте Azure Bastion, "
        "JIT или VPN вместо публикации портов.",
    ),
    "AZFW-DNAT-PUBLIC": (
        "DNAT публикует порт для любого источника",
        "Ограничьте источники DNAT-правила или добавьте порт в public_dnat_allowed_ports, "
        "если публикация согласована.",
    ),
    "AZFW-APP-ANY-FQDN": (
        "Правило приложения разрешает любой FQDN",
        "Замените «*» перечнем FQDN, FQDN-тегов или веб-категорий.",
    ),
    "AZFW-APP-BROAD-FQDN": (
        "Правило приложения разрешает целую доменную зону верхнего уровня",
        "Сузьте шаблон до доменов конкретного поставщика.",
    ),
    "AZFW-DUPLICATE": (
        "Дублирующиеся правила",
        "Удалите лишние копии: дубль остаётся разрешающим, когда основное правило удалят.",
    ),
    "AZFW-EMPTY": (
        "Пустая коллекция или группа правил",
        "Удалите пустой объект или наполните его правилами.",
    ),
    "AZFW-NO-DESC": (
        "У правила нет описания",
        "Опишите назначение правила и укажите номер заявки на изменение.",
    ),
    "NSG-INTERNET-ANY-PORT": (
        "NSG открывает все порты для входящего трафика из Интернета",
        "Удалите правило или ограничьте источники и порты; входящий доступ из Интернета "
        "публикуйте через Azure Firewall, Application Gateway или Load Balancer.",
    ),
    "NSG-SENSITIVE-PORT": (
        "NSG открывает административный или чувствительный порт для Интернета",
        "Ограничьте источник доверенными адресами; для RDP/SSH используйте Azure Bastion, "
        "JIT-доступ Defender for Cloud или VPN.",
    ),
    "NSG-WIDE-PORT": (
        "NSG открывает для Интернета слишком широкий диапазон портов",
        "Укажите только порты, которые нужны приложению.",
    ),
    "NSG-PUBLIC-PORT": (
        "NSG открывает для Интернета порт вне списка разрешённых",
        "Ограничьте источники правила или добавьте порт в nsg_public_allowed_ports, "
        "если публикация согласована.",
    ),
    "NSG-UNUSED": (
        "NSG не привязана ни к подсети, ни к сетевому интерфейсу",
        "Привяжите NSG к нужной подсети или удалите её; проверьте, не осталась ли подсеть без защиты.",
    ),
}

KIND_TITLES = {
    "firewall": "Брандмауэр",
    "firewall_policy": "Политика",
    "rule_collection_group": "Группа коллекций",
    "rule_collection": "Коллекция правил",
    "rule": "Правило",
    "ip_group": "IP-группа",
    "diagnostic_setting": "Диагностика",
    "network_security_group": "NSG",
    "security_rule": "Правило NSG",
}

log = logging.getLogger(TOOL_NAME)


class ConfigError(Exception):
    """Bad command line, snapshot or standard file."""


class AuthError(Exception):
    """No Azure AD token: nothing can be read, so the run stops."""


class ReadOnlyViolation(RuntimeError):
    """Something tried to send a request other than GET to Azure."""


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def utcnow() -> dt.datetime:
    return dt.datetime.now(dt.timezone.utc).replace(microsecond=0)


def isoformat(value: dt.datetime) -> str:
    return value.astimezone(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def parse_time(value: str) -> dt.datetime:
    return dt.datetime.strptime(value[:19], "%Y-%m-%dT%H:%M:%S").replace(tzinfo=dt.timezone.utc)


def fmt_time(value: str | None) -> str:
    return value[:19].replace("T", " ") + " UTC" if value else "—"


def props(resource: dict | None) -> dict:
    return (resource or {}).get("properties") or {}


def ref_id(value: dict | None) -> str:
    """Lower-cased id of a SubResource reference ({"id": ...}), or ""."""
    return ((value or {}).get("id") or "").lower()


_RESOURCE_GROUP_RE = re.compile(r"/resourcegroups/([^/]+)", re.IGNORECASE)


def id_label(resource_id: str) -> str:
    """'<resource group>/<name>' for an ARM id; '<resource group>/<vnet>/<subnet>' for a subnet."""
    parts = resource_id.rstrip("/").split("/")
    name = parts[-1]
    if len(parts) >= 3 and parts[-2].lower() == "subnets":
        name = f"{parts[-3]}/{name}"
    match = _RESOURCE_GROUP_RE.search(resource_id)
    return f"{match.group(1)}/{name}" if match else name


def resource_label(resource: dict) -> str:
    resource_id = resource.get("id") or ""
    match = _RESOURCE_GROUP_RE.search(resource_id)
    name = resource.get("name") or resource_id.rstrip("/").rsplit("/", 1)[-1]
    return f"{match.group(1)}/{name}" if match else name


def under(resource_id: str, scope: str) -> bool:
    resource_id, scope = resource_id.lower(), scope.lower().rstrip("/")
    return resource_id == scope or resource_id.startswith(scope + "/")


def canonical(value: Any) -> str:
    return json.dumps(value, sort_keys=True, ensure_ascii=False, default=str)


def _is_empty(value: Any) -> bool:
    return value is None or value == "" or value == [] or value == {}


def normalize(value: Any) -> Any:
    """Canonical form for comparison: no volatile keys or empty values,
    order-insensitive lists, lower-case ARM ids (ARM ids are case-insensitive)."""
    if isinstance(value, dict):
        result = {}
        for key, item in value.items():
            if key in VOLATILE_KEYS:
                continue
            item = normalize(item)
            if not _is_empty(item):
                result[key] = item
        return result
    if isinstance(value, list):
        items = [normalize(item) for item in value]
        return sorted((item for item in items if not _is_empty(item)), key=canonical)
    if isinstance(value, str) and value.lower().startswith("/subscriptions/"):
        return value.lower()
    return value


def _first(values: Iterable[Any]) -> Any:
    return next((value for value in values if value is not None), None)


def _mode_rank(mode: Any) -> int:
    return MODE_RANK.get(str(mode).lower(), 0)


def short_list(values: Iterable[Any], limit: int = 6) -> str:
    items = [fmt_value(value) for value in values]
    if not items:
        return "—"
    if len(items) > limit:
        return ", ".join(items[:limit]) + f" и ещё {len(items) - limit}"
    return ", ".join(items)


def fmt_value(value: Any, limit: int = 300) -> str:
    if _is_empty(value):
        return "—"
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, str):
        text = id_label(value) if value.lower().startswith("/subscriptions/") else value
    elif isinstance(value, list) and all(not isinstance(item, (dict, list)) for item in value):
        text = ", ".join(fmt_value(item) for item in value)
    else:
        text = canonical(value)
    return text if len(text) <= limit else text[: limit - 1] + "…"


# ---------------------------------------------------------------------------
# Azure Resource Manager client (GET only)
# ---------------------------------------------------------------------------

class ReadOnlyAdapter(HTTPAdapter):
    """Transport adapter that refuses to send anything but GET/HEAD.

    The last line of defence: even if code calls session.put()/post()/delete(),
    the request never leaves the process.
    """

    ALLOWED_METHODS = frozenset({"GET", "HEAD"})

    def send(self, request, *args, **kwargs):
        if (request.method or "").upper() not in self.ALLOWED_METHODS:
            raise ReadOnlyViolation(f"{request.method} {request.url} заблокирован: аудит работает только на чтение")
        return super().send(request, *args, **kwargs)


def read_only_session() -> requests.Session:
    session = requests.Session()
    adapter = ReadOnlyAdapter()
    session.mount("https://", adapter)
    session.mount("http://", adapter)
    return session


class ArmError(Exception):
    def __init__(self, url: str, status: int | None, message: str):
        super().__init__(f"{status or 'сетевая ошибка'}: {message} ({url})")
        self.url = url
        self.status = status
        self.message = message


def _retry_delay(response: requests.Response, attempt: int) -> float:
    try:
        return min(float(response.headers.get("Retry-After", "")), 60.0)
    except ValueError:
        return float(min(2 ** attempt, 30))


def _arm_error_message(response: requests.Response) -> str:
    try:
        error = response.json().get("error") or {}
        if error.get("message"):
            return f"{error.get('code', '')}: {error['message']}".lstrip(": ")
    except ValueError:
        pass
    return (response.text or response.reason or "").strip()[:300]


class ArmClient:
    """Minimal Azure Resource Manager client that can only read."""

    RETRY_STATUSES = frozenset({429, 500, 502, 503, 504})

    def __init__(
        self,
        credential: Any,
        endpoint: str = DEFAULT_ARM_ENDPOINT,
        *,
        timeout: float = 60.0,
        max_attempts: int = 5,
        session: Any = None,
        sleep: Callable[[float], None] = time.sleep,
    ):
        self.endpoint = endpoint.rstrip("/")
        self._host = urlparse(self.endpoint).netloc.lower()
        self._credential = credential
        self._scope = self.endpoint + "/.default"
        self._token = None
        self._session = session or read_only_session()
        self._timeout = timeout
        self._max_attempts = max_attempts
        self._sleep = sleep

    def _authorization(self) -> str:
        # Refresh five minutes before expiry: a large collection can outlive a token.
        if self._token is None or self._token.expires_on - 300 <= time.time():
            try:
                self._token = self._credential.get_token(self._scope)
            except Exception as exc:  # azure-identity raises several unrelated types
                raise AuthError(f"не удалось получить токен Azure AD: {exc}") from exc
        return "Bearer " + self._token.token

    def get(self, path: str, api_version: str, params: dict | None = None) -> dict:
        if path.startswith(("https://", "http://")):
            url, query = path, None  # nextLink already carries api-version and the skip token
        else:
            url, query = self.endpoint + path, {"api-version": api_version, **(params or {})}
        if urlparse(url).netloc.lower() != self._host:
            # The bearer token is never sent anywhere but Resource Manager.
            raise ArmError(url, None, "адрес вне Azure Resource Manager")
        for attempt in range(1, self._max_attempts + 1):
            headers = {"Authorization": self._authorization(), "Accept": "application/json"}
            try:
                response = self._session.get(url, params=query, headers=headers, timeout=self._timeout)
            except requests.RequestException as exc:
                if attempt == self._max_attempts:
                    raise ArmError(url, None, str(exc)) from exc
                self._sleep(min(2 ** attempt, 30))
                continue
            if response.status_code == 200:
                try:
                    return response.json()
                except ValueError as exc:
                    raise ArmError(url, 200, "ответ не в формате JSON") from exc
            if response.status_code in self.RETRY_STATUSES and attempt < self._max_attempts:
                delay = _retry_delay(response, attempt)
                log.debug("HTTP %s, повтор через %.0f с: %s", response.status_code, delay, url)
                self._sleep(delay)
                continue
            raise ArmError(url, response.status_code, _arm_error_message(response))
        raise AssertionError("unreachable")

    def list(self, path: str, api_version: str, params: dict | None = None) -> list[dict]:
        page = self.get(path, api_version, params)
        items = list(page.get("value") or [])
        while page.get("nextLink"):
            page = self.get(page["nextLink"], api_version)
            items.extend(page.get("value") or [])
        return items


def make_client(endpoint: str, timeout: float) -> ArmClient:
    try:
        from azure.identity import DefaultAzureCredential
    except ImportError as exc:
        raise ConfigError("для чтения из Azure нужен пакет azure-identity: pip install -r requirements.txt") from exc
    return ArmClient(DefaultAzureCredential(), endpoint, timeout=timeout)


def list_subscriptions(client: ArmClient) -> list[str]:
    subscriptions = client.list("/subscriptions", SUBSCRIPTIONS_API_VERSION)
    return sorted(s["subscriptionId"] for s in subscriptions if s.get("state") == "Enabled")


# ---------------------------------------------------------------------------
# Collection
# ---------------------------------------------------------------------------

def ip_group_refs(*nodes: Any) -> set[str]:
    """Ids of IP Groups referenced anywhere in rules or IDPS bypass settings."""
    found: set[str] = set()

    def walk(node: Any) -> None:
        if isinstance(node, dict):
            for key, value in node.items():
                if key in ("sourceIpGroups", "destinationIpGroups") and isinstance(value, list):
                    found.update(item.lower() for item in value if isinstance(item, str))
                else:
                    walk(value)
        elif isinstance(node, list):
            for item in node:
                walk(item)

    for node in nodes:
        walk(node)
    return found


class Collector:
    """Reads the configuration through ArmClient; never writes anything."""

    def __init__(
        self,
        client: ArmClient,
        *,
        api_version: str = NETWORK_API_VERSION,
        diagnostics: bool = True,
        nsg: bool = True,
    ):
        self.client = client
        self.api_version = api_version
        self.diagnostics = diagnostics
        self.nsg = nsg
        self.errors: list[dict] = []

    def _error(self, scope: str, stage: str, exc: ArmError, kinds: Iterable[str] | None = None) -> None:
        # 404 means the object does not exist: that is a result (e.g. a deleted
        # firewall), not a gap in the data.
        error = {
            "scope": scope.lower(),
            "stage": stage,
            "status": exc.status,
            "message": exc.message,
            "incomplete": exc.status != 404,
        }
        if kinds:
            error["kinds"] = list(kinds)  # a listing of one resource type hides only that type
        self.errors.append(error)
        log.warning("%s %s: %s", stage, scope, exc.message)

    def _not_found(self, names: list[str], found: set[str], scope: str, stage: str, message: str) -> None:
        for name in names:
            if name.lower() not in found:
                self.errors.append({
                    "scope": f"{scope}/{name.lower()}", "stage": stage, "status": 404,
                    "message": message, "incomplete": False,
                })

    def collect(
        self,
        subscriptions: list[str],
        *,
        resource_group: str | None = None,
        firewall_names: Iterable[str] = (),
        nsg_names: Iterable[str] = (),
        all_policies: bool = False,
        activity_days: int = 0,
    ) -> dict:
        self.errors = []
        started = utcnow()
        names = [name for name in firewall_names if name]
        nsg_filter = [name for name in nsg_names if name]

        firewalls: dict[str, dict] = {}
        for subscription in subscriptions:
            for firewall in self._firewalls(subscription, resource_group, names):
                firewalls[firewall["id"].lower()] = firewall
        if not resource_group:  # with a resource group, a missing name is already a 404 from GET
            found = {fw.get("name", "").lower() for fw in firewalls.values()}
            self._not_found(names, found, "azurefirewalls", "firewall", "брандмауэр с таким именем не найден")

        policy_ids = [ref_id(props(fw).get("firewallPolicy")) for fw in firewalls.values()]
        if all_policies:
            for subscription in subscriptions:
                policy_ids += self._list_ids(subscription, resource_group, "firewallPolicies", "firewall policy list")
        policies = self._policies(policy_ids)
        ip_groups = self._ip_groups(sorted(ip_group_refs(firewalls, policies)))
        diagnostics = self._diagnostics(firewalls) if self.diagnostics else None

        nsgs: dict[str, dict] | None = None
        if self.nsg:
            nsgs = {}
            for subscription in subscriptions:
                for nsg in self._nsgs(subscription, resource_group, nsg_filter):
                    nsgs[nsg["id"].lower()] = nsg
            found = {nsg.get("name", "").lower() for nsg in nsgs.values()}
            self._not_found(nsg_filter, found, "networksecuritygroups", "nsg", "NSG с таким именем не найдена")

        snapshot = {
            "schema_version": SNAPSHOT_SCHEMA_VERSION,
            "tool": {"name": TOOL_NAME, "version": TOOL_VERSION},
            "collected_at": isoformat(started),
            "scope": {
                "subscriptions": sorted(subscriptions),
                "resource_group": resource_group,
                "firewalls": sorted(names),
                "all_policies": all_policies,
                "nsgs": sorted(nsg_filter),
                "include_nsgs": self.nsg,
            },
            "arm_endpoint": self.client.endpoint,
            "api_versions": {"network": self.api_version, "diagnostics": DIAGNOSTICS_API_VERSION},
            "firewalls": firewalls,
            "firewall_policies": policies,
            "ip_groups": ip_groups,
            "diagnostic_settings": diagnostics,
            "network_security_groups": nsgs,
            "activity_log": None,
            "errors": self.errors,
        }
        if activity_days > 0:
            snapshot["activity_log"] = self._activity_log(subscriptions, resource_group, activity_days)
        return snapshot

    def _scope_path(self, subscription: str, resource_group: str | None) -> str:
        path = f"/subscriptions/{subscription}"
        return f"{path}/resourceGroups/{resource_group}" if resource_group else path

    def _firewalls(self, subscription: str, resource_group: str | None, names: list[str]) -> list[dict]:
        base = self._scope_path(subscription, resource_group)
        if resource_group and names:
            result = []
            for name in names:
                path = f"{base}/providers/Microsoft.Network/azureFirewalls/{name}"
                try:
                    result.append(self.client.get(path, self.api_version))
                except ArmError as exc:
                    self._error(path, "firewall", exc)
            return result
        return self._list(base, "azureFirewalls", "firewall list", names, FIREWALL_KINDS)

    def _nsgs(self, subscription: str, resource_group: str | None, names: list[str]) -> list[dict]:
        # A listing returns every NSG with its rules and subnet/NIC associations.
        return self._list(self._scope_path(subscription, resource_group), "networkSecurityGroups", "nsg list", names, NSG_KINDS)

    def _list(self, base: str, resource_type: str, stage: str, names: list[str], kinds: tuple[str, ...]) -> list[dict]:
        try:
            items = self.client.list(f"{base}/providers/Microsoft.Network/{resource_type}", self.api_version)
        except ArmError as exc:
            self._error(base, stage, exc, kinds)
            return []
        if names:
            wanted = {name.lower() for name in names}
            items = [item for item in items if item.get("name", "").lower() in wanted]
        return items

    def _list_ids(self, subscription: str, resource_group: str | None, resource_type: str, stage: str) -> list[str]:
        base = self._scope_path(subscription, resource_group)
        return [item["id"] for item in self._list(base, resource_type, stage, [], FIREWALL_KINDS)]

    def _policies(self, policy_ids: list[str]) -> dict[str, dict]:
        result: dict[str, dict] = {}
        queue = [policy_id for policy_id in policy_ids if policy_id]
        while queue:
            policy_id = queue.pop(0)
            key = policy_id.lower()
            if key in result or any(error["scope"] == key for error in self.errors):
                continue
            try:
                policy = self.client.get(policy_id, self.api_version)
            except ArmError as exc:
                self._error(policy_id, "firewall policy", exc)
                continue
            try:
                groups = self.client.list(f"{policy_id}/ruleCollectionGroups", self.api_version)
            except ArmError as exc:
                self._error(f"{policy_id}/ruleCollectionGroups", "rule collection groups", exc)
                groups = []
            result[key] = {
                "resource": policy,
                "rule_collection_groups": sorted(groups, key=lambda group: str(group.get("name", "")).lower()),
            }
            base_policy = ref_id(props(policy).get("basePolicy"))
            if base_policy:
                queue.append(base_policy)
        return result

    def _ip_groups(self, group_ids: list[str]) -> dict[str, dict]:
        result = {}
        for group_id in group_ids:
            try:
                result[group_id] = self.client.get(group_id, self.api_version)
            except ArmError as exc:
                self._error(group_id, "ip group", exc)
        return result

    def _diagnostics(self, firewalls: dict[str, dict]) -> dict[str, list]:
        result = {}
        for firewall_id, firewall in firewalls.items():
            path = f"{firewall['id']}/providers/Microsoft.Insights/diagnosticSettings"
            try:
                settings = self.client.list(path, DIAGNOSTICS_API_VERSION)
            except ArmError as exc:
                self._error(path, "diagnostic settings", exc)
                continue
            result[firewall_id] = sorted(settings, key=lambda setting: str(setting.get("name", "")).lower())
        return result

    def _activity_log(self, subscriptions: list[str], resource_group: str | None, days: int) -> dict:
        end = utcnow()
        start = end - dt.timedelta(days=min(days, ACTIVITY_LOG_MAX_DAYS))
        result: dict[str, Any] = {"from": isoformat(start), "to": isoformat(end), "events": [], "errors": []}
        # The Activity Log API accepts only a few filter combinations: time plus
        # either a resource group or a resource provider.
        time_filter = f"eventTimestamp ge '{isoformat(start)}' and eventTimestamp le '{isoformat(end)}'"
        if resource_group:
            scope_filter = f" and resourceGroupName eq '{resource_group}'"
        else:
            scope_filter = " and resourceProvider eq 'Microsoft.Network'"
        params = {
            "$filter": time_filter + scope_filter,
            "$select": "eventTimestamp,caller,operationName,resourceId,status,correlationId",
        }
        seen = set()
        for subscription in subscriptions:
            path = f"/subscriptions/{subscription}/providers/Microsoft.Insights/eventtypes/management/values"
            try:
                events = self.client.list(path, ACTIVITY_LOG_API_VERSION, params)
            except ArmError as exc:
                # The Activity Log only adds context; the configuration audit stays complete.
                result["errors"].append({"scope": f"/subscriptions/{subscription}", "status": exc.status, "message": exc.message})
                log.warning("activity log %s: %s", subscription, exc.message)
                continue
            for event in events:
                row = _activity_row(event)
                if row is None:
                    continue
                key = (row["correlation_id"], row["operation"].lower(), row["resource_id"].lower(), row["status"])
                if key not in seen:
                    seen.add(key)
                    result["events"].append(row)
        result["events"].sort(key=lambda row: row["time"])
        return result


def _activity_row(event: dict) -> dict | None:
    operation = (event.get("operationName") or {}).get("value") or ""
    resource_id = event.get("resourceId") or ""
    lowered = operation.lower()
    if not lowered.startswith(ACTIVITY_OPERATION_PREFIXES) or not lowered.endswith(ACTIVITY_OPERATION_SUFFIXES):
        return None
    if lowered.startswith("microsoft.insights/") and "/azurefirewalls/" not in resource_id.lower():
        return None
    status = (event.get("status") or {}).get("value") or ""
    if status not in ("Succeeded", "Failed"):  # skip the Started/Accepted half of each operation
        return None
    return {
        "time": event.get("eventTimestamp") or "",
        "caller": event.get("caller") or "",
        "operation": operation,
        "resource_id": resource_id,
        "status": status,
        "correlation_id": event.get("correlationId") or "",
    }


# ---------------------------------------------------------------------------
# Snapshot model and drift
# ---------------------------------------------------------------------------

def flatten_security_rule(rule: dict) -> dict:
    """NSG rule with single-value fields merged into their lists and application
    security groups as plain ids, so both spellings of one rule compare equal."""
    data = dict(props(rule))
    for single, plural in NSG_SINGLE_TO_LIST:
        value = data.pop(single, None)
        merged = [value] if value not in (None, "") else []
        merged += [item for item in data.get(plural) or [] if item not in merged]
        data[plural] = merged
    for key in NSG_ASG_KEYS:
        data[key] = [ref_id(group) for group in data.get(key) or [] if isinstance(group, dict)]
    return {"name": rule.get("name"), **data}


@dataclass
class Entity:
    kind: str
    label: str
    owner: str  # lower-case ARM path the entity was read from; scopes collection errors
    data: Any


def build_entities(snapshot: dict) -> dict[str, Entity]:
    """Flatten a snapshot into comparable objects keyed by a stable identity."""
    entities: dict[str, Entity] = {}

    def add(key: str, kind: str, label: str, owner: str, data: Any) -> None:
        key = key.lower()
        while key in entities:  # duplicate names inside one collection
            key += "#"
        entities[key] = Entity(kind, label, owner.lower(), normalize(data))

    firewalls = snapshot.get("firewalls") or {}
    for firewall_id, firewall in firewalls.items():
        label = resource_label(firewall)
        firewall_props = dict(props(firewall))
        classic = {kind: firewall_props.pop(prop, None) or [] for kind, prop in CLASSIC_COLLECTIONS}
        for key in BACKREF_KEYS["firewall"]:
            firewall_props.pop(key, None)
        add(firewall_id, "firewall", label, firewall_id, {**firewall, "properties": firewall_props})
        for kind, collections in classic.items():
            for collection in collections:
                collection_props = dict(props(collection))
                rules = collection_props.pop("rules", None) or []
                collection_key = f"{firewall_id}|classic-{kind}|{collection.get('name')}"
                collection_label = f"{label}/classic-{kind}/{collection.get('name')}"
                add(collection_key, "rule_collection", collection_label, firewall_id, collection_props)
                for rule in rules:
                    add(f"{collection_key}|{rule.get('name')}", "rule", f"{collection_label}/{rule.get('name')}", firewall_id, rule)

    for policy_id, entry in (snapshot.get("firewall_policies") or {}).items():
        policy = entry.get("resource") or {}
        label = resource_label(policy)
        policy_props = dict(props(policy))
        for key in BACKREF_KEYS["firewall_policy"]:
            policy_props.pop(key, None)
        add(policy_id, "firewall_policy", label, policy_id, {**policy, "properties": policy_props})
        groups_owner = f"{policy_id}/rulecollectiongroups"
        for group in entry.get("rule_collection_groups") or []:
            group_props = dict(props(group))
            collections = group_props.pop("ruleCollections", None) or []
            group_key = f"{policy_id}|{group.get('name')}"
            group_label = f"{label}/{group.get('name')}"
            add(group_key, "rule_collection_group", group_label, groups_owner, group_props)
            for collection in collections:
                collection_data = dict(collection)
                rules = collection_data.pop("rules", None) or []
                collection_key = f"{group_key}|{collection.get('name')}"
                collection_label = f"{group_label}/{collection.get('name')}"
                add(collection_key, "rule_collection", collection_label, groups_owner, collection_data)
                for rule in rules:
                    add(f"{collection_key}|{rule.get('name')}", "rule", f"{collection_label}/{rule.get('name')}", groups_owner, rule)

    for group_id, group in (snapshot.get("ip_groups") or {}).items():
        group_props = dict(props(group))
        for key in BACKREF_KEYS["ip_group"]:
            group_props.pop(key, None)
        add(group_id, "ip_group", resource_label(group), group_id, {**group, "properties": group_props})

    for firewall_id, settings in (snapshot.get("diagnostic_settings") or {}).items():
        firewall = firewalls.get(firewall_id)
        label = resource_label(firewall) if firewall else id_label(firewall_id)
        owner = firewall_id + DIAGNOSTICS_SUFFIX
        for setting in settings:
            add(f"{owner}|{setting.get('name')}", "diagnostic_setting", f"{label}/diagnostics/{setting.get('name')}", owner, setting)

    for nsg_id, nsg in (snapshot.get("network_security_groups") or {}).items():
        label = resource_label(nsg)
        nsg_props = dict(props(nsg))
        rules = nsg_props.pop("securityRules", None) or []
        nsg_props.pop("defaultSecurityRules", None)  # fixed by Azure, cannot be changed
        # Associations are back-references, but the NSG is the only place they are
        # read from, so they are compared here (as plain ids). NICs of scale set
        # instances come and go with autoscaling and are left out.
        for key in ("subnets", "networkInterfaces", "flowLogs"):
            nsg_props[key] = [
                ref_id(item) for item in nsg_props.get(key) or []
                if isinstance(item, dict) and "/virtualmachinescalesets/" not in ref_id(item)
            ]
        add(nsg_id, "network_security_group", label, nsg_id, {**nsg, "properties": nsg_props})
        for rule in rules:
            add(f"{nsg_id}|{rule.get('name')}", "security_rule", f"{label}/{rule.get('name')}", nsg_id, flatten_security_rule(rule))
    return entities


def _blind(entity: Entity, snapshot: dict) -> bool:
    """True when the snapshot could not read the place the entity lives in."""
    return any(
        error.get("incomplete", True)
        and under(entity.owner, error.get("scope", ""))
        and entity.kind in error.get("kinds", (entity.kind,))
        for error in snapshot.get("errors") or []
    )


def _scalar_list(value: Any) -> bool:
    return value is None or (isinstance(value, list) and all(not isinstance(item, (dict, list)) for item in value))


def deep_diff(old: Any, new: Any, path: str = "") -> list[dict]:
    """Field-level differences between two normalized values."""
    if old == new:
        return []
    if (isinstance(old, dict) or isinstance(new, dict)) and all(v is None or isinstance(v, dict) for v in (old, new)):
        old, new = old or {}, new or {}
        changes = []
        for key in sorted(set(old) | set(new)):
            changes.extend(deep_diff(old.get(key), new.get(key), f"{path}.{key}" if path else key))
        return changes
    if _scalar_list(old) and _scalar_list(new):
        old, new = old or [], new or []
        added = [item for item in new if item not in old]
        removed = [item for item in old if item not in new]
        if added or removed:
            return [{"path": path, "added": added, "removed": removed}]
    return [{"path": path, "old": old, "new": new}]


def _entity_record(key: str, entity: Entity) -> dict:
    return {"key": key, "kind": entity.kind, "label": entity.label, "data": entity.data}


def _pair_renames(added: list[dict], removed: list[dict]) -> list[dict]:
    """A rule removed and an identical one added in the same collection is a rename."""
    def signature(record: dict) -> tuple[str, str]:
        data = {key: value for key, value in record["data"].items() if key != "name"}
        return record["key"].rsplit("|", 1)[0], canonical(data)

    rule_kinds = ("rule", "security_rule")
    pool: dict[tuple[str, str, str], list[dict]] = {}
    for record in added:
        if record["kind"] in rule_kinds:
            pool.setdefault((record["kind"], *signature(record)), []).append(record)
    renamed = []
    for record in list(removed):
        candidates = pool.get((record["kind"], *signature(record))) if record["kind"] in rule_kinds else None
        if candidates:
            new_record = candidates.pop(0)
            removed.remove(record)
            added.remove(new_record)
            renamed.append({
                "key": new_record["key"], "kind": record["kind"], "old_label": record["label"],
                "label": new_record["label"], "data": new_record["data"],
            })
    return renamed


def _scope_key(snapshot: dict) -> str:
    scope = snapshot.get("scope") or {}
    return canonical({
        "subscriptions": sorted(s.lower() for s in scope.get("subscriptions") or []),
        "resource_group": (scope.get("resource_group") or "").lower(),
        "firewalls": sorted(f.lower() for f in scope.get("firewalls") or []),
        "all_policies": bool(scope.get("all_policies")),
        "nsgs": sorted(n.lower() for n in scope.get("nsgs") or []),
    })


def diff_snapshots(baseline: dict, current: dict) -> dict:
    # A section that one of the snapshots did not collect is left out entirely
    # instead of showing all of its objects as added or removed.
    skipped_kinds: set[str] = set()
    notes = []
    for section, (title, kinds) in OPTIONAL_SECTIONS.items():
        missing = [where for where, snapshot in (("эталоне", baseline), ("текущем снимке", current)) if snapshot.get(section) is None]
        if missing:
            skipped_kinds.update(kinds)
            notes.append(f"{title[0].upper() + title[1:]} не сравнивались: в {' и '.join(missing)} они не собирались.")
    old = {key: e for key, e in build_entities(baseline).items() if e.kind not in skipped_kinds}
    new = {key: e for key, e in build_entities(current).items() if e.kind not in skipped_kinds}
    added, removed, modified, not_compared = [], [], [], []
    for key in sorted(old.keys() | new.keys()):
        before, after = old.get(key), new.get(key)
        if before is not None and after is not None:
            changes = deep_diff(before.data, after.data)
            if changes:
                modified.append({"key": key, "kind": after.kind, "label": after.label, "changes": changes})
        elif before is not None:
            if _blind(before, current):
                not_compared.append({**_entity_record(key, before), "reason": "не прочитан в текущем снимке"})
            else:
                removed.append(_entity_record(key, before))
        elif after is not None:
            if _blind(after, baseline):
                not_compared.append({**_entity_record(key, after), "reason": "не был прочитан в эталоне"})
            else:
                added.append(_entity_record(key, after))
    renamed = _pair_renames(added, removed)
    for records in (added, removed, modified, renamed, not_compared):
        records.sort(key=lambda record: record["label"].lower())
    summary = {
        "added": len(added),
        "removed": len(removed),
        "modified": len(modified),
        "renamed": len(renamed),
        "not_compared": len(not_compared),
    }
    summary["total"] = summary["added"] + summary["removed"] + summary["modified"] + summary["renamed"]
    return {
        "baseline_collected_at": baseline.get("collected_at"),
        "current_collected_at": current.get("collected_at"),
        "scope_mismatch": _scope_key(baseline) != _scope_key(current),
        "notes": notes,
        "summary": summary,
        "added": added,
        "removed": removed,
        "modified": modified,
        "renamed": renamed,
        "not_compared": not_compared,
    }


# ---------------------------------------------------------------------------
# Standard and deviation checks
# ---------------------------------------------------------------------------

def _standard_mode(standard: dict, key: str) -> None:
    value = standard.get(key)
    if value is False:  # YAML 1.1 reads a bare Off as false
        value = "Off"
    if value is not None and str(value).lower() not in MODE_RANK:
        raise ConfigError(f"{key}: ожидается Off, Alert, Deny или null, получено {value!r}")
    standard[key] = value


def load_standard(path: str | Path | None) -> dict:
    standard = copy.deepcopy(DEFAULT_STANDARD)
    if path is None:
        return standard
    try:
        data = yaml.safe_load(Path(path).read_text(encoding="utf-8")) or {}
    except (OSError, yaml.YAMLError) as exc:
        raise ConfigError(f"не удалось прочитать стандарт {path}: {exc}") from exc
    if not isinstance(data, dict):
        raise ConfigError(f"{path}: ожидается словарь параметров")
    unknown = sorted(set(data) - set(DEFAULT_STANDARD))
    if unknown:
        log.warning("%s: неизвестные параметры пропущены: %s", path, ", ".join(unknown))
    standard.update({key: value for key, value in data.items() if key in DEFAULT_STANDARD})

    _standard_mode(standard, "threat_intel_mode")
    _standard_mode(standard, "idps_mode")
    tier = standard.get("minimum_sku_tier")
    if tier is not None and str(tier).lower() not in SKU_RANK:
        raise ConfigError(f"minimum_sku_tier: ожидается Basic, Standard, Premium или null, получено {tier!r}")
    lists = (
        "sensitive_ports", "public_dnat_allowed_ports", "any_address_tokens", "required_log_categories",
        "nsg_public_sources", "nsg_public_allowed_ports", "exceptions",
    )
    for key in lists:
        if not isinstance(standard.get(key) or [], list):
            raise ConfigError(f"{key}: ожидается список")
        standard[key] = standard.get(key) or []
    try:
        standard["sensitive_ports"] = sorted({int(port) for port in standard["sensitive_ports"]})
        standard["public_dnat_allowed_ports"] = sorted({int(port) for port in standard["public_dnat_allowed_ports"]})
        standard["nsg_public_allowed_ports"] = sorted({int(port) for port in standard["nsg_public_allowed_ports"]})
        standard["max_port_range"] = int(standard["max_port_range"])
    except (TypeError, ValueError) as exc:
        raise ConfigError(f"порты и max_port_range должны быть числами: {exc}") from exc
    expected = standard.get("expected_properties") or {}
    if not isinstance(expected, dict) or not all(isinstance(v or {}, dict) for v in expected.values()):
        raise ConfigError("expected_properties: ожидается {firewall: {путь: значение}, firewall_policy: {...}, network_security_group: {...}}")
    standard["expected_properties"] = {key: value or {} for key, value in expected.items()}
    return standard


def parse_ports(values: Iterable[Any]) -> list[tuple[str, int, int]]:
    """'*', '443', '8000-8080' -> (raw, low, high); unparsable values are skipped."""
    result = []
    for value in values:
        text = str(value).strip()
        if text in ("*", "any", "Any"):
            result.append((text, 0, 65535))
            continue
        low, sep, high = text.partition("-")
        try:
            low_port = int(low)
            high_port = int(high) if sep else low_port
        except ValueError:
            continue
        result.append((text, min(low_port, high_port), max(low_port, high_port)))
    return result


def covers_all_ports(ranges: list[tuple[str, int, int]]) -> bool:
    return any(low <= 1 and high >= 65535 for _, low, high in ranges)


def _lookup(resource: Any, path: str) -> Any:
    node = resource
    for part in path.split("."):
        if not isinstance(node, dict):
            return None
        node = node.get(part)
    return node


def _matches(actual: Any, expected: Any) -> bool:
    if isinstance(actual, list) and isinstance(expected, list):
        return sorted(str(v).lower() for v in actual) == sorted(str(v).lower() for v in expected)
    if actual is None or expected is None:
        return actual is expected
    if isinstance(actual, str) or isinstance(expected, str):
        return fmt_value(actual).lower() == fmt_value(expected).lower()
    return actual == expected


def subtract_ports(ranges: list[tuple[int, int]], cut: list[tuple[int, int]]) -> list[tuple[int, int]]:
    """Port ranges left after removing the ranges in cut."""
    result = []
    for low, high in ranges:
        pieces = [(low, high)]
        for cut_low, cut_high in cut:
            remaining = []
            for start, end in pieces:
                if cut_high < start or cut_low > end:
                    remaining.append((start, end))
                    continue
                if start < cut_low:
                    remaining.append((start, cut_low - 1))
                if cut_high < end:
                    remaining.append((cut_high + 1, end))
            pieces = remaining
        result.extend(pieces)
    return result


def fmt_port_ranges(ranges: list[tuple[int, int]]) -> list[str]:
    return ["*" if low <= 1 and high >= 65535 else (str(low) if low == high else f"{low}-{high}") for low, high in ranges]


def _nsg_priority(rule: dict) -> int:
    try:
        return int(rule.get("priority"))
    except (TypeError, ValueError):
        return 0


@dataclass
class RuleView:
    """A rule from a policy or a classic collection, in one shape for the checks."""

    path: str
    scope: str  # policy or firewall id; duplicates are searched within it
    kind: str  # network | application | nat
    action: str  # allow | deny | dnat | snat
    rule: dict
    sources: list
    destinations: list
    destination_fqdns: list
    ports: list
    protocols: list


class Auditor:
    def __init__(self, snapshot: dict, standard: dict):
        self.snapshot = snapshot
        self.standard = standard
        self.firewalls = snapshot.get("firewalls") or {}
        self.policies = snapshot.get("firewall_policies") or {}
        self.ip_groups = snapshot.get("ip_groups") or {}
        self.any_tokens = {str(token).strip().lower() for token in standard["any_address_tokens"]}
        self.nsg_public_tokens = {str(token).strip().lower() for token in standard["nsg_public_sources"]}
        self.findings: list[dict] = []
        self.firewall_settings: dict[str, dict] = {}
        self.nsg_settings: dict[str, dict] = {}
        self.policy_rules: dict[str, list[RuleView]] = {}
        self.classic_rules: list[RuleView] = []

    def run(self) -> list[dict]:
        for policy_id, entry in sorted(self.policies.items()):
            self.policy_rules[policy_id] = list(self._policy_rules(policy_id, entry))
        for firewall_id, firewall in sorted(self.firewalls.items()):
            self._check_firewall(firewall_id, firewall)
        for _, entry in sorted(self.policies.items()):
            self._check_policy(entry)
        rules = [rule for rules in self.policy_rules.values() for rule in rules] + self.classic_rules
        for rule in rules:
            self._check_rule(rule)
        self._check_duplicates(rules)
        for nsg_id, nsg in sorted((self.snapshot.get("network_security_groups") or {}).items()):
            self._check_nsg(nsg_id, nsg)
        self.findings.sort(key=lambda f: (-SEVERITY_RANK[f["severity"]], f["object"].lower(), f["check"]))
        return self.findings

    def _add(self, check: str, severity: str, obj: str, details: str) -> None:
        title, recommendation = CHECKS[check]
        fingerprint = hashlib.sha256(f"{check}|{obj.lower()}|{details}".encode()).hexdigest()[:16]
        self.findings.append({
            "id": fingerprint, "check": check, "severity": severity, "title": title,
            "object": obj, "details": details, "recommendation": recommendation,
        })

    # -- rules -------------------------------------------------------------

    def _addresses(self, rule: dict, address_key: str, group_key: str) -> list[str]:
        result = [str(address) for address in rule.get(address_key) or []]
        for group_id in rule.get(group_key) or []:
            group = self.ip_groups.get(str(group_id).lower())
            result.extend(str(address) for address in props(group).get("ipAddresses") or [])
        return result

    def _rule_view(self, path: str, scope: str, kind: str, action: str, rule: dict, protocols: Any) -> RuleView:
        return RuleView(
            path=path,
            scope=scope,
            kind=kind,
            action=action,
            rule=rule,
            sources=self._addresses(rule, "sourceAddresses", "sourceIpGroups"),
            destinations=self._addresses(rule, "destinationAddresses", "destinationIpGroups"),
            destination_fqdns=[str(fqdn) for fqdn in rule.get("destinationFqdns") or []],
            ports=[str(port) for port in rule.get("destinationPorts") or []],
            protocols=[str(protocol).upper() for protocol in protocols or []],
        )

    def _policy_rules(self, policy_id: str, entry: dict) -> Iterator[RuleView]:
        label = resource_label(entry.get("resource") or {})
        for group in entry.get("rule_collection_groups") or []:
            for collection in props(group).get("ruleCollections") or []:
                action = str((collection.get("action") or {}).get("type") or "").lower()
                for rule in collection.get("rules") or []:
                    path = f"{label}/{group.get('name')}/{collection.get('name')}/{rule.get('name')}"
                    kind = POLICY_RULE_KINDS.get(rule.get("ruleType"), "unknown")
                    yield self._rule_view(path, policy_id, kind, action, rule, rule.get("ipProtocols"))

    def _classic_rules(self, firewall_id: str, firewall: dict) -> Iterator[RuleView]:
        label = resource_label(firewall)
        for kind, prop in CLASSIC_COLLECTIONS:
            for collection in props(firewall).get(prop) or []:
                action = str((props(collection).get("action") or {}).get("type") or "").lower()
                for rule in props(collection).get("rules") or []:
                    path = f"{label}/classic-{kind}/{collection.get('name')}/{rule.get('name')}"
                    protocols = None if kind == "application" else rule.get("protocols")
                    yield self._rule_view(path, firewall_id, kind, action, rule, protocols)

    def _any_address(self, value: str) -> bool:
        text = value.strip().lower()
        if text in self.any_tokens:
            return True
        try:
            return ipaddress.ip_network(text, strict=False).prefixlen == 0
        except ValueError:
            pass
        start, sep, end = text.partition("-")
        if not sep:
            return False
        try:
            low, high = ipaddress.ip_address(start.strip()), ipaddress.ip_address(end.strip())
        except ValueError:
            return False
        return low.version == high.version and int(low) == 0 and int(high) == 2 ** low.max_prefixlen - 1

    def _is_any(self, addresses: list[str]) -> bool:
        return any(self._any_address(address) for address in addresses)

    def _sensitive(self, ranges: list[tuple[str, int, int]]) -> list[int]:
        return [port for port in self.standard["sensitive_ports"] if any(low <= port <= high for _, low, high in ranges)]

    def _check_rule(self, rule: RuleView) -> None:
        if self.standard.get("require_rule_description") and not rule.rule.get("description"):
            self._add("AZFW-NO-DESC", "info", rule.path, "Описание не заполнено")
        if rule.kind == "network" and rule.action == "allow":
            self._check_network_rule(rule)
        elif rule.kind == "nat" and rule.action == "dnat":
            self._check_dnat_rule(rule)
        elif rule.kind == "application" and rule.action == "allow":
            self._check_application_rule(rule)

    def _check_network_rule(self, rule: RuleView) -> None:
        any_source = self._is_any(rule.sources)
        any_destination = self._is_any(rule.destinations) or "*" in rule.destination_fqdns
        port_based = not rule.protocols or bool(set(rule.protocols) - {"ICMP"})
        ranges = parse_ports(rule.ports)
        all_ports = port_based and covers_all_ports(ranges)
        traffic = f"протоколы: {short_list(rule.protocols)}; порты: {short_list(rule.ports)}"
        if any_source and any_destination:
            severity = "critical" if all_ports else ("high" if port_based else "low")
            self._add("AZFW-ANY-ANY", severity, rule.path, f"Любой источник → любое назначение; {traffic}")
            return
        if port_based:
            if all_ports:
                self._add("AZFW-ANY-PORT", "medium", rule.path, f"Разрешены все порты; назначение: {short_list(rule.destinations + rule.destination_fqdns)}")
            else:
                limit = self.standard["max_port_range"]
                wide = [raw for raw, low, high in ranges if high - low + 1 > limit]
                if wide:
                    self._add("AZFW-ANY-PORT", "medium", rule.path, f"Диапазон шире {limit} портов: {short_list(wide)}")
            hits = self._sensitive(ranges) if any_source else []
            if hits:
                self._add(
                    "AZFW-SENSITIVE-PORT", "high", rule.path,
                    f"Доступ из любого источника к портам {short_list(hits)}; назначение: "
                    f"{short_list(rule.destinations + rule.destination_fqdns)}",
                )
        if "ANY" in rule.protocols:
            self._add("AZFW-ANY-PROTO", "low", rule.path, f"Протоколы: {short_list(rule.protocols)}")

    def _check_dnat_rule(self, rule: RuleView) -> None:
        if not self._is_any(rule.sources):
            return
        translated_port = rule.rule.get("translatedPort")
        translated = rule.rule.get("translatedAddress") or rule.rule.get("translatedFqdn") or "?"
        target = f"{short_list(rule.destinations)}:{short_list(rule.ports)} → {translated}:{translated_port or '?'}"
        public = parse_ports(rule.ports)
        # The internal port counts too: publishing 50022 -> 22 still exposes SSH.
        hits = self._sensitive(public + parse_ports([translated_port] if translated_port else []))
        if hits:
            self._add("AZFW-SENSITIVE-PORT", "high", rule.path, f"Публикация для любого источника, порты {short_list(hits)}: {target}")
            return
        allowed = set(self.standard["public_dnat_allowed_ports"])
        extra = [raw for raw, low, high in public if not (low == high and low in allowed)]
        if extra:
            self._add("AZFW-DNAT-PUBLIC", "medium", rule.path, f"Публикация для любого источника, порты {short_list(extra)}: {target}")

    def _check_application_rule(self, rule: RuleView) -> None:
        targets = [str(target) for target in rule.rule.get("targetFqdns") or []]
        if "*" in targets:
            self._add("AZFW-APP-ANY-FQDN", "high", rule.path, f"targetFqdns содержит «*»; источники: {short_list(rule.sources)}")
        broad = [target for target in targets if re.fullmatch(r"\*\.[^.*]+", target)]
        if broad:
            self._add("AZFW-APP-BROAD-FQDN", "medium", rule.path, f"Шаблоны: {short_list(broad)}")

    def _check_duplicates(self, rules: list[RuleView]) -> None:
        groups: dict[tuple, list[str]] = {}
        for rule in rules:
            criteria = {key: value for key, value in rule.rule.items() if key not in ("name", "description")}
            groups.setdefault((rule.scope, rule.kind, rule.action, canonical(normalize(criteria))), []).append(rule.path)
        for paths in groups.values():
            if len(paths) > 1:
                self._add("AZFW-DUPLICATE", "low", paths[0], f"Совпадает по условиям с: {short_list(paths[1:])}")

    # -- firewalls and policies ---------------------------------------------

    def _policy_chain(self, policy_id: str) -> list[str]:
        """The policy and its base policies, child first."""
        chain: list[str] = []
        current = policy_id
        while current and current in self.policies and current not in chain:
            chain.append(current)
            current = ref_id(props(self.policies[current].get("resource")).get("basePolicy"))
        return chain

    def _policy_label(self, policy_id: str) -> str:
        entry = self.policies.get(policy_id)
        return resource_label(entry["resource"]) if entry else id_label(policy_id)

    def _check_firewall(self, firewall_id: str, firewall: dict) -> None:
        p = props(firewall)
        label = resource_label(firewall)
        tier = str((p.get("sku") or {}).get("tier") or "Standard")
        policy_id = ref_id(p.get("firewallPolicy"))
        chain = self._policy_chain(policy_id) if policy_id else []
        chain_props = [props(self.policies[pid].get("resource")) for pid in chain]
        classic = list(self._classic_rules(firewall_id, firewall))
        self.classic_rules.extend(classic)
        rules = classic + [rule for pid in chain for rule in self.policy_rules.get(pid, [])]

        state = p.get("provisioningState")
        if state and state != "Succeeded":
            self._add("AZFW-STATE", "high", label, f"provisioningState: {state}")

        minimum = self.standard.get("minimum_sku_tier")
        if minimum and SKU_RANK.get(tier.lower(), 1) < SKU_RANK[str(minimum).lower()]:
            self._add("AZFW-SKU", "medium", label, f"SKU {tier}, стандарт требует не ниже {minimum}")

        # A policy that could not be read leaves its settings unknown (None):
        # the gap is reported in the errors section, not guessed here.
        if policy_id:
            modes = [cp.get("threatIntelMode") or "Alert" for cp in chain_props]
            # A child policy may only make the inherited mode stricter.
            threat_intel = max(modes, key=_mode_rank) if modes else None
            dns_proxy = bool(_first((cp.get("dnsSettings") or {}).get("enableProxy") for cp in chain_props)) if chain else None
        else:
            threat_intel = p.get("threatIntelMode") or "Alert"
            dns_proxy = str((p.get("additionalProperties") or {}).get("Network.DNS.EnableProxy", "")).lower() == "true"
        via = f" (политика {self._policy_label(policy_id)})" if policy_id else ""

        expected_ti = self.standard.get("threat_intel_mode")
        if threat_intel and expected_ti and _mode_rank(threat_intel) < _mode_rank(expected_ti):
            severity = "high" if str(threat_intel).lower() == "off" else "medium"
            self._add("AZFW-TI", severity, label, f"Режим {threat_intel}{via}, стандарт требует {expected_ti}")

        idps = tls = None
        if tier.lower() == "premium" and chain:
            idps = _first((cp.get("intrusionDetection") or {}).get("mode") for cp in chain_props) or "Off"
            tls = any((cp.get("transportSecurity") or {}).get("certificateAuthority") for cp in chain_props)
            expected_idps = self.standard.get("idps_mode")
            if expected_idps and _mode_rank(idps) < _mode_rank(expected_idps):
                severity = "high" if str(idps).lower() == "off" else "medium"
                self._add("AZFW-IDPS", severity, label, f"Режим IDPS {idps}{via}, стандарт требует {expected_idps}")
            if not tls and self.standard.get("require_tls_inspection"):
                self._add("AZFW-TLS", "low", label, f"В политике нет сертификата ЦС для TLS-инспекции{via}")

        fqdn_rules = [rule.path for rule in rules if rule.kind == "network" and rule.destination_fqdns]
        if dns_proxy is False and fqdn_rules:
            self._add("AZFW-DNS-PROXY", "medium", label, f"FQDN используются в сетевых правилах: {short_list(fqdn_rules, 3)}")
        elif dns_proxy is False and self.standard.get("require_dns_proxy"):
            self._add("AZFW-DNS-PROXY", "low", label, "DNS proxy выключен, стандарт требует включить")

        logs = self._check_logs(firewall_id, label)

        if self.standard.get("require_availability_zones") and not firewall.get("zones"):
            self._add("AZFW-ZONES", "low", label, "Зоны доступности не заданы")

        if any(p.get(prop) for _, prop in CLASSIC_COLLECTIONS):
            self._add("AZFW-CLASSIC", "low", label, f"Классических правил: {len(classic)}")
            for kind, prop in CLASSIC_COLLECTIONS:
                for collection in p.get(prop) or []:
                    if not props(collection).get("rules"):
                        self._add("AZFW-EMPTY", "info", f"{label}/classic-{kind}/{collection.get('name')}", "Коллекция не содержит правил")

        self._check_expected(label, "firewall", firewall)

        private_ips = [props(c).get("privateIPAddress") for c in p.get("ipConfigurations") or []]
        hub_ip = (p.get("hubIPAddresses") or {}).get("privateIPAddress")
        self.firewall_settings[firewall_id] = {
            "label": label,
            "location": firewall.get("location"),
            "sku": f"{(p.get('sku') or {}).get('name') or '?'} / {tier}",
            "policy": self._policy_label(policy_id) if policy_id else "классические правила",
            "threat_intel": threat_intel,
            "idps": idps,
            "dns_proxy": dns_proxy,
            "zones": firewall.get("zones") or [],
            "private_ip": [ip for ip in private_ips + [hub_ip] if ip],
            "rules": len(rules),
            "logs": logs,
            "state": state,
        }

    def _check_logs(self, firewall_id: str, label: str) -> str:
        all_settings = self.snapshot.get("diagnostic_settings")
        if all_settings is None or firewall_id not in all_settings:
            return "не проверялось"
        enabled = set()
        for setting in all_settings[firewall_id]:
            sp = props(setting)
            if not any(sp.get(key) for key in LOG_DESTINATIONS):
                continue
            for entry in sp.get("logs") or []:
                if entry.get("enabled"):
                    enabled.add(str(entry.get("category") or entry.get("categoryGroup") or "").lower())
        if not enabled:
            if self.standard.get("require_diagnostic_settings"):
                self._add("AZFW-LOGS", "medium", label, "Журналы брандмауэра никуда не отправляются: нет параметров диагностики с включёнными журналами")
            return "нет"
        if "alllogs" not in enabled:
            missing = [c for c in self.standard.get("required_log_categories") or [] if str(c).lower() not in enabled]
            if missing and self.standard.get("require_diagnostic_settings"):
                self._add("AZFW-LOGS", "medium", label, f"Не включены категории журналов: {short_list(missing)}")
                return "частично"
        return "да"

    def _check_policy(self, entry: dict) -> None:
        policy = entry.get("resource") or {}
        p = props(policy)
        label = resource_label(policy)
        state = p.get("provisioningState")
        if state and state != "Succeeded":
            self._add("AZFW-STATE", "high", label, f"provisioningState: {state}")
        for group in entry.get("rule_collection_groups") or []:
            group_label = f"{label}/{group.get('name')}"
            group_state = props(group).get("provisioningState")
            if group_state and group_state != "Succeeded":
                self._add("AZFW-STATE", "high", group_label, f"provisioningState: {group_state}")
            collections = props(group).get("ruleCollections") or []
            if not collections:
                self._add("AZFW-EMPTY", "info", group_label, "Группа не содержит коллекций правил")
            for collection in collections:
                if not collection.get("rules"):
                    self._add("AZFW-EMPTY", "info", f"{group_label}/{collection.get('name')}", "Коллекция не содержит правил")

        allowlist = p.get("threatIntelWhitelist") or {}
        allowed = list(allowlist.get("ipAddresses") or []) + list(allowlist.get("fqdns") or [])
        if allowed:
            self._add("AZFW-TI-ALLOWLIST", "low", label, f"Исключения: {short_list(allowed)}")

        idps = (p.get("intrusionDetection") or {}).get("configuration") or {}
        disabled = [str(s.get("id")) for s in idps.get("signatureOverrides") or [] if str(s.get("mode")).lower() == "off"]
        if disabled:
            self._add("AZFW-IDPS-BYPASS", "low", label, f"Отключены сигнатуры: {short_list(disabled)}")
        bypass = [str(b.get("name") or "?") for b in idps.get("bypassTrafficSettings") or []]
        if bypass:
            self._add("AZFW-IDPS-BYPASS", "low", label, f"Трафик в обход IDPS: {short_list(bypass)}")

        self._check_expected(label, "firewall_policy", policy)

    def _check_expected(self, label: str, kind: str, resource: dict) -> None:
        for path, expected in (self.standard.get("expected_properties") or {}).get(kind, {}).items():
            actual = _lookup(resource, path)
            if not _matches(actual, expected):
                self._add("AZFW-PROP", "medium", label, f"{path} = {fmt_value(actual)}, по стандарту: {fmt_value(expected)}")

    # -- network security groups ---------------------------------------------

    def _nsg_public(self, address: str) -> bool:
        return address.strip().lower() in self.nsg_public_tokens or self._any_address(address)

    def _covers(self, wide: list[str], narrow: list[str]) -> bool:
        if any(self._any_address(address) for address in wide):
            return True
        return {address.lower() for address in narrow} <= {address.lower() for address in wide}

    def _nsg_internet_ports(self, rule: dict, rules: list[dict]) -> list[tuple[int, int]]:
        """Ports an inbound Allow rule opens to the Internet, minus what Deny rules
        with a higher priority (a lower number) already block."""
        if str(rule.get("direction")).lower() != "inbound" or str(rule.get("access")).lower() != "allow":
            return []
        protocol = str(rule.get("protocol") or "*").lower()
        if protocol in NSG_PORTLESS_PROTOCOLS or not any(self._nsg_public(s) for s in rule["sourceAddressPrefixes"]):
            return []
        ranges = [(low, high) for _, low, high in parse_ports(rule["destinationPortRanges"])]
        destinations = rule["destinationAddressPrefixes"] + rule["destinationApplicationSecurityGroups"]
        for other in rules:  # sorted by priority
            if _nsg_priority(other) >= _nsg_priority(rule):
                break
            other_protocol = str(other.get("protocol") or "*").lower()
            if (
                str(other.get("direction")).lower() != "inbound"
                or str(other.get("access")).lower() != "deny"
                or other_protocol not in ("*", protocol)
                or not any(self._nsg_public(s) for s in other["sourceAddressPrefixes"])
                or not covers_all_ports(parse_ports(other["sourcePortRanges"] or ["*"]))
                or not self._covers(other["destinationAddressPrefixes"] + other["destinationApplicationSecurityGroups"], destinations)
            ):
                continue
            ranges = subtract_ports(ranges, [(low, high) for _, low, high in parse_ports(other["destinationPortRanges"])])
        return ranges

    def _check_nsg(self, nsg_id: str, nsg: dict) -> None:
        p = props(nsg)
        label = resource_label(nsg)
        state = p.get("provisioningState")
        if state and state != "Succeeded":
            self._add("AZFW-STATE", "high", label, f"provisioningState: {state}")
        subnets = [ref_id(item) for item in p.get("subnets") or [] if isinstance(item, dict)]
        nics = [ref_id(item) for item in p.get("networkInterfaces") or [] if isinstance(item, dict)]
        if self.standard.get("require_nsg_association") and not subnets and not nics:
            self._add("NSG-UNUSED", "info", label, "Нет привязанных подсетей и сетевых интерфейсов")

        rules = sorted((flatten_security_rule(rule) for rule in p.get("securityRules") or []), key=_nsg_priority)
        exposed = 0
        for rule in rules:
            path = f"{label}/{rule.get('name')}"
            if self.standard.get("require_rule_description") and not rule.get("description"):
                self._add("AZFW-NO-DESC", "info", path, "Описание не заполнено")
            ranges = self._nsg_internet_ports(rule, rules)
            if ranges:
                exposed += 1
                self._check_nsg_exposure(path, rule, ranges)
        self._check_expected(label, "network_security_group", nsg)
        self.nsg_settings[nsg_id] = {
            "label": label,
            "location": nsg.get("location"),
            "rules": len(rules),
            "subnets": [id_label(subnet) for subnet in subnets],
            "network_interfaces": len(nics),
            "internet_inbound_rules": exposed,
            "state": state,
        }

    def _check_nsg_exposure(self, path: str, rule: dict, ranges: list[tuple[int, int]]) -> None:
        sources = [s for s in rule["sourceAddressPrefixes"] if self._nsg_public(s)]
        where = f"источник {short_list(sources)}, протокол {rule.get('protocol') or '*'}, приоритет {rule.get('priority')}"
        tuples = [(text, low, high) for text, (low, high) in zip(fmt_port_ranges(ranges), ranges)]
        if covers_all_ports(tuples):
            self._add("NSG-INTERNET-ANY-PORT", "critical", path, f"Открыты все порты; {where}")
            return
        hits = self._sensitive(tuples)
        if hits:
            self._add("NSG-SENSITIVE-PORT", "high", path, f"Из Интернета доступны порты {short_list(hits)}; {where}")
            return
        limit = self.standard["max_port_range"]
        wide = [text for text, low, high in tuples if high - low + 1 > limit]
        if wide:
            self._add("NSG-WIDE-PORT", "medium", path, f"Диапазон шире {limit} портов: {short_list(wide)}; {where}")
            return
        allowed = set(self.standard["nsg_public_allowed_ports"])
        extra = [text for text, low, high in tuples if not (low == high and low in allowed)]
        if extra:
            self._add("NSG-PUBLIC-PORT", "medium", path, f"Из Интернета доступны порты {short_list(extra)}; {where}")

    def nsg_inventory(self) -> list[dict]:
        return sorted(self.nsg_settings.values(), key=lambda row: row["label"].lower())

    def policy_inventory(self) -> list[dict]:
        rows = []
        for policy_id, entry in sorted(self.policies.items(), key=lambda item: resource_label(item[1]["resource"]).lower()):
            p = props(entry.get("resource"))
            base = ref_id(p.get("basePolicy"))
            rows.append({
                "label": resource_label(entry["resource"]),
                "tier": (p.get("sku") or {}).get("tier") or "Standard",
                "base_policy": self._policy_label(base) if base else None,
                "firewalls": len(p.get("firewalls") or []),
                "rule_collection_groups": len(entry.get("rule_collection_groups") or []),
                "rules": len(self.policy_rules.get(policy_id, [])),
                "threat_intel": p.get("threatIntelMode") or "Alert",
                "idps": (p.get("intrusionDetection") or {}).get("mode"),
            })
        return rows


def _to_date(value: Any) -> dt.date | None:
    if value is None or value == "":
        return None
    if isinstance(value, dt.datetime):
        return value.date()
    if isinstance(value, dt.date):
        return value
    return dt.date.fromisoformat(str(value))


def apply_exceptions(findings: list[dict], exceptions: list, today: dt.date) -> tuple[list[dict], list[dict], list[dict]]:
    """Split findings into active and accepted; report exceptions that do not work."""
    rules, problems = [], []
    for exception in exceptions or []:
        if not isinstance(exception, dict) or not exception.get("check") or not exception.get("reason"):
            problems.append({"exception": fmt_value(exception), "problem": "нет обязательных полей check и reason — не применяется"})
            continue
        try:
            expires = _to_date(exception.get("expires"))
        except ValueError:
            problems.append({"exception": fmt_value(exception), "problem": "expires не в формате ГГГГ-ММ-ДД — не применяется"})
            continue
        rules.append({
            "check": str(exception["check"]),
            "object": str(exception.get("object") or "*"),
            "reason": str(exception["reason"]),
            "expires": expires,
            "used": 0,
        })
    active, accepted = [], []
    for finding in findings:
        match = next((
            rule for rule in rules
            if not (rule["expires"] and rule["expires"] < today)
            and fnmatch.fnmatchcase(finding["check"].lower(), rule["check"].lower())
            and fnmatch.fnmatchcase(finding["object"].lower(), rule["object"].lower())
        ), None)
        if match:
            match["used"] += 1
            accepted.append({**finding, "exception": {
                "reason": match["reason"],
                "expires": match["expires"].isoformat() if match["expires"] else None,
            }})
        else:
            active.append(finding)
    for rule in rules:
        name = f"{rule['check']} {rule['object']}"
        if rule["expires"] and rule["expires"] < today:
            problems.append({"exception": name, "problem": f"срок действия истёк {rule['expires'].isoformat()} — не применяется"})
        elif not rule["used"]:
            problems.append({"exception": name, "problem": "не совпало ни с одним отклонением — возможно, устарело"})
    return active, accepted, problems


# ---------------------------------------------------------------------------
# Report
# ---------------------------------------------------------------------------

def _snapshot_meta(snapshot: dict) -> dict:
    return {
        "collected_at": snapshot.get("collected_at"),
        "scope": snapshot.get("scope") or {},
        "tool": snapshot.get("tool"),
        "firewalls": len(snapshot.get("firewalls") or {}),
        "firewall_policies": len(snapshot.get("firewall_policies") or {}),
        "ip_groups": len(snapshot.get("ip_groups") or {}),
        # None: the snapshot was taken without NSGs (--no-nsg or an older version)
        "network_security_groups": None if snapshot.get("network_security_groups") is None else len(snapshot["network_security_groups"]),
    }


def build_report(
    current: dict,
    baseline: dict | None = None,
    standard: dict | None = None,
    standard_source: str | None = None,
    today: dt.date | None = None,
) -> dict:
    standard = standard if standard is not None else load_standard(None)
    auditor = Auditor(current, standard)
    findings, accepted, exception_problems = apply_exceptions(auditor.run(), standard.get("exceptions"), today or utcnow().date())
    drift = diff_snapshots(baseline, current) if baseline is not None else None
    errors = current.get("errors") or []
    by_severity = {severity: sum(1 for f in findings if f["severity"] == severity) for severity in SEVERITIES}
    return {
        "tool": {"name": TOOL_NAME, "version": TOOL_VERSION},
        "generated_at": isoformat(utcnow()),
        "read_only": True,
        "snapshot": _snapshot_meta(current),
        "baseline": _snapshot_meta(baseline) if baseline is not None else None,
        "standard": standard_source or "встроенные значения по умолчанию",
        "summary": {
            "findings_total": len(findings),
            "findings_by_severity": by_severity,
            "accepted_findings": len(accepted),
            "drift": drift["summary"] if drift else None,
            "collection_errors": len(errors),
            "incomplete": any(error.get("incomplete", True) for error in errors),
        },
        "inventory": {
            "firewalls": [auditor.firewall_settings[key] for key in sorted(auditor.firewall_settings, key=lambda k: auditor.firewall_settings[k]["label"].lower())],
            "firewall_policies": auditor.policy_inventory(),
            "network_security_groups": auditor.nsg_inventory(),
        },
        "drift": drift,
        "findings": findings,
        "accepted_findings": accepted,
        "exception_problems": exception_problems,
        "activity_log": current.get("activity_log"),
        "errors": errors,
    }


def describe_rule(rule: dict) -> str:
    def join(*lists: Any) -> str:
        return short_list([item for values in lists for item in values or []], 4)

    sources = join(rule.get("sourceAddresses"), rule.get("sourceIpGroups"))
    application = any(rule.get(key) for key in ("targetFqdns", "fqdnTags", "targetUrls", "webCategories"))
    if application or rule.get("ruleType") == "ApplicationRule":
        protocols = ", ".join(
            f"{p.get('protocolType')}:{p.get('port')}" for p in rule.get("protocols") or [] if isinstance(p, dict)
        )
        targets = join(rule.get("targetFqdns"), rule.get("fqdnTags"), rule.get("targetUrls"), rule.get("webCategories"))
        return f"{protocols or '—'} {sources} → {targets}"
    protocols = ", ".join(str(p) for p in rule.get("ipProtocols") or rule.get("protocols") or [])
    destinations = join(rule.get("destinationAddresses"), rule.get("destinationIpGroups"), rule.get("destinationFqdns"))
    text = f"{protocols or '—'} {sources} → {destinations} : {join(rule.get('destinationPorts'))}"
    translated = rule.get("translatedAddress") or rule.get("translatedFqdn")
    if translated:
        text += f" ⇒ {translated}:{rule.get('translatedPort') or '?'}"
    return text


def describe_security_rule(rule: dict) -> str:
    def join(*keys: str) -> str:
        return short_list([item for key in keys for item in rule.get(key) or []], 4)

    sources = join("sourceAddressPrefixes", "sourceApplicationSecurityGroups")
    destinations = join("destinationAddressPrefixes", "destinationApplicationSecurityGroups")
    return (
        f"{rule.get('direction') or '?'} {rule.get('access') or '?'} {rule.get('protocol') or '*'} "
        f"{sources} → {destinations} : {join('destinationPortRanges')}, приоритет {rule.get('priority', '?')}"
    )


def describe_entity(kind: str, data: dict) -> str:
    if kind == "rule":
        return describe_rule(data)
    if kind == "security_rule":
        return describe_security_rule(data)
    if kind == "network_security_group":
        p = props(data)
        return f"{data.get('location') or '?'}, подсетей: {len(p.get('subnets') or [])}, интерфейсов: {len(p.get('networkInterfaces') or [])}"
    if kind == "rule_collection":
        action = (data.get("action") or {}).get("type")
        return f"приоритет {data.get('priority', '?')}, действие {action or '?'}"
    if kind == "rule_collection_group":
        return f"приоритет {data.get('priority', '?')}"
    if kind == "ip_group":
        return short_list(props(data).get("ipAddresses") or [])
    if kind in ("firewall", "firewall_policy"):
        tier = (props(data).get("sku") or {}).get("tier")
        return f"SKU {tier or '?'}, {data.get('location') or '?'}"
    if kind == "diagnostic_setting":
        logs = [entry.get("category") or entry.get("categoryGroup") for entry in props(data).get("logs") or [] if entry.get("enabled")]
        return f"журналы: {short_list(logs)}"
    return ""


def describe_change(change: dict) -> str:
    path = change["path"]
    if path.startswith("properties."):
        path = path[len("properties."):]
    if "added" in change:
        parts = []
        if change["added"]:
            parts.append("добавлено: " + fmt_value(change["added"]))
        if change["removed"]:
            parts.append("удалено: " + fmt_value(change["removed"]))
        return f"{path} — {'; '.join(parts)}"
    return f"{path}: {fmt_value(change['old'])} → {fmt_value(change['new'])}"


def _short_resource(resource_id: str) -> str:
    """'<rg>/<type>/<name>[/<child type>/<child>...]' for Activity Log rows."""
    match = _RESOURCE_GROUP_RE.search(resource_id)
    _, sep, rest = resource_id.partition("/providers/")
    if not sep:
        return resource_id
    rest = rest.split("/", 1)[1] if "/" in rest else rest  # drop the provider namespace
    return f"{match.group(1)}/{rest}" if match else rest


def _scope_text(scope: dict) -> str:
    parts = [f"подписки: {short_list(scope.get('subscriptions') or [])}"]
    if scope.get("resource_group"):
        parts.append(f"группа ресурсов: {scope['resource_group']}")
    if scope.get("firewalls"):
        parts.append(f"брандмауэры: {short_list(scope['firewalls'])}")
    if scope.get("all_policies"):
        parts.append("все политики")
    if scope.get("nsgs"):
        parts.append(f"NSG: {short_list(scope['nsgs'])}")
    elif scope.get("include_nsgs") is False:
        parts.append("без NSG")
    return "; ".join(parts)


def _error_text(error: dict) -> str:
    hints = {
        401: "проверьте учётные данные",
        403: "нет прав на чтение — назначьте роль Reader",
        404: "объект не найден",
    }
    hint = hints.get(error.get("status"))
    return f"{error.get('message', '')} ({hint})" if hint else str(error.get("message", ""))


def _verdict(report: dict) -> str:
    summary = report["summary"]
    parts = []
    if summary["incomplete"]:
        parts.append("Часть конфигурации не удалось прочитать — результаты неполные (см. «Ошибки получения данных»).")
    counts = summary["findings_by_severity"]
    if summary["findings_total"]:
        details = ", ".join(f"{SEVERITY_TITLES[s].lower()}: {counts[s]}" for s in reversed(SEVERITIES) if counts[s])
        parts.append(f"Отклонений от стандарта: {summary['findings_total']} ({details}).")
    else:
        parts.append("Отклонений от стандарта не обнаружено.")
    drift = summary["drift"]
    if drift is None:
        parts.append("Эталон не задан — изменения не проверялись.")
    elif drift["total"]:
        parts.append(f"Изменений относительно эталона: {drift['total']}.")
    else:
        parts.append("Изменений относительно эталона нет.")
    return " ".join(parts)


@dataclass(frozen=True)
class Severity:
    """Table cell with a severity; HTML renders it as a coloured badge."""

    level: str

    def __str__(self) -> str:
        return SEVERITY_TITLES[self.level]


def report_blocks(report: dict) -> list[tuple]:
    """The report as a list of format-neutral blocks: ("h1"|"h2"|"h3"|"p", text),
    ("kv", [(key, value)]) and ("table", headers, rows)."""
    snapshot, baseline, summary = report["snapshot"], report["baseline"], report["summary"]
    blocks: list[tuple] = [("h1", "Отчёт аудита Azure Firewall и NSG")]
    blocks.append(("kv", [
        ("Сформирован", fmt_time(report["generated_at"])),
        ("Снимок конфигурации", f"{fmt_time(snapshot['collected_at'])}; {_scope_text(snapshot['scope'])}"),
        ("Эталон (baseline)", fmt_time(baseline["collected_at"]) if baseline else "не задан"),
        ("Стандарт", report["standard"]),
        ("Режим", "только чтение — конфигурация Azure не изменялась"),
    ]))

    blocks.append(("h2", "Итог"))
    blocks.append(("p", _verdict(report)))
    drift_summary = summary["drift"]
    rows = [[Severity(s), summary["findings_by_severity"][s]] for s in reversed(SEVERITIES)]
    blocks.append(("table", ["Уровень", "Отклонений"], rows))
    stats = [
        ["Брандмауэры", snapshot["firewalls"]],
        ["Политики", snapshot["firewall_policies"]],
        ["IP-группы", snapshot["ip_groups"]],
        ["NSG", "не собирались" if snapshot["network_security_groups"] is None else snapshot["network_security_groups"]],
        ["Принятые исключения", summary["accepted_findings"]],
        ["Ошибки получения данных", summary["collection_errors"]],
    ]
    if drift_summary:
        stats[4:4] = [
            ["Изменения: добавлено / удалено / изменено / переименовано",
             f"{drift_summary['added']} / {drift_summary['removed']} / {drift_summary['modified']} / {drift_summary['renamed']}"],
        ]
    blocks.append(("table", ["Показатель", "Значение"], stats))

    blocks.append(("h2", "Инвентаризация"))
    firewalls = report["inventory"]["firewalls"]
    if firewalls:
        blocks.append(("table", ["Брандмауэр", "Регион", "SKU", "Правила из", "Threat Intel", "IDPS", "DNS proxy", "Зоны", "Частный IP", "Правил", "Журналы", "Состояние"], [
            [fw["label"], fw["location"], fw["sku"], fw["policy"], fw["threat_intel"] or "?", fw["idps"] or "—",
             {True: "вкл", False: "выкл", None: "?"}[fw["dns_proxy"]], fmt_value(fw["zones"]), fmt_value(fw["private_ip"]),
             fw["rules"], fw["logs"], fw["state"] or "?"]
            for fw in firewalls
        ]))
    else:
        blocks.append(("p", "Брандмауэры в заданной области не найдены."))
    policies = report["inventory"]["firewall_policies"]
    if policies:
        blocks.append(("table", ["Политика", "SKU", "Базовая политика", "Брандмауэров", "Групп коллекций", "Правил", "Threat Intel", "IDPS"], [
            [p["label"], p["tier"], p["base_policy"] or "—", p["firewalls"], p["rule_collection_groups"], p["rules"], p["threat_intel"], p["idps"] or "—"]
            for p in policies
        ]))
    nsgs = report["inventory"]["network_security_groups"]
    if nsgs:
        blocks.append(("table", ["NSG", "Регион", "Правил", "Подсети", "Сетевых интерфейсов", "Правил с доступом из Интернета", "Состояние"], [
            [n["label"], n["location"], n["rules"], short_list(n["subnets"], 4), n["network_interfaces"],
             n["internet_inbound_rules"], n["state"] or "?"]
            for n in nsgs
        ]))
    elif snapshot["network_security_groups"] == 0:
        blocks.append(("p", "NSG в заданной области не найдены."))

    blocks.append(("h2", "Изменения относительно эталона"))
    drift = report["drift"]
    if drift is None:
        blocks.append(("p", "Эталон не задан. Сохраните утверждённый снимок командой collect и передайте его в --baseline."))
    else:
        blocks.append(("p", f"Эталон: {fmt_time(drift['baseline_collected_at'])}, текущий снимок: {fmt_time(drift['current_collected_at'])}."))
        if drift["scope_mismatch"]:
            blocks.append(("p", "Внимание: область сбора эталона и текущего снимка различается — часть объектов может быть отмечена как добавленные или удалённые."))
        for note in drift.get("notes") or []:
            blocks.append(("p", note))
        rows = []
        for record in drift["added"]:
            rows.append([record["label"], 1, "Добавлено", KIND_TITLES[record["kind"]], describe_entity(record["kind"], record["data"])])
        for record in drift["removed"]:
            rows.append([record["label"], 2, "Удалено", KIND_TITLES[record["kind"]], describe_entity(record["kind"], record["data"])])
        for record in drift["renamed"]:
            rows.append([record["label"], 3, "Переименовано", KIND_TITLES[record["kind"]], f"было: {record['old_label']}; {describe_entity(record['kind'], record['data'])}"])
        for record in drift["modified"]:
            for change in record["changes"]:
                rows.append([record["label"], 4, "Изменено", KIND_TITLES[record["kind"]], describe_change(change)])
        rows.sort(key=lambda row: (row[0].lower(), row[1]))
        if rows:
            blocks.append(("table", ["Объект", "Изменение", "Тип", "Подробности"], [[r[0], r[2], r[3], r[4]] for r in rows]))
        else:
            blocks.append(("p", "Конфигурация совпадает с эталоном."))
        if drift["not_compared"]:
            blocks.append(("h3", "Не сравнивались"))
            blocks.append(("table", ["Объект", "Тип", "Причина"], [
                [record["label"], KIND_TITLES[record["kind"]], record["reason"]] for record in drift["not_compared"]
            ]))

    activity = report.get("activity_log")
    if activity:
        blocks.append(("h2", "Журнал действий Azure"))
        blocks.append(("p", f"Операции изменения брандмауэров, политик, IP-групп, NSG и диагностики с {fmt_time(activity['from'])} по {fmt_time(activity['to'])}."))
        if activity.get("events"):
            blocks.append(("table", ["Время", "Кто", "Операция", "Ресурс", "Статус"], [
                [fmt_time(e["time"]), e["caller"] or "—", e["operation"].split("/", 1)[-1], _short_resource(e["resource_id"]), e["status"]]
                for e in activity["events"]
            ]))
        else:
            blocks.append(("p", "Операций изменения не найдено."))
        for error in activity.get("errors") or []:
            blocks.append(("p", f"Журнал действий {error['scope']} не прочитан: {_error_text(error)}"))

    blocks.append(("h2", "Отклонения от стандарта"))
    findings = report["findings"]
    if findings:
        blocks.append(("table", ["Уровень", "Проверка", "Объект", "Описание"], [
            [Severity(f["severity"]), f["check"], f["object"], f"{f['title']}. {f['details']}"] for f in findings
        ]))
        blocks.append(("h3", "Рекомендации"))
        checks = sorted({f["check"] for f in findings})
        blocks.append(("table", ["Проверка", "Что не так", "Что сделать"], [
            [check, CHECKS[check][0], CHECKS[check][1]] for check in checks
        ]))
    else:
        blocks.append(("p", "Отклонений не обнаружено."))

    if report["accepted_findings"] or report["exception_problems"]:
        blocks.append(("h2", "Исключения"))
        if report["accepted_findings"]:
            blocks.append(("table", ["Уровень", "Проверка", "Объект", "Основание", "Действует до"], [
                [Severity(f["severity"]), f["check"], f["object"], f["exception"]["reason"], f["exception"]["expires"] or "бессрочно"]
                for f in report["accepted_findings"]
            ]))
        if report["exception_problems"]:
            blocks.append(("table", ["Исключение", "Проблема"], [[p["exception"], p["problem"]] for p in report["exception_problems"]]))

    if report["errors"]:
        blocks.append(("h2", "Ошибки получения данных"))
        blocks.append(("table", ["Объект", "Этап", "Код", "Сообщение"], [
            [_short_resource(e["scope"]) if "/providers/" in e["scope"] else e["scope"], e["stage"], e.get("status") or "—", _error_text(e)]
            for e in report["errors"]
        ]))

    blocks.append(("p", f"{TOOL_NAME} {TOOL_VERSION}: данные получены только GET-запросами к Azure Resource Manager; конфигурация не изменялась."))
    return blocks


_MD_ESCAPE = str.maketrans({
    "\\": "\\\\", "`": "\\`", "*": "\\*", "_": "\\_", "[": "\\[", "]": "\\]",
    "|": "\\|", "<": "&lt;", ">": "&gt;",
})


def _md(value: Any) -> str:
    return str(value).translate(_MD_ESCAPE).replace("\r", "").replace("\n", "<br>")


def render_markdown(report: dict) -> str:
    lines: list[str] = []
    for block in report_blocks(report):
        kind = block[0]
        if kind in ("h1", "h2", "h3"):
            lines.append("#" * int(kind[1]) + " " + _md(block[1]))
        elif kind == "p":
            lines.append(_md(block[1]))
        elif kind == "kv":
            lines.extend(f"- **{_md(key)}:** {_md(value)}" for key, value in block[1])
        elif kind == "table":
            headers, rows = block[1], block[2]
            lines.append("| " + " | ".join(_md(h) for h in headers) + " |")
            lines.append("|" + "|".join("---" for _ in headers) + "|")
            lines.extend("| " + " | ".join(_md(cell) for cell in row) + " |" for row in rows)
        lines.append("")
    return "\n".join(lines)


_HTML_STYLE = """
:root { --bg: #ffffff; --fg: #1f2328; --muted: #59636e; --line: #d1d9e0; --head: #f6f8fa;
  --critical: #a40e26; --high: #d1242f; --medium: #bc4c00; --low: #9a6700; --info: #0969da; }
@media (prefers-color-scheme: dark) {
  :root { --bg: #0d1117; --fg: #e6edf3; --muted: #9198a1; --line: #3d444d; --head: #151b23;
    --critical: #ff7b72; --high: #f85149; --medium: #f0883e; --low: #d29922; --info: #58a6ff; }
}
body { background: var(--bg); color: var(--fg); margin: 0 auto; max-width: 1400px; padding: 24px 16px;
  font: 14px/1.5 -apple-system, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif; }
h1 { font-size: 24px; } h2 { font-size: 19px; margin-top: 32px; border-bottom: 1px solid var(--line); padding-bottom: 4px; }
h3 { font-size: 16px; }
.table-wrap { overflow-x: auto; }
table { border-collapse: collapse; margin: 8px 0 16px; min-width: 50%; }
th, td { border: 1px solid var(--line); padding: 4px 8px; text-align: left; vertical-align: top; overflow-wrap: break-word; }
th { background: var(--head); }
dl { display: grid; grid-template-columns: max-content 1fr; gap: 2px 16px; }
dt { color: var(--muted); }
dd { margin: 0; }
.sev { font-weight: 600; white-space: nowrap; }
.sev-critical { color: var(--critical); } .sev-high { color: var(--high); } .sev-medium { color: var(--medium); }
.sev-low { color: var(--low); } .sev-info { color: var(--info); }
"""


def _html_cell(value: Any) -> str:
    if isinstance(value, Severity):
        return f'<span class="sev sev-{value.level}">{html.escape(str(value))}</span>'
    # Long rule paths may wrap after "/" instead of in the middle of a word.
    return html.escape(str(value)).replace("/", "/<wbr>").replace("\n", "<br>")


def render_html(report: dict) -> str:
    parts = [
        "<!doctype html>",
        '<html lang="ru"><head><meta charset="utf-8">',
        '<meta name="viewport" content="width=device-width, initial-scale=1">',
        "<title>Аудит Azure Firewall и NSG</title>",
        f"<style>{_HTML_STYLE}</style></head><body>",
    ]
    for block in report_blocks(report):
        kind = block[0]
        if kind in ("h1", "h2", "h3"):
            parts.append(f"<{kind}>{html.escape(block[1])}</{kind}>")
        elif kind == "p":
            parts.append(f"<p>{html.escape(block[1])}</p>")
        elif kind == "kv":
            items = "".join(f"<dt>{html.escape(k)}</dt><dd>{html.escape(str(v))}</dd>" for k, v in block[1])
            parts.append(f"<dl>{items}</dl>")
        elif kind == "table":
            head = "".join(f"<th>{html.escape(h)}</th>" for h in block[1])
            body = "".join("<tr>" + "".join(f"<td>{_html_cell(c)}</td>" for c in row) + "</tr>" for row in block[2])
            parts.append(f'<div class="table-wrap"><table><thead><tr>{head}</tr></thead><tbody>{body}</tbody></table></div>')
    parts.append("</body></html>")
    return "\n".join(parts)


def render_json(report: dict) -> str:
    return json.dumps(report, ensure_ascii=False, indent=2, default=str) + "\n"


RENDERERS = {"md": render_markdown, "html": render_html, "json": render_json}


# ---------------------------------------------------------------------------
# Command line
# ---------------------------------------------------------------------------

def write_text(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    log.info("записан %s", path)


def write_snapshot(path: Path, snapshot: dict) -> None:
    write_text(path, json.dumps(snapshot, ensure_ascii=False, indent=2, sort_keys=True) + "\n")


def load_snapshot(path: str | Path) -> dict:
    try:
        data = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise ConfigError(f"не удалось прочитать снимок {path}: {exc}") from exc
    if not isinstance(data, dict) or "firewalls" not in data or "collected_at" not in data:
        raise ConfigError(f"{path} — не снимок {TOOL_NAME}")
    if int(data.get("schema_version") or 0) > SNAPSHOT_SCHEMA_VERSION:
        raise ConfigError(f"{path} создан более новой версией {TOOL_NAME}")
    return data


def _formats(value: str) -> list[str]:
    formats = [item.strip().lower() for item in value.split(",") if item.strip()]
    unknown = [item for item in formats if item not in RENDERERS]
    if unknown or not formats:
        raise ConfigError(f"--format: допустимы {', '.join(RENDERERS)}, получено {value!r}")
    return formats


def _standard_from_args(args: argparse.Namespace) -> tuple[dict, str | None]:
    path = args.standard
    if path is None:
        default = Path(__file__).with_name("standard.yaml")
        path = str(default) if default.exists() else None
    return load_standard(path), path


def _subscriptions(args: argparse.Namespace, client: ArmClient) -> list[str]:
    if args.all_subscriptions:
        subscriptions = list_subscriptions(client)
    else:
        subscriptions = args.subscription or [s for s in [os.getenv("AZURE_SUBSCRIPTION_ID")] if s]
    if not subscriptions:
        raise ConfigError("укажите --subscription, --all-subscriptions или переменную AZURE_SUBSCRIPTION_ID")
    return sorted(set(subscriptions))


def _collect(args: argparse.Namespace, activity_days: int) -> dict:
    client = make_client(args.arm_endpoint, args.timeout)
    collector = Collector(client, api_version=args.api_version, diagnostics=not args.no_diagnostics, nsg=not args.no_nsg)
    return collector.collect(
        _subscriptions(args, client),
        resource_group=args.resource_group,
        firewall_names=args.firewall,
        nsg_names=args.nsg,
        all_policies=args.all_policies,
        activity_days=activity_days,
    )


def _incomplete(snapshot: dict) -> bool:
    return any(error.get("incomplete", True) for error in snapshot.get("errors") or [])


def _stamp(snapshot: dict) -> str:
    return parse_time(snapshot["collected_at"]).strftime("%Y%m%dT%H%M%SZ")


def _exit_code(report: dict, fail_on: str, fail_on_drift: bool) -> int:
    summary = report["summary"]
    counts = summary["findings_by_severity"]
    drift = summary["drift"]
    log.info(
        "отклонений: %d (%s); изменений: %s; ошибок чтения: %d",
        summary["findings_total"],
        ", ".join(f"{s}={counts[s]}" for s in reversed(SEVERITIES) if counts[s]) or "нет",
        drift["total"] if drift else "эталон не задан",
        summary["collection_errors"],
    )
    if summary["incomplete"]:
        return EXIT_INCOMPLETE
    if fail_on != "none" and any(counts[s] for s in SEVERITIES if SEVERITY_RANK[s] >= SEVERITY_RANK[fail_on]):
        return EXIT_ATTENTION
    if fail_on_drift and drift and drift["total"]:
        return EXIT_ATTENTION
    return EXIT_OK


def _write_reports(report: dict, formats: list[str], output_dir: Path, stamp: str) -> None:
    for fmt in formats:
        write_text(output_dir / f"azfw-report-{stamp}.{fmt}", RENDERERS[fmt](report))


def cmd_collect(args: argparse.Namespace) -> int:
    snapshot = _collect(args, args.activity_days or 0)
    write_snapshot(Path(args.output), snapshot)
    log.info("брандмауэров: %d, политик: %d, IP-групп: %d, NSG: %s, ошибок: %d",
             len(snapshot["firewalls"]), len(snapshot["firewall_policies"]), len(snapshot["ip_groups"]),
             "не собирались" if snapshot["network_security_groups"] is None else len(snapshot["network_security_groups"]),
             len(snapshot["errors"]))
    return EXIT_INCOMPLETE if _incomplete(snapshot) else EXIT_OK


def cmd_report(args: argparse.Namespace) -> int:
    formats = _formats(args.format)
    current = load_snapshot(args.current)
    baseline = load_snapshot(args.baseline) if args.baseline else None
    standard, source = _standard_from_args(args)
    report = build_report(current, baseline, standard, source)
    if args.output:
        output = Path(args.output)
        fmt = output.suffix.lstrip(".").lower()
        if fmt not in RENDERERS:
            raise ConfigError(f"{output}: расширение должно быть .md, .html или .json")
        write_text(output, RENDERERS[fmt](report))
    elif args.output_dir:
        _write_reports(report, formats, Path(args.output_dir), _stamp(current))
    else:
        sys.stdout.write(RENDERERS[formats[0]](report))
    return _exit_code(report, args.fail_on, args.fail_on_drift)


def cmd_run(args: argparse.Namespace) -> int:
    formats = _formats(args.format)
    baseline = load_snapshot(args.baseline) if args.baseline else None
    standard, source = _standard_from_args(args)
    days = args.activity_days
    if days is None:
        # By default read the Activity Log back to the baseline: who changed what since then.
        if baseline:
            elapsed = (utcnow() - parse_time(baseline["collected_at"])).total_seconds() / 86400
            days = max(1, min(ACTIVITY_LOG_MAX_DAYS, math.ceil(elapsed)))
        else:
            days = 0
    snapshot = _collect(args, days)
    output_dir = Path(args.output_dir)
    stamp = _stamp(snapshot)
    write_snapshot(output_dir / f"azfw-snapshot-{stamp}.json", snapshot)
    report = build_report(snapshot, baseline, standard, source)
    _write_reports(report, formats, output_dir, stamp)
    return _exit_code(report, args.fail_on, args.fail_on_drift)


def build_parser() -> argparse.ArgumentParser:
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("-v", "--verbose", action="store_true", help="подробный журнал")

    collect = argparse.ArgumentParser(add_help=False)
    group = collect.add_argument_group("сбор конфигурации (только чтение)")
    group.add_argument("-s", "--subscription", action="append", default=[],
                       help="ID подписки; можно указать несколько раз (по умолчанию AZURE_SUBSCRIPTION_ID)")
    group.add_argument("--all-subscriptions", action="store_true", help="все доступные включённые подписки")
    group.add_argument("-g", "--resource-group", help="только эта группа ресурсов")
    group.add_argument("-f", "--firewall", action="append", default=[], help="только брандмауэр с этим именем; можно несколько раз")
    group.add_argument("--all-policies", action="store_true", help="также политики, не привязанные к найденным брандмауэрам")
    group.add_argument("--nsg", action="append", default=[], help="только NSG с этим именем; можно несколько раз")
    group.add_argument("--no-nsg", action="store_true", help="не читать Network Security Groups")
    group.add_argument("--no-diagnostics", action="store_true", help="не читать параметры диагностики")
    group.add_argument("--activity-days", type=int, default=None,
                       help="читать журнал действий Azure за N дней (0 — не читать; в run по умолчанию — с даты эталона)")
    group.add_argument("--arm-endpoint", default=os.getenv("AZURE_ARM_ENDPOINT", DEFAULT_ARM_ENDPOINT),
                       help=f"адрес Resource Manager (по умолчанию {DEFAULT_ARM_ENDPOINT})")
    group.add_argument("--api-version", default=NETWORK_API_VERSION, help=f"версия API Microsoft.Network (по умолчанию {NETWORK_API_VERSION})")
    group.add_argument("--timeout", type=float, default=60.0, help="тайм-аут запроса, с")

    report = argparse.ArgumentParser(add_help=False)
    group = report.add_argument_group("отчёт")
    group.add_argument("-b", "--baseline", help="эталонный снимок для поиска изменений")
    group.add_argument("--standard", help="стандарт конфигурации (YAML); по умолчанию standard.yaml рядом со скриптом")
    group.add_argument("--fail-on", choices=("none",) + SEVERITIES, default="none",
                       help="код выхода 2, если есть отклонения этого уровня или выше")
    group.add_argument("--fail-on-drift", action="store_true", help="код выхода 2, если конфигурация отличается от эталона")

    parser = argparse.ArgumentParser(
        prog="azfw_audit.py",
        description="Аудит конфигурации Azure Firewall и Network Security Groups только на чтение: снимок, "
                    "изменения относительно эталона, отклонения от стандарта, отчёт.",
        epilog="Коды выхода: 0 — норма, 1 — ошибка, 2 — сработали --fail-on/--fail-on-drift, "
               "3 — часть конфигурации не прочитана.",
    )
    commands = parser.add_subparsers(dest="command", required=True)

    sub = commands.add_parser("collect", parents=[common, collect], help="сохранить снимок конфигурации")
    sub.add_argument("-o", "--output", required=True, help="файл снимка (JSON)")
    sub.set_defaults(handler=cmd_collect)

    sub = commands.add_parser("report", parents=[common, report], help="отчёт по сохранённому снимку (без обращения к Azure)")
    sub.add_argument("-c", "--current", required=True, help="текущий снимок")
    sub.add_argument("--format", default="md", help="md, html, json или список через запятую (по умолчанию md)")
    target = sub.add_mutually_exclusive_group()
    target.add_argument("-o", "--output", help="файл отчёта; формат по расширению .md/.html/.json")
    target.add_argument("--output-dir", help="каталог для отчётов во всех форматах из --format")
    sub.set_defaults(handler=cmd_report)

    sub = commands.add_parser("run", parents=[common, collect, report], help="собрать снимок и сразу сформировать отчёт")
    sub.add_argument("--output-dir", required=True, help="каталог для снимка и отчётов")
    sub.add_argument("--format", default="md,html,json", help="форматы отчёта (по умолчанию md,html,json)")
    sub.set_defaults(handler=cmd_run)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    logging.basicConfig(level=logging.DEBUG if args.verbose else logging.INFO, format="%(levelname)s: %(message)s")
    if not args.verbose:
        logging.getLogger("azure").setLevel(logging.WARNING)
    try:
        return args.handler(args)
    except (ConfigError, AuthError, ArmError, ReadOnlyViolation) as exc:
        log.error("%s", exc)
        return EXIT_ERROR


if __name__ == "__main__":
    sys.exit(main())
