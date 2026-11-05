import copy
import datetime as dt
import json
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from types import SimpleNamespace
from urllib.parse import urlparse

import pytest
import requests

import azfw_audit as audit

ROOT = Path(__file__).resolve().parents[1]
EXAMPLES = ROOT / "examples"
SUB = "00000000-0000-0000-0000-000000000000"
ARM = "https://management.azure.com"
FW_HUB = f"/subscriptions/{SUB}/resourcegroups/rg-hub-network/providers/microsoft.network/azurefirewalls/fw-hub-weu"
POL_BASE = f"/subscriptions/{SUB}/resourcegroups/rg-security/providers/microsoft.network/firewallpolicies/fwpol-base-global"
POL_HUB = f"/subscriptions/{SUB}/resourcegroups/rg-hub-network/providers/microsoft.network/firewallpolicies/fwpol-hub-prod"
NSG_WEB = f"/subscriptions/{SUB}/resourcegroups/rg-app/providers/microsoft.network/networksecuritygroups/nsg-snet-web"
NSG_DB = f"/subscriptions/{SUB}/resourcegroups/rg-app/providers/microsoft.network/networksecuritygroups/nsg-snet-db"


def load(name):
    return json.loads((EXAMPLES / f"{name}.snapshot.json").read_text(encoding="utf-8"))


@pytest.fixture
def baseline():
    return load("baseline")


@pytest.fixture
def current():
    return load("current")


# ---------------------------------------------------------------------------
# Fake Azure Resource Manager
# ---------------------------------------------------------------------------

class FakeCredential:
    def __init__(self, expires_in=3600):
        self.calls = 0
        self.expires_in = expires_in

    def get_token(self, scope):
        self.calls += 1
        assert scope == ARM + "/.default"
        return SimpleNamespace(token=f"token-{self.calls}", expires_on=time.time() + self.expires_in)


class FakeResponse:
    def __init__(self, status, body=None, headers=None):
        self.status_code = status
        self._body = body
        self.headers = headers or {}
        self.text = json.dumps(body) if body is not None else ""
        self.reason = "reason"

    def json(self):
        if self._body is None:
            raise ValueError("no body")
        return self._body


class FakeArm:
    """Session double with only a get() method: any other verb would fail loudly."""

    def __init__(self, routes):
        # path (lower case) -> body | FakeResponse | list of those (consumed in order)
        self.routes = {key.lower(): value for key, value in routes.items()}
        self.calls = []

    def get(self, url, params=None, headers=None, timeout=None):
        self.calls.append({"url": url, "params": params, "headers": headers})
        assert headers["Authorization"].startswith("Bearer ")
        path = urlparse(url).path.lower()
        if path not in self.routes:
            return FakeResponse(404, {"error": {"code": "ResourceNotFound", "message": f"{path} not found"}})
        value = self.routes[path]
        if isinstance(value, list) and value and isinstance(value[0], FakeResponse):
            value = value.pop(0) if len(value) > 1 else value[0]
        return value if isinstance(value, FakeResponse) else FakeResponse(200, value)


def routes_from_snapshot(snapshot):
    """ARM answers that reproduce a snapshot."""
    routes = {f"/subscriptions/{SUB}/providers/Microsoft.Network/azureFirewalls": {"value": list(snapshot["firewalls"].values())}}
    routes.update(snapshot["firewalls"])
    for policy_id, entry in snapshot["firewall_policies"].items():
        routes[policy_id] = entry["resource"]
        routes[f"{policy_id}/ruleCollectionGroups"] = {"value": entry["rule_collection_groups"]}
    for group_id, group in snapshot["ip_groups"].items():
        routes[group_id] = group
    for firewall_id, settings in snapshot["diagnostic_settings"].items():
        routes[f"{firewall_id}/providers/Microsoft.Insights/diagnosticSettings"] = {"value": settings}
    nsgs = list(snapshot["network_security_groups"].values())
    routes[f"/subscriptions/{SUB}/providers/Microsoft.Network/networkSecurityGroups"] = {"value": nsgs}
    for group in ("rg-app", "rg-hub-network", "rg-dmz"):
        for resource_type, items in (("networkSecurityGroups", nsgs), ("azureFirewalls", list(snapshot["firewalls"].values()))):
            in_group = [item for item in items if f"/resourcegroups/{group}/" in item["id"].lower()]
            routes[f"/subscriptions/{SUB}/resourceGroups/{group}/providers/Microsoft.Network/{resource_type}"] = {"value": in_group}
    return routes


def make_client(routes, **kwargs):
    session = FakeArm(routes)
    client = audit.ArmClient(FakeCredential(), session=session, sleep=lambda s: None, **kwargs)
    return client, session


# ---------------------------------------------------------------------------
# Read-only guarantees and the ARM client
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("method", ["POST", "PUT", "PATCH", "DELETE"])
def test_session_refuses_every_write_method(method):
    session = audit.read_only_session()
    with pytest.raises(audit.ReadOnlyViolation):
        session.request(method, f"{ARM}/subscriptions/{SUB}/providers/Microsoft.Network/azureFirewalls")


def test_arm_client_exposes_only_reads():
    public = {name for name in dir(audit.ArmClient) if not name.startswith("_")}
    assert public == {"get", "list", "RETRY_STATUSES"}


def test_list_follows_next_link_and_sends_api_version():
    client, session = make_client({
        "/subscriptions/x/items": {"value": [1, 2], "nextLink": f"{ARM}/subscriptions/x/items2?api-version=1&$skiptoken=a"},
        "/subscriptions/x/items2": {"value": [3]},
    })
    assert client.list("/subscriptions/x/items", "2024-05-01") == [1, 2, 3]
    assert session.calls[0]["params"] == {"api-version": "2024-05-01"}
    assert session.calls[1]["params"] is None  # nextLink is used as is


def test_retries_throttling_with_retry_after():
    delays = []
    session = FakeArm({"/subscriptions/x": [
        FakeResponse(429, {"error": {"message": "slow down"}}, {"Retry-After": "7"}),
        FakeResponse(200, {"ok": True}),
    ]})
    client = audit.ArmClient(FakeCredential(), session=session, sleep=delays.append)
    assert client.get("/subscriptions/x", "v") == {"ok": True}
    assert delays == [7.0]


def test_http_error_carries_status_and_message():
    client, _ = make_client({"/subscriptions/x": FakeResponse(403, {"error": {"code": "AuthorizationFailed", "message": "no access"}})})
    with pytest.raises(audit.ArmError) as error:
        client.get("/subscriptions/x", "v")
    assert error.value.status == 403
    assert "AuthorizationFailed: no access" in error.value.message


def test_token_never_leaves_resource_manager():
    client, session = make_client({"/subscriptions/x": {"value": [], "nextLink": "https://evil.example.com/steal"}})
    with pytest.raises(audit.ArmError):
        client.list("/subscriptions/x", "v")
    assert all(urlparse(call["url"]).netloc == "management.azure.com" for call in session.calls)


def test_token_is_refreshed_before_expiry():
    credential = FakeCredential(expires_in=60)  # inside the 5 minute refresh window
    client = audit.ArmClient(credential, session=FakeArm({"/s": {}}), sleep=lambda s: None)
    client.get("/s", "v")
    client.get("/s", "v")
    assert credential.calls == 2


def test_auth_failure_is_fatal():
    class Broken:
        def get_token(self, scope):
            raise RuntimeError("no credentials")

    client = audit.ArmClient(Broken(), session=FakeArm({}))
    with pytest.raises(audit.AuthError):
        client.get("/s", "v")


# ---------------------------------------------------------------------------
# Collection
# ---------------------------------------------------------------------------

def test_collect_reproduces_the_configuration(baseline):
    client, session = make_client(routes_from_snapshot(baseline))
    snapshot = audit.Collector(client).collect([SUB])

    assert snapshot["errors"] == []
    assert snapshot["firewalls"].keys() == baseline["firewalls"].keys()
    assert snapshot["firewall_policies"].keys() == {POL_HUB, POL_BASE}  # base policy found via basePolicy
    assert snapshot["ip_groups"].keys() == baseline["ip_groups"].keys()  # found via sourceIpGroups
    assert snapshot["diagnostic_settings"] == baseline["diagnostic_settings"]
    assert snapshot["network_security_groups"] == baseline["network_security_groups"]
    assert audit.diff_snapshots(baseline, snapshot)["summary"]["total"] == 0
    assert {call["params"]["api-version"] for call in session.calls if call["params"]} <= {
        audit.NETWORK_API_VERSION, audit.DIAGNOSTICS_API_VERSION}


def test_unreadable_policy_is_not_reported_as_removed(baseline):
    routes = routes_from_snapshot(baseline)
    routes[POL_BASE] = FakeResponse(403, {"error": {"code": "AuthorizationFailed", "message": "denied"}})
    client, _ = make_client(routes)
    snapshot = audit.Collector(client).collect([SUB])

    assert [(e["scope"], e["status"], e["incomplete"]) for e in snapshot["errors"]] == [(POL_BASE, 403, True)]
    drift = audit.diff_snapshots(baseline, snapshot)
    assert drift["removed"] == []
    assert {r["label"] for r in drift["not_compared"]} >= {"rg-security/fwpol-base-global"}

    reports = audit.build_reports(snapshot, baseline=baseline)
    assert all(report["summary"]["incomplete"] for report in reports.values())
    assert audit.evaluate(reports, "none", False, False) == (audit.EXIT_INCOMPLETE, [])


def test_missing_named_firewall_counts_as_removed(baseline):
    routes = routes_from_snapshot(baseline)
    client, _ = make_client(routes)
    snapshot = audit.Collector(client, diagnostics=False).collect(
        [SUB], resource_group="rg-hub-network", firewall_names=["fw-hub-weu", "fw-gone"])

    assert [e["status"] for e in snapshot["errors"]] == [404]
    assert snapshot["errors"][0]["incomplete"] is False
    assert snapshot["diagnostic_settings"] is None
    drift = audit.diff_snapshots(baseline, snapshot)
    removed = {r["label"] for r in drift["removed"] if r["kind"] == "firewall"}
    assert removed == {"rg-dmz/fw-legacy-dmz"}
    # Diagnostics were not read this time, so they are not "removed".
    assert all(r["kind"] != "diagnostic_setting" for r in drift["removed"])


def test_activity_log_keeps_completed_changes_only():
    events = [
        {"eventTimestamp": "2026-10-20T10:00:00Z", "caller": "a@example.com", "correlationId": "1",
         "operationName": {"value": "Microsoft.Network/firewallPolicies/ruleCollectionGroups/write"},
         "resourceId": POL_HUB + "/ruleCollectionGroups/x", "status": {"value": "Started"}},
        {"eventTimestamp": "2026-10-20T10:01:00Z", "caller": "a@example.com", "correlationId": "1",
         "operationName": {"value": "Microsoft.Network/firewallPolicies/ruleCollectionGroups/write"},
         "resourceId": POL_HUB + "/ruleCollectionGroups/x", "status": {"value": "Succeeded"}},
        {"eventTimestamp": "2026-10-20T11:00:00Z", "caller": "b@example.com", "correlationId": "2",
         "operationName": {"value": "Microsoft.Network/virtualNetworks/write"},
         "resourceId": "/subscriptions/x/vnet", "status": {"value": "Succeeded"}},
        {"eventTimestamp": "2026-10-20T12:00:00Z", "caller": "c@example.com", "correlationId": "3",
         "operationName": {"value": "microsoft.insights/diagnosticSettings/write"},
         "resourceId": FW_HUB + "/providers/microsoft.insights/diagnosticSettings/d", "status": {"value": "Succeeded"}},
        {"eventTimestamp": "2026-10-20T12:00:00Z", "caller": "c@example.com", "correlationId": "4",
         "operationName": {"value": "microsoft.insights/diagnosticSettings/write"},
         "resourceId": "/subscriptions/x/storage/providers/microsoft.insights/diagnosticSettings/d", "status": {"value": "Succeeded"}},
    ]
    path = f"/subscriptions/{SUB}/providers/Microsoft.Insights/eventtypes/management/values"
    client, session = make_client({path: {"value": events}})
    result = audit.Collector(client)._activity_log([SUB], None, 30)

    assert [(e["caller"], e["status"]) for e in result["events"]] == [("a@example.com", "Succeeded"), ("c@example.com", "Succeeded")]
    flt = session.calls[0]["params"]["$filter"]
    assert flt.startswith("eventTimestamp ge '") and flt.endswith("resourceProvider eq 'Microsoft.Network'")


# ---------------------------------------------------------------------------
# Drift
# ---------------------------------------------------------------------------

def test_drift_between_example_snapshots(baseline, current):
    drift = audit.diff_snapshots(baseline, current)
    hub = "rg-hub-network/fwpol-hub-prod"

    assert {r["label"] for r in drift["added"]} == {
        f"{hub}/rcg-workloads/dnat-published/rdp-jumphost",
        f"{hub}/rcg-workloads/net-allow-workloads/temp-any-any",
        "rg-app/nsg-snet-web/allow-rdp-temp",
    }
    assert [r["label"] for r in drift["removed"]] == [f"{hub}/rcg-workloads/net-allow-workloads/legacy-ftp"]
    assert [(r["old_label"], r["label"]) for r in drift["renamed"]] == [
        (f"{hub}/rcg-workloads/app-allow-saas/github", f"{hub}/rcg-workloads/app-allow-saas/github-com")]

    changes = {(r["label"], c["path"]): c for r in drift["modified"] for c in r["changes"]}
    assert changes.keys() == {
        ("rg-hub-network/fw-hub-weu", "tags.changeTicket"),
        (hub, "properties.threatIntelMode"),
        (hub, "properties.intrusionDetection.mode"),
        (f"{hub}/rcg-workloads/net-allow-workloads/web-to-sql", "destinationPorts"),
        ("rg-hub-network/ipg-spokes", "properties.ipAddresses"),
        ("rg-app/nsg-snet-web/allow-https-in", "destinationPortRanges"),
        ("rg-app/nsg-snet-db", "properties.subnets"),
    }
    assert changes[(hub, "properties.threatIntelMode")] == {"path": "properties.threatIntelMode", "old": "Deny", "new": "Alert"}
    assert changes[("rg-hub-network/ipg-spokes", "properties.ipAddresses")]["added"] == ["10.3.0.0/16"]
    # allow-https-in moved from destinationPortRange to destinationPortRanges: only 8443 is new.
    assert changes[("rg-app/nsg-snet-web/allow-https-in", "destinationPortRanges")] == {
        "path": "destinationPortRanges", "added": ["8443"], "removed": []}
    assert changes[("rg-app/nsg-snet-db", "properties.subnets")]["removed"] == [
        f"/subscriptions/{SUB}/resourcegroups/rg-app/providers/microsoft.network/virtualnetworks/vnet-app/subnets/snet-db"]
    # etag, size, provisioningState, changeNumber and reordered lists are not drift.
    assert not drift["scope_mismatch"]
    assert drift["notes"] == []
    assert drift["summary"] == {"added": 3, "removed": 1, "modified": 6, "renamed": 1, "not_compared": 0, "total": 11}


def test_ids_differing_only_in_case_are_not_drift(baseline):
    shifted = copy.deepcopy(baseline)
    firewall = shifted["firewalls"][FW_HUB]
    firewall["properties"]["firewallPolicy"]["id"] = firewall["properties"]["firewallPolicy"]["id"].upper().replace("/SUBSCRIPTIONS/", "/subscriptions/")
    assert audit.diff_snapshots(baseline, shifted)["summary"]["total"] == 0


def test_deep_diff_reports_set_changes_and_nested_fields():
    old = audit.normalize({"a": {"b": 1}, "ports": ["80", "443"], "x": None})
    new = audit.normalize({"a": {"b": 2, "c": True}, "ports": ["443", "8443"]})
    assert audit.deep_diff(old, new) == [
        {"path": "a.b", "old": 1, "new": 2},
        {"path": "a.c", "old": None, "new": True},
        {"path": "ports", "added": ["8443"], "removed": ["80"]},
    ]


# ---------------------------------------------------------------------------
# Deviations
# ---------------------------------------------------------------------------

def test_findings_on_example_snapshot(current):
    findings = audit.Auditor(current, audit.load_standard(ROOT / "standard.yaml")).run()
    hub = "rg-hub-network/fwpol-hub-prod/rcg-workloads"
    assert {(f["check"], f["severity"], f["object"]) for f in findings} == {
        ("AZFW-ANY-ANY", "critical", f"{hub}/net-allow-workloads/temp-any-any"),
        ("AZFW-SENSITIVE-PORT", "high", f"{hub}/dnat-published/rdp-jumphost"),
        ("AZFW-SENSITIVE-PORT", "high", "rg-dmz/fw-legacy-dmz/classic-nat/nat-dmz/ssh-admin"),
        ("AZFW-APP-ANY-FQDN", "high", "rg-dmz/fw-legacy-dmz/classic-application/app-dmz/any-web"),
        ("AZFW-TI", "medium", "rg-hub-network/fw-hub-weu"),
        ("AZFW-IDPS", "medium", "rg-hub-network/fw-hub-weu"),
        ("AZFW-TI", "medium", "rg-dmz/fw-legacy-dmz"),
        ("AZFW-DNS-PROXY", "medium", "rg-dmz/fw-legacy-dmz"),
        ("AZFW-LOGS", "medium", "rg-dmz/fw-legacy-dmz"),
        ("AZFW-CLASSIC", "low", "rg-dmz/fw-legacy-dmz"),
        ("NSG-SENSITIVE-PORT", "high", "rg-app/nsg-snet-web/allow-rdp-temp"),
        ("NSG-PUBLIC-PORT", "medium", "rg-app/nsg-snet-web/allow-https-in"),
        ("NSG-UNUSED", "info", "rg-app/nsg-snet-db"),
    }
    assert findings[0]["severity"] == "critical"  # most severe first


def test_baseline_policy_was_compliant(baseline):
    findings = audit.Auditor(baseline, audit.load_standard(None)).run()
    assert not [f for f in findings if f["object"].startswith("rg-hub-network/")]


def _snapshot_with_rules(rules, ip_groups=None, collection_type="FirewallPolicyFilterRuleCollection", action="Allow"):
    policy_id = "/subscriptions/s/resourcegroups/rg/providers/microsoft.network/firewallpolicies/p"
    return {
        "collected_at": "2026-10-27T00:00:00Z",
        "firewalls": {},
        "firewall_policies": {policy_id: {
            "resource": {"id": policy_id, "name": "p", "properties": {"sku": {"tier": "Standard"}}},
            "rule_collection_groups": [{"name": "g", "properties": {"priority": 100, "ruleCollections": [
                {"ruleCollectionType": collection_type, "name": "c", "priority": 100, "action": {"type": action}, "rules": rules},
            ]}}],
        }},
        "ip_groups": ip_groups or {},
        "diagnostic_settings": None,
        "errors": [],
    }


def _checks(snapshot, **overrides):
    standard = audit.load_standard(None)
    standard.update(overrides)
    return sorted((f["check"], f["severity"]) for f in audit.Auditor(snapshot, standard).run())


def test_any_source_via_ip_group_and_wide_ports():
    group_id = "/subscriptions/s/resourcegroups/rg/providers/microsoft.network/ipgroups/everything"
    rules = [{"ruleType": "NetworkRule", "name": "r", "ipProtocols": ["TCP"], "sourceIpGroups": [group_id],
              "destinationAddresses": ["10.0.0.4"], "destinationPorts": ["3000-5000"]}]
    snapshot = _snapshot_with_rules(rules, {group_id: {"id": group_id, "properties": {"ipAddresses": ["0.0.0.0/0"]}}})
    assert _checks(snapshot) == [("AZFW-ANY-PORT", "medium"), ("AZFW-SENSITIVE-PORT", "high")]  # 3306, 3389, 5432 in range


def test_icmp_only_any_any_is_low():
    rules = [{"ruleType": "NetworkRule", "name": "ping", "ipProtocols": ["ICMP"], "sourceAddresses": ["*"],
              "destinationAddresses": ["*"], "destinationPorts": ["*"]}]
    assert _checks(_snapshot_with_rules(rules)) == [("AZFW-ANY-ANY", "low")]


def test_deny_rules_are_not_permissive():
    rules = [{"ruleType": "NetworkRule", "name": "deny-all", "ipProtocols": ["Any"], "sourceAddresses": ["*"],
              "destinationAddresses": ["*"], "destinationPorts": ["*"]}]
    assert _checks(_snapshot_with_rules(rules, action="Deny")) == []


def test_dnat_translated_port_and_unlisted_public_port():
    rules = [
        {"ruleType": "NatRule", "name": "ssh-hidden", "ipProtocols": ["TCP"], "sourceAddresses": ["*"],
         "destinationAddresses": ["203.0.113.1"], "destinationPorts": ["50022"], "translatedAddress": "10.0.0.5", "translatedPort": "22"},
        {"ruleType": "NatRule", "name": "app", "ipProtocols": ["TCP"], "sourceAddresses": ["*"],
         "destinationAddresses": ["203.0.113.1"], "destinationPorts": ["8443"], "translatedAddress": "10.0.0.6", "translatedPort": "8443"},
        {"ruleType": "NatRule", "name": "web", "ipProtocols": ["TCP"], "sourceAddresses": ["*"],
         "destinationAddresses": ["203.0.113.1"], "destinationPorts": ["443"], "translatedAddress": "10.0.0.7", "translatedPort": "443"},
    ]
    snapshot = _snapshot_with_rules(rules, collection_type="FirewallPolicyNatRuleCollection", action="DNAT")
    assert _checks(snapshot) == [("AZFW-DNAT-PUBLIC", "medium"), ("AZFW-SENSITIVE-PORT", "high")]


def test_broad_fqdn_duplicates_and_descriptions():
    rule = {"ruleType": "ApplicationRule", "name": "a", "sourceAddresses": ["10.0.0.0/24"],
            "protocols": [{"protocolType": "Https", "port": 443}], "targetFqdns": ["*.com"]}
    rules = [rule, {**rule, "name": "b", "description": "copy"}]
    assert _checks(_snapshot_with_rules(rules), require_rule_description=True) == [
        ("AZFW-APP-BROAD-FQDN", "medium"), ("AZFW-APP-BROAD-FQDN", "medium"),
        ("AZFW-DUPLICATE", "low"), ("AZFW-NO-DESC", "info"),
    ]


def test_expected_properties(current):
    standard = audit.load_standard(None)
    standard["expected_properties"] = {
        "firewall": {"properties.sku.tier": "Premium", "zones": ["3", "2", "1"]},
        "firewall_policy": {"properties.dnsSettings.enableProxy": True},
    }
    findings = [f for f in audit.Auditor(current, standard).run() if f["check"] == "AZFW-PROP"]
    assert sorted((f["object"], f["details"]) for f in findings) == [
        ("rg-dmz/fw-legacy-dmz", "properties.sku.tier = Standard, по стандарту: Premium"),
        ("rg-dmz/fw-legacy-dmz", "zones = —, по стандарту: 3, 2, 1"),
        ("rg-security/fwpol-base-global", "properties.dnsSettings.enableProxy = —, по стандарту: true"),
    ]


def test_exceptions_accept_expire_and_report_unused():
    findings = [
        {"check": "AZFW-SENSITIVE-PORT", "object": "rg/p/g/c/rdp", "severity": "high"},
        {"check": "AZFW-CLASSIC", "object": "rg-dmz/fw", "severity": "low"},
    ]
    exceptions = [
        {"check": "azfw-sensitive-*", "object": "RG/p/*", "reason": "CHG-1", "expires": dt.date(2026, 12, 31)},
        {"check": "AZFW-CLASSIC", "object": "rg-dmz/*", "reason": "migration", "expires": "2026-01-01"},
        {"check": "AZFW-TI", "reason": "nothing matches"},
        {"check": "AZFW-TI"},
    ]
    active, accepted, problems = audit.apply_exceptions(findings, exceptions, dt.date(2026, 10, 27))
    assert [f["check"] for f in active] == ["AZFW-CLASSIC"]
    assert accepted[0]["exception"] == {"reason": "CHG-1", "expires": "2026-12-31"}
    assert [p["problem"].split(" —")[0] for p in problems] == [
        "нет обязательных полей check и reason", "срок действия истёк 2026-01-01", "не совпало ни с одним отклонением"]


def test_standard_validation(tmp_path):
    path = tmp_path / "standard.yaml"
    path.write_text("threat_intel_mode: Off\nidps_mode: null\nunknown_key: 1\n", encoding="utf-8")
    standard = audit.load_standard(path)
    assert standard["threat_intel_mode"] == "Off"  # YAML reads a bare Off as false
    assert standard["idps_mode"] is None
    path.write_text("minimum_sku_tier: Gold\n", encoding="utf-8")
    with pytest.raises(audit.ConfigError):
        audit.load_standard(path)


# ---------------------------------------------------------------------------
# Network Security Groups
# ---------------------------------------------------------------------------

NSG_ID = "/subscriptions/s/resourcegroups/rg/providers/microsoft.network/networksecuritygroups/nsg"
SUBNET = "/subscriptions/s/resourcegroups/rg/providers/microsoft.network/virtualnetworks/vnet/subnets/snet"


def nsg_rule(name, priority, source, ports, access="Allow", direction="Inbound", protocol="Tcp", destination="*", **extra):
    return {"name": name, "properties": {
        "priority": priority, "direction": direction, "access": access, "protocol": protocol,
        "sourceAddressPrefix": source, "sourcePortRange": "*", "destinationAddressPrefix": destination,
        "destinationPortRanges": ports, **extra,
    }}


def _nsg_snapshot(rules, subnets=(SUBNET,), nics=()):
    return {
        "collected_at": "2026-10-27T00:00:00Z", "firewalls": {}, "firewall_policies": {}, "ip_groups": {},
        "diagnostic_settings": {}, "errors": [],
        "network_security_groups": {NSG_ID: {"id": NSG_ID, "name": "nsg", "location": "westeurope", "properties": {
            "securityRules": rules, "subnets": [{"id": i} for i in subnets], "networkInterfaces": [{"id": i} for i in nics],
        }}},
    }


def _nsg_findings(rules, **kwargs):
    findings = audit.Auditor(_nsg_snapshot(rules, **kwargs), audit.load_standard(None)).run()
    return sorted((f["check"], f["severity"], f["object"].rsplit("/", 1)[-1]) for f in findings)


def test_nsg_internet_exposure_levels():
    rules = [
        nsg_rule("all", 100, "Internet", ["*"]),
        nsg_rule("rdp", 110, "*", ["3389"]),
        nsg_rule("wide", 120, "0.0.0.0/0", ["30000-40000"]),  # no sensitive port inside
        nsg_rule("app", 130, "Internet", ["443", "8443"]),
        nsg_rule("web", 140, "Internet", ["443"]),
        nsg_rule("vnet", 150, "VirtualNetwork", ["*"]),
        nsg_rule("asg", 160, "", ["22"], sourceApplicationSecurityGroups=[{"id": "/subscriptions/s/asg/jump"}]),
        nsg_rule("ping", 170, "Internet", ["*"], protocol="Icmp"),
        nsg_rule("out", 180, "*", ["*"], direction="Outbound", destination="Internet"),
    ]
    assert _nsg_findings(rules) == [
        ("NSG-INTERNET-ANY-PORT", "critical", "all"),
        ("NSG-PUBLIC-PORT", "medium", "app"),
        ("NSG-SENSITIVE-PORT", "high", "rdp"),
        ("NSG-WIDE-PORT", "medium", "wide"),
    ]


def test_nsg_deny_with_higher_priority_closes_ports():
    rules = [
        nsg_rule("deny-admin", 100, "Internet", ["22", "3389"], access="Deny", protocol="*"),
        nsg_rule("deny-udp-only", 105, "*", ["*"], access="Deny", protocol="Udp"),  # does not cover TCP
        nsg_rule("ssh", 110, "Internet", ["22"]),  # fully closed
        nsg_rule("admin-and-web", 120, "*", ["22", "443", "3389", "8080"]),  # 8080 stays open
        nsg_rule("deny-later", 200, "Internet", ["*"], access="Deny", protocol="*"),
        nsg_rule("rdp-before-deny", 150, "Internet", ["3390"]),
    ]
    findings = _nsg_findings(rules)
    assert findings == [("NSG-PUBLIC-PORT", "medium", "admin-and-web"), ("NSG-PUBLIC-PORT", "medium", "rdp-before-deny")]
    details = {f["object"].rsplit("/", 1)[-1]: f["details"] for f in audit.Auditor(_nsg_snapshot(rules), audit.load_standard(None)).run()}
    assert details["admin-and-web"].startswith("Из Интернета доступны порты 8080;")


def test_unattached_nsg_and_rule_descriptions():
    assert _nsg_findings([], subnets=()) == [("NSG-UNUSED", "info", "nsg")]
    assert _nsg_findings([], subnets=(), nics=("/subscriptions/s/nic",)) == []
    standard = audit.load_standard(None)
    standard["require_rule_description"] = True
    findings = audit.Auditor(_nsg_snapshot([nsg_rule("x", 100, "10.0.0.0/8", ["22"])]), standard).run()
    assert [(f["check"], f["object"]) for f in findings] == [("AZFW-NO-DESC", "rg/nsg/x")]


def test_subtract_ports():
    assert audit.subtract_ports([(0, 65535)], [(22, 22), (3389, 3389)]) == [(0, 21), (23, 3388), (3390, 65535)]
    assert audit.subtract_ports([(80, 90)], [(0, 65535)]) == []
    assert audit.fmt_port_ranges([(0, 65535), (22, 22), (80, 90)]) == ["*", "22", "80-90"]


def test_nsg_rule_spelling_and_scale_set_nics_are_not_drift():
    single = _nsg_snapshot([nsg_rule("web", 100, "Internet", ["443"], destinationPortRange="443")])
    single["network_security_groups"][NSG_ID]["properties"]["securityRules"][0]["properties"].pop("destinationPortRanges")
    plural = _nsg_snapshot(
        [{"name": "web", "properties": {
            "priority": 100, "direction": "Inbound", "access": "Allow", "protocol": "Tcp",
            "sourceAddressPrefixes": ["Internet"], "sourcePortRanges": ["*"], "destinationAddressPrefixes": ["*"],
            "destinationPortRanges": ["443"], "provisioningState": "Succeeded"}}],
        nics=("/subscriptions/s/resourcegroups/rg/providers/microsoft.compute/virtualmachinescalesets/vmss/virtualmachines/3/networkinterfaces/nic",),
    )
    assert audit.diff_snapshots(single, plural)["summary"]["total"] == 0


def test_snapshot_without_nsgs_skips_the_section(baseline, current):
    old = copy.deepcopy(baseline)
    del old["network_security_groups"]  # snapshot of a version that did not collect NSGs
    drift = audit.diff_snapshots(old, current)
    assert drift["notes"] == ["NSG не сравнивались: в эталоне они не собирались."]
    assert not [r for r in drift["added"] + drift["not_compared"] if r["kind"].startswith(("network_security", "security_rule"))]
    assert drift["summary"]["total"] == 8  # the firewall changes are still found

    report = audit.build_reports(old)["compliance"]
    assert report["snapshot"]["network_security_groups"] is None
    assert "| NSG | не собирались |" in audit.render_markdown(report)


def test_failed_nsg_listing_hides_only_nsgs(baseline):
    routes = routes_from_snapshot(baseline)
    routes[f"/subscriptions/{SUB}/providers/Microsoft.Network/networkSecurityGroups"] = FakeResponse(
        403, {"error": {"code": "AuthorizationFailed", "message": "denied"}})
    client, _ = make_client(routes)
    snapshot = audit.Collector(client).collect([SUB])
    assert snapshot["errors"][0]["kinds"] == list(audit.NSG_KINDS)

    drift = audit.diff_snapshots(baseline, snapshot)
    assert drift["summary"]["total"] == 0
    assert drift["removed"] == []
    assert {r["kind"] for r in drift["not_compared"]} == {"network_security_group", "security_rule"}


def test_nsg_filter_and_switch(baseline):
    client, _ = make_client(routes_from_snapshot(baseline))
    snapshot = audit.Collector(client).collect([SUB], resource_group="rg-app", nsg_names=["nsg-snet-web", "nsg-gone"])
    assert list(snapshot["network_security_groups"]) == [NSG_WEB]
    assert [(e["scope"], e["incomplete"]) for e in snapshot["errors"]] == [("networksecuritygroups/nsg-gone", False)]

    snapshot = audit.Collector(client, nsg=False).collect([SUB])
    assert snapshot["network_security_groups"] is None
    assert snapshot["scope"]["include_nsgs"] is False


def test_activity_log_keeps_nsg_and_subnet_changes():
    event = {"eventTimestamp": "2026-10-20T10:00:00Z", "caller": "a@example.com", "correlationId": "1", "status": {"value": "Succeeded"}}
    rows = [audit._activity_row({**event, "operationName": {"value": op}, "resourceId": "/x"}) for op in (
        "Microsoft.Network/networkSecurityGroups/securityRules/write",
        "Microsoft.Network/virtualNetworks/subnets/write",
        "Microsoft.Network/virtualNetworks/write",
    )]
    assert [row is not None for row in rows] == [True, True, False]


# ---------------------------------------------------------------------------
# Report and command line
# ---------------------------------------------------------------------------

def test_html_and_markdown_escape_configuration_text(current):
    groups = current["firewall_policies"][POL_HUB]["rule_collection_groups"]
    rules = [r for g in groups for c in g["properties"]["ruleCollections"] for r in c["rules"]]
    rule = next(r for r in rules if r["name"] == "temp-any-any")  # has a finding, so it is in the report
    rule["name"] = "<script>alert(1)</script>|x"
    report = audit.build_reports(current)["compliance"]
    html_text = audit.render_html(report)
    assert "<script>alert(1)</script>" not in html_text
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in html_text.replace("<wbr>", "")
    markdown = audit.render_markdown(report)
    assert "&lt;script&gt;alert(1)&lt;/script&gt;\\|x" in markdown


def example_args(*extra):
    return ["report", "-c", str(EXAMPLES / "current.snapshot.json"), "-p", str(EXAMPLES / "previous.snapshot.json"),
            "-b", str(EXAMPLES / "baseline.snapshot.json"), "--standard", str(ROOT / "standard.yaml"), *extra]


def test_three_reports_on_example_snapshots(current, baseline):
    previous = load("previous")
    reports = audit.build_reports(current, previous, baseline, audit.load_standard(ROOT / "standard.yaml"))
    assert list(reports) == ["changes", "drift", "compliance"]

    changes, drift, compliance = reports["changes"], reports["drift"], reports["compliance"]
    # 1: since the run of 21 October only the two NSG changes happened
    assert changes["reference"]["collected_at"] == "2026-10-21T08:00:00Z"
    assert {(r["label"], c["path"]) for r in changes["drift"]["modified"] for c in r["changes"]} == {
        ("rg-app/nsg-snet-web/allow-https-in", "destinationPortRanges"),
        ("rg-app/nsg-snet-db", "properties.subnets"),
    }
    assert [e["time"][:10] for e in changes["activity_log"]["events"]] == ["2026-10-22", "2026-10-23"]
    # 2: everything since the baseline, with the whole Activity Log window
    assert drift["drift"]["summary"]["total"] == 11
    assert len(drift["activity_log"]["events"]) == len(current["activity_log"]["events"])
    # 3: the standard, independent of any reference snapshot
    assert compliance["summary"]["findings_total"] == 13
    assert "drift" not in compliance and "findings" not in changes


def test_reports_without_previous_or_baseline(current):
    reports = audit.build_reports(current)
    for kind in ("changes", "drift"):
        assert reports[kind]["drift"] is None and reports[kind]["activity_log"] is None
        assert audit.NO_REFERENCE_TEXTS[kind] in audit.render_markdown(reports[kind])
    assert audit.evaluate(reports, "none", True, True) == (audit.EXIT_OK, [])


def test_report_command_writes_three_reports(tmp_path):
    code = audit.main(example_args("--format", "md,html,json", "--output-dir", str(tmp_path)))
    assert code == audit.EXIT_OK
    stamp = "20261027T080000Z"
    assert sorted(p.name for p in tmp_path.iterdir()) == sorted(
        f"azfw-{kind}-{stamp}.{fmt}" for kind in ("changes", "drift", "compliance") for fmt in ("md", "html", "json"))

    compliance = json.loads((tmp_path / f"azfw-compliance-{stamp}.json").read_text(encoding="utf-8"))
    assert compliance["kind"] == "compliance" and compliance["summary"]["findings_by_severity"]["critical"] == 1
    drift = json.loads((tmp_path / f"azfw-drift-{stamp}.json").read_text(encoding="utf-8"))
    assert drift["summary"]["drift"]["total"] == 11
    changes = (tmp_path / f"azfw-changes-{stamp}.md").read_text(encoding="utf-8")
    assert changes.startswith("# Изменения с прошлого сбора")
    assert "app-deploy@example.com" in changes and "contractor@example.com" not in changes  # only after 21 October
    html_text = (tmp_path / f"azfw-drift-{stamp}.html").read_text(encoding="utf-8")
    assert "<title>Отличия от эталона · Azure Firewall и NSG</title>" in html_text


def test_report_kind_selection(tmp_path):
    code = audit.main(example_args("--kind", "drift", "--kind", "compliance", "--format", "json", "--output-dir", str(tmp_path)))
    assert code == audit.EXIT_OK
    assert sorted(p.name.split("-")[1] for p in tmp_path.iterdir()) == ["compliance", "drift"]
    # One file or stdout takes exactly one report.
    assert audit.main(example_args("-o", str(tmp_path / "r.md"))) == audit.EXIT_ERROR
    assert audit.main(example_args("--kind", "changes", "-o", str(tmp_path / "r.md"))) == audit.EXIT_OK
    assert (tmp_path / "r.md").read_text(encoding="utf-8").startswith("# Изменения с прошлого сбора")


@pytest.mark.parametrize("flags, expected", [
    ([], audit.EXIT_OK),
    (["--fail-on", "critical"], audit.EXIT_ATTENTION),
    (["--fail-on-drift"], audit.EXIT_ATTENTION),
    (["--fail-on-change"], audit.EXIT_ATTENTION),
])
def test_exit_codes(tmp_path, flags, expected):
    output = tmp_path / "report.md"
    code = audit.main(example_args("--kind", "compliance", "-o", str(output), *flags))
    assert code == expected  # thresholds apply to all three reports, whichever is written
    assert output.exists()


def test_unchanged_compliant_configuration_passes(tmp_path):
    snapshot = str(EXAMPLES / "baseline.snapshot.json")
    standard = tmp_path / "standard.yaml"
    standard.write_text(
        "threat_intel_mode: Alert\nexceptions:\n"
        "  - {check: '*', object: 'rg-dmz/*', reason: 'legacy DMZ, decommissioning'}\n",
        encoding="utf-8",
    )
    code = audit.main(["report", "-c", snapshot, "-p", snapshot, "-b", snapshot, "--standard", str(standard),
                       "--output-dir", str(tmp_path), "--fail-on", "info", "--fail-on-drift", "--fail-on-change"])
    assert code == audit.EXIT_OK


def test_run_compares_with_the_previous_snapshot(tmp_path, baseline, monkeypatch):
    client, session = make_client(routes_from_snapshot(baseline))
    monkeypatch.setattr(audit, "make_client", lambda endpoint, timeout: client)
    # Snapshots of earlier runs: the newest readable one is the previous collection.
    older = copy.deepcopy(baseline)
    older["firewalls"] = {}
    (tmp_path / "azfw-snapshot-20260901T080000Z.json").write_text(json.dumps(older), encoding="utf-8")
    (tmp_path / "azfw-snapshot-20261001T080000Z.json").write_text(json.dumps(baseline), encoding="utf-8")
    (tmp_path / "azfw-snapshot-20261002T080000Z.json").write_text("{broken", encoding="utf-8")

    code = audit.main(["run", "-s", SUB, "--baseline", str(EXAMPLES / "baseline.snapshot.json"),
                       "--activity-days", "0", "--output-dir", str(tmp_path), "--format", "json",
                       "--fail-on-drift", "--fail-on-change"])
    assert code == audit.EXIT_OK
    changes = json.loads(next(tmp_path.glob("azfw-changes-*.json")).read_text(encoding="utf-8"))
    assert changes["reference"]["collected_at"] == baseline["collected_at"]
    assert changes["summary"]["drift"]["total"] == 0
    assert len(list(tmp_path.glob("azfw-snapshot-*.json"))) == 4
    assert all(call["url"].startswith(audit.DEFAULT_ARM_ENDPOINT) for call in session.calls)


def test_find_previous_snapshot(tmp_path):
    assert audit.find_previous_snapshot(tmp_path / "missing") is None
    assert audit.find_previous_snapshot(tmp_path) is None
    (tmp_path / "azfw-snapshot-20261001T000000Z.json").write_text(json.dumps(load("baseline")), encoding="utf-8")
    (tmp_path / "azfw-snapshot-20261101T000000Z.json").write_text("[]", encoding="utf-8")
    path, snapshot = audit.find_previous_snapshot(tmp_path)
    assert path.name == "azfw-snapshot-20261001T000000Z.json"
    assert snapshot["collected_at"] == "2026-10-01T08:00:00Z"


def test_usage_error_is_not_mistaken_for_findings(capsys):
    assert audit.main(["report"]) == audit.EXIT_ERROR  # argparse alone would exit with 2
    assert audit.main(["--help"]) == audit.EXIT_OK
    assert "usage:" in capsys.readouterr().out


def test_bad_snapshot_is_an_error(tmp_path):
    path = tmp_path / "x.json"
    path.write_text("{}", encoding="utf-8")
    assert audit.main(["report", "-c", str(path), "--kind", "compliance"]) == audit.EXIT_ERROR


# ---------------------------------------------------------------------------
# Rocket.Chat
# ---------------------------------------------------------------------------

WEBHOOK = "https://chat.example.com/hooks/abc123/secret-token"


class FakeChat:
    """Webhook double: records every POST."""

    def __init__(self):
        self.posts = []
        self.responses = [FakeResponse(200, {"success": True})]
        self.error = None

    def post(self, url, json=None, timeout=None, **kwargs):
        assert not kwargs, "nothing but the JSON body goes to Rocket.Chat"
        self.posts.append({"url": url, "json": json})
        if self.error:
            raise self.error
        return self.responses.pop(0) if len(self.responses) > 1 else self.responses[0]


@pytest.fixture
def chat(monkeypatch):
    fake = FakeChat()
    monkeypatch.setattr(audit, "notifier_session", lambda: fake)
    monkeypatch.setattr(audit.time, "sleep", lambda seconds: None)
    monkeypatch.setenv("ROCKETCHAT_WEBHOOK_URL", WEBHOOK)
    monkeypatch.delenv("ROCKETCHAT_NOTIFY", raising=False)
    return fake


def message_text(post):
    attachment = post["json"]["attachments"][0]
    fields = {field["title"]: field["value"] for field in attachment["fields"]}
    return post["json"]["text"], attachment.get("text", ""), attachment["color"], fields


def test_fatal_error_goes_to_rocketchat(chat, tmp_path):
    path = tmp_path / "x.json"
    path.write_text("{}", encoding="utf-8")
    assert audit.main(["report", "-c", str(path), "--kind", "compliance"]) == audit.EXIT_ERROR
    assert [post["url"] for post in chat.posts] == [WEBHOOK]
    title, text, color, fields = message_text(chat.posts[0])
    assert title == ":x: *Аудит Azure Firewall и NSG не выполнен*"
    assert "не снимок azfw-audit" in text and color == "#c62828"
    assert fields["Команда"] == "report" and fields["Код выхода"] == "1"


def test_unexpected_crash_goes_to_rocketchat(chat, monkeypatch):
    monkeypatch.setattr(audit, "build_parser", _parser_with_handler(lambda args: 1 / 0))
    assert audit.main(["report", "-c", "x"]) == audit.EXIT_ERROR
    assert "ZeroDivisionError" in message_text(chat.posts[0])[1]


def _parser_with_handler(handler):
    original = audit.build_parser

    def build():
        parser = original()
        for action in parser._subparsers._group_actions:
            for sub in action.choices.values():
                sub.set_defaults(handler=handler)
        return parser
    return build


def test_incomplete_run_goes_to_rocketchat(chat, tmp_path, baseline, monkeypatch):
    routes = routes_from_snapshot(baseline)
    routes[POL_BASE] = FakeResponse(403, {"error": {"code": "AuthorizationFailed", "message": "denied"}})
    client, _ = make_client(routes)
    monkeypatch.setattr(audit, "make_client", lambda endpoint, timeout: client)
    code = audit.main(["run", "-s", SUB, "--baseline", str(EXAMPLES / "baseline.snapshot.json"),
                       "--activity-days", "0", "--output-dir", str(tmp_path), "--format", "html"])
    assert code == audit.EXIT_INCOMPLETE
    title, text, color, fields = message_text(chat.posts[0])
    assert title.startswith(":warning:") and color == "#ef6c00" and fields["Код выхода"] == "3"
    assert "Не прочитано: 1" in text and "fwpol-base-global" in text and "403" in text and "Reader" in text
    assert "Отличия от эталона: нет; не сравнивались: 4" in text and "Нарушения стандарта ИБ:" in text
    assert f"Файлы: `{tmp_path}`" in text and "azfw-compliance-" in text
    assert fields["Область"].startswith("подписки: " + SUB)


def test_notification_levels(chat):
    assert audit.main(example_args("--kind", "compliance", "--format", "json")) == audit.EXIT_OK
    assert audit.main(example_args("--kind", "compliance", "--format", "json", "--fail-on", "high")) == audit.EXIT_ATTENTION
    assert chat.posts == []  # by default only errors are sent

    assert audit.main(example_args("--kind", "compliance", "--format", "json", "--fail-on", "high", "--notify", "attention")) == audit.EXIT_ATTENTION
    title, text, color, _ = message_text(chat.posts[-1])
    assert title.startswith(":warning:") and color == "#f9a825"
    assert "Сработали пороги: --fail-on high" in text
    assert "Изменения с прошлого сбора: 2 (добавлено 0, удалено 0, изменено 2, переименовано 0)" in text
    assert "• Критический · AZFW-ANY-ANY · `rg-hub-network/fwpol-hub-prod/rcg-workloads/net-allow-workloads/temp-any-any`" in text

    assert audit.main(example_args("--kind", "compliance", "--format", "json", "--notify", "always")) == audit.EXIT_OK
    assert message_text(chat.posts[-1])[0].startswith(":white_check_mark:")


def test_webhook_failure_keeps_exit_code_and_hides_token(chat, tmp_path, caplog):
    chat.error = requests.ConnectionError(f"Max retries exceeded with url: {WEBHOOK}")
    path = tmp_path / "x.json"
    path.write_text("{}", encoding="utf-8")
    with caplog.at_level("INFO"):
        assert audit.main(["report", "-c", str(path), "--kind", "drift", "--rocketchat-webhook", WEBHOOK]) == audit.EXIT_ERROR
    assert len(chat.posts) == 3  # retried
    assert "secret-token" not in caplog.text and "abc123" not in caplog.text
    assert "chat.example.com" in caplog.text and "ConnectionError" in caplog.text


def test_notifier_retries_only_temporary_failures():
    chat = FakeChat()
    chat.responses = [FakeResponse(503), FakeResponse(200)]
    delays = []
    notifier = audit.RocketChatNotifier(WEBHOOK, session=chat, sleep=delays.append)
    assert notifier.send({"text": "x"}) is True and delays == [2]
    chat.responses = [FakeResponse(400)]
    assert notifier.send({"text": "x"}) is False and len(chat.posts) == 3


def test_notifier_configuration(monkeypatch, caplog):
    with pytest.raises(audit.ConfigError):
        audit.RocketChatNotifier("ftp://chat.example.com/hooks/x")
    with pytest.raises(audit.ConfigError):
        audit.RocketChatNotifier(WEBHOOK, level="never")
    audit.RocketChatNotifier("http://chat.example.com/hooks/x/y")
    assert "открытым текстом" in caplog.text

    monkeypatch.delenv("ROCKETCHAT_WEBHOOK_URL", raising=False)
    args = audit.build_parser().parse_args(["report", "-c", "x"])
    assert audit.make_notifier(args) is None
    monkeypatch.setenv("ROCKETCHAT_WEBHOOK_URL", WEBHOOK)
    monkeypatch.setenv("ROCKETCHAT_NOTIFY", "always")
    assert audit.make_notifier(args).level == "always"
    args = audit.build_parser().parse_args(["report", "-c", "x", "--notify", "attention"])
    assert audit.make_notifier(args).level == "attention"
    # The secret never appears in --help, whatever the environment holds.
    assert "secret-token" not in audit.build_parser().format_help()


def test_rocketchat_session_is_not_the_azure_session():
    assert isinstance(audit.read_only_session().get_adapter("https://management.azure.com"), audit.ReadOnlyAdapter)
    assert not isinstance(audit.notifier_session().get_adapter("https://chat.example.com"), audit.ReadOnlyAdapter)


def test_payload_is_bounded():
    errors = [{"scope": f"/subscriptions/s/resourcegroups/rg/providers/microsoft.network/ipgroups/g{i}",
               "stage": "ip group", "status": 403, "message": "denied " * 40, "incomplete": True} for i in range(30)]
    payload = audit.rocketchat_payload("run", audit.EXIT_INCOMPLETE, {"errors": errors}, host="audit-01")
    text = payload["attachments"][0]["text"]
    assert len(text) <= audit.ROCKETCHAT_MAX_TEXT
    assert "Не прочитано: 30" in text


def test_webhook_over_real_http(monkeypatch):
    received = []

    class Hook(BaseHTTPRequestHandler):
        def do_POST(self):
            body = self.rfile.read(int(self.headers["Content-Length"]))
            received.append((self.path, self.headers.get("Content-Type"), self.headers.get("Authorization"), json.loads(body)))
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(b'{"success": true}')

        def log_message(self, *args):
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Hook)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        monkeypatch.setenv("NO_PROXY", "127.0.0.1,localhost")
        monkeypatch.setenv("no_proxy", "127.0.0.1,localhost")
        notifier = audit.RocketChatNotifier(f"http://127.0.0.1:{server.server_port}/hooks/id/token")
        payload = audit.rocketchat_payload("run", audit.EXIT_ERROR, {"error": "не удалось получить токен Azure AD"}, host="h")
        assert notifier.send(payload) is True
    finally:
        server.shutdown()
    path, content_type, authorization, body = received[0]
    assert path == "/hooks/id/token" and content_type == "application/json" and authorization is None
    assert body["alias"] == "azfw-audit" and body["attachments"][0]["fields"][2] == {"title": "Узел", "value": "h", "short": True}
