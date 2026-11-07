"""
Cisco ASA / ASAv collector.

Runs the ASA assessment command blocks on every unit. The standby unit of a
failover pair only gets the platform, HA and configuration blocks; its
traffic, VPN and policy counters belong to the active unit. On a multiple-
context unit the system context answers the platform blocks and every
security context is visited with changeto for the rest, its output stored
under "context <name>: <command>".

Config-bearing output is redacted before it is stored. Parsing works from
the stored raw output alone, so a saved scan re-parses without the device.
"""
import re

from .base import BaseCollector, ASA_TYPE
from . import asa_parsers as p

try:
    from app.collectors.errors import send_failure_output
    from app.redact import redact_config
    from app.settings import redact_secrets_enabled
except ImportError:
    from collectors.errors import send_failure_output
    from redact import redact_config
    from settings import redact_secrets_enabled

SHOW_MODE = "show mode"
SHOW_VERSION = "show version"
RUNNING_CONFIG = "show running-config"
STARTUP_CHECKSUM = "show startup-config | include Cryptochecksum"
SHOW_CONTEXT = "show context"

BLOCK_SESSION = ["show clock", "show hostname"]
BLOCK_PLATFORM = [
    SHOW_VERSION, "show inventory", SHOW_MODE, "show license all", "show license features",
    "show activation-key", "show environment", "show cpu usage", "show cpu detail",
    "show memory", "show memory detail", "show processes cpu-usage sorted non-zero",
    "show disk0:", "show bootvar", "show asp drop", "show asp drop frame", "show blocks",
    "show conn count", "show xlate count", "show resource usage",
    "show resource usage counter all 1",
    "show crashinfo | include Saved|Traceback|Thread Name|ERROR",
    "show ntp status", "show ntp associations", "show logging | include %ASA-[1-3]-",
    "show route summary",
]
BLOCK_HA = [
    "show failover", "show failover state", "show failover history",
    "show failover interface", "show monitor-interface", "show running-config failover",
    "show cluster info",
]
BLOCK_CONFIG = [
    RUNNING_CONFIG, "show running-config all crypto", "show running-config all ssl",
    "show running-config all sysopt",
    "show startup-config | include ^hostname|^ASA Version|^: Saved",
    "show checksum", STARTUP_CHECKSUM,
]
BLOCK_INTERFACES = [
    "show interface", "show interface ip brief", "show nameif", "show interface summary",
    "show ip address", "show arp", "show arp statistics", "show mac-address-table",
    "show vlan", "show port-channel summary", "show lacp neighbor", "show traffic",
    "show interface | include line protocol|errors|overrun|underrun|drops|input rate|output rate",
]
BLOCK_ROUTING = [
    "show route", "show route summary", "show running-config router",
    "show running-config route", "show ospf", "show ospf neighbor",
    "show ospf interface brief", "show ospf database", "show eigrp neighbors",
    "show eigrp topology", "show bgp summary", "show bgp neighbors", "show bgp",
    "show sla monitor configuration", "show sla monitor operational-state", "show track",
    "show running-config prefix-list", "show running-config route-map",
    "show running-config object-group", "show multicast-routing", "show pim neighbor",
]
BLOCK_POLICY = [
    "show access-list", "show access-list | include elements|line [0-9]+ .*hitcnt=0",
    "show running-config access-group", "show running-config access-list",
    "show running-config object", "show running-config object-group", "show nat detail",
    "show nat pool", "show running-config nat", "show running-config service-policy",
    "show service-policy", "show running-config policy-map",
    "show running-config class-map", "show threat-detection statistics top",
    "show threat-detection rate", "show shun", "show running-config same-security-traffic",
    "show running-config dynamic-filter", "show dynamic-filter statistics",
]
BLOCK_S2S = [
    "show crypto isakmp sa detail", "show crypto ikev1 sa detail",
    "show crypto ikev2 sa detail", "show crypto ipsec sa", "show crypto ipsec sa summary",
    "show vpn-sessiondb summary", "show vpn-sessiondb l2l", "show vpn-sessiondb detail l2l",
    "show running-config crypto", "show running-config tunnel-group",
    "show running-config group-policy", "show crypto map", "show crypto ikev1 stats",
    "show crypto ikev2 stats", "show crypto protocol statistics all",
]
BLOCK_RA = [
    "show vpn-sessiondb anyconnect", "show vpn-sessiondb license-summary",
    "show vpn-sessiondb ratio protocol", "show webvpn anyconnect",
    "show running-config webvpn", "show running-config all tunnel-group",
    "show running-config all group-policy", "show running-config ip local pool",
    "show ip local pool", "show running-config username",
    "show running-config dynamic-access-policy-record", "show running-config aaa-server",
    "show aaa-server", "show running-config ldap", "show running-config tunnel-group-map",
]
BLOCK_CERTS = [
    "show crypto ca certificates", "show crypto ca trustpoints", "show crypto ca crls",
    "show ssl", "show ssl ciphers", "show ssl information", "show running-config ssl",
]
BLOCK_MGMT = [
    "show running-config aaa", "show running-config aaa-server", "show running-config ssh",
    "show running-config telnet", "show running-config http", "show running-config icmp",
    "show running-config snmp-server", "show snmp-server statistics",
    "show running-config logging", "show logging", "show running-config ntp",
    "show running-config dns", "show running-config domain-name",
    "show running-config banner", "show running-config management-access",
    "show running-config flow-export", "show flow-export counters",
    "show running-config call-home", "show running-config password-policy",
    "show running-config passwd", "show running-config enable", "show users",
    "show ssh sessions", "show asdm sessions", "show running-config smart-licensing",
    "show license status",
]
BLOCK_SYSTEM = [SHOW_CONTEXT, "show context detail", "show resource allocation",
                "show resource usage all"]
BLOCK_ASAV = ["show vm", "show cpu", "show license platform", "show license all",
              "show running-config license", "show interface ip brief"]


def _ordered(*blocks):
    seen, out = set(), []
    for block in blocks:
        for cmd in block:
            if cmd not in seen:
                seen.add(cmd)
                out.append(cmd)
    return out


UNIT_COMMANDS = _ordered(BLOCK_SESSION, BLOCK_PLATFORM, BLOCK_HA, BLOCK_CONFIG)
TRAFFIC_COMMANDS = _ordered(BLOCK_INTERFACES, BLOCK_ROUTING, BLOCK_POLICY, BLOCK_S2S,
                            BLOCK_RA, BLOCK_CERTS, BLOCK_MGMT)
# A context's own configuration is what its config file and management plane
# come from, so each context gets the full running-config as well.
CONTEXT_COMMANDS = _ordered([RUNNING_CONFIG], TRAFFIC_COMMANDS)

# Outputs that run to tens of thousands of lines on a hub firewall.
_LONG = ("show running-config", "show access-list", "show route", "show bgp",
         "show ospf database", "show eigrp topology", "show logging", "show crypto ipsec sa",
         "show nat detail", "show vpn-sessiondb", "show arp", "show mac-address-table",
         "show crypto ca certificates", "show interface", "show conn")
LONG_TIMEOUT = 300
SHORT_TIMEOUT = 60

CONTEXT_KEY = "context {name}: {cmd}"
_CONTEXT_KEY_RE = re.compile(r"^context (\S+): (.+)$")


def read_timeout(cmd):
    return LONG_TIMEOUT if cmd.startswith(_LONG) else SHORT_TIMEOUT


def context_key(name, cmd):
    return CONTEXT_KEY.format(name=name, cmd=cmd)


def split_raw(raw):
    """({cmd: text} for the unit, {context: {cmd: text}})."""
    unit, contexts = {}, {}
    for key, text in (raw or {}).items():
        m = _CONTEXT_KEY_RE.match(key)
        if m:
            contexts.setdefault(m.group(1), {})[m.group(2)] = text
        else:
            unit[key] = text
    return unit, contexts


def _text(outputs, cmd):
    """Output of cmd, or None when it was not run or came back empty
    (rejected commands are blanked before parsing)."""
    value = (outputs or {}).get(cmd)
    return value if value else None


class AsaCollector(BaseCollector):
    name = "asa"
    label = "Cisco ASA"
    description = ("Platform, failover, interfaces, policy, VPN, certificates and "
                   "management plane from ASA and ASAv firewalls")
    enabled_by_default = True
    optional = True
    serves_asa = True
    needs_custom_collect = True
    needs_device_context = True

    def applies_to(self, device_type):
        return device_type == ASA_TYPE

    def get_commands(self, device_type):
        if device_type != ASA_TYPE:
            return []
        return UNIT_COMMANDS + TRAFFIC_COMMANDS

    def collect(self, connection, device_type, context=None):
        if device_type != ASA_TYPE:
            return {"raw": {}, "parsed": {"not_applicable": True,
                                          "reason": f"asa does not apply to {device_type}"}}
        unit = (context or {}).get("asa_unit") or {}
        standby = unit.get("role") == "standby"
        raw = {}

        def run(cmds, prefix=None):
            for cmd in cmds:
                key = context_key(prefix, cmd) if prefix else cmd
                if key in raw:
                    continue
                try:
                    raw[key] = connection.send_command(cmd, read_timeout=read_timeout(cmd))
                except Exception as e:
                    raw[key] = send_failure_output(e)

        def switch(cmd):
            # Always sent, even when the same switch ran before: returning
            # to the system context is a state change, not a lookup.
            try:
                raw[cmd] = connection.send_command(cmd, read_timeout=SHORT_TIMEOUT)
            except Exception as e:
                raw[cmd] = send_failure_output(e)
            return raw[cmd]

        run([SHOW_MODE])
        multiple = p.parse_mode(raw.get(SHOW_MODE)) == "multiple"
        if multiple:
            switch("changeto system")
        run(UNIT_COMMANDS)
        version = p.parse_version(raw.get(SHOW_VERSION)) or {}
        if version.get("platform_type") == "ASAv":
            run(BLOCK_ASAV)

        if multiple:
            run(BLOCK_SYSTEM)
            if not standby:
                for ctx in p.parse_contexts(raw.get(SHOW_CONTEXT)):
                    name = ctx["name"]
                    if _rejected(switch(f"changeto context {name}")):
                        continue
                    run(CONTEXT_COMMANDS, prefix=name)
                switch("changeto system")
        elif not standby:
            run(TRAFFIC_COMMANDS)

        if redact_secrets_enabled():
            raw = {k: redact_config(v) if "config" in k else v for k, v in raw.items()}
        return {"raw": raw, "parsed": self.parse_collected(raw, device_type)}

    def parse(self, raw_outputs, device_type):
        unit_raw, ctx_raw = split_raw(raw_outputs)
        mode = p.parse_mode(unit_raw.get(SHOW_MODE))
        version = p.parse_version(unit_raw.get(SHOW_VERSION))
        inventory = p.parse_inventory(unit_raw.get("show inventory"))
        failover = p.parse_failover(unit_raw.get("show failover"))
        config = _text(unit_raw, RUNNING_CONFIG)
        monitored = p.parse_monitor_interface(unit_raw.get("show monitor-interface"))
        resources = p.parse_resource_usage(unit_raw.get("show resource usage"))
        conns_row = p.resource(resources, "Conns")

        parsed = {
            "mode": mode,
            "version": version,
            "inventory": inventory,
            "chassis": p.chassis(inventory),
            "clock": p.parse_clock(unit_raw.get("show clock")),
            "firewall_mode": p.firewall_mode(config),
            "boot": p.parse_bootvar(unit_raw.get("show bootvar")),
            "licence_status": p.parse_license_status(
                (unit_raw.get("show license all") or "") + "\n"
                + (unit_raw.get("show license status") or "")),
            "failover": failover,
            "failover_history": p.parse_failover_history(unit_raw.get("show failover history")),
            "failover_key_set": _failover_key_set(
                _text(unit_raw, "show running-config failover"), config),
            "monitored": monitored,
            "health": {
                "cpu": p.parse_cpu(unit_raw.get("show cpu usage")),
                "memory": p.parse_memory(unit_raw.get("show memory")),
                "disk": p.parse_disk(unit_raw.get("show disk0:")),
                "processes": p.parse_processes(
                    unit_raw.get("show processes cpu-usage sorted non-zero")),
                "blocks_low_zero": p.parse_blocks(unit_raw.get("show blocks")),
                "asp_drops": p.parse_asp_drop(unit_raw.get("show asp drop")),
                "conns": _merge(p.parse_in_use(unit_raw.get("show conn count")),
                                {"limit": conns_row["limit"]} if conns_row else None),
                "xlates": p.parse_in_use(unit_raw.get("show xlate count")),
                "resources": resources,
                "crashinfo": p.parse_crashinfo(
                    unit_raw.get("show crashinfo | include Saved|Traceback|Thread Name|ERROR")),
                "critical_logs": p.parse_critical_logs(
                    unit_raw.get("show logging | include %ASA-[1-3]-")),
            },
            "ntp": p.parse_ntp_status(unit_raw.get("show ntp status")),
            "config_saved": p.config_saved(unit_raw.get("show checksum"),
                                           unit_raw.get(STARTUP_CHECKSUM)),
            "contexts": {},
        }
        if mode == "multiple":
            parsed["system"] = {
                "contexts": p.parse_contexts(unit_raw.get(SHOW_CONTEXT)),
                "config": config is not None,
            }
            for name, outputs in ctx_raw.items():
                parsed["contexts"][name] = parse_context(outputs, monitored)
        else:
            parsed["contexts"][""] = parse_context(unit_raw, monitored)
        return parsed


def _rejected(output):
    try:
        from app.collectors.errors import error_reason
    except ImportError:
        from collectors.errors import error_reason
    return bool(error_reason(output or ""))


def _failover_key_set(failover_config, config):
    text = "\n".join(t for t in (failover_config, config) if t)
    if not text:
        return None
    return bool(re.search(r"^failover key", text, re.M))


def _merge(a, b):
    if a is None:
        return None
    return {**a, **(b or {})}


def _config_text(outputs):
    """The context's running-config, or the running-config sections the
    management block collected when the full one is missing."""
    full = _text(outputs, RUNNING_CONFIG)
    if full is not None:
        return full
    parts = [v for k, v in outputs.items() if k.startswith("show running-config ") and v]
    return "\n".join(parts) if parts else None


def parse_context(outputs, monitored=None):
    """Interfaces, certificates, management plane and counts for one context
    (or the whole unit in single mode)."""
    config = _config_text(outputs)
    cfg_intf = p.parse_config_interfaces(config) if config else {}
    shown = {r["interface"]: r for r in p.parse_show_interface(outputs.get("show interface"))}
    nameif = p.parse_nameif(outputs.get("show nameif"))
    interfaces = []
    for name in list(shown) + [n for n in cfg_intf if n not in shown]:
        row = dict(shown.get(name) or {"interface": name})
        cfg = cfg_intf.get(name, {})
        named, level = nameif.get(name, (None, None))
        row["nameif"] = row.get("nameif") or cfg.get("nameif") or named or ""
        row["security_level"] = (cfg.get("security_level") if cfg.get("security_level")
                                 is not None else level)
        for field in ("ip", "mask", "description"):
            row[field] = row.get(field) or cfg.get(field, "")
        row["standby_ip"] = cfg.get("standby_ip", "")
        row["vlan"] = row.get("vlan") if row.get("vlan") is not None else cfg.get("vlan")
        row["channel_group"] = cfg.get("channel_group")
        row["management_only"] = bool(row.get("management_only") or cfg.get("management_only"))
        if name not in shown:
            row["admin"] = "down" if cfg.get("shutdown") else ""
        status = (monitored or {}).get(row["nameif"]) if row["nameif"] else None
        row["monitored"] = None if monitored is None or not monitored else \
            p.is_monitored(status)
        interfaces.append(row)

    certs = p.parse_certificates(outputs.get("show crypto ca certificates"))
    users = p.trustpoint_users(config) if config else {}
    for c in certs:
        c["used_by"] = sorted({u for tp in c["trustpoints"] for u in users.get(tp, [])})
    mgmt = p.parse_management(config)
    brief = p.parse_ip_brief(outputs.get("show interface ip brief"))
    vpn = p.parse_vpn_summary(outputs.get("show vpn-sessiondb summary"))
    anyconnect = (vpn or {}).get("anyconnect client") or {}
    return {
        "interfaces": interfaces,
        "same_security": p.same_security(config),
        "certificates": certs,
        "mgmt": mgmt,
        "enable_password_set": p.enable_password_set(mgmt),
        "aaa_status": p.parse_aaa_server_status(outputs.get("show aaa-server")),
        "threat_top": p.parse_threat_top(outputs.get("show threat-detection statistics top")),
        "counts": {
            "interfaces_up": (sum(1 for r in brief if r["status"] == "up"
                                  and r["protocol"] == "up") if brief else None),
            "interfaces_total": len(brief) if brief else None,
            "acl_elements": p.acl_elements(outputs.get("show access-list")),
            "nat_rules": p.nat_rule_count(outputs.get("show nat detail")),
            "s2s_configured": p.s2s_configured(config),
            "s2s_up": p.l2l_sessions(outputs.get("show vpn-sessiondb l2l"))
            if "show vpn-sessiondb l2l" in outputs else None,
            "anyconnect_active": anyconnect.get("active") if vpn else None,
            "anyconnect_peak": anyconnect.get("peak") if vpn else None,
            "vpn_capacity": (vpn or {}).get("capacity"),
        },
    }
