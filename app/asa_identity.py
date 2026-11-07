"""
Telling an ASA apart before anything else is collected from it.

A host list often names firewalls without a device type, and the IOS driver
logs into an ASA without complaint. The ASA then pages every output after 24
lines, so the probe pipes show version down to the one line that matters.

Both units of a failover pair answer to the same hostname. The standby unit
is kept as <hostname>/stby, the ASA's own prompt convention, so the engine's
duplicate-hostname check does not drop it.
"""
import re

ASA_TYPE = "cisco_asa"
ASA_PROBE = "show version | include Adaptive Security Appliance Software"
FAILOVER_PROBE = "show failover | include Failover On|Failover Off|This host"
STANDBY_SUFFIX = "/stby"

ROLE_ACTIVE = "active"
ROLE_STANDBY = "standby"
ROLE_STANDALONE = "standalone"

_PROBE_RE = re.compile(r"Adaptive Security Appliance Software Version", re.I)
_THIS_HOST_RE = re.compile(r"This host\s*:\s*(Primary|Secondary)\s*-\s*(.+?)\s*$",
                           re.I | re.M)


def is_asa(probe_output):
    return bool(_PROBE_RE.search(probe_output or ""))


def asa_hostname(prompt_hostname):
    """'fw01/pri/stby', 'fw01/admin' or 'fw01/act' -> 'fw01'."""
    return str(prompt_hostname or "").split("/", 1)[0].strip()


def parse_unit(output):
    """Unit role from show failover.

    Returns {"role", "failover_role", "failover_state"}; failover_role is
    primary/secondary or "" when failover is off or unknown.
    """
    text = output or ""
    m = _THIS_HOST_RE.search(text)
    if re.search(r"Failover Off", text, re.I) or not m:
        return {"role": ROLE_STANDALONE, "failover_role": "",
                "failover_state": "" if not m else m.group(2)}
    state = m.group(2)
    lowered = state.lower()
    if lowered.startswith("active"):
        role = ROLE_ACTIVE
    elif lowered.startswith("standby"):
        role = ROLE_STANDBY
    else:
        # Failed, Cold Standby, Negotiation, ... still a pair member, not the
        # one carrying traffic. Keyed as standby so it is not merged away.
        role = ROLE_STANDBY
    return {"role": role, "failover_role": m.group(1).lower(),
            "failover_state": state}


def unit_key(hostname, role):
    return hostname + STANDBY_SUFFIX if role == ROLE_STANDBY else hostname


def base_hostname(key):
    key = str(key or "")
    return key[:-len(STANDBY_SUFFIX)] if key.endswith(STANDBY_SUFFIX) else key
