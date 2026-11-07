"""
Config Archive report -- ZIP of running configs (one .txt per device).

Configs are redacted at collection time. Inventories saved before that
existed carry no "redacted" flag, so their configs are redacted here;
only an explicit opt-out (redacted: False) is archived as collected.

Configs that were redacted at collection get a second pass here as well, so
secrets the collection-time rules missed (older inventories, line forms
added since) are caught. Leftovers are redacted and counted in SUMMARY.txt
rather than failing the export.
"""
import io
import re
import zipfile

from .base import BaseReport

try:
    from app.redact import redact_config_counted
except ImportError:
    from redact import redact_config_counted

SUMMARY_NAME = "SUMMARY.txt"
ASA_RUNNING_CONFIG = "show running-config"
_ASA_CONTEXT_CONFIG = re.compile(r"^context (\S+): show running-config$")


class ConfigArchiveReport(BaseReport):
    name = "config_archive"
    label = "Config Archive"
    description = "Running configuration backup for all devices"
    category = "Compliance & Config"
    required_collectors = ["config"]
    supported_formats = ["zip"]

    def can_generate(self, inventory_data):
        return any(_device_configs(device)
                   for device in (inventory_data.get("devices") or {}).values())

    def generate(self, inventory_data: dict, fmt: str = "zip") -> bytes:
        redacted_hosts = []
        clear_hosts = []
        leftovers = {}
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
            for hostname, device in sorted(inventory_data.get("devices", {}).items()):
                for name, config_text, redacted in _device_configs(device, hostname):
                    if redacted is False:
                        clear_hosts.append(name)
                    else:
                        config_text, count = redact_config_counted(config_text)
                        redacted_hosts.append(name)
                        if count and redacted is True:
                            leftovers[name] = count
                    zf.writestr(f"{name}.txt", config_text)
            if redacted_hosts or clear_hosts:
                zf.writestr(SUMMARY_NAME, _summary_text(redacted_hosts, clear_hosts,
                                                        leftovers))
        return buf.getvalue()


def _file_name(text):
    # An ASA standby unit is keyed <hostname>/stby; a slash would make a
    # folder in the zip.
    return re.sub(r"[/\\:]+", "_", text)


def _device_configs(device, hostname=""):
    """[(file name, config text, redacted flag)] for one device: its
    running-config, and on a multiple-context ASA one file per context.

    An ASA's running-config is also kept by the asa collector, so a scan
    without the opt-in config collector still archives firewall configs.
    """
    cd = device.get("collector_data", {})
    parsed = (cd.get("config") or {}).get("parsed") or {}
    out = []
    if parsed.get("config"):
        out.append((_file_name(hostname), parsed["config"], parsed.get("redacted")))
    asa_raw = (cd.get("asa") or {}).get("raw") or {}
    if not out and asa_raw.get(ASA_RUNNING_CONFIG):
        out.append((_file_name(hostname), asa_raw[ASA_RUNNING_CONFIG], None))
    for key, text in sorted(asa_raw.items()):
        m = _ASA_CONTEXT_CONFIG.match(key)
        if m and text:
            out.append((_file_name(f"{hostname}_{m.group(1)}"), text, None))
    return out


def _summary_text(redacted_hosts, clear_hosts, leftovers=None):
    total = len(redacted_hosts) + len(clear_hosts)
    lines = [f"Config archive: {total} device configs", ""]
    if not clear_hosts:
        lines.append("Secrets redacted: yes")
        lines.append("Passwords, SNMP communities and keys are replaced with <REDACTED>.")
    else:
        lines.append(f"Secrets redacted: no ({len(clear_hosts)} of {total} configs"
                     " were collected with redaction turned off)")
        lines.append("WARNING: these configs contain clear-text secrets:")
        lines.extend(f"  {h}" for h in clear_hosts)
    if leftovers:
        lines.append("")
        lines.append(f"WARNING: {sum(leftovers.values())} secret tokens survived "
                     f"collection-time redaction on {len(leftovers)} configs and "
                     "were redacted while building this archive:")
        lines.extend(f"  {h}: {n}" for h, n in sorted(leftovers.items()))
    return "\n".join(lines) + "\n"
