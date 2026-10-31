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
import zipfile

from .base import BaseReport

try:
    from app.redact import redact_config_counted
except ImportError:
    from redact import redact_config_counted

SUMMARY_NAME = "SUMMARY.txt"


class ConfigArchiveReport(BaseReport):
    name = "config_archive"
    label = "Config Archive"
    description = "Running configuration backup for all devices"
    category = "Compliance & Config"
    required_collectors = ["config"]
    supported_formats = ["zip"]

    def generate(self, inventory_data: dict, fmt: str = "zip") -> bytes:
        redacted_hosts = []
        clear_hosts = []
        leftovers = {}
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
            for hostname, device in sorted(inventory_data.get("devices", {}).items()):
                config_data = device.get("collector_data", {}).get("config", {})
                parsed = config_data.get("parsed", {})
                config_text = parsed.get("config", "")
                if not config_text:
                    continue
                if parsed.get("redacted") is False:
                    clear_hosts.append(hostname)
                else:
                    config_text, count = redact_config_counted(config_text)
                    redacted_hosts.append(hostname)
                    if count and parsed.get("redacted") is True:
                        leftovers[hostname] = count
                zf.writestr(f"{hostname}.txt", config_text)
            if redacted_hosts or clear_hosts:
                zf.writestr(SUMMARY_NAME, _summary_text(redacted_hosts, clear_hosts,
                                                        leftovers))
        return buf.getvalue()


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
