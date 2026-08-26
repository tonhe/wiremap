"""Derive hardware and software facts from device_inventory collector output.

ntc-templates spells these keys several ways depending on which template
matched, so every consumer needs the same fallback chain. Shared so discovery
and the inventory report cannot drift apart.
"""


def _normalize_keys(row):
    if not isinstance(row, dict):
        return {}
    return {str(k).lower(): v for k, v in row.items()}


def _as_text(value):
    if isinstance(value, list):
        return ", ".join(str(x) for x in value)
    return str(value) if value else ""


def extract_device_facts(parsed) -> dict:
    facts = {"serial": "", "software_version": "", "model": ""}
    if not parsed or parsed.get("collector_failed"):
        return facts

    version_list = parsed.get("version", [])
    if isinstance(version_list, list) and version_list:
        v = _normalize_keys(version_list[0])
        facts["software_version"] = _as_text(
            v.get("version") or v.get("os_version") or v.get("os"))
        facts["serial"] = _as_text(
            v.get("serial") or v.get("serial_number") or v.get("serialnum"))
        facts["model"] = _as_text(v.get("hardware") or v.get("platform"))

    if not facts["serial"]:
        inv_list = parsed.get("inventory", [])
        if isinstance(inv_list, list) and inv_list:
            vi = _normalize_keys(inv_list[0])
            facts["serial"] = _as_text(vi.get("sn") or vi.get("serial_number"))

    return facts
