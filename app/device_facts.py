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


_CHASSIS_NAMES = ("chassis", "switch 1", "switch1", "1")


def _inventory_model(inventory):
    """Chassis PID from show inventory: the chassis or first stack member,
    then a stack entry, then the first entry that has a PID at all."""
    rows = [_normalize_keys(r) for r in inventory or [] if isinstance(r, dict)]
    rows = [r for r in rows if str(r.get("pid") or "").strip()]

    def pid(row):
        return str(row["pid"]).strip()

    for row in rows:
        name = str(row.get("name") or "").strip().lower()
        if name in _CHASSIS_NAMES or name.startswith("chassis"):
            return pid(row)
    for row in rows:
        name = str(row.get("name") or "").lower()
        descr = str(row.get("descr") or row.get("description") or "").lower()
        if "stack" in name or "chassis" in descr:
            return pid(row)
    return pid(rows[0]) if rows else ""


def _platform_model(platform):
    """Model from a CDP/LLDP platform string such as 'cisco WS-C2960X-48FPD-L'."""
    text = _as_text(platform).strip()
    if text.lower().startswith("cisco "):
        text = text[6:].strip()
    return text


def extract_device_facts(parsed, platform_hint=None) -> dict:
    """Serial, software version and model.

    The model falls back from the show version template, to the collector's
    own reading of show version (stack table, processor line, Model number),
    to the show inventory chassis PID, to platform_hint: the CDP/LLDP
    platform the device was discovered with.
    """
    facts = _extract_facts(parsed)
    if not facts["model"] and platform_hint:
        facts["model"] = _platform_model(platform_hint)
    return facts


def _extract_facts(parsed):
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
        # PAN-OS "show system info" reports the chassis under "model"; Cisco
        # templates use "hardware".
        facts["model"] = _as_text(
            v.get("hardware") or v.get("platform") or v.get("model"))

    if not facts["serial"]:
        inv_list = parsed.get("inventory", [])
        if isinstance(inv_list, list) and inv_list:
            vi = _normalize_keys(inv_list[0])
            facts["serial"] = _as_text(vi.get("sn") or vi.get("serial_number"))

    if not facts["model"]:
        own = parsed.get("version_details") or {}
        facts["model"] = (_as_text(own.get("model"))
                          or _inventory_model(parsed.get("inventory")))

    return facts


def _first(value):
    if isinstance(value, list):
        return str(value[0]) if value else ""
    return str(value) if value else ""


def _chassis_entry(inventory):
    """The show inventory row describing the chassis itself."""
    rows = [_normalize_keys(r) for r in inventory or [] if isinstance(r, dict)]
    for row in rows:
        name = str(row.get("name") or "").lower()
        descr = str(row.get("descr") or row.get("description") or "").lower()
        if "chassis" in name or "chassis" in descr:
            return row
    return rows[0] if rows else {}


_UNUSED_LICENSE_STATES = ("not in use", "unused", "not authorized", "expired")


def _license_text(version_license, parsed):
    """Licence level from show version, plus the in-use licences and Smart
    Licensing state from show license, so one cell answers 'what is this box
    licensed for, and is it reporting'."""
    names = [n.strip() for n in str(version_license or "").split(",") if n.strip()]
    for lic in parsed.get("licenses") or []:
        status = str(lic.get("status") or "").lower()
        name = str(lic.get("name") or "").strip()
        if not name or status.startswith(_UNUSED_LICENSE_STATES):
            continue
        if name.lower() not in (n.lower() for n in names):
            names.append(name)
    text = ", ".join(names)
    smart = parsed.get("smart_licensing") or {}
    state = smart.get("registration") or smart.get("status") or ""
    if smart.get("mode") and state:
        label = "SLP" if "policy" in smart["mode"].lower() else "Smart"
        text = f"{text} [{label}: {state}]".strip()
    return text


def extract_version_details(parsed) -> dict:
    """Uptime, reload reason, image, licence and a platform description.

    Prefers the collector's own reading of show version (version_details),
    then whatever ntc-templates captured, so scans saved before
    version_details existed still fill in.
    """
    details = {"uptime": "", "reload_reason": "", "image": "", "license": "",
               "platform_description": ""}
    if not parsed or parsed.get("collector_failed"):
        return details

    own = parsed.get("version_details") or {}
    version_list = parsed.get("version") or []
    v = _normalize_keys(version_list[0]) if (
        isinstance(version_list, list) and version_list) else {}

    details["uptime"] = own.get("uptime") or _first(
        v.get("uptime") or v.get("kernel_uptime"))
    details["reload_reason"] = own.get("reload_reason") or _first(
        v.get("reload_reason") or v.get("last_reboot_reason"))
    details["image"] = own.get("image") or _first(
        v.get("running_image") or v.get("boot_image") or v.get("image")
        or v.get("system_image"))
    details["license"] = _license_text(
        own.get("license") or _first(v.get("license")), parsed)

    # Description: the chassis line from show inventory when it says more
    # than the PID; otherwise model plus software image from show version.
    chassis = _chassis_entry(parsed.get("inventory"))
    descr = str(chassis.get("descr") or chassis.get("description") or "").strip()
    pid = str(chassis.get("pid") or "").strip()
    if descr and descr != pid:
        details["platform_description"] = descr
    else:
        model = pid or _first(v.get("hardware") or v.get("platform")
                              or v.get("model"))
        image = _first(v.get("software_image"))
        if model and image:
            details["platform_description"] = f"{model} ({image})"
        else:
            details["platform_description"] = model
    return details
