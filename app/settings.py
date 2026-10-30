"""
Discovery settings — simple JSON config for non-secret settings.
"""
import json
import os

DEFAULT_CONFIG_DIR = "/app/config"
SETTINGS_FILE = "discovery.json"

DEFAULTS = {
    "max_workers": 10,
    "disable_autodetect": False,
    # Ordered hostname -> site rules: [{"pattern": regex, "site": code}].
    # Empty means the first hyphen-delimited hostname token.
    "site_rules": [],
    # Replace secrets (SNMP communities, enable/user secrets, AAA keys, ...)
    # in collected configs with <REDACTED> before they are stored.
    "redact_secrets": True,
    # ACI fabric nodes and UCS Fabric Interconnects authenticate against
    # their controller, so logging in with the network credential fails.
    "collect_controller_managed": False,
    # Login attempts per minute across all workers (SSH, telnet and the
    # legacy-algorithm retry), so a large run does not trip TACACS+/ISE
    # throttling. 0 means no limit.
    "max_logins_per_minute": 0,
}

VALID_RANGES = {
    "max_workers": (1, 20),
    "max_logins_per_minute": (0, 600),
}


def get_discovery_settings(config_dir=None):
    config_dir = config_dir or DEFAULT_CONFIG_DIR
    filepath = os.path.join(config_dir, SETTINGS_FILE)
    if not os.path.exists(filepath):
        return dict(DEFAULTS)
    with open(filepath, "r") as f:
        stored = json.load(f)
    result = dict(DEFAULTS)
    for key in DEFAULTS:
        if key in stored:
            result[key] = stored[key]
    return result


def _clean_site_rules(value):
    try:
        from site_mapping import compile_rules, parse_rules_text
    except ImportError:
        from app.site_mapping import compile_rules, parse_rules_text
    if isinstance(value, str):
        return parse_rules_text(value)
    if not isinstance(value, list):
        raise ValueError("site_rules must be a list or 'regex => SITE' lines")
    compile_rules(value)
    return [{"pattern": str(r["pattern"]).strip(),
             "site": str(r.get("site", "")).strip()} for r in value]


def save_discovery_settings(settings, config_dir=None):
    config_dir = config_dir or DEFAULT_CONFIG_DIR
    # Keys the caller leaves out keep their stored value, so a form that
    # edits one setting does not reset the others.
    current = get_discovery_settings(config_dir)
    cleaned = {}
    for key in DEFAULTS:
        value = settings.get(key, current[key])
        if key == "site_rules":
            value = _clean_site_rules(value)
        if key in VALID_RANGES:
            try:
                value = int(value)
            except (TypeError, ValueError):
                raise ValueError(f"{key} must be a whole number")
            lo, hi = VALID_RANGES[key]
            if not (lo <= value <= hi):
                raise ValueError(f"{key} must be between {lo} and {hi}")
        if isinstance(DEFAULTS[key], bool):
            value = bool(value)
        cleaned[key] = value
    os.makedirs(config_dir, exist_ok=True)
    filepath = os.path.join(config_dir, SETTINGS_FILE)
    with open(filepath, "w") as f:
        json.dump(cleaned, f, indent=2)


def redact_secrets_enabled(config_dir=None):
    """True unless the user turned redaction off. Fails closed."""
    try:
        return get_discovery_settings(config_dir).get("redact_secrets", True) is not False
    except Exception:
        return True
