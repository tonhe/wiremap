"""
Discovery settings — simple JSON config for non-secret settings.
"""
import json
import os

DEFAULT_CONFIG_DIR = "/app/config"
SETTINGS_FILE = "discovery.json"

DEFAULTS = {
    "max_workers": 10,
}

VALID_RANGES = {
    "max_workers": (1, 20),
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


def save_discovery_settings(settings, config_dir=None):
    config_dir = config_dir or DEFAULT_CONFIG_DIR
    cleaned = {}
    for key in DEFAULTS:
        value = settings.get(key, DEFAULTS[key])
        if key in VALID_RANGES:
            lo, hi = VALID_RANGES[key]
            if not (lo <= value <= hi):
                raise ValueError(f"{key} must be between {lo} and {hi}")
        cleaned[key] = value
    os.makedirs(config_dir, exist_ok=True)
    filepath = os.path.join(config_dir, SETTINGS_FILE)
    with open(filepath, "w") as f:
        json.dump(cleaned, f, indent=2)
