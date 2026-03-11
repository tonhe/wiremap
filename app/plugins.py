"""
Plugin configuration manager with encrypted credential storage.
"""

import base64
import json
import logging
import os

from cryptography.fernet import Fernet

logger = logging.getLogger(__name__)

DEFAULT_CONFIG_DIR = "/app/config"

PLUGIN_DEFINITIONS = {
    "cisco_eox": {
        "label": "Cisco EOX API",
        "secret_fields": ["client_id", "client_secret"],
    },
}


def _get_fernet(config_dir):
    key_path = os.path.join(config_dir, "plugins.key")
    if os.path.exists(key_path):
        with open(key_path, "rb") as f:
            key = f.read().strip()
    else:
        key = Fernet.generate_key()
        os.makedirs(config_dir, exist_ok=True)
        with open(key_path, "wb") as f:
            f.write(key)
        os.chmod(key_path, 0o600)
    return Fernet(key)


def _read_config(config_dir):
    config_path = os.path.join(config_dir, "plugins.json")
    if not os.path.exists(config_path):
        return {}
    with open(config_path, "r") as f:
        return json.load(f)


def _write_config(config_dir, data):
    config_path = os.path.join(config_dir, "plugins.json")
    os.makedirs(config_dir, exist_ok=True)
    with open(config_path, "w") as f:
        json.dump(data, f, indent=2)
    os.chmod(config_path, 0o600)


def _encrypt(fernet, value):
    return base64.urlsafe_b64encode(fernet.encrypt(value.encode())).decode()


def _decrypt(fernet, value):
    return fernet.decrypt(base64.urlsafe_b64decode(value.encode())).decode()


def get_plugin_config(plugin_name, config_dir=None):
    config_dir = config_dir or DEFAULT_CONFIG_DIR
    all_config = _read_config(config_dir)
    plugin_cfg = all_config.get(plugin_name)
    if not plugin_cfg:
        return None

    fernet = _get_fernet(config_dir)
    defn = PLUGIN_DEFINITIONS.get(plugin_name, {})
    secret_fields = defn.get("secret_fields", [])

    result = {"enabled": plugin_cfg.get("enabled", False)}
    for field in secret_fields:
        encrypted_val = plugin_cfg.get(field)
        if encrypted_val:
            try:
                result[field] = _decrypt(fernet, encrypted_val)
            except Exception:
                logger.warning("Failed to decrypt %s for plugin %s", field, plugin_name)
                result[field] = None
        else:
            result[field] = None
    return result


def save_plugin_config(plugin_name, config_dict, config_dir=None):
    config_dir = config_dir or DEFAULT_CONFIG_DIR
    fernet = _get_fernet(config_dir)
    all_config = _read_config(config_dir)

    defn = PLUGIN_DEFINITIONS.get(plugin_name, {})
    secret_fields = defn.get("secret_fields", [])

    plugin_cfg = all_config.get(plugin_name, {})
    plugin_cfg["enabled"] = config_dict.get("enabled", plugin_cfg.get("enabled", False))

    for field in secret_fields:
        value = config_dict.get(field)
        if value:
            plugin_cfg[field] = _encrypt(fernet, value)

    all_config[plugin_name] = plugin_cfg
    _write_config(config_dir, all_config)


def get_plugin_status(plugin_name, config_dir=None):
    config_dir = config_dir or DEFAULT_CONFIG_DIR
    all_config = _read_config(config_dir)
    plugin_cfg = all_config.get(plugin_name)
    defn = PLUGIN_DEFINITIONS.get(plugin_name, {})

    if not plugin_cfg:
        return {
            "name": plugin_name,
            "label": defn.get("label", plugin_name),
            "enabled": False,
            "configured": False,
            "client_id_mask": None,
        }

    # Check if secrets are present (configured)
    secret_fields = defn.get("secret_fields", [])
    configured = all(plugin_cfg.get(f) for f in secret_fields)

    # Mask: decrypt client_id and show last 4 chars
    client_id_mask = None
    if plugin_cfg.get("client_id"):
        try:
            fernet = _get_fernet(config_dir)
            full_id = _decrypt(fernet, plugin_cfg["client_id"])
            if len(full_id) >= 4:
                client_id_mask = full_id[-4:]
            else:
                client_id_mask = full_id
        except Exception:
            pass

    return {
        "name": plugin_name,
        "label": defn.get("label", plugin_name),
        "enabled": plugin_cfg.get("enabled", False),
        "configured": configured,
        "client_id_mask": client_id_mask,
    }


def list_plugins(config_dir=None):
    config_dir = config_dir or DEFAULT_CONFIG_DIR
    return [get_plugin_status(name, config_dir) for name in PLUGIN_DEFINITIONS]
