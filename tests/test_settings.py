import json
import os
import pytest


def test_get_discovery_settings_defaults(tmp_path):
    """Returns defaults when no config file exists."""
    from app.settings import get_discovery_settings
    settings = get_discovery_settings(config_dir=str(tmp_path))
    assert settings == {"max_workers": 10, "disable_autodetect": False,
                        "site_rules": [], "redact_secrets": True,
                        "collect_controller_managed": False,
                        "max_logins_per_minute": 0, "connect_timeout_s": 10,
                        "allow_telnet": False, "source_ip": "",
                        "dns_server": "", "dns_search": [],
                        "expand_non_cdp_neighbors": False}


def test_save_and_load_discovery_settings(tmp_path):
    """Saved settings can be loaded back."""
    from app.settings import get_discovery_settings, save_discovery_settings
    save_discovery_settings({"max_workers": 5}, config_dir=str(tmp_path))
    settings = get_discovery_settings(config_dir=str(tmp_path))
    assert settings["max_workers"] == 5


def test_save_validates_max_workers_range(tmp_path):
    """max_workers must be between 1 and 20."""
    from app.settings import save_discovery_settings
    with pytest.raises(ValueError):
        save_discovery_settings({"max_workers": 0}, config_dir=str(tmp_path))
    with pytest.raises(ValueError):
        save_discovery_settings({"max_workers": 21}, config_dir=str(tmp_path))


def test_save_ignores_unknown_keys(tmp_path):
    """Unknown keys are silently dropped."""
    from app.settings import save_discovery_settings, get_discovery_settings
    save_discovery_settings({"max_workers": 8, "bogus": "value"}, config_dir=str(tmp_path))
    settings = get_discovery_settings(config_dir=str(tmp_path))
    assert settings == {"max_workers": 8, "disable_autodetect": False,
                        "site_rules": [], "redact_secrets": True,
                        "collect_controller_managed": False,
                        "max_logins_per_minute": 0, "connect_timeout_s": 10,
                        "allow_telnet": False, "source_ip": "",
                        "dns_server": "", "dns_search": [],
                        "expand_non_cdp_neighbors": False}


def test_disable_autodetect_default(tmp_path):
    from app.settings import get_discovery_settings
    settings = get_discovery_settings(config_dir=str(tmp_path))
    assert settings["disable_autodetect"] is False


def test_disable_autodetect_roundtrip(tmp_path):
    from app.settings import get_discovery_settings, save_discovery_settings
    save_discovery_settings({"max_workers": 5, "disable_autodetect": True},
                            config_dir=str(tmp_path))
    settings = get_discovery_settings(config_dir=str(tmp_path))
    assert settings["disable_autodetect"] is True


def test_redact_secrets_default_on(tmp_path):
    from app.settings import get_discovery_settings, redact_secrets_enabled
    assert get_discovery_settings(config_dir=str(tmp_path))["redact_secrets"] is True
    assert redact_secrets_enabled(config_dir=str(tmp_path)) is True


def test_redact_secrets_opt_out_roundtrip(tmp_path):
    from app.settings import save_discovery_settings, redact_secrets_enabled
    save_discovery_settings({"redact_secrets": False}, config_dir=str(tmp_path))
    assert redact_secrets_enabled(config_dir=str(tmp_path)) is False


def test_redact_secrets_fails_closed_on_bad_file(tmp_path):
    from app.settings import redact_secrets_enabled
    (tmp_path / "discovery.json").write_text("{not json")
    assert redact_secrets_enabled(config_dir=str(tmp_path)) is True


def test_partial_save_keeps_other_settings(tmp_path):
    from app.settings import get_discovery_settings, save_discovery_settings
    save_discovery_settings({"max_workers": 5, "disable_autodetect": True,
                             "redact_secrets": False}, config_dir=str(tmp_path))
    save_discovery_settings({"max_workers": 7}, config_dir=str(tmp_path))
    settings = get_discovery_settings(config_dir=str(tmp_path))
    assert settings == {"max_workers": 7, "disable_autodetect": True,
                        "redact_secrets": False, "site_rules": [],
                        "collect_controller_managed": False,
                        "max_logins_per_minute": 0, "connect_timeout_s": 10,
                        "allow_telnet": False, "source_ip": "",
                        "dns_server": "", "dns_search": [],
                        "expand_non_cdp_neighbors": False}
def test_collect_controller_managed_defaults_off(tmp_path):
    from app.settings import get_discovery_settings
    settings = get_discovery_settings(config_dir=str(tmp_path))
    assert settings["collect_controller_managed"] is False


def test_partial_save_keeps_other_saved_values(tmp_path):
    """Saving only max_workers must not reset other saved settings."""
    from app.settings import get_discovery_settings, save_discovery_settings
    save_discovery_settings({"max_workers": 5, "collect_controller_managed": True},
                            config_dir=str(tmp_path))
    save_discovery_settings({"max_workers": 7}, config_dir=str(tmp_path))
    settings = get_discovery_settings(config_dir=str(tmp_path))
    assert settings["max_workers"] == 7
    assert settings["collect_controller_managed"] is True


def test_max_logins_per_minute_defaults_to_unlimited(tmp_path):
    from app.settings import get_discovery_settings
    assert get_discovery_settings(config_dir=str(tmp_path))["max_logins_per_minute"] == 0


def test_max_logins_per_minute_roundtrip_and_range(tmp_path):
    from app.settings import get_discovery_settings, save_discovery_settings
    save_discovery_settings({"max_logins_per_minute": "120"},
                            config_dir=str(tmp_path))
    assert get_discovery_settings(config_dir=str(tmp_path))["max_logins_per_minute"] == 120
    with pytest.raises(ValueError):
        save_discovery_settings({"max_logins_per_minute": 601},
                                config_dir=str(tmp_path))
    with pytest.raises(ValueError):
        save_discovery_settings({"max_logins_per_minute": -1},
                                config_dir=str(tmp_path))
    with pytest.raises(ValueError):
        save_discovery_settings({"max_logins_per_minute": "lots"},
                                config_dir=str(tmp_path))
