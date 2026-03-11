import json
import os
import pytest


def test_get_discovery_settings_defaults(tmp_path):
    """Returns defaults when no config file exists."""
    from app.settings import get_discovery_settings
    settings = get_discovery_settings(config_dir=str(tmp_path))
    assert settings == {"max_workers": 10}


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
    assert settings == {"max_workers": 8}
