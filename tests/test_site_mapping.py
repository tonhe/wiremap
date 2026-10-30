import importlib
import sys

import pytest

from app.site_mapping import (
    compile_rules, default_site, derive_site, parse_rules_text,
)
from app.settings import get_discovery_settings, save_discovery_settings


def test_default_site_is_first_hyphen_token():
    assert default_site("AB001-IDF-SWA-01") == "AB001"
    assert default_site("SWITCH1") == ""
    assert default_site("") == ""
    assert default_site(None) == ""


def test_default_site_strips_domain_first():
    assert default_site("AB001-IDF-SWA-01.example.net") == "AB001"
    # A hyphen in the domain is not a site delimiter.
    assert default_site("sw1.my-corp.example.com") == ""


def test_rules_apply_in_order_first_match_wins():
    rules = compile_rules([
        {"pattern": r"^AB001-", "site": "HQ"},
        {"pattern": r"^AB", "site": "BRANCH"},
    ])
    assert derive_site("AB001-IDF-SWA-01", rules) == "HQ"
    assert derive_site("AB002-IDF-SWA-01", rules) == "BRANCH"


def test_rules_fall_back_to_default():
    rules = compile_rules([{"pattern": r"^ZZ", "site": "X"}])
    assert derive_site("CD003-CORE-01.example.net", rules) == "CD003"


def test_rules_are_case_insensitive_and_see_fqdn():
    rules = compile_rules([{"pattern": r"\.east\.example\.net$", "site": "EAST"}])
    assert derive_site("sw1.EAST.example.net", rules) == "EAST"


def test_rule_site_supports_group_references():
    rules = compile_rules([{"pattern": r"^([a-z]{2})\d{3}-", "site": r"\1"}])
    assert derive_site("AB001-IDF-SWA-01", rules) == "AB"


def test_compile_rules_rejects_bad_regex():
    with pytest.raises(ValueError, match="rule 1"):
        compile_rules([{"pattern": "(", "site": "X"}])


def test_parse_rules_text():
    text = "# comment\n\n^AB0 => HQ\n  \\.east\\. =>EAST  \n"
    assert parse_rules_text(text) == [
        {"pattern": "^AB0", "site": "HQ"},
        {"pattern": r"\.east\.", "site": "EAST"},
    ]


def test_parse_rules_text_requires_separator():
    with pytest.raises(ValueError, match="line 2"):
        parse_rules_text("^AB => HQ\n^CD HQ")


def test_settings_roundtrip_site_rules(tmp_path):
    save_discovery_settings({"site_rules": "^AB0 => HQ"}, config_dir=str(tmp_path))
    stored = get_discovery_settings(config_dir=str(tmp_path))
    assert stored["site_rules"] == [{"pattern": "^AB0", "site": "HQ"}]


def test_settings_rejects_bad_site_rule(tmp_path):
    with pytest.raises(ValueError):
        save_discovery_settings({"site_rules": "( => X"}, config_dir=str(tmp_path))


def test_saving_one_setting_keeps_the_others(tmp_path):
    save_discovery_settings({"site_rules": "^AB0 => HQ", "disable_autodetect": True},
                            config_dir=str(tmp_path))
    save_discovery_settings({"max_workers": 4}, config_dir=str(tmp_path))
    stored = get_discovery_settings(config_dir=str(tmp_path))
    assert stored["max_workers"] == 4
    assert stored["disable_autodetect"] is True
    assert stored["site_rules"] == [{"pattern": "^AB0", "site": "HQ"}]


def test_report_site_uses_configured_rules(tmp_path, monkeypatch):
    """_derive_site in reports reads site_rules from the live settings file."""
    bare_settings = sys.modules.get("settings") or importlib.import_module("settings")
    monkeypatch.setattr(bare_settings, "DEFAULT_CONFIG_DIR", str(tmp_path))
    from app.reports.l2_discovery import _derive_site

    assert _derive_site("AB001-IDF-SWA-01") == "AB001"
    bare_settings.save_discovery_settings({"site_rules": "^AB001- => HQ"})
    assert _derive_site("AB001-IDF-SWA-01.example.net") == "HQ"
    assert _derive_site("CD002-CORE-01") == "CD002"
