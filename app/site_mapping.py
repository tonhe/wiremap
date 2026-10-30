"""
Site mapping -- hostname to site code.

Operators name devices to a convention, but the convention varies by customer.
`site_rules` (a discovery setting) is an ordered list of
{"pattern": regex, "site": code}. The first rule whose pattern matches the
hostname (case-insensitive, searched against the name as given, FQDN
included) wins. The site may use regex group references such as \\1, so one
rule can cover a whole family of sites. With no matching rule the site is the
first hyphen-delimited token of the short hostname (domain stripped).
"""
import os
import re
import threading

try:
    import settings as _settings
except ImportError:
    from app import settings as _settings

RULE_SEPARATOR = "=>"


def default_site(hostname):
    if not hostname:
        return ""
    short = hostname.split(".")[0]
    parts = short.split("-")
    if len(parts) >= 2:
        return parts[0]
    return ""


def compile_rules(rules):
    """Return [(compiled_regex, site_template)]. Raises ValueError on bad input."""
    compiled = []
    for idx, rule in enumerate(rules or [], 1):
        if not isinstance(rule, dict):
            raise ValueError(f"Site rule {idx}: expected pattern and site")
        pattern = str(rule.get("pattern", "")).strip()
        site = str(rule.get("site", "")).strip()
        if not pattern:
            raise ValueError(f"Site rule {idx}: pattern is empty")
        try:
            regex = re.compile(pattern, re.IGNORECASE)
        except re.error as e:
            raise ValueError(f"Site rule {idx}: invalid regex '{pattern}': {e}")
        compiled.append((regex, site))
    return compiled


def parse_rules_text(text):
    """Parse `regex => SITE` lines. Blank lines and # comments are skipped."""
    rules = []
    for lineno, line in enumerate((text or "").splitlines(), 1):
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if RULE_SEPARATOR not in stripped:
            raise ValueError(
                f"Site rules line {lineno}: expected 'regex {RULE_SEPARATOR} SITE'")
        pattern, site = stripped.rsplit(RULE_SEPARATOR, 1)
        rules.append({"pattern": pattern.strip(), "site": site.strip()})
    compile_rules(rules)
    return rules


def derive_site(hostname, rules=None):
    """Site code for a hostname. rules is the compiled list; None loads settings."""
    if not hostname:
        return ""
    if rules is None:
        rules = _configured_rules()
    for regex, site in rules:
        match = regex.search(hostname)
        if match:
            try:
                return match.expand(site)
            except (re.error, IndexError):
                return site
    return default_site(hostname)


# Reports call derive_site once per row, so the configured rules are cached
# and re-read only when the settings file changes.
_cache_lock = threading.Lock()
_cache = {"key": None, "rules": []}


def _configured_rules():
    path = os.path.join(_settings.DEFAULT_CONFIG_DIR, _settings.SETTINGS_FILE)
    try:
        key = (path, os.stat(path).st_mtime_ns)
    except OSError:
        return []
    with _cache_lock:
        if _cache["key"] == key:
            return _cache["rules"]
        try:
            raw = _settings.get_discovery_settings().get("site_rules") or []
            rules = compile_rules(raw)
        except (ValueError, OSError):
            rules = []
        _cache["key"] = key
        _cache["rules"] = rules
        return rules
