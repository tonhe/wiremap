"""Every module must import the way it does inside the container.

Docker sets WORKDIR /app and copies app/ flat into it, so at import time `app`
resolves to app.py -- not a package. `from app.foo import bar` therefore raises
"ModuleNotFoundError: ... 'app' is not a package" there, while importing
cleanly under pytest, which puts both the repo root and app/ on sys.path.

That gap took the container down with a 500 once already. These tests run a
fresh interpreter with only app/ on the path, reproducing the container's
import environment.
"""
import subprocess
import sys
import textwrap
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent
APP_DIR = REPO / "app"

# app.py logs to /app/logs, which exists in the container and not here.
_PREAMBLE = textwrap.dedent("""
    import logging

    class _NullFileHandler(logging.NullHandler):
        def __init__(self, *args, **kwargs):
            super().__init__()

    logging.FileHandler = _NullFileHandler
    logging.disable(logging.CRITICAL)
""")

# Modules imported at container start, directly or by the report and collector
# registries walking their packages.
CRITICAL_MODULES = [
    "app",
    "inventory",
    "discovery_engine",
    "connection_manager",
    "identity",
    "device_facts",
    "snmp_probe",
    "settings",
    "collectors",
    "collectors.base",
    "collectors.errors",
    "neighbors",
    "reports",
]


def _run_in_container_env(body):
    """Run a script with only app/ on sys.path, as the container does."""
    return subprocess.run(
        [sys.executable, "-c", _PREAMBLE + textwrap.dedent(body)],
        cwd=str(APP_DIR),
        capture_output=True,
        text=True,
        env={"PATH": "/usr/bin:/bin", "PYTHONPATH": ""},
    )


def _assert_ok(result, what):
    assert result.returncode == 0, (
        f"{what} fails the way the container runs it:\n{result.stderr}")


@pytest.mark.parametrize("module", CRITICAL_MODULES)
def test_module_imports_without_app_package(module):
    _assert_ok(_run_in_container_env(f"import {module}"), module)


def test_report_registry_builds_without_app_package():
    """The 500 came from the report registry importing every report module on
    the first request."""
    result = _run_in_container_env("""
        from reports import get_registry
        print(len(get_registry()))
    """)
    _assert_ok(result, "report registry")
    assert int(result.stdout.strip()) > 0


def test_collector_registry_builds_without_app_package():
    result = _run_in_container_env("""
        from collectors import get_registry
        print(len(get_registry()))
    """)
    _assert_ok(result, "collector registry")
    assert int(result.stdout.strip()) > 0


def test_collector_collect_runs_without_app_package():
    """collect() imports the error detector lazily, so a bad import there
    surfaces mid-scan rather than at startup."""
    result = _run_in_container_env("""
        from collectors.arp import ArpCollector

        class FakeConn:
            def send_command(self, cmd):
                return "Internet  10.0.0.1  1  aabb.cc00.0101  ARPA  Gi0/1"

        out = ArpCollector().collect(FakeConn(), "cisco_ios")
        assert "parsed" in out
        print("ok")
    """)
    _assert_ok(result, "collector.collect()")
    assert result.stdout.strip() == "ok"


def test_inventory_merge_runs_without_app_package():
    """merge_duplicates imports identity lazily, at the end of every scan."""
    result = _run_in_container_env("""
        from inventory import DiscoveryInventory
        inv = DiscoveryInventory.create(seed_ip="10.0.0.1")
        inv.add_device("SW1(FOC1)")
        inv.add_device("SW1")
        print(inv.merge_duplicates())
    """)
    _assert_ok(result, "merge_duplicates")
    assert result.stdout.strip() == "1"


def test_device_inventory_report_generates_without_app_package():
    """The exact module whose import took the container down."""
    result = _run_in_container_env("""
        from reports.device_inventory import DeviceInventoryReport
        inv = {"devices": {"SW1": {"hostname": "SW1", "mgmt_ip": "10.0.0.1",
                                   "collector_data": {}}}}
        out = DeviceInventoryReport().generate(inv, fmt="xlsx")
        print(len(out) > 0)
    """)
    _assert_ok(result, "device inventory report")
    assert result.stdout.strip() == "True"


def test_diagram_report_generates_without_app_package():
    result = _run_in_container_env("""
        from reports.diagram_data import DiagramDataReport
        inv = {"devices": {"SW1": {"hostname": "SW1", "mgmt_ip": "10.0.0.1",
                                   "collector_data": {}}}}
        out = DiagramDataReport().generate(inv, fmt="xlsx")
        print(len(out) > 0)
    """)
    _assert_ok(result, "diagram data report")
    assert result.stdout.strip() == "True"
