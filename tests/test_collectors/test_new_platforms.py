"""Every device type offered in the UI must be answerable by every collector.

A platform in DEVICE_TYPES that no collector knows about would connect fine and
then run Cisco commands at a VyOS box, so this asserts each new platform is
either given real commands or explicitly marked out of scope.
"""
from unittest.mock import patch

import pytest
from app.collectors import get_registry

# Patch the FileHandler before importing app.app so the module-level
# logging.basicConfig() call doesn't try to open /app/logs/app.log.
with patch("logging.FileHandler"):
    from app.app import DEVICE_TYPES

NEW_PLATFORMS = ["vyos", "cisco_wlc", "watchguard_fireware",
                 "paloalto_panos"]


@pytest.mark.parametrize("platform", NEW_PLATFORMS)
def test_platform_is_handled_by_every_collector(platform):
    unhandled = []
    for name, collector in get_registry().items():
        if platform in collector.unsupported_platforms:
            continue
        cmds = collector.get_commands(platform)
        if not cmds:
            continue
        # A collector that returns the Cisco defaults for this platform has
        # not actually been taught it.
        cisco = collector.get_commands("cisco_ios")
        if cmds == cisco and platform not in ("cisco_wlc",):
            unhandled.append(f"{name}: falls through to cisco_ios commands")
    assert not unhandled, "\n".join(unhandled)


@pytest.mark.parametrize("platform", NEW_PLATFORMS)
def test_platform_has_at_least_one_working_collector(platform):
    """A platform nothing can collect from is not supported, just listed."""
    usable = [
        name for name, c in get_registry().items()
        if platform not in c.unsupported_platforms and c.get_commands(platform)
    ]
    assert len(usable) >= 3, f"{platform} only usable by {usable}"


def test_device_types_and_netmiko_agree():
    """Every device type in the UI must be a real netmiko platform."""
    from netmiko.ssh_dispatcher import CLASS_MAPPER

    missing = [dt for dt, _ in DEVICE_TYPES if dt not in CLASS_MAPPER]
    assert not missing, f"not netmiko platforms: {missing}"


def test_new_platforms_are_offered_in_ui():
    offered = {dt for dt, _ in DEVICE_TYPES}
    for platform in NEW_PLATFORMS:
        assert platform in offered


def test_new_platforms_detected_from_cdp():
    """A VyOS or Firebox neighbour must be classified, not defaulted to IOS."""
    from app.device_detector import DeviceTypeDetector
    det = DeviceTypeDetector(config_path="config/device_type_patterns.yaml")
    cases = [
        ("VyOS 1.4-rolling", "vyos"),
        ("Vyatta Router", "vyos"),
        ("Cisco Controller AIR-CT5520-K9", "cisco_wlc"),
        ("WatchGuard Firebox M470", "watchguard_fireware"),
    ]
    for platform, expected in cases:
        got = det.detect_from_cdp(platform, "Router Switch")
        assert got == expected, f"{platform!r} detected as {got}, expected {expected}"


@pytest.mark.parametrize("platform", NEW_PLATFORMS)
def test_no_collector_sends_ios_commands_to_a_non_ios_platform(platform):
    """A firewall that authenticates and then answers "Invalid syntax." to
    every command reads as a successful scan with no data."""
    # Overlap with the Cisco set is not itself wrong -- VyOS runs FRR, so
    # "show ip route" is genuinely correct there. The defect is a platform
    # with no entry at all, which silently inherits _DEFAULT_COMMANDS.
    offenders = []
    for name, collector in get_registry().items():
        if platform in collector.unsupported_platforms:
            continue
        cmds = collector.get_commands(platform)
        fallthrough = collector.get_commands("nonexistent_platform_xyz")
        if cmds and cmds == fallthrough:
            offenders.append(f"{name}: no entry, inherits {sorted(set(cmds))}")
    assert not offenders, (
        f"{platform} is offered in the UI but these collectors have no command "
        f"set for it, so the device is sent Cisco commands and answers with "
        f"syntax errors:\n" + "\n".join(offenders))


def test_panos_identity_command_is_wired():
    """show system info carries model, serial and version; sniffing for the
    word "version" missed it entirely."""
    cmds = get_registry()["device_inventory"].get_commands("paloalto_panos")
    assert "show system info" in cmds


def test_panos_neighbour_command_is_wired():
    cmds = get_registry()["cdp_lldp"].get_commands("paloalto_panos")
    assert "show lldp neighbors all" in cmds
