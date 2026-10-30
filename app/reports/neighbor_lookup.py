"""CDP/LLDP neighbour lookup by local interface, shared by port-level reports."""
try:
    from app.ifname import canonical_ifname
except ImportError:
    from ifname import canonical_ifname


def neighbors_by_interface(device):
    """Map canonical local interface name -> neighbour name(s) on that port.

    Keyed canonically so a switchport row (Gi1/0/1) finds the CDP record
    (GigabitEthernet1/0/1). A port with more than one neighbour (a hub, or a
    phone with a PC behind it) lists them all.
    """
    parsed = device.get("collector_data", {}).get("cdp_lldp", {}).get("parsed", {})
    names = {}
    for n in parsed.get("neighbors", []) or []:
        local = canonical_ifname(n.get("local_intf"))
        remote = n.get("remote_device") or n.get("remote_ip") or ""
        if not local or not remote:
            continue
        found = names.setdefault(local, [])
        if remote not in found:
            found.append(remote)
    return {intf: ", ".join(found) for intf, found in names.items()}
