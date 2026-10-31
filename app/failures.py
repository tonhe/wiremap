"""
Login failure classification -- why a device could not be collected.

A failed count on its own tells the operator nothing they can act on. Each
failure is put in one class with a likely cause and remediation, so a scan
summary can say "8 refused: run from a permitted management host" instead
of "8 failed".

Kept free of netmiko/paramiko imports so reports and saved-scan readers can
use it outside Docker. Exceptions are recognised by class name and message.
"""
import errno

TIMEOUT = "timeout"
REFUSED = "refused"
AUTH = "auth"
LEGACY_CRYPTO = "legacy_crypto"
NO_TELNET_DRIVER = "no_telnet_driver"
OTHER = "other"

# Overall reason when attempts disagree. An auth failure proves the device
# was reachable and spoke SSH, so it outranks anything network-layer.
REASON_PRIORITY = [AUTH, LEGACY_CRYPTO, REFUSED, TIMEOUT, OTHER,
                   NO_TELNET_DRIVER]

REASON_LABELS = {
    TIMEOUT: "Timeout",
    REFUSED: "Connection refused",
    AUTH: "Authentication failed",
    LEGACY_CRYPTO: "SSH negotiation failed",
    NO_TELNET_DRIVER: "No telnet driver",
    OTHER: "Other error",
}

HINTS = {
    TIMEOUT: ("No answer on TCP 22/23 (host down, filtered by a firewall or "
              "ACL, or no route from the wiremap host); confirm reachability "
              "from where wiremap runs"),
    REFUSED: ("TCP port 22 refused by host (likely vty access-class or SSH "
              "disabled); run wiremap from a permitted management host or add "
              "this host to the vty ACL"),
    AUTH: ("Credentials rejected; the device likely uses a different AAA "
           "source or local account, or is managed by a controller"),
    LEGACY_CRYPTO: ("SSH negotiation failed even with legacy algorithms "
                    "enabled (no common key exchange, cipher or host key); "
                    "regenerate the device's RSA key (2048 bit) and enable "
                    "SSH v2, or turn on 'Allow telnet' in Settings"),
    NO_TELNET_DRIVER: ("SSH failed and there is no telnet driver for this "
                       "platform; fix SSH access to collect it"),
    OTHER: "Unexpected error; see the attempt detail for the exception",
}

SKIP_HINTS = {
    "aci": ("ACI fabric node, managed by APIC; collect it from the APIC or "
            "enable 'collect controller-managed devices'"),
    "ucsm": ("UCS Fabric Interconnect, managed by UCS Manager; enable "
             "'collect controller-managed devices' to log in anyway"),
}

_CRYPTO_MARKERS = (
    "incompatible ssh", "no acceptable", "no matching", "kex",
    "key exchange", "cipher", "host key", "negotiat",
)
_REFUSED_MARKERS = ("[errno 111]", "connection refused", "errno 10061")
_UNREACHABLE_ERRNOS = {errno.EHOSTUNREACH, errno.ENETUNREACH,
                       errno.ETIMEDOUT}


def hint_for(reason):
    return HINTS.get(reason, HINTS[OTHER])


def _exception_chain(exc, limit=8):
    """exc and whatever it was raised from -- netmiko wraps the socket error."""
    seen = []
    while exc is not None and exc not in seen and len(seen) < limit:
        seen.append(exc)
        # paramiko's NoValidConnectionsError keeps the per-address socket
        # errors here; its own errno is None.
        per_address = getattr(exc, "errors", None)
        if isinstance(per_address, dict):
            seen.extend(e for e in per_address.values()
                        if isinstance(e, BaseException) and e not in seen)
        exc = exc.__cause__ or exc.__context__
    return seen


def classify_exception(exc):
    """Return the failure class for one connection attempt's exception."""
    chain = _exception_chain(exc)
    names = [type(e).__name__ for e in chain]

    if any("AuthenticationException" in n for n in names):
        return AUTH

    for e in chain:
        if isinstance(e, ConnectionRefusedError):
            return REFUSED
        if getattr(e, "errno", None) == errno.ECONNREFUSED:
            return REFUSED

    text = " ".join(str(e) for e in chain).lower()
    if any(m in text for m in _REFUSED_MARKERS):
        return REFUSED

    if any(n == "IncompatiblePeer" for n in names) or \
            any(m in text for m in _CRYPTO_MARKERS):
        return LEGACY_CRYPTO

    for e in chain:
        if isinstance(e, TimeoutError):
            return TIMEOUT
        if getattr(e, "errno", None) in _UNREACHABLE_ERRNOS:
            return TIMEOUT
    if any("Timeout" in n for n in names) or "timed out" in text \
            or "timeout" in text:
        return TIMEOUT

    return OTHER


def classify_message(message):
    """Best-effort class for a bare error string (old saved scans)."""
    text = (message or "").lower()
    if "authentication" in text:
        return AUTH
    if any(m in text for m in _REFUSED_MARKERS) or "refused" in text:
        return REFUSED
    if any(m in text for m in _CRYPTO_MARKERS):
        return LEGACY_CRYPTO
    if "timeout" in text or "timed out" in text or "unreachable" in text:
        return TIMEOUT
    if "telnet not supported" in text:
        return NO_TELNET_DRIVER
    return OTHER


def pick_reason(reasons):
    """Highest-priority class among several attempts' classes."""
    present = [r for r in reasons if r]
    for reason in REASON_PRIORITY:
        if reason in present:
            return reason
    return OTHER


def failure_record(value, hostname=None):
    """Normalise a scan_summary["failed"] value to the structured shape.

    Saved scans from before structured failures hold a plain error string.
    Readers call this on every value so they need not care which they got.
    """
    if isinstance(value, dict):
        reason = value.get("reason") or classify_message(value.get("message"))
        record = {
            "hostname": value.get("hostname") or hostname,
            "reason": reason,
            "hint": value.get("hint") or hint_for(reason),
            "message": value.get("message") or "",
            "attempts": list(value.get("attempts") or []),
        }
        # Outcome of the SNMP fallback (app.snmp_probe OUTCOME_*), when one
        # was recorded. Absent on scans from before it was tracked.
        if value.get("snmp"):
            record["snmp"] = value["snmp"]
        return record
    message = "" if value is None else str(value)
    reason = classify_message(message)
    return {
        "hostname": hostname,
        "reason": reason,
        "hint": hint_for(reason),
        "message": message,
        "attempts": [],
    }


# Matches app.snmp_probe.OUTCOME_OK; repeated so this module keeps no app
# imports.
SNMP_ANSWERED = ("v2c ok", "v3 ok")


def snmp_answered(value):
    """True when the login failed but the SNMP fallback collected the device."""
    return isinstance(value, dict) and value.get("snmp") in SNMP_ANSWERED


def plain_failures(failed):
    """The failed map minus devices SNMP collected instead.

    Those keep their failure record, since it explains why there is no CLI
    data, but they were collected and do not count as failed devices.
    """
    return {ip: value for ip, value in (failed or {}).items()
            if not snmp_answered(value)}


def reason_counts(failed):
    """[{reason, label, count, hint}] for a failed map, most common first.

    Devices the SNMP fallback collected are not counted.
    """
    counts = {}
    for value in plain_failures(failed).values():
        reason = failure_record(value)["reason"]
        counts[reason] = counts.get(reason, 0) + 1
    order = {r: i for i, r in enumerate(REASON_PRIORITY)}
    return [
        {"reason": r, "label": REASON_LABELS.get(r, r), "count": n,
         "hint": hint_for(r)}
        for r, n in sorted(counts.items(),
                           key=lambda kv: (-kv[1], order.get(kv[0], 99)))
    ]
