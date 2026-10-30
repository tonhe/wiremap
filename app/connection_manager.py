"""
Connection Manager -- SSH and Telnet connections to network devices.
Dumb pipe: connects, runs commands, returns raw output. No parsing.
"""
import logging
import re
import socket
import time
from collections import namedtuple

try:
    from app import failures
except ImportError:
    import failures

logger = logging.getLogger(__name__)

_TELNET_SUFFIX = "_telnet"

_PORTS = {"ssh": 22, "telnet": 23}

# A bare TCP connect before netmiko. A filtered address otherwise costs a
# full netmiko timeout per protocol; the probe answers in this long at most
# and never counts against the login rate limit.
TCP_PROBE_TIMEOUT = 1.5
PROBE_NOTE = "tcp probe"


def _tcp_probe(host, port, timeout=TCP_PROBE_TIMEOUT):
    """Open and close a TCP connection. Returns None when the port accepted,
    else (reason, exception_class, message). Failures that are neither a
    timeout nor a refusal return None too, so netmiko reports them itself."""
    try:
        sock = socket.create_connection((host, port), timeout=timeout)
    except Exception as e:
        reason = failures.classify_exception(e)
        if reason == failures.REFUSED:
            return reason, type(e).__name__, f"{PROBE_NOTE}: port {port} refused"
        if reason == failures.TIMEOUT:
            return (reason, type(e).__name__,
                    f"{PROBE_NOTE}: no answer on port {port} within {timeout:g}s")
        return None
    try:
        sock.close()
    except OSError:
        pass
    return None

# Failures where the device type is not the problem. Retrying the same host
# with three other netmiko drivers only triples the wait and the AAA noise.
_NETWORK_LAYER = {failures.TIMEOUT, failures.REFUSED, failures.LEGACY_CRYPTO}

# Platforms where an SSH refusal means telnet is closed for the same reason
# (vty access-class, or telnet disabled by default). Trying it only logs
# another failed login on the AAA server.
_NO_TELNET_AFTER_REFUSAL_TYPES = {"cisco_xe", "cisco_nxos"}
_NO_TELNET_AFTER_REFUSAL_PLATFORM = re.compile(
    r"(\bC9\d{3}|\bN\dK-|\bN\d{4}|nexus|ios-?xe)", re.IGNORECASE)

# Second SSH attempt after a negotiation failure. paramiko 3.5.1 (pinned)
# already offers SHA-1 kex, ssh-rsa and CBC ciphers, so what actually trips
# old IOS is the rsa-sha2 signature upgrade and group-exchange moduli the
# device cannot handle. Disabling those leaves the legacy set to negotiate.
LEGACY_DISABLED_ALGORITHMS = {
    "pubkeys": ["rsa-sha2-512", "rsa-sha2-256"],
    "keys": ["rsa-sha2-512", "rsa-sha2-256"],
    "kex": ["diffie-hellman-group-exchange-sha256",
            "diffie-hellman-group-exchange-sha1"],
}
LEGACY_ALGORITHMS = {
    "_preferred_kex": ("_kex_info", ["diffie-hellman-group14-sha1",
                                     "diffie-hellman-group1-sha1"]),
    "_preferred_keys": ("_key_info", ["ssh-rsa"]),
    "_preferred_pubkeys": ("_key_info", ["ssh-rsa"]),
    "_preferred_ciphers": ("_cipher_info", ["aes128-cbc", "aes256-cbc",
                                            "3des-cbc"]),
}


def _ensure_legacy_algorithms():
    """Make sure paramiko offers the legacy set, at lowest preference.

    A no-op on the pinned paramiko. If a later version drops one from the
    default offer but still implements it, this puts it back at the end of
    the list, so modern devices still negotiate modern algorithms.
    """
    try:
        from paramiko.transport import Transport
    except ImportError:
        return
    for attr, (info_attr, names) in LEGACY_ALGORITHMS.items():
        preferred = tuple(getattr(Transport, attr, ()))
        known = getattr(Transport, info_attr, {})
        missing = tuple(n for n in names if n in known and n not in preferred)
        if missing:
            setattr(Transport, attr, preferred + missing)

# Used when a host list line names no device type. Matches
# default_device_type in config/device_type_patterns.yaml.
DEFAULT_DEVICE_TYPE = "cisco_ios"


def telnet_type_for(device_type: str):
    """Return the netmiko telnet platform for device_type, or None.

    Netmiko has no telnet driver for many platforms -- cisco_nxos and
    cisco_xe among them. Appending _telnet blindly raises ValueError
    carrying a 40-line dump of every supported platform, which then
    buries the genuine SSH failure.
    """
    from netmiko.ssh_dispatcher import CLASS_MAPPER

    if not device_type:
        return None
    candidate = device_type
    if not candidate.endswith(_TELNET_SUFFIX):
        candidate = candidate + _TELNET_SUFFIX
    return candidate if candidate in CLASS_MAPPER else None

ConnectionResult = namedtuple("ConnectionResult", ["connection", "protocol_used", "fallback_occurred"])


def _connect_handler(**params):
    """Indirection point for ConnectHandler so tests can substitute it."""
    from netmiko import ConnectHandler
    return ConnectHandler(**params)


class ConnectionError(Exception):
    """Raised when connection fails.

    attempts holds one dict per try -- protocol, port, device_type,
    exception_class, message, elapsed_ms, reason -- so the genuine SSH
    failure survives alongside later fallback failures. reason is the
    overall failure class (see app.failures), hint its remediation.
    """
    def __init__(self, message: str, error_type: str = "connection",
                 attempts=None, reason: str = None):
        super().__init__(message)
        self.message = message
        self.error_type = error_type
        self.attempts = attempts or []
        self.reason = reason or failures.OTHER
        self.hint = failures.hint_for(self.reason)

    def to_record(self, hostname=None) -> dict:
        """The scan_summary["failed"] value for this failure."""
        return {
            "hostname": hostname,
            "reason": self.reason,
            "hint": self.hint,
            "message": self.message,
            "attempts": [dict(a) for a in self.attempts],
        }


def _attempt(protocol, device_type, reason, exception_class, message,
             elapsed_ms=0):
    return {
        "protocol": protocol,
        "port": _PORTS.get(protocol),
        "device_type": device_type,
        "exception_class": exception_class,
        "message": message,
        "elapsed_ms": elapsed_ms,
        "reason": reason,
    }


def _short_message(exc) -> str:
    """First meaningful line of an exception -- netmiko pads its messages
    with multi-line "Common causes" boilerplate."""
    lines = [ln.strip() for ln in str(exc).splitlines() if ln.strip()]
    for ln in lines:
        if ln.lower().startswith(("incompatible", "no acceptable",
                                  "authentication failed", "[errno")):
            return ln
    return lines[0] if lines else type(exc).__name__


def overall_reason(attempts) -> str:
    """One class for the whole failure, judged on the SSH attempts.

    Telnet runs only after SSH failed, so its outcome says little about why
    the device is not collectable -- unless telnet was all there was.
    """
    ssh = [a["reason"] for a in attempts if a["protocol"] == "ssh"]
    pool = ssh or [a["reason"] for a in attempts]
    return failures.pick_reason(pool)


class ConnectionManager:
    """Manages SSH/Telnet connections to network devices."""

    def __init__(self, host: str, device_type: str, username: str,
                 password: str, protocol: str = "ssh",
                 allow_fallback: bool = True, platform: str = None,
                 login_limiter=None, allow_telnet: bool = False):
        self.host = host
        # protocol="auto" stays on SSH unless telnet is allowed: most sites
        # run "transport input ssh", so a telnet try only adds a timeout and
        # an AAA failure. An explicit protocol="telnet" is always honoured.
        self.allow_telnet = allow_telnet
        # Shared across workers; spaces logins so AAA servers do not throttle.
        self.login_limiter = login_limiter
        self.login_wait_ms = 0
        # Neighbour-reported platform, when known. Only used to decide
        # whether telnet is worth trying after SSH is refused.
        self.platform = platform or ""
        # A host list line may name no device type at all. Carrying None
        # through crashes on the first .endswith() -- three Citrix NetScalers
        # were never reached because of exactly that.
        self.device_type = device_type or DEFAULT_DEVICE_TYPE
        self.device_type_supplied = bool(device_type)
        self.username = username
        self.password = password
        self.protocol = protocol  # "ssh", "telnet", "auto"
        # False when the caller supplied device_type explicitly -- trying
        # other platforms then contradicts what the operator asked for.
        self.allow_fallback = allow_fallback
        self.effective_device_type = None

    def _build_device_params(self, device_type: str = None) -> dict:
        """Build Netmiko connection parameters."""
        dt = device_type or self.device_type
        if self.protocol == "telnet" and not dt.endswith(_TELNET_SUFFIX):
            dt = dt + _TELNET_SUFFIX
        return {
            "device_type": dt,
            "host": self.host,
            "username": self.username,
            "password": self.password,
            "timeout": 10,
            "session_timeout": 20,
            "auth_timeout": 10,
            "banner_timeout": 10,
            "fast_cli": True,
            "global_delay_factor": 1,
        }

    def _get_fallback_types(self, device_type: str) -> list[str]:
        """Return fallback device types to try if primary fails."""
        fallbacks = {
            "cisco_ios": ["cisco_xe", "cisco_nxos"],
            "cisco_xe": ["cisco_ios"],
            "cisco_nxos": ["cisco_ios"],
            "hp_procurve": ["hp_comware", "aruba_os"],
            "hp_comware": ["hp_procurve", "aruba_os"],
            "aruba_os": ["hp_procurve"],
            "dell_os10": ["dell_force10"],
            "dell_force10": ["dell_os10"],
            "extreme": ["extreme_vsp"],
            "extreme_vsp": ["extreme"],
            "ubiquiti_edge": ["ubiquiti_unifi"],
        }
        return fallbacks.get(device_type, [])

    def _types_to_try(self) -> list[str]:
        if not self.allow_fallback:
            return [self.device_type]
        return [self.device_type] + self._get_fallback_types(self.device_type)

    def connect(self):
        """Connect to device. Returns Netmiko connection object.

        Tries primary device type, then fallbacks.
        For protocol="auto", tries SSH first then telnet.
        """
        # Check mock mode BEFORE importing netmiko (which may not be
        # available outside Docker, e.g. Python 3.14 removed telnetlib).
        try:
            from mock_devices import is_mock_mode, get_mock_connection
        except ImportError:
            try:
                from app.mock_devices import is_mock_mode, get_mock_connection
            except ImportError:
                is_mock_mode = lambda host: False
                get_mock_connection = None

        if is_mock_mode(self.host):
            logger.warning(
                f"MOCK MODE: returning simulated data for {self.host} -- "
                f"this is not a real device"
            )
            mock_conn = get_mock_connection(self.host, self.device_type,
                                            self.username, self.password)
            return ConnectionResult(connection=mock_conn, protocol_used="mock", fallback_occurred=False)

        if self.protocol != "auto":
            protocols_to_try = [self.protocol]
        elif self.allow_telnet:
            protocols_to_try = ["ssh", "telnet"]
        else:
            protocols_to_try = ["ssh"]
            logger.debug(f"Telnet to {self.host} not allowed: allow_telnet is off")
        attempts = []
        fallback_occurred = False

        for proto in protocols_to_try:
            if proto == "telnet" and attempts and self._telnet_pointless(attempts):
                attempts.append(_attempt(
                    proto, self.device_type, "skipped", "Skipped",
                    "telnet not tried: SSH was refused and this platform "
                    "refuses telnet for the same reason"))
                logger.info(f"Not trying telnet to {self.host}: SSH refused")
                continue
            if proto == "telnet" and attempts:
                fallback_occurred = True

            if not self._port_open(proto, attempts):
                continue

            for dt in self._types_to_try():
                if proto == "telnet":
                    effective_dt = telnet_type_for(dt)
                    if effective_dt is None:
                        attempts.append(_attempt(
                            proto, dt, failures.NO_TELNET_DRIVER, "Unsupported",
                            "telnet not supported for this platform"))
                        continue
                else:
                    effective_dt = dt

                params = self._build_device_params(effective_dt)
                params["device_type"] = effective_dt
                conn, reason = self._try_connect(proto, effective_dt, params,
                                                 attempts)
                if conn is None and reason == failures.LEGACY_CRYPTO \
                        and proto == "ssh":
                    _ensure_legacy_algorithms()
                    legacy = dict(params,
                                  disabled_algorithms=LEGACY_DISABLED_ALGORITHMS)
                    logger.info(f"Retrying {self.host} with legacy SSH algorithms")
                    conn, reason = self._try_connect(proto, effective_dt,
                                                     legacy, attempts)
                if conn is not None:
                    self.effective_device_type = effective_dt
                    return ConnectionResult(connection=conn, protocol_used=proto,
                                            fallback_occurred=fallback_occurred)
                if reason == failures.AUTH:
                    raise ConnectionError(
                        f"Authentication failed to {self.host}", "auth",
                        attempts, failures.AUTH)
                if reason in _NETWORK_LAYER:
                    # Another driver will hit the same closed port.
                    break

        summary = "; ".join(
            f"{a['protocol']}/{a['device_type']}: {a['message']}"
            for a in attempts)
        raise ConnectionError(
            f"Connection failed to {self.host}: {summary}", "connection",
            attempts, overall_reason(attempts))

    def _try_connect(self, proto, device_type, params, attempts):
        """One connection attempt. Returns (connection, None) or (None, reason)
        after appending the attempt record."""
        if self.login_limiter is not None:
            waited = self.login_limiter.acquire()
            if waited:
                self.login_wait_ms += int(waited * 1000)
        logger.info(f"Connecting to {self.host} ({device_type} via {proto})")
        started = time.monotonic()
        try:
            conn = _connect_handler(**params)
        except Exception as e:
            elapsed_ms = int((time.monotonic() - started) * 1000)
            reason = failures.classify_exception(e)
            message = _short_message(e)
            if params.get("disabled_algorithms"):
                message = f"legacy algorithms retry: {message}"
            attempts.append(_attempt(proto, device_type, reason,
                                     type(e).__name__, message, elapsed_ms))
            logger.warning(f"Failed {self.host} with {device_type} via "
                           f"{proto} ({reason}): {message}")
            return None, reason
        logger.info(f"Connected to {self.host} ({device_type} via {proto})")
        return conn, None

    def _port_open(self, proto, attempts):
        """TCP-probe the protocol's port. A timeout or refusal is recorded
        as that protocol's attempt, so netmiko is not run against it."""
        port = _PORTS.get(proto)
        if port is None:
            return True
        started = time.monotonic()
        result = _tcp_probe(self.host, port)
        if result is None:
            return True
        reason, exception_class, message = result
        record = _attempt(proto, self.device_type, reason, exception_class,
                          message, int((time.monotonic() - started) * 1000))
        record["note"] = PROBE_NOTE
        attempts.append(record)
        logger.warning(f"Not trying {proto} to {self.host} ({reason}): "
                       f"{message}")
        return False

    def _telnet_pointless(self, attempts) -> bool:
        """True when SSH was refused on a platform that refuses telnet too."""
        ssh_reasons = {a["reason"] for a in attempts if a["protocol"] == "ssh"}
        if ssh_reasons != {failures.REFUSED}:
            return False
        if self.device_type in _NO_TELNET_AFTER_REFUSAL_TYPES:
            return True
        return bool(_NO_TELNET_AFTER_REFUSAL_PLATFORM.search(self.platform))

    @staticmethod
    def get_hostname(connection) -> str:
        """Extract hostname from device prompt.

        PAN-OS reports admin@fw01(active), so a raw prompt is not a hostname.
        """
        try:
            from app.identity import parse_device_prompt
        except ImportError:
            from identity import parse_device_prompt

        prompt = connection.find_prompt()
        return parse_device_prompt(prompt)["hostname"] or prompt.rstrip("#>").strip()

    @staticmethod
    def get_prompt_facts(connection) -> dict:
        """Hostname plus anything else the prompt encodes, such as HA role."""
        try:
            from app.identity import parse_device_prompt
        except ImportError:
            from identity import parse_device_prompt

        return parse_device_prompt(connection.find_prompt())

    @staticmethod
    def run_commands(connection, commands: list[str],
                     read_timeout: int = 30, timings=None) -> dict[str, str]:
        """Run a list of commands and return dict of command -> raw output.

        A command whose send raised (timeout, prompt desync, dropped session)
        is logged and stored as a failure marker, so it is not mistaken for
        a command that printed nothing. When timings is a dict, each
        command's wall time in ms is put in it.
        """
        try:
            from app.collectors.errors import send_failure_output
        except ImportError:
            from collectors.errors import send_failure_output

        results = {}
        for cmd in commands:
            started = time.monotonic()
            try:
                output = connection.send_command(cmd, read_timeout=read_timeout)
                results[cmd] = output
            except Exception as e:
                logger.warning(f"Command failed '{cmd}': {e}")
                results[cmd] = send_failure_output(e)
            if timings is not None:
                timings[cmd] = int((time.monotonic() - started) * 1000)
        return results
