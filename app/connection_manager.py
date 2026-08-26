"""
Connection Manager -- SSH and Telnet connections to network devices.
Dumb pipe: connects, runs commands, returns raw output. No parsing.
"""
import logging
from collections import namedtuple

logger = logging.getLogger(__name__)

_TELNET_SUFFIX = "_telnet"


def telnet_type_for(device_type: str):
    """Return the netmiko telnet platform for device_type, or None.

    Netmiko has no telnet driver for many platforms -- cisco_nxos and
    cisco_xe among them. Appending _telnet blindly raises ValueError
    carrying a 40-line dump of every supported platform, which then
    buries the genuine SSH failure.
    """
    from netmiko.ssh_dispatcher import CLASS_MAPPER

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

    attempts holds every (protocol, device_type, error) tried, so the
    genuine SSH failure survives alongside later fallback failures.
    """
    def __init__(self, message: str, error_type: str = "connection",
                 attempts=None):
        super().__init__(message)
        self.message = message
        self.error_type = error_type
        self.attempts = attempts or []


class ConnectionManager:
    """Manages SSH/Telnet connections to network devices."""

    def __init__(self, host: str, device_type: str, username: str,
                 password: str, protocol: str = "ssh",
                 allow_fallback: bool = True):
        self.host = host
        self.device_type = device_type
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

        # Lazy import -- netmiko is only available inside Docker
        from netmiko import NetmikoTimeoutException, NetmikoAuthenticationException

        protocols_to_try = ["ssh", "telnet"] if self.protocol == "auto" else [self.protocol]
        attempts = []
        fallback_occurred = False

        for proto in protocols_to_try:
            for dt in self._types_to_try():
                if proto == "telnet":
                    effective_dt = telnet_type_for(dt)
                    if effective_dt is None:
                        attempts.append(
                            (proto, dt, "telnet not supported for this platform"))
                        continue
                else:
                    effective_dt = dt

                params = self._build_device_params(effective_dt)
                params["device_type"] = effective_dt
                try:
                    logger.info(f"Connecting to {self.host} ({effective_dt} via {proto})")
                    conn = _connect_handler(**params)
                    logger.info(f"Connected to {self.host} ({effective_dt} via {proto})")
                    self.effective_device_type = effective_dt
                    return ConnectionResult(connection=conn, protocol_used=proto,
                                            fallback_occurred=fallback_occurred)
                except NetmikoAuthenticationException as e:
                    attempts.append((proto, effective_dt, f"authentication failed: {e}"))
                    raise ConnectionError(
                        f"Authentication failed to {self.host}", "auth", attempts)
                except NetmikoTimeoutException as e:
                    attempts.append((proto, effective_dt, f"timeout: {e}"))
                    logger.warning(f"Timeout {self.host} with {effective_dt} via {proto}")
                    if proto == "ssh" and "telnet" in protocols_to_try:
                        fallback_occurred = True
                        break  # skip remaining ssh types, try telnet
                except Exception as e:
                    detail = f"{type(e).__name__}: {e}"
                    attempts.append((proto, effective_dt, detail))
                    logger.warning(f"Failed {self.host} with {effective_dt} via {proto}: {detail}")

        summary = "; ".join(f"{p}/{d}: {e}" for p, d, e in attempts)
        raise ConnectionError(
            f"Connection failed to {self.host}: {summary}", "connection", attempts)

    @staticmethod
    def get_hostname(connection) -> str:
        """Extract hostname from device prompt."""
        prompt = connection.find_prompt()
        return prompt.rstrip("#>").strip()

    @staticmethod
    def run_commands(connection, commands: list[str],
                     read_timeout: int = 30) -> dict[str, str]:
        """Run a list of commands and return dict of command -> raw output.

        Commands that fail are logged and stored with empty string output.
        """
        results = {}
        for cmd in commands:
            try:
                output = connection.send_command(cmd, read_timeout=read_timeout)
                results[cmd] = output
            except Exception as e:
                logger.warning(f"Command failed '{cmd}': {e}")
                results[cmd] = ""
        return results
