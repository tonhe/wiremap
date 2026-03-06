"""
Connection Manager -- SSH and Telnet connections to network devices.
Dumb pipe: connects, runs commands, returns raw output. No parsing.
"""
import logging

logger = logging.getLogger(__name__)

_TELNET_SUFFIX = "_telnet"


class ConnectionError(Exception):
    """Raised when connection fails."""
    def __init__(self, message: str, error_type: str = "connection"):
        super().__init__(message)
        self.message = message
        self.error_type = error_type


class ConnectionManager:
    """Manages SSH/Telnet connections to network devices."""

    def __init__(self, host: str, device_type: str, username: str,
                 password: str, protocol: str = "ssh"):
        self.host = host
        self.device_type = device_type
        self.username = username
        self.password = password
        self.protocol = protocol  # "ssh", "telnet", "auto"

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
            logger.info(f"Using MOCK mode for {self.host}")
            return get_mock_connection(self.host, self.device_type,
                                       self.username, self.password)

        # Lazy import -- netmiko is only available inside Docker
        from netmiko import ConnectHandler, NetmikoTimeoutException, NetmikoAuthenticationException

        protocols_to_try = ["ssh", "telnet"] if self.protocol == "auto" else [self.protocol]
        last_error = None

        for proto in protocols_to_try:
            types_to_try = [self.device_type] + self._get_fallback_types(self.device_type)

            for dt in types_to_try:
                try:
                    if proto == "telnet" and not dt.endswith(_TELNET_SUFFIX):
                        effective_dt = dt + _TELNET_SUFFIX
                    else:
                        effective_dt = dt
                    params = {
                        "device_type": effective_dt,
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
                    logger.info(f"Connecting to {self.host} ({effective_dt} via {proto})")
                    conn = ConnectHandler(**params)
                    logger.info(f"Connected to {self.host} ({effective_dt} via {proto})")
                    return conn
                except NetmikoTimeoutException:
                    if proto == "ssh" and "telnet" in protocols_to_try:
                        logger.info(f"SSH timeout to {self.host}, will try telnet")
                        break  # skip fallback types, try telnet
                    raise ConnectionError(f"Connection timeout to {self.host}", "timeout")
                except NetmikoAuthenticationException:
                    raise ConnectionError(f"Authentication failed to {self.host}", "auth")
                except Exception as e:
                    last_error = f"{type(e).__name__}: {e}"
                    logger.warning(f"Failed {self.host} with {dt} via {proto}: {last_error}")
                    continue

        raise ConnectionError(
            f"Connection failed to {self.host} (tried {protocols_to_try}): {last_error}",
            "connection"
        )

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
