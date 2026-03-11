"""
Discovery Engine -- orchestrates collector-based network discovery.
Replaces the monolithic TopologyDiscoverer with modular collectors.
Supports parallel device discovery via ThreadPoolExecutor.
"""
import logging
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

try:
    from app.connection_manager import ConnectionManager, ConnectionError
    from app.collectors import get_registry, get_collector
    from app.inventory import DiscoveryInventory
except ImportError:
    from connection_manager import ConnectionManager, ConnectionError
    from collectors import get_registry, get_collector
    from inventory import DiscoveryInventory

logger = logging.getLogger(__name__)

# Thread-local storage for per-device log context
_log_context = threading.local()


class DeviceLogFilter(logging.Filter):
    """Injects [device_ip] into log records from discovery threads."""

    def filter(self, record):
        device_ip = getattr(_log_context, "device_ip", None)
        if device_ip:
            record.msg = f"[{device_ip}] {record.msg}"
        return True


# Default inventory directory inside the Docker container
DEFAULT_INVENTORY_DIR = "/app/inventories"


class DiscoveryError(Exception):
    def __init__(self, message: str, error_type: str = "generic"):
        super().__init__(message)
        self.message = message
        self.error_type = error_type


class DiscoveryEngine:
    """Orchestrates BFS discovery using ConnectionManager and Collectors."""

    def __init__(self, seed_ip: str, seed_device_type: str,
                 username: str, password: str,
                 max_depth: int = 3, protocol: str = "ssh",
                 filters: dict = None,
                 inventory_dir: str = None,
                 device_detector=None,
                 max_workers: int = 10,
                 target_hosts: list = None,
                 progress_callback=None,
                 cancelled=None):
        self.seed_ip = seed_ip
        self.seed_device_type = seed_device_type
        self.username = username
        self.password = password
        self.target_hosts = target_hosts
        self.max_depth = 0 if target_hosts else max_depth
        self.protocol = protocol
        self.filters = filters or {
            "include_routers": True,
            "include_switches": True,
            "include_phones": False,
            "include_servers": False,
            "include_aps": False,
            "include_other": False,
            "include_l3": True,
        }
        self.inventory_dir = inventory_dir or DEFAULT_INVENTORY_DIR
        self.visited: set[str] = set()
        self._visited_lock = threading.Lock()
        self._discovered_hostnames: set[str] = set()
        self._hostname_lock = threading.Lock()
        self.failed: dict[str, str] = {}
        self._failed_lock = threading.Lock()
        self.max_workers = max(1, max_workers)
        self._progress_cb = progress_callback or (lambda event: None)
        self._cancelled = cancelled

        # Always use all collectors
        registry = get_registry()
        self._collectors = dict(registry)

        # Device detector for neighbor type classification
        if device_detector is None:
            try:
                from app.device_detector import DeviceTypeDetector
            except ImportError:
                from device_detector import DeviceTypeDetector
            self._detector = DeviceTypeDetector()
        else:
            self._detector = device_detector

        # Install device-context filter on all root-logger handlers so
        # log lines from any module get the [device_ip] tag
        self._log_filter = DeviceLogFilter()
        for handler in logging.getLogger().handlers:
            handler.addFilter(self._log_filter)

        logger.info(
            f"DiscoveryEngine: seed={seed_ip}, depth={max_depth}, "
            f"workers={self.max_workers}, "
            f"collectors={list(self._collectors.keys())}"
        )

    def discover(self) -> DiscoveryInventory:
        """Run BFS discovery and return a populated DiscoveryInventory.

        Devices at each BFS depth layer are discovered in parallel using
        a thread pool. Neighbor queueing happens between layers.
        """
        inventory = DiscoveryInventory.create(
            seed_ip=self.seed_ip,
            params={
                "max_depth": self.max_depth,
                "connection_protocol": self.protocol,
                "collectors_enabled": list(self._collectors.keys()),
                "filters": self.filters,
            },
        )

        # Layer-based BFS: process all devices at a given depth in parallel,
        # then collect neighbors and advance to the next depth.
        if self.target_hosts:
            current_layer = list(self.target_hosts)
        else:
            current_layer = [(self.seed_ip, self.seed_device_type)]

        start_time = time.time()
        total_hosts = len(self.target_hosts) if self.target_hosts else None
        self._progress_cb({
            "event": "scan_started",
            "scan_type": "targeted" if self.target_hosts else "discovery",
            "total_hosts": total_hosts,
        })

        for depth in range(self.max_depth + 1):
            if not current_layer:
                break

            if self._cancelled and self._cancelled.is_set():
                break

            # Filter out already-visited IPs before submitting work
            work_items = []
            for ip, device_type in current_layer:
                with self._visited_lock:
                    if ip in self.visited:
                        continue
                    self.visited.add(ip)
                work_items.append((ip, device_type))

            if not work_items:
                break

            logger.info(
                f"Depth {depth}: discovering {len(work_items)} device(s) "
                f"with {min(self.max_workers, len(work_items))} worker(s)"
            )

            # Discover all devices at this depth in parallel
            next_layer = []
            with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
                futures = {}
                for ip, device_type in work_items:
                    if self._cancelled and self._cancelled.is_set():
                        break
                    self._progress_cb({"event": "device_connecting", "ip": ip, "device_type": device_type or "auto"})
                    futures[executor.submit(
                        self._discover_device, ip, device_type, depth, inventory
                    )] = (ip, device_type)

                for future in as_completed(futures):
                    ip, dtype = futures[future]
                    try:
                        neighbors = future.result()
                        next_layer.extend(neighbors)
                    except Exception as e:
                        logger.error(f"[{ip}] Unexpected error: {e}")
                        with self._failed_lock:
                            self.failed[ip] = str(e)
                        self._progress_cb({"event": "device_failed", "ip": ip, "error": str(e)})

            self._progress_cb({
                "event": "layer_complete",
                "depth": depth,
                "devices_in_layer": len(work_items),
                "total_discovered": len(self.visited),
            })

            current_layer = next_layer

        elapsed = time.time() - start_time

        logger.info(
            f"Discovery complete. {len(inventory.devices)} devices, "
            f"{len(self.failed)} failed"
        )

        # Persist scan summary metadata for the Reports tab stat bar
        inventory.set_scan_summary(
            elapsed=round(elapsed, 1),
            failed=dict(self.failed),
        )

        # Save inventory before emitting scan_complete so the file
        # exists when the frontend fetches /api/reports/available/<key>
        try:
            filepath = inventory.save(self.inventory_dir)
            logger.info(f"Saved inventory: {filepath}")
        except Exception as e:
            logger.warning(f"Failed to save inventory: {e}")

        if self._cancelled and self._cancelled.is_set():
            self._progress_cb({
                "event": "scan_cancelled",
                "total_devices": len(self.visited),
                "failed_count": len(self.failed),
                "elapsed": round(elapsed, 1),
            })
        else:
            self._progress_cb({
                "event": "scan_complete",
                "total_devices": len(self.visited),
                "failed_count": len(self.failed),
                "elapsed": round(elapsed, 1),
                "inventory_key": inventory.discovery_id,
            })

        # Remove the device-context filter now that discovery is done
        for handler in logging.getLogger().handlers:
            handler.removeFilter(self._log_filter)

        return inventory

    def _discover_device(self, ip: str, device_type: str, depth: int,
                         inventory: DiscoveryInventory) -> list[tuple[str, str]]:
        """Discover a single device: connect, collect, parse, return neighbors.

        Returns a list of (ip, device_type) tuples for the next BFS layer.
        Runs in a thread pool worker.
        """
        _log_context.device_ip = ip
        logger.info(f"Discovering device at depth {depth}")

        try:
            # Seed host uses user-selected protocol; discovered neighbors use auto
            is_seed = (ip == self.seed_ip and depth == 0)
            proto = self.protocol if is_seed else "auto"
            conn_mgr = ConnectionManager(
                host=ip, device_type=device_type,
                username=self.username, password=self.password,
                protocol=proto,
            )
            result = conn_mgr.connect()
            conn = result.connection
            if result.fallback_occurred:
                self._progress_cb({
                    "event": "connection_fallback",
                    "ip": ip,
                    "from_protocol": "ssh",
                    "to_protocol": result.protocol_used,
                })
            self._progress_cb({
                "event": "device_authenticated",
                "ip": ip,
                "protocol": result.protocol_used,
            })
            hostname = ConnectionManager.get_hostname(conn)
            logger.info(f"Connected as {hostname}")

            # Hostname-based dedup: a device may be reachable via multiple IPs
            with self._hostname_lock:
                if hostname in self._discovered_hostnames:
                    logger.info(
                        f"Skipping {ip}: already discovered as {hostname}"
                    )
                    self._progress_cb({
                        "event": "device_complete",
                        "ip": ip,
                        "hostname": hostname,
                        "device_type": device_type or "auto",
                        "skipped": True,
                        "reason": "duplicate hostname",
                    })
                    conn.disconnect()
                    return []
                self._discovered_hostnames.add(hostname)

            # Handle IP-placeholder rename
            self._rename_placeholder(inventory, ip, hostname)

            # Add device to inventory
            inventory.add_device(
                hostname, mgmt_ip=ip, device_type=device_type,
            )

            self._progress_cb({
                "event": "collecting_data",
                "ip": ip,
                "hostname": hostname,
            })

            # Split collectors into batch (standard) and custom (need connection)
            batch_collectors = {}
            custom_collectors = {}
            for cname, collector in self._collectors.items():
                if collector.needs_custom_collect:
                    custom_collectors[cname] = collector
                else:
                    batch_collectors[cname] = collector

            # Gather commands for batch collectors
            all_commands = []
            collector_commands = {}
            for cname, collector in batch_collectors.items():
                cmds = collector.get_commands(device_type)
                collector_commands[cname] = cmds
                all_commands.extend(cmds)

            # Deduplicate commands while preserving order
            seen_cmds = set()
            unique_commands = []
            for cmd in all_commands:
                if cmd not in seen_cmds:
                    seen_cmds.add(cmd)
                    unique_commands.append(cmd)

            # Run all batch commands in single session
            raw_outputs = ConnectionManager.run_commands(
                conn, unique_commands,
            )

            # Parse batch collectors
            for cname, collector in batch_collectors.items():
                cmds = collector_commands[cname]
                collector_raw = {cmd: raw_outputs.get(cmd, "") for cmd in cmds}
                try:
                    parsed = collector.parse(collector_raw, device_type)
                except Exception as e:
                    logger.warning(f"Collector {cname} parse failed on {hostname}: {e}")
                    parsed = {}
                inventory.set_collector_data(hostname, cname,
                                             raw=collector_raw, parsed=parsed)

            # Run custom collectors (dynamic commands, post-processing)
            for cname, collector in custom_collectors.items():
                try:
                    result = collector.collect(conn, device_type)
                    inventory.set_collector_data(
                        hostname, cname,
                        raw=result["raw"], parsed=result["parsed"],
                    )
                except Exception as e:
                    logger.warning(f"Collector {cname} collect failed on {hostname}: {e}")
                    inventory.set_collector_data(hostname, cname, raw={}, parsed={})

            conn.disconnect()

            # Extract neighbors for next BFS layer
            neighbors = self._extract_neighbors(inventory, hostname, ip,
                                                device_type, depth)

            device_data = inventory.devices.get(hostname, {})
            cdp_data = device_data.get("collector_data", {}).get("cdp_lldp", {})
            all_neighbor_ips = [
                n.get("remote_ip") for n in cdp_data.get("parsed", {}).get("neighbors", [])
                if n.get("remote_ip")
            ]
            total_cdp_neighbors = len(all_neighbor_ips)
            with self._visited_lock:
                new_count = sum(1 for nip in all_neighbor_ips if nip not in self.visited)

            self._progress_cb({
                "event": "neighbors_found",
                "ip": ip,
                "hostname": hostname,
                "total": total_cdp_neighbors,
                "new": new_count,
            })

            self._progress_cb({
                "event": "device_complete",
                "ip": ip,
                "hostname": hostname,
                "device_type": device_type or "auto",
            })

            return neighbors

        except ConnectionError as e:
            logger.error(f"Connection error: {e.message}")
            with self._failed_lock:
                self.failed[ip] = e.message
            self._progress_cb({"event": "device_failed", "ip": ip, "error": e.message})
            return []
        except Exception as e:
            logger.error(f"Unexpected error: {e}")
            with self._failed_lock:
                self.failed[ip] = str(e)
            self._progress_cb({"event": "device_failed", "ip": ip, "error": str(e)})
            return []
        finally:
            _log_context.device_ip = None

    def _extract_neighbors(self, inventory: DiscoveryInventory,
                           hostname: str, ip: str, device_type: str,
                           depth: int) -> list[tuple[str, str]]:
        """Extract neighbors from cdp_lldp collector data.

        Returns list of (ip, device_type) for next BFS layer.
        """
        device = inventory.devices.get(hostname, {})
        cdp_lldp_data = device.get("collector_data", {}).get("cdp_lldp", {})
        parsed = cdp_lldp_data.get("parsed", {})
        neighbors = parsed.get("neighbors", [])

        next_layer = []

        for neighbor in neighbors:
            neighbor_info = self._detect_neighbor_type(neighbor)
            if not neighbor_info:
                logger.info(
                    f"Skipping {neighbor.get('remote_device', 'Unknown')}: "
                    f"no device type detected"
                )
                continue

            neighbor_device_type, neighbor_category, neighbor_has_routing = neighbor_info

            if not self._should_include(neighbor_category):
                logger.info(
                    f"Skipping {neighbor.get('remote_device', 'Unknown')}: "
                    f"{neighbor_category} filtered out "
                    f"(caps={neighbor.get('remote_capabilities', '')}, "
                    f"platform={neighbor.get('remote_platform', '')})"
                )
                continue

            # Add neighbor as placeholder in inventory
            remote_name = (
                neighbor.get("remote_device")
                or self._find_hostname_by_ip(inventory, neighbor.get("remote_ip"))
                or neighbor.get("remote_ip")
                or "Unknown"
            )

            inventory.add_device(
                remote_name,
                mgmt_ip=neighbor.get("remote_ip"),
                device_type=neighbor_device_type,
                device_category=neighbor_category,
                platform=neighbor.get("remote_platform"),
            )

            # Queue for next layer
            remote_ip = neighbor.get("remote_ip")
            if remote_ip:
                with self._visited_lock:
                    already_visited = remote_ip in self.visited
                if not already_visited:
                    capabilities = neighbor.get("remote_capabilities", "")
                    if self._detector._should_crawl(capabilities, self.filters):
                        next_layer.append((remote_ip, neighbor_device_type))
                        logger.info(
                            f"Queued {remote_name} ({remote_ip}) at depth {depth + 1}"
                        )

        return next_layer

    def _rename_placeholder(self, inventory: DiscoveryInventory,
                            ip: str, hostname: str):
        """If a device was added as an IP placeholder, rename it."""
        with inventory._lock:
            for existing_name, dev in list(inventory.devices.items()):
                if dev.get("mgmt_ip") == ip and existing_name != hostname:
                    inventory.devices[hostname] = inventory.devices.pop(existing_name)
                    inventory.devices[hostname]["hostname"] = hostname
                    logger.info(f"Renamed placeholder '{existing_name}' -> '{hostname}'")
                    break

    def _detect_neighbor_type(self, neighbor: dict):
        """Detect device type, category, and routing capability for a neighbor."""
        platform = neighbor.get("remote_platform") or ""
        capabilities = neighbor.get("remote_capabilities") or ""
        system_desc = neighbor.get("system_description") or ""

        caps = set()
        if capabilities:
            cap_str = capabilities.replace(",", " ").upper()
            caps = set(cap_str.split())

        device_category, has_routing = (
            self._detector._categorize_device(caps, platform, system_desc)
            if (caps or platform or system_desc)
            else ("unknown", False)
        )

        if platform:
            dt = self._detector.detect_from_cdp(platform, capabilities, self.filters)
            if dt:
                return (dt, device_category, has_routing)

        if system_desc:
            dt = self._detector.detect_from_lldp(system_desc, capabilities, self.filters)
            if dt:
                return (dt, device_category, has_routing)

        if device_category and device_category != "unknown":
            return (self._detector.default_type, device_category, has_routing)

        return None

    def _should_include(self, category: str) -> bool:
        """Check if a device category passes the current filters."""
        category_filter_map = {
            "router": "include_routers",
            "firewall": "include_routers",
            "switch": "include_switches",
            "phone": "include_phones",
            "server": "include_servers",
            "access_point": "include_aps",
        }
        filter_key = category_filter_map.get(category, "include_other")
        return self.filters.get(filter_key, False)

    def _find_hostname_by_ip(self, inventory: DiscoveryInventory,
                             ip: str):
        """Find a hostname in the inventory by management IP."""
        if not ip:
            return None
        with inventory._lock:
            for name, dev in inventory.devices.items():
                if dev.get("mgmt_ip") == ip:
                    return name
        return None
