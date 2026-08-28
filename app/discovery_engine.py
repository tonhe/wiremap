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
    from app.identity import normalize_hostname, looks_like_mac, looks_like_host_nic
    from app.device_facts import extract_device_facts
    from app.neighbors import extract_all, default_enabled, CrawlScope
    from app.snmp_probe import probe as snmp_probe, make_walker as snmp_make_walker
    from app.snmp_tables import collect_all as snmp_collect_all
except ImportError:
    from connection_manager import ConnectionManager, ConnectionError
    from collectors import get_registry, get_collector
    from inventory import DiscoveryInventory
    from identity import normalize_hostname, looks_like_mac, looks_like_host_nic
    from device_facts import extract_device_facts
    from neighbors import extract_all, default_enabled, CrawlScope
    from snmp_probe import probe as snmp_probe, make_walker as snmp_make_walker
    from snmp_tables import collect_all as snmp_collect_all

logger = logging.getLogger(__name__)

# Thread-local storage for per-device log context
_log_context = threading.local()


def _neighbour_platform_fields(remote_platform):
    """Split a neighbour's reported platform into (platform, chassis_id).

    LLDP often reports a chassis MAC where a platform string belongs. A MAC
    is not a platform -- record it separately and leave platform empty rather
    than writing 009a.d2d4.9700 into a Platform column.
    """
    if not remote_platform:
        return None, None
    if looks_like_mac(remote_platform):
        return None, str(remote_platform).strip()
    return remote_platform, None


def _should_create_neighbour_device(neighbor) -> bool:
    """A device row requires a real name, not just an address.

    vPC peer-keepalive addresses (1.1.1.1, 1.1.1.2) repeat across every pair
    in a fabric. Creating a device per address invents phantom chassis with
    no serial and a keepalive address as their management IP.
    """
    name = (neighbor.get("remote_device") or "").strip()
    return bool(name)


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
                 cancelled=None,
                 disable_autodetect: bool = False,
                 crawl_from_targets: bool = False,
                 neighbor_sources=None,
                 crawl_scope=None,
                 snmp_credentials=None,
                 base_inventory=None):
        self.seed_ip = seed_ip
        self.seed_device_type = seed_device_type
        self.username = username
        self.password = password
        self.target_hosts = target_hosts
        self.disable_autodetect = disable_autodetect
        self.crawl_from_targets = crawl_from_targets
        self.neighbor_sources = (set(neighbor_sources)
                                 if neighbor_sources is not None
                                 else default_enabled())
        # Without a scope, next-hop crawling walks out into ISP space.
        self.crawl_scope = crawl_scope or CrawlScope()
        # Used only after SSH and telnet have both failed.
        self.snmp_credentials = snmp_credentials
        # When set, this run adds to an existing scan rather than starting
        # empty. Devices already collected are not re-visited; devices that
        # failed last time are, since a retry is usually the point.
        self.base_inventory = base_inventory
        # A targeted scan visits exactly its host list unless the operator
        # asks it to keep going from each target. Already-visited IPs are
        # filtered per layer, so targets are never reprocessed.
        if target_hosts and not crawl_from_targets:
            self.max_depth = 0
        else:
            self.max_depth = max_depth
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
        # Hosts the operator asked for by name. These are never skipped as
        # duplicates, so re-listing a device refreshes it.
        self._requested_ips: set[str] = set()
        # Addresses seen but deliberately not crawled -- reported so a silent
        # boundary never reads as "nothing was there".
        self._out_of_scope: set[str] = set()
        self._ceiling_hit = False
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

    def _prime_from_base(self, inventory: DiscoveryInventory):
        """Seed dedup state so a continuation behaves like a resumed scan.

        Devices already logged into are treated as visited. Explicitly
        requested hosts are exempt -- asking for a host is a request to scan
        it, which is how a refresh of one device works.
        """
        requested = {ip for ip, _ in (self.target_hosts or [])}
        if not self.target_hosts:
            requested.add(self.seed_ip)

        collected_ips = inventory.collected_ips() - requested
        self.visited |= collected_ips
        self._discovered_hostnames |= inventory.collected_hostnames()
        self._requested_ips = requested
        self.failed.update(inventory.prior_failures())

        logger.info(
            f"Continuing from {inventory.to_dict().get('continued_from')}: "
            f"{len(inventory.devices)} known device(s), "
            f"{len(collected_ips)} already collected, "
            f"{len(self.failed)} prior failure(s) to retry"
        )

    def discover(self) -> DiscoveryInventory:
        """Run BFS discovery and return a populated DiscoveryInventory.

        Devices at each BFS depth layer are discovered in parallel using
        a thread pool. Neighbor queueing happens between layers.
        """
        params = {
            "max_depth": self.max_depth,
            "connection_protocol": self.protocol,
            "collectors_enabled": list(self._collectors.keys()),
            "filters": self.filters,
        }

        if self.base_inventory is not None:
            params["continued_from"] = self.base_inventory.discovery_id
            inventory = DiscoveryInventory.continue_from(
                self.base_inventory, seed_ip=self.seed_ip, params=params)
            self._prime_from_base(inventory)
        else:
            inventory = DiscoveryInventory.create(
                seed_ip=self.seed_ip, params=params)

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

        # Fold records that turned out to be the same chassis under different
        # names before anything downstream counts devices.
        folded = inventory.merge_duplicates()
        if folded:
            logger.info(f"Merged {folded} duplicate device record(s)")

        logger.info(
            f"Discovery complete. {len(inventory.devices)} devices, "
            f"{len(self.failed)} failed"
        )

        # Persist scan summary metadata for the Reports tab stat bar
        inventory.set_scan_summary(
            elapsed=round(elapsed, 1),
            failed=dict(self.failed),
            out_of_scope=set(self._out_of_scope),
            ceiling_hit=self._ceiling_hit,
        )
        if self._out_of_scope:
            logger.info(
                f"{len(self._out_of_scope)} address(es) seen but not crawled "
                f"(outside scope)"
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
            # A device type supplied by the operator (host list or seed) is
            # authoritative -- trying other platforms contradicts the request.
            explicit_type = bool(device_type)
            conn_mgr = ConnectionManager(
                host=ip, device_type=device_type,
                username=self.username, password=self.password,
                protocol=proto,
                allow_fallback=not (explicit_type or self.disable_autodetect),
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
                "device_type_effective": conn_mgr.effective_device_type,
            })
            prompt_facts = ConnectionManager.get_prompt_facts(conn)
            hostname = prompt_facts["hostname"]
            ha_state = prompt_facts["ha_state"]
            if ha_state:
                logger.info(f"Connected as {hostname} (HA {ha_state})")
            else:
                logger.info(f"Connected as {hostname}")

            # Hostname-based dedup: a device may be reachable via multiple IPs.
            # Normalized, so SW1 and SW1(FOC1234) are recognised as one chassis.
            norm_hostname = normalize_hostname(hostname)
            explicitly_requested = ip in self._requested_ips
            with self._hostname_lock:
                if norm_hostname in self._discovered_hostnames and not explicitly_requested:
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
                self._discovered_hostnames.add(norm_hostname)

            # Handle IP-placeholder rename
            self._rename_placeholder(inventory, ip, hostname)

            # Add device to inventory. A record that already exists from a
            # neighbour sighting is promoted rather than replaced, so how the
            # device was first seen survives alongside the collected data.
            inventory.add_device(
                hostname, mgmt_ip=ip, device_type=device_type,
                discovery_source="login",
            )
            inventory.mark_login_succeeded(hostname)
            # A device that failed in the scan being continued and works now
            # must stop being reported as a failure.
            with self._failed_lock:
                self.failed.pop(ip, None)
            if ha_state:
                inventory.set_ha_state(hostname, ha_state)

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

            # Record collected hardware facts. These only ever come from a
            # real login, which is what makes them a reliable signal that a
            # device was actually reached.
            inv_parsed = (inventory.devices.get(hostname, {})
                          .get("collector_data", {})
                          .get("device_inventory", {})
                          .get("parsed", {}))
            facts = extract_device_facts(inv_parsed)
            inventory.mark_login_succeeded(
                hostname,
                serial=facts["serial"] or None,
                model=facts["model"] or None,
                software_version=facts["software_version"] or None,
            )

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
            # A device seen as a neighbour keeps its record but records why
            # the login attempt against it failed.
            inventory.mark_login_failed_by_ip(ip, e.message)
            # SSH and telnet are gone; SNMP may still say what this thing is.
            if self._snmp_fallback(inventory, ip, e.message):
                return []
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

    def _snmp_fallback(self, inventory: DiscoveryInventory, ip: str,
                       login_error: str) -> bool:
        """Try SNMP after a failed login. Returns True if the device answered.

        The record is still login_succeeded=False -- SNMP identifies a device,
        it does not collect one.
        """
        if not self.snmp_credentials or not self.snmp_credentials.is_configured():
            return False

        record = snmp_probe(ip, self.snmp_credentials)
        if not record:
            return False

        hostname = record["hostname"]
        logger.info(f"SNMP identified {ip} as {hostname} "
                    f"({record.get('device_type') or 'unknown platform'})")

        inventory.add_device(
            hostname,
            mgmt_ip=ip,
            device_type=record.get("device_type"),
            discovery_source="snmp",
        )
        inventory.mark_login_failed(hostname, login_error)
        inventory.set_snmp_facts(hostname, record)

        # Standard MIBs give interfaces, addressing, routes and neighbours on
        # devices that will never accept a CLI session. Shaped like the CLI
        # collectors, so the reports need no special case.
        collected = {}
        try:
            walker = snmp_make_walker(ip, self.snmp_credentials)
            collected = snmp_collect_all(walker)
        except Exception as e:
            logger.debug(f"SNMP table collection failed for {ip}: "
                         f"{type(e).__name__}: {e}")

        for collector_name, parsed in collected.items():
            inventory.set_collector_data(hostname, collector_name,
                                         raw={"source": "snmp"}, parsed=parsed)
        if collected:
            logger.info(f"SNMP collected {sorted(collected)} from {hostname}")
        self._progress_cb({
            "event": "device_snmp_identified",
            "ip": ip,
            "hostname": hostname,
            "device_type": record.get("device_type"),
        })
        return True

    def _extract_neighbors(self, inventory: DiscoveryInventory,
                           hostname: str, ip: str, device_type: str,
                           depth: int) -> list[tuple[str, str]]:
        """Extract neighbors from every enabled neighbour source.

        Returns list of (ip, device_type) for next BFS layer.
        """
        device = inventory.devices.get(hostname, {})
        neighbors = extract_all(device, enabled=self.neighbor_sources)

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

            # A server NIC advertises its product description over LLDP, so it
            # arrives looking like a device with no management address and
            # nothing to log into. Categorise it so it stops being counted as
            # network hardware.
            if looks_like_host_nic(neighbor.get("remote_device"),
                                   neighbor.get("remote_platform"),
                                   neighbor.get("system_description")):
                neighbor_category = "host_nic"

            if not self._should_include(neighbor_category):
                logger.info(
                    f"Skipping {neighbor.get('remote_device', 'Unknown')}: "
                    f"{neighbor_category} filtered out "
                    f"(caps={neighbor.get('remote_capabilities', '')}, "
                    f"platform={neighbor.get('remote_platform', '')})"
                )
                continue

            # Add neighbor as placeholder in inventory. A bare address is not
            # a chassis -- it becomes evidence on the device that saw it, and
            # is still queued below for a login attempt that can name it.
            platform, chassis_id = _neighbour_platform_fields(
                neighbor.get("remote_platform"))
            source = neighbor.get("source", "cdp_lldp")

            remote_name = (neighbor.get("remote_device") or "").strip() \
                or neighbor.get("remote_ip") or "unnamed"

            if _should_create_neighbour_device(neighbor):
                inventory.add_device(
                    remote_name,
                    mgmt_ip=neighbor.get("remote_ip"),
                    device_type=neighbor_device_type,
                    device_category=neighbor_category,
                    platform=platform,
                    discovery_source=source,
                )
                if chassis_id:
                    inventory.set_chassis_id(remote_name, chassis_id)
                inventory.add_evidence(
                    remote_name, source=source, seen_from=hostname,
                    remote_port=neighbor.get("remote_port"),
                )
            else:
                existing = self._find_hostname_by_ip(
                    inventory, neighbor.get("remote_ip"))
                if existing:
                    inventory.add_evidence(
                        existing, source=source, seen_from=hostname,
                        remote_port=neighbor.get("remote_port"),
                    )
                else:
                    inventory.add_unresolved_neighbour(hostname, neighbor)

            # Queue for next layer
            remote_ip = neighbor.get("remote_ip")
            if remote_ip:
                with self._visited_lock:
                    already_visited = remote_ip in self.visited
                    visited_count = len(self.visited)
                if already_visited:
                    continue
                if not self.crawl_scope.allows(remote_ip):
                    logger.info(
                        f"Out of scope, not crawling {remote_name} ({remote_ip}) "
                        f"seen via {neighbor.get('source', 'cdp_lldp')}"
                    )
                    self._out_of_scope.add(remote_ip)
                    continue
                if not self.crawl_scope.under_ceiling(visited_count):
                    logger.warning(
                        f"Device ceiling {self.crawl_scope.max_devices} reached; "
                        f"not queueing {remote_ip}"
                    )
                    self._ceiling_hit = True
                    continue
                capabilities = neighbor.get("remote_capabilities", "")
                if self._detector._should_crawl(capabilities, self.filters):
                    next_layer.append((remote_ip, neighbor_device_type))
                    logger.info(
                        f"Queued {remote_name} ({remote_ip}) at depth {depth + 1} "
                        f"via {neighbor.get('source', 'cdp_lldp')}"
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
            # Server NICs are endpoints, not network devices. Off unless the
            # operator explicitly asks for other devices.
            "host_nic": "include_other",
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
