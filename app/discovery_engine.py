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
    from app.device_role import is_switchless_router
    from app.neighbors import extract_all, default_enabled, CrawlScope
    from app.snmp_probe import probe as snmp_probe, make_walker as snmp_make_walker
    from app.snmp_tables import collect_all as snmp_collect_all
    from app.failures import failure_record, reason_counts, hint_for, OTHER, SKIP_HINTS
    from app.login_rate import LoginRateLimiter
    from app.source_access import local_source_ip, check_source_access, refused_hint
    from app.scan_timing import collector_ms, summarize as summarize_timing
except ImportError:
    from connection_manager import ConnectionManager, ConnectionError
    from collectors import get_registry, get_collector
    from inventory import DiscoveryInventory
    from identity import normalize_hostname, looks_like_mac, looks_like_host_nic
    from device_facts import extract_device_facts
    from device_role import is_switchless_router
    from neighbors import extract_all, default_enabled, CrawlScope
    from snmp_probe import probe as snmp_probe, make_walker as snmp_make_walker
    from snmp_tables import collect_all as snmp_collect_all
    from failures import failure_record, reason_counts, hint_for, OTHER, SKIP_HINTS
    from login_rate import LoginRateLimiter
    from source_access import local_source_ip, check_source_access, refused_hint
    from scan_timing import collector_ms, summarize as summarize_timing

logger = logging.getLogger(__name__)

# Thread-local storage for per-device log context
_log_context = threading.local()


def _neighbour_platform_fields(remote_platform, chassis_id=None):
    """Split a neighbour's reported platform into (platform, chassis_id).

    LLDP often reports a chassis MAC where a platform string belongs. A MAC
    is not a platform -- record it separately and leave platform empty rather
    than writing 009a.d2d4.9700 into a Platform column. The LLDP parser now
    reports the chassis id on its own; only a MAC is kept from it.
    """
    mac = str(chassis_id).strip() if looks_like_mac(chassis_id) else None
    if not remote_platform:
        return None, mac
    if looks_like_mac(remote_platform):
        return None, str(remote_platform).strip()
    return remote_platform, mac


def _neighbour_remote_port(neighbor):
    # Parsers name the far-end port remote_intf; remote_port is the older
    # spelling still accepted from hand-built records.
    return neighbor.get("remote_intf") or neighbor.get("remote_port")


def _dedupe(commands):
    seen = set()
    unique = []
    for cmd in commands:
        if cmd not in seen:
            seen.add(cmd)
            unique.append(cmd)
    return unique


def _should_create_neighbour_device(neighbor) -> bool:
    """A device row requires a real name, not just an address.

    vPC peer-keepalive addresses (1.1.1.1, 1.1.1.2) repeat across every pair
    in a fabric. Creating a device per address invents phantom chassis with
    no serial and a keepalive address as their management IP.
    """
    name = (neighbor.get("remote_device") or "").strip()
    return bool(name)


def _ms_since(started):
    return int((time.monotonic() - started) * 1000)


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
                 base_inventory=None,
                 target_resolution=None,
                 collect_controller_managed: bool = False,
                 max_logins_per_minute: int = 0):
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
        # How a targeted host list was resolved: names that resolved (kept
        # as each target's expected name) and names that did not, so the
        # scan summary says which inventory entries were never attempted.
        self.target_resolution = target_resolution
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
        # Hostnames logged into during this run. Unlike names inherited from
        # a continued scan, these are never re-collected, even when two
        # requested targets turn out to be the same device.
        self._run_hostnames: set[str] = set()
        self._hostname_lock = threading.Lock()
        # IP -> failure record (app.failures.failure_record shape). Prior
        # failures inherited from a continued scan may still be strings.
        self.failed: dict = {}
        self._failed_lock = threading.Lock()
        # ACI fabric nodes and UCS Fabric Interconnects take their CLI
        # accounts from the controller; logging in with the network
        # credential fails auth every run. Skipped unless asked for.
        self.collect_controller_managed = collect_controller_managed
        self.skipped: dict = {}
        # Hosts the operator asked for by name. These are never skipped as
        # duplicates, so re-listing a device refreshes it.
        self._requested_ips: set[str] = set()
        # Addresses seen but deliberately not crawled -- reported so a silent
        # boundary never reads as "nothing was there".
        self._out_of_scope: set[str] = set()
        self._ceiling_hit = False
        self.max_workers = max(1, max_workers)
        # One limiter for every worker: the AAA server counts logins from
        # this host, not per thread.
        self._login_limiter = LoginRateLimiter(max_logins_per_minute)
        # hostname -> per-device timing record (see app.scan_timing).
        self.timing: dict = {}
        self._timing_lock = threading.Lock()
        # Local address used to reach the seed, and any management ACL on
        # the seed that does not permit it.
        self.source_ip = None
        self.source_access_warnings: list = []
        self._source_checked = False
        self._refused_hint = None
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
            # Lets the inventory report tell a host-list target from a seed.
            "target_ips": [ip for ip, _ in (self.target_hosts or [])],
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
        self.source_ip = local_source_ip(current_layer[0][0])
        if self.source_ip:
            logger.info(f"Source address towards the seed: {self.source_ip}")
        self._progress_cb({
            "event": "scan_started",
            "scan_type": "targeted" if self.target_hosts else "discovery",
            "total_hosts": total_hosts,
            "source_ip": self.source_ip,
            "max_logins_per_minute": self._login_limiter.per_minute,
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
                        self._record_failure(inventory, ip,
                                             self._unexpected_record(e))

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

        # Persist scan summary metadata for the Reports tab stat bar.
        # Prior failures from a continued scan may be bare strings; normalise
        # so every saved record has the same shape.
        with self._failed_lock:
            for ip in self.skipped:
                self.failed.pop(ip, None)
            failed = {
                ip: failure_record(value,
                                   hostname=self._find_hostname_by_ip(inventory, ip))
                for ip, value in self.failed.items()
            }
        inventory.set_scan_summary(
            elapsed=round(elapsed, 1),
            failed=failed,
            out_of_scope=set(self._out_of_scope),
            ceiling_hit=self._ceiling_hit,
            skipped=dict(self.skipped),
        )
        with self._timing_lock:
            timing = dict(self.timing)
        slowest = summarize_timing(timing)
        hint = refused_hint(failed, self.source_ip)
        inventory.update_scan_summary(
            source_ip=self.source_ip,
            source_access_warnings=list(self.source_access_warnings),
            refused_hint=hint,
            max_logins_per_minute=self._login_limiter.per_minute,
            timing=timing,
            slowest=slowest,
        )
        if self.target_resolution:
            inventory.update_scan_summary(
                targets=list(self.target_resolution.get("targets", [])),
                unresolved=list(self.target_resolution.get("unresolved", [])),
            )
        failure_summary = reason_counts(failed)
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
                "failed_count": len(failed),
                "failure_reasons": failure_summary,
                "skipped_count": len(self.skipped),
                "elapsed": round(elapsed, 1),
                "source_ip": self.source_ip,
                "source_access_warnings": list(self.source_access_warnings),
                "refused_hint": hint,
                "slowest": slowest,
            })
        else:
            self._progress_cb({
                "event": "scan_complete",
                "total_devices": len(self.visited),
                "failed_count": len(failed),
                "failure_reasons": failure_summary,
                "skipped_count": len(self.skipped),
                "elapsed": round(elapsed, 1),
                "inventory_key": inventory.discovery_id,
                "source_ip": self.source_ip,
                "source_access_warnings": list(self.source_access_warnings),
                "refused_hint": hint,
                "slowest": slowest,
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
        visit_started = time.monotonic()

        try:
            known_name = self._find_hostname_by_ip(inventory, ip)
            known = inventory.devices.get(known_name, {}) if known_name else {}
            # A continued scan, or a host list naming an address already seen
            # as an ACI/UCS neighbour, must not log into it either.
            if known.get("managed_by") and self._skip_controller_managed(
                    inventory, ip, known_name, known.get("managed_by"),
                    known.get("platform")):
                return []

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
                platform=known.get("platform"),
                login_limiter=self._login_limiter,
            )
            connect_started = time.monotonic()
            result = conn_mgr.connect()
            connect_ms = _ms_since(connect_started)
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
                already_this_run = norm_hostname in self._run_hostnames
                if already_this_run or (
                        norm_hostname in self._discovered_hostnames
                        and not explicitly_requested):
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
                self._run_hostnames.add(norm_hostname)

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

            # Gather commands for batch collectors. Switch-only commands are
            # held back until show version has said whether this is a router.
            collector_commands = {}
            general_cmds = []
            switching_cmds = []
            for cname, collector in batch_collectors.items():
                cmds = collector.get_commands(device_type)
                collector_commands[cname] = cmds
                for cmd in cmds:
                    if (collector.switching_only
                            or cmd in collector.switching_commands):
                        switching_cmds.append(cmd)
                    else:
                        general_cmds.append(cmd)

            command_ms = {}
            batch_started = time.monotonic()
            raw_outputs = ConnectionManager.run_commands(
                conn, _dedupe(general_cmds), timings=command_ms,
            )

            record = inventory.devices.get(hostname, {})
            router_model = is_switchless_router(
                show_version=raw_outputs.get("show version", ""),
                model=record.get("model") or "",
                platform=record.get("platform") or "",
                category=record.get("device_category") or "",
            )
            if router_model:
                logger.info("Router: skipping switching commands")
            else:
                pending = [c for c in _dedupe(switching_cmds)
                           if c not in raw_outputs]
                raw_outputs.update(ConnectionManager.run_commands(
                    conn, pending, timings=command_ms))
            batch_ms = _ms_since(batch_started)
            collectors_ms = collector_ms(collector_commands, command_ms)

            # Parse batch collectors
            for cname, collector in batch_collectors.items():
                if router_model and collector.switching_only:
                    inventory.set_collector_data(
                        hostname, cname, raw={},
                        parsed={"not_applicable": True,
                                "reason": f"{cname} does not apply to a router"},
                    )
                    continue
                cmds = collector_commands[cname]
                if router_model:
                    cmds = [c for c in cmds
                            if c not in collector.switching_commands]
                collector_raw = {cmd: raw_outputs.get(cmd, "") for cmd in cmds}
                try:
                    # Same error handling as BaseCollector.collect: rejected
                    # commands are blanked and recorded, never parsed.
                    parsed = collector.parse_collected(collector_raw, device_type)
                except Exception as e:
                    logger.warning(f"Collector {cname} parse failed on {hostname}: {e}")
                    parsed = {}
                inventory.set_collector_data(hostname, cname,
                                             raw=collector_raw, parsed=parsed)

            # Run custom collectors (dynamic commands, post-processing)
            for cname, collector in custom_collectors.items():
                collector_started = time.monotonic()
                try:
                    result = collector.collect(conn, device_type)
                    inventory.set_collector_data(
                        hostname, cname,
                        raw=result["raw"], parsed=result["parsed"],
                    )
                except Exception as e:
                    logger.warning(f"Collector {cname} collect failed on {hostname}: {e}")
                    inventory.set_collector_data(hostname, cname, raw={}, parsed={})
                collectors_ms[cname] = _ms_since(collector_started)

            conn.disconnect()

            if ip == self.seed_ip and not self._source_checked:
                self._check_source_access(inventory, hostname)

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

            total_ms = _ms_since(visit_started)
            with self._timing_lock:
                self.timing[hostname] = {
                    "ip": ip,
                    "connect_ms": connect_ms,
                    "login_wait_ms": conn_mgr.login_wait_ms,
                    "batch_ms": batch_ms,
                    "commands_ms": command_ms,
                    "collectors_ms": collectors_ms,
                    "total_ms": total_ms,
                }

            self._progress_cb({
                "event": "device_complete",
                "ip": ip,
                "hostname": hostname,
                "device_type": device_type or "auto",
                "total_ms": total_ms,
            })

            return neighbors

        except ConnectionError as e:
            logger.error(f"Connection error ({e.reason}): {e.message}")
            record = e.to_record(
                hostname=self._find_hostname_by_ip(inventory, ip))
            # A device seen as a neighbour keeps its record but records why
            # the login attempt against it failed.
            inventory.mark_login_failed_by_ip(ip, e.message)
            # SSH and telnet are gone; SNMP may still say what this thing is.
            # It is still a failed login, so it is still recorded as one.
            if self._snmp_fallback(inventory, ip, e.message):
                with self._failed_lock:
                    self.failed[ip] = record
                self._maybe_refused_hint()
                return []
            self._record_failure(inventory, ip, record)
            return []
        except Exception as e:
            logger.error(f"Unexpected error: {e}")
            self._record_failure(inventory, ip, self._unexpected_record(
                e, hostname=self._find_hostname_by_ip(inventory, ip)))
            return []
        finally:
            _log_context.device_ip = None

    @staticmethod
    def _unexpected_record(exc, hostname=None) -> dict:
        message = f"{type(exc).__name__}: {exc}"
        return {
            "hostname": hostname,
            "reason": OTHER,
            "hint": hint_for(OTHER),
            "message": message,
            "attempts": [],
        }

    def _record_failure(self, inventory, ip, record):
        """Store a structured failure and tell the UI why it failed."""
        with self._failed_lock:
            self.failed[ip] = record
        self._progress_cb({
            "event": "device_failed",
            "ip": ip,
            "hostname": record.get("hostname"),
            "error": record.get("message"),
            "reason": record.get("reason"),
            "hint": record.get("hint"),
        })
        self._maybe_refused_hint()

    def _maybe_refused_hint(self):
        """Point at the vty ACLs once enough devices have refused us."""
        with self._failed_lock:
            if self._refused_hint:
                return
            hint = refused_hint(self.failed, self.source_ip)
            if not hint:
                return
            self._refused_hint = hint
        logger.warning(hint)
        self._progress_cb({"event": "refused_hint", "message": hint,
                           "source_ip": self.source_ip})

    def _check_source_access(self, inventory, hostname):
        """Warn when the seed's vty or SNMP ACLs do not permit this host."""
        self._source_checked = True
        if not self.source_ip:
            return
        data = inventory.devices.get(hostname, {}).get("collector_data", {})
        config_data = data.get("config", {})
        config = (config_data.get("parsed") or {}).get("config", "")
        if not config:
            raw = config_data.get("raw") or {}
            config = next(iter(raw.values()), "") if raw else ""
        acl_output = (data.get("edge_services", {}).get("raw") or {}).get(
            "show access-lists", "")
        if not config:
            logger.info("No running-config from the seed; source access "
                        "check skipped")
            return
        try:
            warnings = check_source_access(config, self.source_ip, hostname,
                                           acl_output=acl_output)
        except Exception as e:
            logger.warning(f"Source access check failed: {type(e).__name__}: {e}")
            return
        for warning in warnings:
            self.source_access_warnings.append(warning)
            logger.warning(warning["message"])
            self._progress_cb({"event": "source_access_warning", **warning})

    def _skip_controller_managed(self, inventory, ip, hostname, managed_by,
                                 platform) -> bool:
        """Record a controller-managed device as skipped. False when the
        operator asked for these to be collected anyway."""
        if self.collect_controller_managed:
            return False
        with self._failed_lock:
            self.failed.pop(ip, None)
            self.skipped[ip] = {
                "hostname": hostname,
                "reason": "controller_managed",
                "managed_by": managed_by,
                "platform": platform,
            }
        logger.info(f"Not logging into {hostname} ({ip}): managed by "
                    f"{managed_by}")
        self._progress_cb({
            "event": "device_skipped",
            "ip": ip,
            "hostname": hostname,
            "reason": "controller_managed",
            "managed_by": managed_by,
            "hint": SKIP_HINTS.get(managed_by, ""),
        })
        return True

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

            managed = self._detector.detect_controller_managed(
                neighbor.get("remote_platform"), neighbor.get("remote_device"))
            if managed and managed.get("device_category"):
                neighbor_category = managed["device_category"]

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
                neighbor.get("remote_platform"), neighbor.get("chassis_id"))
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
                if managed:
                    inventory.set_controller_managed(
                        remote_name, managed["managed_by"],
                        managed.get("device_category"))
                inventory.add_evidence(
                    remote_name, source=source, seen_from=hostname,
                    remote_port=_neighbour_remote_port(neighbor),
                )
            else:
                existing = self._find_hostname_by_ip(
                    inventory, neighbor.get("remote_ip"))
                if existing:
                    inventory.add_evidence(
                        existing, source=source, seen_from=hostname,
                        remote_port=_neighbour_remote_port(neighbor),
                    )
                else:
                    inventory.add_unresolved_neighbour(hostname, neighbor)

            # Queue for next layer
            remote_ip = neighbor.get("remote_ip")
            if remote_ip and not self._detector.is_collectible(neighbor_device_type):
                logger.info(
                    f"Not crawling {remote_name} ({remote_ip}): "
                    f"{neighbor_device_type} has no CLI to collect from"
                )
                continue
            if remote_ip:
                with self._visited_lock:
                    already_visited = remote_ip in self.visited
                    visited_count = len(self.visited)
                if already_visited:
                    continue
                if managed and self._skip_controller_managed(
                        inventory, remote_ip, remote_name,
                        managed["managed_by"], platform):
                    # Seen and recorded; never queued for a login.
                    with self._visited_lock:
                        self.visited.add(remote_ip)
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

        # The LLDP system description names the OS outright ("Arista Networks
        # EOS ..."), so it outranks a platform string. Neither lookup may fall
        # back to the default type here, or an unmatched platform would hide
        # a perfectly good description.
        if system_desc:
            dt = self._detector.detect_from_lldp(
                system_desc, capabilities, self.filters, fallback=False)
            if dt:
                return (dt, device_category, has_routing)

        if platform:
            dt = self._detector.detect_from_cdp(
                platform, capabilities, self.filters, fallback=False)
            if dt:
                return (dt, device_category, has_routing)

        if platform or system_desc:
            return (self._detector.default_type, device_category, has_routing)

        if device_category and device_category != "unknown":
            return (self._detector.default_type, device_category, has_routing)

        return None

    def _should_include(self, category: str) -> bool:
        """Check if a device category passes the current filters."""
        category_filter_map = {
            "router": "include_routers",
            "firewall": "include_routers",
            "switch": "include_switches",
            "fabric-interconnect": "include_switches",
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
