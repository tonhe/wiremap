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
    from app.connection_manager import (ConnectionManager, ConnectionError,
                                        DEFAULT_CONNECT_TIMEOUT, TCP_PROBE_TIMEOUT)
    from app.collectors import get_registry, get_collector
    from app.inventory import DiscoveryInventory
    from app.identity import normalize_hostname, looks_like_mac, looks_like_host_nic
    from app.device_facts import extract_device_facts
    from app.device_role import (
        CISCO_FAMILY_TYPES, category_for_model, device_type_from_show_version,
        is_switchless_router, model_from_show_version, skips_routing,
    )
    from app.neighbors import extract_all, default_enabled, CrawlScope
    from app.neighbors import expansion
    from app.snmp_probe import (probe_with_outcome as snmp_probe_outcome,
                                make_walker as snmp_make_walker,
                                OUTCOME_OK as SNMP_OK,
                                OUTCOME_TIMEOUT as SNMP_TIMEOUT,
                                OUTCOME_REJECTED as SNMP_REJECTED,
                                OUTCOME_NO_CREDENTIALS as SNMP_NO_CREDENTIALS)
    from app.snmp_tables import collect_all as snmp_collect_all
    from app.failures import (failure_record, reason_counts, hint_for, OTHER,
                              SKIP_HINTS, snmp_answered, plain_failures)
    from app.login_rate import LoginRateLimiter
    from app.source_access import (
        local_source_ip, refused_hint, assess_source_access, access_warnings,
        learn_source_ip, summary_line, SOURCE_CONFIGURED, SOURCE_LOCAL_SOCKET)
    from app.scan_timing import collector_ms, summarize as summarize_timing
    from app import target_outcomes
except ImportError:
    from connection_manager import (ConnectionManager, ConnectionError,
                                    DEFAULT_CONNECT_TIMEOUT, TCP_PROBE_TIMEOUT)
    from collectors import get_registry, get_collector
    from inventory import DiscoveryInventory
    from identity import normalize_hostname, looks_like_mac, looks_like_host_nic
    from device_facts import extract_device_facts
    from device_role import (
        CISCO_FAMILY_TYPES, category_for_model, device_type_from_show_version,
        is_switchless_router, model_from_show_version, skips_routing,
    )
    from neighbors import extract_all, default_enabled, CrawlScope
    from neighbors import expansion
    from snmp_probe import (probe_with_outcome as snmp_probe_outcome,
                            make_walker as snmp_make_walker,
                            OUTCOME_OK as SNMP_OK,
                            OUTCOME_TIMEOUT as SNMP_TIMEOUT,
                            OUTCOME_REJECTED as SNMP_REJECTED,
                            OUTCOME_NO_CREDENTIALS as SNMP_NO_CREDENTIALS)
    from snmp_tables import collect_all as snmp_collect_all
    from failures import (failure_record, reason_counts, hint_for, OTHER,
                          SKIP_HINTS, snmp_answered, plain_failures)
    from login_rate import LoginRateLimiter
    from source_access import (
        local_source_ip, refused_hint, assess_source_access, access_warnings,
        learn_source_ip, summary_line, SOURCE_CONFIGURED, SOURCE_LOCAL_SOCKET)
    from scan_timing import collector_ms, summarize as summarize_timing
    import target_outcomes
try:
    from app.credentials import Credential, CredentialChain
except ImportError:
    from credentials import Credential, CredentialChain

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
                 expand_non_cdp_neighbors: bool = False,
                 snmp_credentials=None,
                 base_inventory=None,
                 target_resolution=None,
                 collect_controller_managed: bool = False,
                 max_logins_per_minute: int = 0,
                 allow_telnet: bool = False,
                 source_ip=None,
                 credentials=None,
                 connect_timeout: int = DEFAULT_CONNECT_TIMEOUT):
        self.seed_ip = seed_ip
        self.connect_timeout = int(connect_timeout or DEFAULT_CONNECT_TIMEOUT)
        self.seed_device_type = seed_device_type
        # Credential sets in configured order; username/password alone is a
        # single set. The chain keeps the last set that worked at the front.
        self._credentials = CredentialChain(
            credentials or [Credential(1, username, password)])
        self.username = self._credentials.first.username
        self.target_hosts = target_hosts
        self.disable_autodetect = disable_autodetect
        self.crawl_from_targets = crawl_from_targets
        self.neighbor_sources = (set(neighbor_sources)
                                 if neighbor_sources is not None
                                 else default_enabled())
        # Without a scope, next-hop crawling walks out into ISP space.
        self.crawl_scope = crawl_scope or CrawlScope()
        # Addresses from routing adjacencies, next-hops and FHRP peers are
        # only crawled once they earn it (see app.neighbors.expansion).
        # Candidates wait here until the end of a BFS layer, by which time
        # CDP/LLDP or a collected ARP table may vouch for them.
        self.expand_non_cdp_neighbors = bool(expand_non_cdp_neighbors)
        self._expansion_lock = threading.Lock()
        self._pending_non_cdp: dict = {}
        self._cdp_visible: set = set()
        self.not_attempted: dict = {}
        # How each address and placeholder was first found, for the
        # per-device discovered_via field.
        self._queued_via: dict = {}
        self._via_by_name: dict = {}
        # Tried after any failed login (see _snmp_fallback).
        self.snmp_credentials = snmp_credentials
        self.snmp_stats = {"tried": 0, "v2c": 0, "v3": 0, "no_response": 0,
                           "rejected": 0, "error": 0}
        self._snmp_lock = threading.Lock()
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
        # Telnet fallback for auto-protocol logins (see ConnectionManager).
        self.allow_telnet = allow_telnet
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
        # Per-address login results this run, for target reconciliation:
        # IP -> {"hostname", "serial"} when collected, IP -> hostname when
        # the login reached a device already collected under another address.
        self._collected_by_ip: dict = {}
        self._merged_by_ip: dict = {}
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
        # Source address as devices see it: stated by the operator, else
        # learned from the first session that reports its peer, else the
        # local socket (wrong behind NAT or a container bridge).
        self.configured_source_ip = source_ip or None
        self.source_ip_method = None
        self.source_access = None
        self.source_access_line = None
        self._source_learned = False
        self._source_learn_lock = threading.Lock()
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
        params.update(self._target_params())
        params["expand_non_cdp_neighbors"] = self.expand_non_cdp_neighbors
        # Which accounts were offered, in order -- never a password.
        params["credential_usernames"] = self._credentials.usernames()
        # How hard each login tried, so a short-timeout run can be told
        # apart from an unreachable network when comparing scans.
        params["connect_timeout_s"] = self.connect_timeout
        params["telnet_probe_timeout_s"] = TCP_PROBE_TIMEOUT
        params["allow_telnet"] = self.allow_telnet
        params["max_logins_per_minute"] = self._login_limiter.per_minute

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
            for ip, _ in current_layer:
                self._queued_via[ip] = "target"
        else:
            current_layer = [(self.seed_ip, self.seed_device_type)]
            self._queued_via[self.seed_ip] = "seed"

        start_time = time.time()
        total_hosts = len(self.target_hosts) if self.target_hosts else None
        if self.configured_source_ip:
            self.source_ip = self.configured_source_ip
            self.source_ip_method = SOURCE_CONFIGURED
            self._source_learned = True
        else:
            self.source_ip = local_source_ip(current_layer[0][0])
            self.source_ip_method = (SOURCE_LOCAL_SOCKET if self.source_ip
                                     else None)
        if self.source_ip:
            logger.info(f"Source address towards the seed: {self.source_ip} "
                        f"({self.source_ip_method})")
        self._progress_cb({
            "event": "scan_started",
            "scan_type": "targeted" if self.target_hosts else "discovery",
            "total_hosts": total_hosts,
            "source_ip": self.source_ip,
            "source_ip_method": self.source_ip_method,
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

            next_layer.extend(self._resolve_non_cdp(inventory))
            current_layer = next_layer

        elapsed = time.time() - start_time

        # Fold records that turned out to be the same chassis under different
        # names before anything downstream counts devices.
        folded = inventory.merge_duplicates()
        if folded:
            logger.info(f"Merged {folded} duplicate device record(s)")
        # Every sighting is in now, so the management address can be chosen
        # by rule rather than by which neighbour reported the device first.
        inventory.resolve_mgmt_ips()

        self._finalize_non_cdp(inventory)
        self._record_discovered_via(inventory)

        logger.info(
            f"Discovery complete. {len(inventory.devices)} devices, "
            f"{len(plain_failures(self.failed))} failed"
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
            source_ip_method=self.source_ip_method,
            source_access=self.source_access,
            source_access_line=self._current_access_line(),
            source_access_warnings=list(self.source_access_warnings),
            refused_hint=hint,
            max_logins_per_minute=self._login_limiter.per_minute,
            peak_logins_per_minute=self._login_limiter.peak_per_minute,
            timing=timing,
            slowest=slowest,
        )
        target_line = self._reconcile_targets(inventory, failed)
        inventory.update_scan_summary(
            not_attempted=dict(self.not_attempted),
            not_attempted_count=len(self.not_attempted),
        )
        if self.not_attempted:
            logger.info(
                f"{len(self.not_attempted)} address(es) from routing, "
                f"next-hop or FHRP sightings not attempted (not seen by "
                f"CDP/LLDP; see scan_summary.not_attempted)"
            )
        failure_summary = reason_counts(failed)
        snmp_line = self.snmp_summary_line()
        if snmp_line:
            logger.info(snmp_line)
            with self._snmp_lock:
                stats = dict(self.snmp_stats)
            inventory.update_scan_summary(snmp_fallback=stats)
            self._progress_cb({"event": "snmp_fallback_summary",
                               "message": snmp_line, **stats})
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
                "failed_count": len(plain_failures(failed)),
                "failure_reasons": failure_summary,
                "skipped_count": len(self.skipped),
                "not_attempted_count": len(self.not_attempted),
                "elapsed": round(elapsed, 1),
                "source_ip": self.source_ip,
                "source_ip_method": self.source_ip_method,
                "source_access_line": self._current_access_line(),
                "source_access_warnings": list(self.source_access_warnings),
                "refused_hint": hint,
                "slowest": slowest,
                "target_summary": target_line,
            })
        else:
            self._progress_cb({
                "event": "scan_complete",
                "total_devices": len(self.visited),
                "failed_count": len(plain_failures(failed)),
                "failure_reasons": failure_summary,
                "skipped_count": len(self.skipped),
                "not_attempted_count": len(self.not_attempted),
                "elapsed": round(elapsed, 1),
                "inventory_key": inventory.discovery_id,
                "source_ip": self.source_ip,
                "source_ip_method": self.source_ip_method,
                "source_access_line": self._current_access_line(),
                "source_access_warnings": list(self.source_access_warnings),
                "refused_hint": hint,
                "slowest": slowest,
                "target_summary": target_line,
            })

        # Remove the device-context filter now that discovery is done
        for handler in logging.getLogger().handlers:
            handler.removeFilter(self._log_filter)

        return inventory

    def _reconcile_targets(self, inventory, failed):
        """Record an outcome for every requested target in the scan summary.
        Returns the console summary line, or None for a run without targets."""
        if not (self.target_hosts or self.target_resolution):
            return None
        cancelled = bool(self._cancelled and self._cancelled.is_set())
        with self._failed_lock:
            collected = {ip: dict(v) for ip, v in self._collected_by_ip.items()}
            merged = dict(self._merged_by_ip)
            skipped = dict(self.skipped)
        targets = target_outcomes.reconcile(
            target_outcomes.target_list(self.target_resolution,
                                        self.target_hosts),
            inventory.devices, collected, merged, failed, skipped,
            cancelled=cancelled)
        line = target_outcomes.summary_line(targets)
        inventory.update_scan_summary(
            targets=targets,
            unresolved=list((self.target_resolution or {}).get(
                "unresolved", [])),
            target_outcomes=target_outcomes.outcome_counts(targets),
        )
        if line:
            logger.info(line)
        return line

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
                username=self.username, password=None,
                credentials=self._credentials.ordered(),
                protocol=proto,
                allow_fallback=not (explicit_type or self.disable_autodetect),
                platform=known.get("platform"),
                login_limiter=self._login_limiter,
                allow_telnet=self.allow_telnet,
                connect_timeout=self.connect_timeout,
            )
            connect_started = time.monotonic()
            result = conn_mgr.connect()
            connect_ms = _ms_since(connect_started)
            conn = result.connection
            login_cred = conn_mgr.credential
            self._credentials.mark_success(login_cred)
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
                "login_user": login_cred.username if login_cred else None,
                "credential_set": login_cred.number if login_cred else None,
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
                    # The login worked, so a prior failure at this address
                    # is stale; the address is the same device as hostname.
                    with self._failed_lock:
                        self.failed.pop(ip, None)
                        self._merged_by_ip[ip] = hostname
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
            inventory.set_reached_ip(hostname, ip)
            inventory.mark_login_succeeded(hostname)
            if login_cred is not None:
                inventory.set_login_credential(
                    hostname, login_cred.username, login_cred.number)
            # A device that failed in the scan being continued and works now
            # must stop being reported as a failure.
            with self._failed_lock:
                self.failed.pop(ip, None)
                self._collected_by_ip[ip] = {"hostname": hostname,
                                             "serial": None}
            if ha_state:
                inventory.set_ha_state(hostname, ha_state)

            self._maybe_learn_source_ip(
                conn, conn_mgr.effective_device_type or device_type, ip,
                result.protocol_used, username=conn_mgr.username)

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

            command_ms = {}
            batch_started = time.monotonic()

            # Cisco IOS, IOS-XE and NX-OS all log in on the cisco_ios driver,
            # so the type a neighbour guessed decides nothing. Show version
            # runs first and settles it before any command is chosen.
            raw_outputs = {}
            if not device_type or device_type in CISCO_FAMILY_TYPES:
                raw_outputs = ConnectionManager.run_commands(
                    conn, ["show version"], timings=command_ms)
                proven = device_type_from_show_version(
                    raw_outputs.get("show version", ""), device_type)
                if proven != device_type:
                    logger.info(f"show version identifies {proven} "
                                f"(was {device_type or 'auto'})")
                    device_type = proven
            # The type commands were chosen for is the one recorded, so a
            # neighbour's guess never outlives the login.
            if device_type:
                inventory.set_collected_role(hostname, device_type=device_type)

            record = inventory.devices.get(hostname, {})
            # A voice gateway has no routing table worth collecting either.
            no_routing = skips_routing(
                show_version=raw_outputs.get("show version", ""),
                model=record.get("model") or "",
                platform=record.get("platform") or "",
                category=record.get("device_category") or "",
            )
            if no_routing:
                logger.info("Voice gateway: skipping routing commands")

            # Gather commands for batch collectors. Switch-only commands are
            # held back until show version has said whether this is a router.
            collector_commands = {}
            general_cmds = []
            switching_cmds = []
            for cname, collector in batch_collectors.items():
                if no_routing and collector.routing_only:
                    continue
                cmds = collector.get_commands(device_type)
                collector_commands[cname] = cmds
                for cmd in cmds:
                    if (collector.switching_only
                            or cmd in collector.switching_commands):
                        switching_cmds.append(cmd)
                    else:
                        general_cmds.append(cmd)

            raw_outputs.update(ConnectionManager.run_commands(
                conn, [c for c in _dedupe(general_cmds) if c not in raw_outputs],
                timings=command_ms,
            ))

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
                if no_routing and collector.routing_only:
                    inventory.set_collector_data(
                        hostname, cname, raw={},
                        parsed={"not_applicable": True,
                                "reason": f"{cname} does not apply to a "
                                          f"voice gateway"},
                    )
                    continue
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
            # The CDP/LLDP platform it was discovered with is the last
            # resort for the model when show version and show inventory
            # both come up empty.
            facts = extract_device_facts(
                inv_parsed,
                platform_hint=inventory.devices.get(hostname, {}).get("platform"))
            if facts["serial"]:
                with self._failed_lock:
                    self._collected_by_ip[ip]["serial"] = facts["serial"]
            inventory.mark_login_succeeded(
                hostname,
                serial=facts["serial"] or None,
                model=facts["model"] or None,
                software_version=facts["software_version"] or None,
            )
            # Category from what the device says it is, not from the
            # capabilities its first neighbour saw advertised.
            category = category_for_model(
                model_from_show_version(raw_outputs.get("show version", ""))
                or facts["model"])
            if category:
                inventory.set_collected_role(hostname,
                                             device_category=category)

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
            kept = inventory.mark_login_failed_by_ip(ip, e.message)
            if kept:
                self._warn_kept_device(kept, ip, record)
                self._record_failure(inventory, ip, record)
                return []
            # The login is gone; SNMP may still say what this thing is. Every
            # login failure class qualifies: auth and refused prove the host
            # is up, and a TCP timeout says nothing about UDP 161. It is
            # still a failed login, so it keeps its failure record, which
            # carries the SNMP outcome either way.
            outcome = self._snmp_fallback(inventory, ip, e.message)
            record["snmp"] = outcome
            if snmp_answered(record):
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

    def _warn_kept_device(self, hostname, ip, record):
        """A device already collected failed this login. Its data is kept,
        but its neighbours were not crawled from it this run, so a
        distribution switch failing here can hide a site's access layer."""
        record["kept_collected"] = True
        if normalize_hostname(hostname) in self._run_hostnames:
            # Collected this run under another address; nothing was lost.
            logger.info(f"{hostname} already collected this run; "
                        f"{ip} failed ({record.get('reason')})")
            return
        message = (f"{hostname} ({ip}) was collected in the scan being "
                   f"continued but failed this time ({record.get('reason')}); "
                   f"its earlier data is kept, but its neighbours were not "
                   f"crawled from it")
        logger.warning(message)
        self._progress_cb({"event": "device_kept", "ip": ip,
                           "hostname": hostname, "message": message})

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
            "snmp": record.get("snmp"),
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

    def _current_access_line(self):
        return summary_line(self.source_ip, self.source_ip_method,
                            self.source_access)

    def _maybe_learn_source_ip(self, conn, device_type, ip, protocol,
                               username=None):
        """Ask the first device that can tell which address it sees us as.

        Tried once per scan on a platform that supports it (normally the
        seed), before its collectors run, so their output is untouched.
        """
        with self._source_learn_lock:
            if self._source_learned:
                return
            platform = (device_type or "").lower()
            if not platform.startswith(("cisco_ios", "cisco_xe",
                                        "cisco_nxos")):
                return
            self._source_learned = True
        try:
            addr, method = learn_source_ip(conn, device_type,
                                           username=username or self.username,
                                           local_ip=ip, protocol=protocol)
        except Exception as e:
            logger.info(f"Could not learn source address: "
                        f"{type(e).__name__}: {e}")
            return
        if not addr:
            logger.info("Device did not report our session address; keeping "
                        f"{self.source_ip} ({self.source_ip_method})")
            return
        previous = self.source_ip
        self.source_ip = addr
        self.source_ip_method = method
        logger.info(f"Source address as seen by {ip}: {addr} ({method})")
        self._progress_cb({"event": "source_ip_learned", "source_ip": addr,
                           "source_ip_method": method, "previous": previous,
                           "ip": ip})

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
            assessment = assess_source_access(config, self.source_ip,
                                              acl_output=acl_output)
            warnings = access_warnings(assessment, self.source_ip, hostname,
                                       method=self.source_ip_method)
        except Exception as e:
            logger.warning(f"Source access check failed: {type(e).__name__}: {e}")
            return
        self.source_access = assessment
        line = self._current_access_line()
        if line:
            logger.info(line)
            self._progress_cb({"event": "source_access", "message": line,
                               "source_ip": self.source_ip,
                               "source_ip_method": self.source_ip_method,
                               "source_access": assessment})
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
                       login_error: str) -> str:
        """Try SNMP after a failed login. Returns the outcome string
        (app.snmp_probe OUTCOME_*): "v2c ok" / "v3 ok" when it answered.

        The record is still login_succeeded=False -- SNMP identifies a device,
        it does not log into one.
        """
        if not self.snmp_credentials or not self.snmp_credentials.is_configured():
            return SNMP_NO_CREDENTIALS

        # Not throttled by the login limiter: SNMP never touches AAA. The
        # worker pool already bounds how many run at once.
        record, outcome = snmp_probe_outcome(ip, self.snmp_credentials)
        self._tally_snmp(outcome)
        if not record:
            note = ""
            if (outcome == SNMP_TIMEOUT
                    and self.snmp_credentials.version == "v2c"):
                note = " (a wrong v2c community also looks like this)"
            logger.info(f"SNMP fallback on {ip}: {outcome}{note}")
            return outcome

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
            "snmp": outcome,
        })
        return outcome

    def _tally_snmp(self, outcome):
        with self._snmp_lock:
            stats = self.snmp_stats
            stats["tried"] += 1
            if outcome == SNMP_OK.get("v2c"):
                stats["v2c"] += 1
            elif outcome == SNMP_OK.get("v3"):
                stats["v3"] += 1
            elif outcome == SNMP_TIMEOUT:
                stats["no_response"] += 1
            elif outcome == SNMP_REJECTED:
                stats["rejected"] += 1
            else:
                stats["error"] += 1

    def snmp_summary_line(self):
        """One console line for the fallback, or None if it never ran."""
        with self._snmp_lock:
            s = dict(self.snmp_stats)
        if not s["tried"]:
            return None
        line = (f"SNMP fallback: {s['tried']} tried, "
                f"{s['v2c'] + s['v3']} answered "
                f"(v2c {s['v2c']}, v3 {s['v3']}), "
                f"{s['no_response']} no response")
        if s["rejected"]:
            line += f", {s['rejected']} rejected"
        if s["error"]:
            line += f", {s['error']} error"
        return line

    def _extract_neighbors(self, inventory: DiscoveryInventory,
                           hostname: str, ip: str, device_type: str,
                           depth: int) -> list[tuple[str, str]]:
        """Extract neighbors from every enabled neighbour source.

        Returns list of (ip, device_type) for next BFS layer.
        """
        device = inventory.devices.get(hostname, {})
        neighbors = extract_all(device, enabled=self.neighbor_sources)

        next_layer = []

        with self._expansion_lock:
            for neighbor in neighbors:
                if neighbor.get("remote_ip") and expansion.is_cdp_lldp(neighbor):
                    self._cdp_visible.add(neighbor["remote_ip"])

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
                with self._expansion_lock:
                    self._via_by_name.setdefault(
                        remote_name, expansion.discovered_via_label(neighbor))
                if chassis_id:
                    inventory.set_chassis_id(remote_name, chassis_id)
                inventory.set_neighbour_serial(
                    remote_name, neighbor.get("remote_serial"))
                if managed:
                    inventory.set_controller_managed(
                        remote_name, managed["managed_by"],
                        managed.get("device_category"))
                inventory.add_evidence(
                    remote_name, source=source, seen_from=hostname,
                    remote_port=_neighbour_remote_port(neighbor),
                    mgmt_address=neighbor.get("remote_mgmt_ip"),
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
                if not self._detector._should_crawl(capabilities, self.filters):
                    continue
                if not expansion.is_cdp_lldp(neighbor):
                    # Decided at the end of the layer, once every CDP/LLDP
                    # table and ARP table in it has been collected.
                    if depth < self.max_depth:
                        self._defer_non_cdp(remote_ip, neighbor,
                                            neighbor_device_type, hostname)
                    continue
                with self._expansion_lock:
                    self._queued_via.setdefault(
                        remote_ip, expansion.discovered_via_label(neighbor))
                next_layer.append((remote_ip, neighbor_device_type))
                logger.info(
                    f"Queued {remote_name} ({remote_ip}) at depth {depth + 1} "
                    f"via {neighbor.get('source', 'cdp_lldp')}"
                )

        return next_layer

    def _defer_non_cdp(self, ip, neighbor, device_type, seen_on):
        with self._expansion_lock:
            self._pending_non_cdp.setdefault(ip, []).append({
                "ref": neighbor,
                "device_type": device_type,
                "seen_on": seen_on,
            })

    def _decide_non_cdp(self, ip, sightings, arp):
        """(allowed, sighting, reason) for one pending address.

        Any sighting that qualifies is enough: an address seen both as a BGP
        peer and as an EIGRP neighbour with a Cisco MAC is crawlable.
        """
        cdp_visible = ip in self._cdp_visible
        first_reason = None
        for sighting in sightings:
            allowed, reason = expansion.decide(
                sighting["ref"], cdp_visible, mac=arp.get(ip),
                expand=self.expand_non_cdp_neighbors)
            if allowed:
                return True, sighting, None
            first_reason = first_reason or reason
        return False, sightings[0], first_reason

    def _resolve_non_cdp(self, inventory):
        """Queue the pending non-CDP addresses that have earned a login.

        Runs between BFS layers. Addresses that do not qualify yet stay
        pending: a later layer may see them over CDP/LLDP or collect an ARP
        table that names their vendor.
        """
        with self._expansion_lock:
            pending = dict(self._pending_non_cdp)
        if not pending:
            return []
        with inventory._lock:
            arp = expansion.arp_map(inventory.devices)
        queued = []
        for ip, sightings in pending.items():
            with self._visited_lock:
                already_visited = ip in self.visited
            if already_visited or ip in self._cdp_visible:
                # CDP/LLDP queues (or filters) the address on its own terms.
                with self._expansion_lock:
                    self._pending_non_cdp.pop(ip, None)
                continue
            allowed, sighting, _ = self._decide_non_cdp(ip, sightings, arp)
            if not allowed:
                continue
            with self._expansion_lock:
                self._pending_non_cdp.pop(ip, None)
                self._queued_via.setdefault(
                    ip, expansion.discovered_via_label(sighting["ref"]))
            queued.append((ip, sighting["device_type"]))
            logger.info(
                f"Queued {ip} via {sighting['ref'].get('source')} "
                f"(seen on {sighting['seen_on']})"
            )
        return queued

    def _finalize_non_cdp(self, inventory):
        """Record every address the expansion gate kept from a login."""
        with self._expansion_lock:
            pending = dict(self._pending_non_cdp)
            self._pending_non_cdp.clear()
        if not pending:
            return
        with inventory._lock:
            arp = expansion.arp_map(inventory.devices)
        for ip, sightings in pending.items():
            with self._visited_lock:
                already_visited = ip in self.visited
            if already_visited or ip in self._cdp_visible:
                continue
            allowed, sighting, reason = self._decide_non_cdp(ip, sightings, arp)
            if allowed:
                # Qualified, but the crawl ended first (depth or cancel).
                continue
            ref = sighting["ref"]
            record = {
                "source": ref.get("source"),
                "seen_on": sighting["seen_on"],
                "reason": reason,
            }
            if ref.get("protocol"):
                record["protocol"] = ref["protocol"]
            if arp.get(ip):
                record["mac"] = arp[ip]
            self.not_attempted[ip] = record
            logger.info(
                f"Not attempting {ip} from {record['source']} on "
                f"{record['seen_on']}: {reason}"
            )

    def _target_params(self):
        """Scan params describing a targeted run's host list."""
        if not self.target_hosts:
            return {}
        resolution = self.target_resolution or {}
        return {
            "targets_file": resolution.get("targets_file") or None,
            "targets_count": len(self.target_hosts),
            "resolver": resolution.get("resolver") or None,
            "target_hints": {ip: dtype for ip, dtype in self.target_hosts
                             if dtype},
        }

    def _record_discovered_via(self, inventory):
        """Stamp each device with how this scan first found it."""
        with self._expansion_lock:
            queued = dict(self._queued_via)
            by_name = dict(self._via_by_name)
        with inventory._lock:
            for name, dev in inventory.devices.items():
                ip = dev.get("mgmt_ip")
                run_via = queued.get(ip) if ip else None
                if run_via in ("target", "seed"):
                    dev["discovered_via"] = run_via
                    continue
                if dev.get("discovered_via"):
                    continue
                via = run_via or by_name.get(name)
                if not via and dev.get("discovery_source") == "snmp":
                    via = "snmp"
                if via:
                    dev["discovered_via"] = via

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
            # Crawled as routers before they had a category of their own.
            "voice-gateway": "include_routers",
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
