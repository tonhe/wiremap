"""
Cisco EOX API v5 client.
Handles OAuth token management, PID batch lookups, and software release lookups.
"""

import logging
import time

import requests

logger = logging.getLogger(__name__)

EOX_TOKEN_URL = "https://id.cisco.com/oauth2/default/v1/token"
EOX_BASE_URL = "https://apix.cisco.com/supporttools/eox/rest/5"

# Max PIDs or SW release combos per API call
BATCH_SIZE = 20

# device_type -> EOX OS type string
DEVICE_TYPE_TO_OS = {
    "cisco_ios": "IOS",
    "cisco_xe": "IOS-XE",
    "cisco_nxos": "NX-OS",
    "cisco_xr": "IOS XR",
    "cisco_asa": "ASA",
    "cisco_wlc": "WLC",
}


class EoxApiError(Exception):
    pass


class EoxClient:
    """Cisco EOX API v5 client with token caching and batch lookups."""

    def __init__(self, client_id, client_secret):
        self._client_id = client_id
        self._client_secret = client_secret
        self._token = None
        self._token_expiry = 0

    def _get_token(self):
        if self._token and time.time() < self._token_expiry:
            return self._token

        try:
            resp = requests.post(
                EOX_TOKEN_URL,
                data={"grant_type": "client_credentials"},
                auth=(self._client_id, self._client_secret),
                timeout=15,
            )
            resp.raise_for_status()
        except requests.RequestException as e:
            raise EoxApiError(f"OAuth token request failed: {e}")

        data = resp.json()
        self._token = data.get("access_token")
        if not self._token:
            raise EoxApiError("No access_token in OAuth response")

        # Expire 60s early to avoid edge cases
        self._token_expiry = time.time() + data.get("expires_in", 3600) - 60
        return self._token

    def _api_get(self, path, params=None):
        token = self._get_token()
        url = f"{EOX_BASE_URL}/{path}"
        try:
            resp = requests.get(
                url,
                headers={"Authorization": f"Bearer {token}"},
                params=params,
                timeout=30,
            )
            resp.raise_for_status()
        except requests.RequestException as e:
            raise EoxApiError(f"EOX API request failed: {e}")
        return resp.json()

    def _fetch_sw_pages(self, query_params):
        """Fetch all pages for EOXBySWReleaseString using query parameters."""
        records = []
        page = 1
        while True:
            data = self._api_get(f"EOXBySWReleaseString/{page}", params=query_params)

            # Top-level error (e.g. invalid format)
            if data.get("EOXError"):
                err = data["EOXError"]
                raise EoxApiError(f"EOX SW API error {err.get('ErrorID')}: {err.get('ErrorDescription')}")

            eox_records = data.get("EOXRecord", [])
            for rec in eox_records:
                err = rec.get("EOXError", {})
                if err.get("ErrorID") and not rec.get("EOLProductID"):
                    continue
                records.append(rec)

            pagination = data.get("PaginationResponseRecord", {})
            last_index = pagination.get("LastIndex", 1)
            if page >= last_index:
                break
            page += 1

        return records

    def _fetch_all_pages(self, path_template, param_string):
        """Fetch all pages for a given EOX endpoint + param string."""
        records = []
        page = 1
        while True:
            path = path_template.format(page=page, params=param_string)
            data = self._api_get(path)

            eox_records = data.get("EOXRecord", [])
            for rec in eox_records:
                err = rec.get("EOXError", {})
                error_id = err.get("ErrorID", "")
                input_val = rec.get("EOXInputValue", "")
                returned_pid = rec.get("EOLProductID", "")
                logger.debug(
                    "EOX record: input=%r returned_pid=%r error=%r",
                    input_val, returned_pid, error_id or None,
                )
                if error_id and not returned_pid:
                    # SSA_ERR_026: PID exists but no EOX dates yet (still active)
                    # Synthesise a minimal record so the report shows "Current"
                    if error_id == "SSA_ERR_026":
                        # PID is in Cisco catalog but no EoL dates yet (still active)
                        records.append({
                            "EOLProductID": input_val,
                            "EOXInputValue": input_val,
                            "ProductIDDescription": "",
                            "_active_no_eox": True,
                        })
                    else:
                        # PID not found / no EOX record exists
                        records.append({
                            "EOLProductID": input_val,
                            "EOXInputValue": input_val,
                            "ProductIDDescription": "",
                            "_pid_not_found": True,
                        })
                    continue
                records.append(rec)

            pagination = data.get("PaginationResponseRecord", {})
            last_index = pagination.get("LastIndex", 1)
            if page >= last_index:
                break
            page += 1

        return records

    def lookup_pids(self, pids):
        """Look up EOX records for a list of hardware PIDs.

        Args:
            pids: List of PID strings.

        Returns:
            Dict mapping PID -> EOX record dict.
        """
        results = {}
        unique_pids = list(set(pids))

        for i in range(0, len(unique_pids), BATCH_SIZE):
            batch = unique_pids[i:i + BATCH_SIZE]
            param_string = ",".join(batch)

            # Check 250 char limit
            if len(param_string) > 250:
                sub_results = self._lookup_pids_under_limit(batch)
                results.update(sub_results)
                continue

            try:
                records = self._fetch_all_pages(
                    "EOXByProductID/{page}/{params}",
                    param_string,
                )
                self._process_pid_records(records, batch, results)
            except EoxApiError as e:
                logger.error("EOX PID batch lookup failed: %s", e)

        return results

    @staticmethod
    def _process_pid_records(records, batch, results):
        """Process API records into results dict; mark silently-omitted PIDs as not found."""
        responded = set()
        for rec in records:
            returned_pid = rec.get("EOLProductID", "")
            input_val = rec.get("EOXInputValue", "")
            simplified = _simplify_record(rec)
            if returned_pid:
                results[returned_pid] = simplified
                responded.add(returned_pid)
            # Also key by queried PID so variant EOLProductIDs still map back
            if input_val and input_val != returned_pid:
                results[input_val] = simplified
                responded.add(input_val)

        # The EOX API silently omits PIDs it doesn't recognise instead of returning
        # an error record.  Mark any batch input that got no response as not-found
        # so downstream code shows "Not in EOX" rather than "No Data".
        for pid in batch:
            if pid not in responded:
                logger.debug("EOX API returned no record for %r — marking as not found", pid)
                results[pid] = _simplify_record({
                    "EOLProductID": pid,
                    "EOXInputValue": pid,
                    "_pid_not_found": True,
                })

    def _lookup_pids_under_limit(self, pids):
        """Handle batches that exceed 250 char limit by splitting smaller."""
        results = {}
        current_batch = []
        current_len = 0

        for pid in pids:
            needed = len(pid) + (1 if current_batch else 0)  # comma separator
            if current_len + needed > 250:
                if current_batch:
                    param_string = ",".join(current_batch)
                    try:
                        records = self._fetch_all_pages(
                            "EOXByProductID/{page}/{params}",
                            param_string,
                        )
                        self._process_pid_records(records, current_batch, results)
                    except EoxApiError as e:
                        logger.error("EOX PID sub-batch failed: %s", e)
                current_batch = [pid]
                current_len = len(pid)
            else:
                current_batch.append(pid)
                current_len += needed

        if current_batch:
            param_string = ",".join(current_batch)
            try:
                records = self._fetch_all_pages(
                    "EOXByProductID/{page}/{params}",
                    param_string,
                )
                self._process_pid_records(records, current_batch, results)
            except EoxApiError as e:
                logger.error("EOX PID sub-batch failed: %s", e)

        return results

    def lookup_software(self, version_os_pairs):
        """Look up EOX records for software release + OS type pairs.

        Args:
            version_os_pairs: List of (version_string, os_type) tuples.
                e.g., [("16.09.04", "IOS-XE"), ("15.2(4)M7", "IOS")]

        Returns:
            Dict mapping "version|os_type" -> EOX record dict.
        """
        results = {}
        unique_pairs = list(set(version_os_pairs))

        # Send one pair per call — batching returns combined EOXInputValue making
        # per-record attribution impossible.
        for ver, os_type in unique_pairs:
            try:
                records = self._fetch_sw_pages({"input1": f"{ver},{os_type}"})
                for rec in records:
                    if rec.get("EOXInputValue"):
                        results[f"{ver}|{os_type}"] = _simplify_record(rec)
                        break  # first record is representative; rest are variant SKUs
            except EoxApiError as e:
                logger.error("EOX software lookup failed for %s %s: %s", ver, os_type, e)

        return results

    @staticmethod
    def get_os_type(device_type):
        """Map a device_type string to the EOX API OS type."""
        return DEVICE_TYPE_TO_OS.get(device_type)


def _match_sw_record_to_key(record, pairs):
    """Try to match an EOX SW record back to a version|os_type cache key."""
    input_val = record.get("EOXInputValue", "")
    # EOXInputValue might be "16.09.04,IOS-XE" or just the version
    for ver, os_type in pairs:
        if ver in input_val:
            return f"{ver}|{os_type}"
    # Fallback: use EOLProductID if present
    pid = record.get("EOLProductID", "")
    if pid and pairs:
        return f"{pid}|{pairs[0][1]}"
    return None


def _simplify_record(rec):
    """Extract the useful fields from a raw EOX API record."""
    result = {
        "pid": rec.get("EOLProductID", ""),
        "description": rec.get("ProductIDDescription", ""),
        "bulletin_number": rec.get("ProductBulletinNumber", ""),
        "bulletin_url": rec.get("LinkToProductBulletinURL", ""),
        "eox_announcement": _date_val(rec.get("EOXExternalAnnouncementDate")),
        "end_of_sale": _date_val(rec.get("EndOfSaleDate")),
        "end_of_sw_maintenance": _date_val(rec.get("EndOfSWMaintenanceReleases")),
        "end_of_vulnerability_support": _date_val(rec.get("EndOfSecurityVulSupportDate")),
        "end_of_routine_failure_analysis": _date_val(rec.get("EndOfRoutineFailureAnalysisDate")),
        "end_of_service_contract_renewal": _date_val(rec.get("EndOfServiceContractRenewal")),
        "last_date_of_support": _date_val(rec.get("LastDateOfSupport")),
        "end_of_svc_attach": _date_val(rec.get("EndOfSvcAttachDate")),
        "migration_pid": (rec.get("EOXMigrationDetails") or {}).get("MigrationProductId", ""),
        "migration_name": (rec.get("EOXMigrationDetails") or {}).get("MigrationProductName", ""),
        "migration_strategy": (rec.get("EOXMigrationDetails") or {}).get("MigrationStrategy", ""),
    }
    if rec.get("_pid_not_found"):
        result["_pid_not_found"] = True
    if rec.get("_active_no_eox"):
        result["_active_no_eox"] = True
    return result


def _date_val(date_obj):
    """Extract date string from EOX date object, or empty string."""
    if not date_obj or not isinstance(date_obj, dict):
        return ""
    val = date_obj.get("value", "")
    # API returns empty string or " " for dates that don't apply
    return val.strip() if val else ""
