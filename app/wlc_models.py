"""
Controller and AP lifecycle facts from config/wlc_models.yaml.

The table is configuration so an engineer can correct it against Cisco's
current compatibility matrix without a code change.
"""
import logging
import re
from functools import lru_cache
from pathlib import Path

import yaml

logger = logging.getLogger(__name__)

_HERE = Path(__file__).resolve().parent
# Repository layout first (app/../config), then the image's (/app/config).
_CANDIDATES = [_HERE.parent / "config" / "wlc_models.yaml", _HERE / "config" / "wlc_models.yaml"]

EMPTY = {"max_aireos": "", "c9800": "", "wifi": ""}


@lru_cache(maxsize=None)
def load(path=None):
    for candidate in ([Path(path)] if path else _CANDIDATES):
        try:
            with open(candidate) as f:
                data = yaml.safe_load(f) or {}
            return {"controllers": data.get("controllers") or {}, "aps": data.get("aps") or {}}
        except FileNotFoundError:
            continue
        except Exception as e:
            logger.warning(f"Could not read {candidate}: {e}")
            break
    return {"controllers": {}, "aps": {}}


def _facts(entry):
    return {k: str((entry or {}).get(k) or "") for k in EMPTY}


def controller_facts(pid, table=None):
    table = (table or load())["controllers"]
    pid = str(pid or "").upper()
    best = max((k for k in table if pid.startswith(k.upper())), key=len, default=None)
    return _facts(table.get(best)) if best else dict(EMPTY)


def ap_series(model):
    """'AIR-CAP2602I-A-K9' -> '2602', 'C9120AXI-B' -> '9120'."""
    m = re.search(r"(?:AP|^C|-)(\d{4})", str(model or "").upper())
    return m.group(1) if m else ""


def ap_facts(model, table=None):
    table = (table or load())["aps"]
    series = ap_series(model)
    if not series:
        return dict(EMPTY)
    for key in (series, series[:3] + "0", series[:2] + "00"):
        if key in table:
            return _facts(table[key])
    return dict(EMPTY)


def version_tuple(version):
    return tuple(int(p) for p in re.findall(r"\d+", str(version or ""))[:4])
