"""
Report registry. Auto-discovers all report modules in this package.
"""
import importlib
import pkgutil
from pathlib import Path

from .base import BaseReport

_registry: dict[str, BaseReport] | None = None


def _discover() -> dict[str, BaseReport]:
    """Import all modules in this package and find BaseReport subclasses."""
    reports = {}
    package_dir = Path(__file__).parent
    for info in pkgutil.iter_modules([str(package_dir)]):
        if info.name == "base":
            continue
        try:
            module = importlib.import_module(f"app.reports.{info.name}")
        except ImportError:
            module = importlib.import_module(f"reports.{info.name}")
        for attr_name in dir(module):
            attr = getattr(module, attr_name)
            if (isinstance(attr, type)
                    and issubclass(attr, BaseReport)
                    and attr is not BaseReport):
                instance = attr()
                reports[instance.name] = instance
    return reports


def get_registry() -> dict[str, BaseReport]:
    """Return the report registry, discovering on first call."""
    global _registry
    if _registry is None:
        _registry = _discover()
    return _registry


def get_report(name: str) -> BaseReport | None:
    """Return a report by name, or None."""
    return get_registry().get(name)
