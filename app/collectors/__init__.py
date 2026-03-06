"""
Collector registry. Auto-discovers all collector modules in this package.
"""
import importlib
import pkgutil
from pathlib import Path

from .base import BaseCollector

_registry: dict[str, BaseCollector] | None = None


def _discover() -> dict[str, BaseCollector]:
    """Import all modules in this package and find BaseCollector subclasses."""
    collectors = {}
    package_dir = Path(__file__).parent
    for info in pkgutil.iter_modules([str(package_dir)]):
        if info.name == "base":
            continue
        try:
            module = importlib.import_module(f"app.collectors.{info.name}")
        except ImportError:
            module = importlib.import_module(f"collectors.{info.name}")
        for attr_name in dir(module):
            attr = getattr(module, attr_name)
            if (isinstance(attr, type)
                    and issubclass(attr, BaseCollector)
                    and attr is not BaseCollector):
                instance = attr()
                collectors[instance.name] = instance
    return collectors


def get_registry() -> dict[str, BaseCollector]:
    """Return the collector registry, discovering on first call."""
    global _registry
    if _registry is None:
        _registry = _discover()
    return _registry


def get_collector(name: str) -> BaseCollector | None:
    """Return a collector by name, or None."""
    return get_registry().get(name)
