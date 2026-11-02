"""
Reading and writing scan files as plain or gzip-compressed JSON.

A large scan is hundreds of MB of JSON and compresses about 20:1, so scans
are saved as <id>.json.gz. Readers accept either form and tell them apart by
the gzip magic bytes, not the name, so a renamed file still loads.
"""
import gzip
import json
import os
import tempfile

GZ_SUFFIX = ".json.gz"
SUFFIXES = (GZ_SUFFIX, ".json")
_GZIP_MAGIC = b"\x1f\x8b"


def is_scan_file(name):
    return name.endswith(SUFFIXES)


def strip_suffix(name):
    """'scan.json.gz' and 'scan.json' -> 'scan'."""
    for suffix in SUFFIXES:
        if name.endswith(suffix):
            return name[:-len(suffix)]
    return name


def loads_bytes(data):
    if data[:2] == _GZIP_MAGIC:
        data = gzip.decompress(data)
    return json.loads(data)


def load_json(source):
    """JSON from a path or a binary/text file object, gzip or plain."""
    if isinstance(source, (str, os.PathLike)):
        with open(source, "rb") as f:
            return loads_bytes(f.read())
    data = source.read()
    if isinstance(data, str):
        return json.loads(data)
    return loads_bytes(data)


def write_json(data, path, indent=2):
    """Write data atomically; gzip when path ends in .gz."""
    directory = os.path.dirname(os.path.abspath(path))
    os.makedirs(directory, exist_ok=True)
    fd, tmp_path = tempfile.mkstemp(dir=directory, suffix=".tmp")
    try:
        if path.endswith(".gz"):
            with os.fdopen(fd, "wb") as raw, gzip.GzipFile(
                    fileobj=raw, mode="wb", compresslevel=6, mtime=0) as gz:
                gz.write(json.dumps(data, indent=indent, default=str).encode())
        else:
            with os.fdopen(fd, "w") as f:
                json.dump(data, f, indent=indent, default=str)
        os.replace(tmp_path, path)
    except BaseException:
        os.unlink(tmp_path)
        raise
    return path


def find_scan(directory, key):
    """Path of the saved scan for key (compressed or not), or None."""
    key = strip_suffix(os.path.basename(key))
    for suffix in SUFFIXES:
        path = os.path.join(directory, key + suffix)
        if os.path.exists(path):
            return path
    return None
