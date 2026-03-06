import io
import zipfile
from app.reports.config_archive import ConfigArchiveReport


def test_report_attrs():
    r = ConfigArchiveReport()
    assert r.name == "config_archive"
    assert "config" in r.required_collectors
    assert "zip" in r.supported_formats


def test_generate_zip(sample_inventory):
    r = ConfigArchiveReport()
    data = r.generate(sample_inventory)
    zf = zipfile.ZipFile(io.BytesIO(data))
    names = zf.namelist()
    assert "SW1.txt" in names
    assert "SW2.txt" in names
    content = zf.read("SW1.txt").decode()
    assert "hostname SW1" in content
