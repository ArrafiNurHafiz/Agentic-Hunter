import subprocess
import pytest
from bughunter.adapters import get_adapter, list_adapters
from bughunter.adapters.base import AdapterMode, RawFinding
from bughunter.adapters.subfinder_adapter import SubfinderAdapter
from bughunter.adapters.httpx_adapter import HttpxAdapter
from bughunter.adapters.nmap_adapter import NmapAdapter
from bughunter.adapters.katana_adapter import KatanaAdapter
from bughunter.adapters.nuclei_adapter import NucleiAdapter
from bughunter.adapters.ffuf_adapter import FFuFAdapter


def test_registry_and_manifests():
    adapters = list_adapters()
    assert set(adapters) == {"subfinder", "httpx", "nmap", "katana", "nuclei", "ffuf"}

    sub = get_adapter("subfinder")
    assert sub.manifest.mode == AdapterMode.PASSIVE

    for name in ["httpx", "nmap", "katana", "nuclei", "ffuf"]:
        adapter = get_adapter(name)
        assert adapter is not None
        assert adapter.manifest.mode == AdapterMode.ACTIVE


def test_subfinder_parsing():
    adapter = SubfinderAdapter()
    raw = '{"host":"api.target.com","input":"target.com"}\n{"host":"admin.target.com","input":"target.com"}'
    findings = adapter.parse_output(raw, "target.com")
    assert len(findings) == 2
    assert findings[0].endpoint == "api.target.com"
    assert findings[0].tool == "subfinder"
    assert findings[0].vuln_type == "subdomain"


def test_httpx_parsing():
    adapter = HttpxAdapter()
    raw = '{"url":"http://192.168.1.50:8000","status_code":200,"title":"Dashboard","tech":["PHP","Laravel"]}'
    findings = adapter.parse_output(raw, "192.168.1.50:8000")
    assert len(findings) == 1
    f = findings[0]
    assert f.endpoint == "http://192.168.1.50:8000"
    assert f.evidence["status_code"] == 200
    assert "Laravel" in f.evidence["tech"]


def test_nmap_parsing():
    adapter = NmapAdapter()
    raw = """
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.2p1 Ubuntu
80/tcp   open  http    nginx 1.18.0
443/tcp  closed https
"""
    findings = adapter.parse_output(raw, "192.168.1.50")
    assert len(findings) == 2
    assert findings[0].evidence["port"] == 22
    assert findings[1].evidence["port"] == 80
    assert findings[1].evidence["service"] == "http"


def test_katana_parsing():
    adapter = KatanaAdapter()
    raw = '{"request":{"endpoint":"http://target.local/api/v1/users","method":"GET"}}\n{"request":{"endpoint":"http://target.local/login","method":"POST"}}'
    findings = adapter.parse_output(raw, "target.local")
    assert len(findings) == 2
    assert findings[0].endpoint == "http://target.local/api/v1/users"
    assert findings[0].evidence["method"] == "GET"


def test_nuclei_parsing():
    adapter = NucleiAdapter()
    raw = '{"template-id":"cve-2023-1234","info":{"name":"Sample Vulnerability","severity":"critical","classification":{"cve-id":"CVE-2023-1234"}},"matched-at":"http://target.local/vuln"}'
    findings = adapter.parse_output(raw, "target.local")
    assert len(findings) == 1
    f = findings[0]
    assert f.vuln_type == "cve-2023-1234"
    assert f.severity == "CRITICAL"
    assert f.endpoint == "http://target.local/vuln"


def test_ffuf_parsing():
    adapter = FFuFAdapter()
    raw = '{"results":[{"input":{"FUZZ":"admin"},"url":"http://target.local/admin","status":200,"length":512,"words":32}]}'
    findings = adapter.parse_output(raw, "target.local")
    assert len(findings) == 1
    assert findings[0].endpoint == "http://target.local/admin"
    assert findings[0].evidence["input"] == "admin"


def test_adapter_timeout_handling(monkeypatch):
    adapter = HttpxAdapter()
    def mock_run_command(argv, timeout=60):
        raise subprocess.TimeoutExpired(argv, timeout)
    monkeypatch.setattr("bughunter.adapters.base.run_command", mock_run_command)
    findings = adapter.run("http://timeout.local", timeout=5)
    assert len(findings) == 1
    assert findings[0].vuln_type == "scan_timeout"
