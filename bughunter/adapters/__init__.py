"""Adapter registry for external security tools."""
from typing import Dict, List, Optional
from bughunter.adapters.base import BaseScannerAdapter
from bughunter.adapters.subfinder_adapter import SubfinderAdapter
from bughunter.adapters.httpx_adapter import HttpxAdapter
from bughunter.adapters.nmap_adapter import NmapAdapter
from bughunter.adapters.katana_adapter import KatanaAdapter
from bughunter.adapters.nuclei_adapter import NucleiAdapter
from bughunter.adapters.ffuf_adapter import FFuFAdapter

_REGISTRY: Dict[str, BaseScannerAdapter] = {
    "subfinder": SubfinderAdapter(),
    "httpx": HttpxAdapter(),
    "nmap": NmapAdapter(),
    "katana": KatanaAdapter(),
    "nuclei": NucleiAdapter(),
    "ffuf": FFuFAdapter(),
}


def get_adapter(name: str) -> Optional[BaseScannerAdapter]:
    return _REGISTRY.get(name.lower())


def list_adapters() -> List[str]:
    return list(_REGISTRY.keys())
