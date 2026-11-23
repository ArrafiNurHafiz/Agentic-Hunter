"""FFuF fast web fuzzer adapter."""
import json
from typing import List
from bughunter.adapters.base import BaseScannerAdapter, CapabilityManifest, AdapterMode, RawFinding


class FFuFAdapter(BaseScannerAdapter):
    def __init__(self):
        super().__init__(CapabilityManifest(
            name="ffuf",
            mode=AdapterMode.ACTIVE,
            timeout=180,
            rate_limit_cost=10,
            supported_targets=["url"],
            description="Fast web fuzzer written in Go",
        ))

    def build_command(self, target: str, **kwargs) -> List[str]:
        wordlist = kwargs.get("wordlist", "/dev/null")
        url = target if "FUZZ" in target else target.rstrip("/") + "/FUZZ"
        cmd = ["ffuf", "-u", url, "-w", wordlist, "-of", "json", "-s"]
        match_codes = kwargs.get("match_codes", "200,204,301,302,307,401,403,500")
        cmd.extend(["-mc", match_codes])
        return cmd

    def parse_output(self, raw_output: str, target: str) -> List[RawFinding]:
        findings = []
        try:
            data = json.loads(raw_output)
            results = data.get("results", [])
            for res in results:
                url = res.get("url", "")
                status = res.get("status", 0)
                length = res.get("length", 0)
                words = res.get("words", 0)
                input_word = (res.get("input") or {}).get("FUZZ", "")
                findings.append(RawFinding(
                    tool="ffuf",
                    target=target,
                    endpoint=url,
                    vuln_type="fuzzed_path",
                    severity="INFO" if status < 400 else "LOW",
                    description=f"Fuzz match: {input_word} (HTTP {status}, length: {length})",
                    raw_output=json.dumps(res),
                    evidence={
                        "status": status,
                        "length": length,
                        "words": words,
                        "input": input_word,
                        "url": url,
                    },
                ))
        except json.JSONDecodeError:
            # Fallback for line-by-line if not valid top-level JSON
            for line in raw_output.splitlines():
                line = line.strip()
                if line:
                    findings.append(RawFinding(
                        tool="ffuf",
                        target=target,
                        endpoint=target,
                        vuln_type="fuzz_result",
                        severity="INFO",
                        description=line,
                        raw_output=line,
                    ))
        return findings
