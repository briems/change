from __future__ import annotations

import shutil
import subprocess
from pathlib import Path


class SubdomainProvider:
    def discover(self, domain: str) -> list[str]:
        raise NotImplementedError


class FileProvider(SubdomainProvider):
    def __init__(self, subs_file: str) -> None:
        self.subs_file = Path(subs_file)

    def discover(self, domain: str) -> list[str]:
        if not self.subs_file.exists():
            return []
        hosts = [line.strip().lower() for line in self.subs_file.read_text(encoding="utf-8").splitlines()]
        hosts = [h for h in hosts if h and (h == domain or h.endswith(f".{domain}"))]
        return sorted(set(hosts))


class AmassProvider(SubdomainProvider):
    def __init__(self) -> None:
        self.binary = self._find_binary()

    @staticmethod
    def _find_binary() -> list[str] | None:
        if shutil.which("snap"):
            return ["snap", "run", "amass"]
        if shutil.which("amass"):
            return ["amass"]
        return None

    def discover(self, domain: str) -> list[str]:
        if not self.binary:
            return []
        cmd = [*self.binary, "enum", "-passive", "-d", domain]
        try:
            out = subprocess.check_output(cmd, stderr=subprocess.STDOUT, text=True, timeout=120)
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired):
            return []
        hosts = [line.strip().lower() for line in out.splitlines() if line.strip()]
        hosts = [h for h in hosts if h == domain or h.endswith(f".{domain}")]
        return sorted(set(hosts))
