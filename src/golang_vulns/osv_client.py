from __future__ import annotations

import io
import json
import urllib.request
import zipfile
from dataclasses import dataclass
from typing import Any, Dict, List


@dataclass
class OsvVulnerability:
    """Simplified representation of an OSV vulnerability."""

    id: str
    summary: str
    details: str
    aliases: List[str]
    affected: List[Dict[str, Any]]
    references: List[Dict[str, Any]]


class OSVClient:
    """Client for fetching vulnerabilities from OSV."""

    BASE_URL: str = "https://osv-vulnerabilities.storage.googleapis.com"
    ECOSYSTEM: str = "Go"

    def fetch_all_vulnerabilities(self) -> List[OsvVulnerability]:
        """Fetch all known vulnerabilities for the Go ecosystem."""

        url = f"{self.BASE_URL}/{self.ECOSYSTEM}/all.zip"
        with urllib.request.urlopen(url) as response:
            data = response.read()

        vulnerabilities: List[OsvVulnerability] = []
        with zipfile.ZipFile(io.BytesIO(data)) as archive:
            for name in archive.namelist():
                with archive.open(name) as file:
                    payload: Dict[str, Any] = json.load(file)
                    vulnerabilities.append(
                        OsvVulnerability(
                            id=payload.get("id", ""),
                            summary=payload.get("summary", ""),
                            details=payload.get("details", ""),
                            aliases=payload.get("aliases", []),
                            affected=payload.get("affected", []),
                            references=payload.get("references", []),
                        )
                    )
        return vulnerabilities
