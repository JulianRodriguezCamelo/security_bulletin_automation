import os
import re
import time
import logging
import requests

logger = logging.getLogger(__name__)

_BASE = "https://www.virustotal.com/api/v3"


class VirusTotalClient:
    def __init__(self):
        self.api_key = os.getenv("VT_API_KEY", "")
        self.headers = {"x-apikey": self.api_key}

    def _get(self, endpoint: str) -> dict:
        if not self.api_key:
            return {}
        try:
            r = requests.get(f"{_BASE}/{endpoint}", headers=self.headers, timeout=15)
            if r.status_code == 200:
                return r.json()
            logger.warning(f"VT {endpoint}: {r.status_code}")
        except Exception as e:
            logger.warning(f"VT request error: {e}")
        return {}

    def score_ioc(self, ioc: str) -> dict:
        ioc = ioc.strip()
        if not ioc or not self.api_key:
            return {"ioc": ioc, "malicious": 0, "total": 0, "type": "unknown"}

        if re.match(r"^\d+\.\d+\.\d+\.\d+$", ioc):
            endpoint, ioc_type = f"ip_addresses/{ioc}", "IP"
        elif re.match(r"^[a-fA-F0-9]{32}$", ioc):
            endpoint, ioc_type = f"files/{ioc}", "Hash MD5"
        elif re.match(r"^[a-fA-F0-9]{64}$", ioc):
            endpoint, ioc_type = f"files/{ioc}", "Hash SHA256"
        elif re.match(r"^https?://", ioc):
            import base64
            encoded = base64.urlsafe_b64encode(ioc.encode()).decode().rstrip("=")
            endpoint, ioc_type = f"urls/{encoded}", "URL"
        else:
            endpoint, ioc_type = f"domains/{ioc}", "Dominio"

        data = self._get(endpoint)
        if not data:
            return {"ioc": ioc, "malicious": 0, "total": 0, "type": ioc_type}

        stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
        return {
            "ioc": ioc,
            "type": ioc_type,
            "malicious": stats.get("malicious", 0),
            "suspicious": stats.get("suspicious", 0),
            "total": sum(stats.values()) if stats else 0,
        }

    def score_iocs(self, iocs: list[dict], delay: float = 1.0) -> list[dict]:
        results = []
        for item in iocs:
            valor = item.get("valor", "")
            if valor:
                score = self.score_ioc(valor)
                score["tipo"] = item.get("tipo", score.get("type", ""))
                results.append(score)
                time.sleep(delay)
        return results
