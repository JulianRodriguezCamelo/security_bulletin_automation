import requests
import re
import logging

logger = logging.getLogger(__name__)

class VirusTotalAnalyzer:
    def __init__(self, api_key):
        self.api_key = api_key
        self.base_url = "https://www.virustotal.com/api/v3/"
        self.headers = {"x-apikey": self.api_key} if self.api_key else {}

    def check_iocs(self, iocs: list[str]) -> dict[str, dict]:
        """
        Analyzes a list of IoCs (IPs, Domains, Hashes) using VirusTotal v3.
        Returns a dict mapping the cleaned IOC to its analysis results.
        """
        results = {}
        if not self.api_key:
            logger.warning("[VT] No API key provided. Skipping real analysis.")
            return results

        for raw_ioc in iocs:
            ioc = self._clean_ioc(raw_ioc)
            if not ioc: continue

            ioc_type = self._detect_type(ioc)
            if not ioc_type:
                logger.warning(f"[VT] Unknown IoC type for: {ioc}")
                continue

            try:
                endpoint = f"{ioc_type}/{ioc}"
                # For files, the endpoint is /v3/files/{hash}
                if ioc_type == "files":
                    endpoint = f"files/{ioc}"
                elif ioc_type == "ip_addresses":
                    endpoint = f"ip_addresses/{ioc}"
                elif ioc_type == "domains":
                    endpoint = f"domains/{ioc}"

                response = requests.get(self.base_url + endpoint, headers=self.headers, timeout=10)
                
                if response.status_code == 200:
                    data = response.json().get("data", {})
                    attributes = data.get("attributes", {})
                    stats = attributes.get("last_analysis_stats", {})
                    
                    malicious = stats.get("malicious", 0)
                    suspicious = stats.get("suspicious", 0)
                    total = sum(stats.values()) if stats else 0
                    
                    results[ioc] = {
                        "type": ioc_type.replace("_", " ").title(),
                        "malicious": malicious,
                        "suspicious": suspicious,
                        "total": total,
                        "status": f"VT detection: {malicious}/{total} malicious",
                        "positives": malicious
                    }
                    logger.info(f"[VT] Analysis for {ioc}: {malicious} malicious detections.")
                else:
                    logger.debug(f"[VT] Error {response.status_code} for {ioc}: {response.text}")
                    results[ioc] = {"status": f"VT Error: {response.status_code}", "malicious": 0, "positives": 0}
            
            except Exception as e:
                logger.error(f"[VT] Exception analyzing {ioc}: {e}")
                results[ioc] = {"status": f"Exception: {str(e)}", "malicious": 0, "positives": 0}

        return results

    # ── Helpers ───────────────────────────────────────────────────────────

    def _clean_ioc(self, ioc: str) -> str:
        """Removes common 'defanging' like [.] or hxxp."""
        if not ioc: return ""
        # Remove [.] and [:]
        cleaned = ioc.replace("[.]", ".").replace("[:]", ":").replace("[", "").replace("]", "")
        # Remove whitespace
        cleaned = cleaned.strip()
        # Remove hxxp prefix if present
        cleaned = re.sub(r'^hxxps?://', '', cleaned, flags=re.IGNORECASE)
        return cleaned

    def _detect_type(self, ioc: str) -> str:
        """Detects if IOC is ip_addresses, domains, or files (hash)."""
        # IP Address (v4)
        if re.match(r'^\d{1,3}(\.\d{1,3}){3}$', ioc):
            return "ip_addresses"
        
        # Hash (MD5: 32, SHA1: 40, SHA256: 64)
        if re.match(r'^[a-fA-F0-9]{32}$|^[a-fA-F0-9]{40}$|^[a-fA-F0-9]{64}$', ioc):
            return "files"
        
        # Domain (generic regex)
        if re.match(r'^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', ioc):
            return "domains"
            
        return ""
