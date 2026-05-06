import time
import logging
import requests

logger = logging.getLogger(__name__)

NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"


class NVDClient:
    """Queries the NVD API to get CPE (affected products) for a given CVE."""

    def __init__(self, api_key: str = None):
        self.headers = {"apiKey": api_key} if api_key else {}
        # Without API key: 5 req/30s → sleep 6s. With key: 50 req/30s → sleep 0.6s
        self._sleep = 0.6 if api_key else 6.0

    def get_cve_products(self, cve_id: str) -> list[dict]:
        """Return a list of affected products for the given CVE.

        Each entry:
            {vendor, product, version, version_start, version_end, cpe}
        """
        for attempt in range(3):
            try:
                r = requests.get(
                    NVD_URL,
                    headers=self.headers,
                    params={"cveId": cve_id},
                    timeout=15,
                )
                if r.status_code == 429:
                    wait = 30 * (attempt + 1)
                    logger.warning(f"[NVD] Rate limited on {cve_id}. Waiting {wait}s...")
                    time.sleep(wait)
                    continue
                if r.status_code != 200:
                    logger.warning(f"[NVD] {cve_id} returned HTTP {r.status_code}")
                    return []

                vulns = r.json().get("vulnerabilities", [])
                if not vulns:
                    return []

                products = self._extract_products(vulns[0].get("cve", {}))
                time.sleep(self._sleep)
                return products

            except Exception as exc:
                logger.error(f"[NVD] Error fetching {cve_id} (attempt {attempt+1}): {exc}")
                time.sleep(self._sleep)

        return []

    def _extract_products(self, cve_data: dict) -> list[dict]:
        products = []
        for config in cve_data.get("configurations", []):
            for node in config.get("nodes", []):
                for match in node.get("cpeMatch", []):
                    if not match.get("vulnerable", False):
                        continue
                    product = self._parse_cpe(match)
                    if product:
                        products.append(product)

        # Also check references descriptions for context (just CPE-based is enough)
        return self._deduplicate(products)

    def _parse_cpe(self, cpe_match: dict) -> dict | None:
        # CPE 2.3 format: cpe:2.3:type:vendor:product:version:...
        uri = cpe_match.get("criteria", "")
        parts = uri.split(":")
        if len(parts) < 6:
            return None

        vendor = parts[3]
        product = parts[4]
        version = parts[5] if parts[5] not in ("*", "-", "") else "*"

        return {
            "vendor": vendor,
            "product": product,
            "version": version,
            "version_start": cpe_match.get("versionStartIncluding")
                             or cpe_match.get("versionStartExcluding"),
            "version_end": cpe_match.get("versionEndIncluding")
                           or cpe_match.get("versionEndExcluding"),
            "cpe": uri,
        }

    @staticmethod
    def _deduplicate(products: list[dict]) -> list[dict]:
        seen, unique = set(), []
        for p in products:
            key = f"{p['vendor']}:{p['product']}"
            if key not in seen:
                seen.add(key)
                unique.append(p)
        return unique
