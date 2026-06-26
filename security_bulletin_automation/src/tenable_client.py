import re
import logging
import requests

logger = logging.getLogger(__name__)

CVE_PATTERN = re.compile(r'CVE-\d{4}-\d{4,7}', re.IGNORECASE)
SEVERITY_LABELS = {4: "Crítico", 3: "Alto", 2: "Medio", 1: "Bajo", 0: "Info"}


class TenableClient:
    """Queries Tenable Vulnerability Management (cloud.tenable.com) to check
    whether CVEs found in a bulletin affect company assets."""

    BASE_URL = "https://cloud.tenable.com"
    # Look back 90 days so recently-remediated hosts still appear
    DATE_RANGE = 90

    def __init__(self, access_key: str, secret_key: str):
        self.headers = {
            "X-ApiKeys": f"accessKey={access_key};secretKey={secret_key}",
            "Accept": "application/json",
        }

    # ── Public API ────────────────────────────────────────────────────────────

    def check_bulletin(self, text: str) -> dict:
        """Extract CVEs from bulletin text and look them up in Tenable.

        Returns:
            {
                "cves_found":    [str, ...],
                "affected":      [str, ...],   # CVEs with vulnerable hosts
                "not_affected":  [str, ...],   # CVEs with no hosts in Tenable
                "hosts":         {cve: [host_str, ...], ...},
                "severities":    {cve: label_str, ...},
            }
        """
        cves = self._extract_cves(text)
        if not cves:
            return {"cves_found": [], "affected": [], "not_affected": [], "hosts": {}, "severities": {}}

        affected, not_affected, hosts_by_cve, sev_by_cve = [], [], {}, {}

        for cve in cves:
            plugins = self._get_plugins_for_cve(cve)
            if not plugins:
                not_affected.append(cve)
                continue

            # Track the highest severity across all plugins for this CVE
            max_sev = max((p.get("severity", 0) for p in plugins), default=0)
            sev_by_cve[cve] = SEVERITY_LABELS.get(max_sev, "Desconocido")

            # Collect affected hostnames from every matching plugin
            cve_hosts = []
            for plugin in plugins:
                plugin_id = plugin.get("plugin_id")
                if plugin_id:
                    cve_hosts.extend(self._get_hosts_for_plugin(plugin_id))

            cve_hosts = sorted(set(cve_hosts))
            if cve_hosts:
                affected.append(cve)
                hosts_by_cve[cve] = cve_hosts
            else:
                not_affected.append(cve)

        if affected:
            probabilidad = "Alta"
        elif not_affected:
            probabilidad = "Media"
        else:
            probabilidad = "Baja"

        return {
            "cves_found": cves,
            "affected": affected,
            "not_affected": not_affected,
            "hosts": hosts_by_cve,
            "severities": sev_by_cve,
            "probabilidad": probabilidad,
        }

    # ── Internal helpers ──────────────────────────────────────────────────────

    def _extract_cves(self, text: str) -> list[str]:
        return sorted(set(m.upper() for m in CVE_PATTERN.findall(text)))

    def _get_plugins_for_cve(self, cve: str) -> list[dict]:
        """Return vulnerability plugin records that reference this CVE."""
        url = f"{self.BASE_URL}/workbenches/vulnerabilities"
        params = {
            "date_range": self.DATE_RANGE,
            "filter.search_type": "and",
            "filter.0.filter": "plugin.attributes.cve",
            "filter.0.quality": "eq",
            "filter.0.value": cve,
        }
        try:
            r = requests.get(url, headers=self.headers, params=params, timeout=15)
            if r.status_code == 200:
                return r.json().get("vulnerabilities", [])
            logger.warning(f"[Tenable] CVE {cve} query returned HTTP {r.status_code}")
        except Exception as exc:
            logger.error(f"[Tenable] Error querying {cve}: {exc}")
        return []

    def _get_hosts_for_plugin(self, plugin_id: int) -> list[str]:
        """Return display strings for hosts with an open finding for this plugin."""
        url = f"{self.BASE_URL}/workbenches/vulnerabilities/{plugin_id}/outputs"
        try:
            r = requests.get(url, headers=self.headers, timeout=15)
            if r.status_code != 200:
                logger.warning(f"[Tenable] Plugin {plugin_id} outputs returned HTTP {r.status_code}")
                return []

            hosts = []
            for output in r.json().get("outputs", []):
                for state in output.get("states", []):
                    if state.get("name") != "open":
                        continue
                    for result in state.get("results", []):
                        asset = result.get("asset", {})
                        hostname = asset.get("hostname") or result.get("hostname", "")
                        ipv4 = asset.get("ipv4", "")
                        fqdn = asset.get("fqdn", "")
                        label = fqdn or hostname
                        if label and ipv4:
                            hosts.append(f"{label} ({ipv4})")
                        elif label:
                            hosts.append(label)
                        elif ipv4:
                            hosts.append(ipv4)
            return hosts
        except Exception as exc:
            logger.error(f"[Tenable] Error fetching plugin {plugin_id} outputs: {exc}")
            return []


def format_tenable_comment(result: dict) -> str:
    """Build the Spanish-language SOC comment string from a check_bulletin result."""
    if not result.get("cves_found"):
        return "[TENABLE] Sin CVEs identificados en este boletín."

    lines = [f"[TENABLE] {len(result['cves_found'])} CVE(s) analizados en Tenable"]

    if result["affected"]:
        lines.append(f"AFECTA LA EMPRESA ({len(result['affected'])}):")
        for cve in result["affected"]:
            sev = result["severities"].get(cve, "")
            sev_str = f" [{sev}]" if sev else ""
            host_list = result["hosts"].get(cve, [])
            hosts_str = ", ".join(host_list[:10])
            if len(host_list) > 10:
                hosts_str += f" (+{len(host_list) - 10} más)"
            lines.append(f"  • {cve}{sev_str} → {hosts_str}")
    else:
        lines.append(" Ningún CVE del boletín afecta activos de la empresa")

    if result["not_affected"]:
        lines.append(f"❌ NO AFECTA ({len(result['not_affected'])}):")
        for cve in result["not_affected"]:
            lines.append(f"  • {cve}")

    return "\n".join(lines)
