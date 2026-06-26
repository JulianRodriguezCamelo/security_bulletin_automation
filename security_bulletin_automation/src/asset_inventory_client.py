import re
import logging
import requests

logger = logging.getLogger(__name__)

# CPE vendor/product tokens that indicate an OS entry
_OS_VENDORS = {
    "microsoft", "canonical", "ubuntu", "debian", "redhat", "red_hat",
    "centos", "oracle", "suse", "novell", "fedoraproject", "amazon",
    "rocky", "almalinux",
}
_OS_PRODUCT_TOKENS = {
    "windows", "linux", "ubuntu", "debian", "centos", "rhel",
    "enterprise_linux", "windows_server", "ubuntu_linux",
}

# Keywords to scan in plain bulletin text for OS mentions
_BULLETIN_OS_TERMS = [
    "ubuntu", "debian", "centos", "red hat", "rhel", "windows server",
    "windows 10", "windows 11", "rocky linux", "almalinux", "oracle linux",
    "suse", "opensuse", "fedora", "amazon linux", "alpine linux",
]


class AssetInventoryClient:
    """Fetches the internal server inventory and cross-references it with
    vulnerability bulletin data (CVEs / CPE products / OS mentions)."""

    def __init__(self, api_key: str, base_url: str = "http://172.16.0.216/api/external"):
        self.base_url = base_url.rstrip("/")
        self.headers = {"x-api-key": api_key, "Accept": "application/json"}
        self._cache: list[dict] | None = None

    # ── Public API ────────────────────────────────────────────────────────────

    def get_servers(self, force_refresh: bool = False) -> list[dict]:
        """Fetch server list from the inventory API (cached after first call)."""
        if self._cache is None or force_refresh:
            try:
                r = requests.get(
                    f"{self.base_url}/servers",
                    headers=self.headers,
                    timeout=15,
                )
                r.raise_for_status()
                data = r.json()
                # Handle both bare list and wrapped {"data": [...]} responses
                self._cache = data if isinstance(data, list) else data.get("data", data.get("servers", []))
                logger.info(f"[AssetInventory] {len(self._cache)} servidores cargados del inventario")
            except Exception as exc:
                logger.error(f"[AssetInventory] Error al consultar inventario: {exc}")
                self._cache = []
        return self._cache

    def correlate(self, cve_products_map: dict[str, list[dict]], bulletin_text: str = "") -> dict:
        """Compare CVE/CPE products against the internal server inventory.

        Args:
            cve_products_map: {cve_id: [cpe_product_dict, ...]}  — from NVDClient
            bulletin_text:    raw bulletin text for broadening OS keyword matches

        Returns:
            {
                "affected_servers": {cve_id: [server_label_str, ...]},
                "by_server":        {server_name: [cve_id, ...]},
                "summary":          str,
            }
        """
        servers = self.get_servers()
        if not servers:
            return {
                "affected_servers": {},
                "by_server": {},
                "summary": "Sin servidores en inventario o error de conexión",
            }

        bulletin_os_kw = self._extract_os_keywords(bulletin_text)
        affected_servers: dict[str, list[str]] = {}
        by_server: dict[str, list[str]] = {}

        for cve_id, products in cve_products_map.items():
            cve_hits: list[str] = []
            for server in servers:
                reasons = self._match_server(server, products, bulletin_os_kw)
                if reasons:
                    cve_hits.append(self._server_label(server, reasons))
                    srv_key = server.get("nombre") or server.get("id", "desconocido")
                    by_server.setdefault(srv_key, [])
                    if cve_id not in by_server[srv_key]:
                        by_server[srv_key].append(cve_id)
            if cve_hits:
                affected_servers[cve_id] = sorted(cve_hits)

        total_svr = len(by_server)
        total_cve = len(affected_servers)
        summary = (
            f"{total_cve} CVE(s) afectan {total_svr} servidor(es) del inventario interno"
            if total_cve
            else "Ningún servidor del inventario interno afectado"
        )
        return {
            "affected_servers": affected_servers,
            "by_server": by_server,
            "summary": summary,
        }

    def format_report(self, result: dict) -> str:
        """Build the Spanish-language comment block from a correlate() result."""
        lines = ["[INVENTARIO INTERNO DE ACTIVOS]"]
        affected = result.get("affected_servers", {})

        if not affected:
            lines.append("  Ningún servidor del inventario afectado por este boletín.")
            return "\n".join(lines)

        for cve_id, servers in affected.items():
            lines.append(f"  {cve_id} → AFECTA {len(servers)} SERVIDOR(ES) DEL INVENTARIO:")
            for label in servers[:15]:
                lines.append(f"    • {label}")
            if len(servers) > 15:
                lines.append(f"    ... (+{len(servers) - 15} más)")

        by_server = result.get("by_server", {})
        if len(by_server) > 1:
            lines.append(f"  Total servidores expuestos: {len(by_server)}")

        return "\n".join(lines)

    # ── Internal helpers ──────────────────────────────────────────────────────

    def _match_server(
        self,
        server: dict,
        products: list[dict],
        bulletin_os_kw: set[str],
    ) -> list[str]:
        """Return list of match reasons if this server is affected, else []."""
        reasons: list[str] = []
        server_os = (server.get("sistemaOperativo") or "").lower()
        sw_list = server.get("softwareInstalado") or []

        for product in products:
            vendor = (product.get("vendor") or "").lower()
            prod = (product.get("product") or "").lower()
            prod_clean = re.sub(r"[_\-]", " ", prod)

            # 1. OS match via CPE vendor/product
            if self._is_os_cpe(vendor, prod):
                if self._os_matches(server_os, vendor, prod_clean):
                    reasons.append(f"SO:{product.get('product')}")
                    continue

            # 2. Software match against installed packages
            for sw in sw_list:
                sw_name = (sw.get("nombre") or "").lower()
                sw_name_clean = re.sub(r"[_\-]", " ", sw_name)
                if prod_clean and (prod_clean in sw_name_clean or sw_name_clean in prod_clean):
                    sw_ver = sw.get("version") or ""
                    if self._version_in_range(sw_ver, product):
                        reasons.append(f"SW:{sw.get('nombre')}@{sw_ver or '?'}")
                    break

        # 3. Broad OS keyword match from bulletin text (catches free-text like "Ubuntu 22.04")
        if bulletin_os_kw and server_os:
            for kw in bulletin_os_kw:
                already = any(kw in r.lower() for r in reasons)
                if not already and kw in server_os:
                    reasons.append(f"SO-mencion:{kw}")
                    break

        return reasons

    @staticmethod
    def _is_os_cpe(vendor: str, product: str) -> bool:
        return vendor in _OS_VENDORS or any(tok in product for tok in _OS_PRODUCT_TOKENS)

    @staticmethod
    def _os_matches(server_os: str, vendor: str, product_clean: str) -> bool:
        for term in (vendor, product_clean):
            term = re.sub(r"[_\-]", " ", term).strip()
            if term and term in server_os:
                return True
        return False

    @staticmethod
    def _extract_os_keywords(text: str) -> set[str]:
        text_lower = text.lower()
        return {term for term in _BULLETIN_OS_TERMS if term in text_lower}

    @staticmethod
    def _version_in_range(detected: str, product: dict) -> bool:
        """True if detected package version falls within the CPE version range."""
        if not detected:
            return True  # Unknown version → assume potentially affected

        v_exact = product.get("version")
        v_start = product.get("version_start")
        v_end = product.get("version_end")

        if not v_exact and not v_start and not v_end:
            return True  # All versions affected

        def parts(v: str) -> list[int]:
            return [int(x) for x in re.split(r"[.\-]", str(v)) if x.isdigit()]

        def ver_lte(a: str, b: str) -> bool:
            try:
                return parts(a) <= parts(b)
            except Exception:
                return True

        try:
            if v_exact and v_exact not in ("*", "-", ""):
                return ver_lte(v_exact, detected) and ver_lte(detected, v_exact)
            ok_start = ver_lte(v_start, detected) if v_start else True
            ok_end = ver_lte(detected, v_end) if v_end else True
            return ok_start and ok_end
        except Exception:
            return True

    @staticmethod
    def _server_label(server: dict, reasons: list[str]) -> str:
        name = server.get("nombre") or "?"
        ip = server.get("ipInterna") or server.get("ipGestion") or ""
        so = server.get("sistemaOperativo") or ""
        env = server.get("ambiente") or ""
        parts = [name]
        if ip:
            parts.append(f"({ip})")
        if so:
            parts.append(f"[{so}]")
        if env:
            parts.append(env)
        parts.append(f"— {', '.join(reasons[:3])}")
        return " ".join(parts)
