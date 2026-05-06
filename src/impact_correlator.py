import re
import logging

logger = logging.getLogger(__name__)

# Maps "vendor:product" (CPE) → Wappalyzer technology names
# Extend this table as your environment grows
CPE_TO_WAPPALYZER: dict[str, list[str]] = {
    # CMS
    "wordpress:wordpress": ["WordPress"],
    "automattic:wordpress": ["WordPress"],
    "drupal:drupal": ["Drupal"],
    "joomla:joomla!": ["Joomla"],
    "joomla:joomla": ["Joomla"],
    "typo3:typo3": ["TYPO3 CMS"],
    # Web servers
    "apache:http_server": ["Apache HTTP Server", "Apache"],
    "apache:httpd": ["Apache HTTP Server", "Apache"],
    "nginx:nginx": ["Nginx"],
    "microsoft:iis": ["IIS", "Microsoft IIS"],
    "litespeed_technologies:litespeed_web_server": ["LiteSpeed"],
    # Languages / runtimes
    "php:php": ["PHP"],
    "nodejs:node.js": ["Node.js"],
    "python:python": ["Python"],
    "oracle:jdk": ["Java"],
    "oracle:jre": ["Java"],
    # Frameworks
    "djangoproject:django": ["Django"],
    "django:django": ["Django"],
    "laravel:laravel": ["Laravel"],
    "rubyonrails:ruby_on_rails": ["Ruby on Rails"],
    "spring:spring_framework": ["Spring Framework"],
    "pivotal_software:spring_framework": ["Spring Framework"],
    "expressjs:express": ["Express"],
    "facebook:react": ["React"],
    "google:angular": ["Angular"],
    "angular:angular": ["Angular"],
    "vuejs:vue.js": ["Vue.js"],
    "vercel:next.js": ["Next.js"],
    "nextjs:next.js": ["Next.js"],
    "nuxt:nuxt.js": ["Nuxt.js"],
    # JS libraries
    "jquery:jquery": ["jQuery"],
    "jquery:jquery_ui": ["jQuery UI"],
    "jquery:jquery_migrate": ["jQuery Migrate"],
    "bootstrap:bootstrap": ["Bootstrap"],
    "lodash:lodash": ["Lodash"],
    "moment:moment.js": ["Moment.js"],
    # Application servers
    "apache:tomcat": ["Apache Tomcat"],
    "eclipse:jetty": ["Jetty"],
    "redhat:jboss": ["JBoss"],
    "oracle:weblogic_server": ["Oracle WebLogic Server"],
    # E-commerce
    "magento:magento": ["Magento"],
    "adobe:magento": ["Magento", "Adobe Commerce"],
    "woocommerce:woocommerce": ["WooCommerce"],
    "shopify:shopify": ["Shopify"],
    "prestashop:prestashop": ["PrestaShop"],
    # Security / network
    "openssl:openssl": ["OpenSSL"],
    "fortinet:fortios": ["Fortinet"],
    "fortinet:fortigate": ["FortiGate"],
    "cisco:ios": ["Cisco IOS"],
    "cisco:adaptive_security_appliance_software": ["Cisco ASA"],
    "citrix:netscaler": ["Citrix ADC"],
    "f5:big-ip": ["F5 BIG-IP"],
    "paloaltonetworks:pan-os": ["Palo Alto Networks PAN-OS"],
    "cloudflare:cloudflare": ["Cloudflare"],
    # CDN / caching
    "varnish-software:varnish_cache": ["Varnish"],
    "squid-cache:squid": ["Squid"],
    # Databases (sometimes exposed via admin panels)
    "mysql:mysql": ["MySQL"],
    "mariadb:mariadb": ["MariaDB"],
    "postgresql:postgresql": ["PostgreSQL"],
    "microsoft:sql_server": ["Microsoft SQL Server"],
    "mongodb:mongodb": ["MongoDB"],
    "elastic:elasticsearch": ["Elasticsearch"],
    "redis:redis": ["Redis"],
    # OS (Wappalyzer can sometimes detect these)
    "canonical:ubuntu_linux": ["Ubuntu"],
    "ubuntu:ubuntu_linux": ["Ubuntu"],
    "debian:debian_linux": ["Debian"],
    "redhat:enterprise_linux": ["Red Hat Enterprise Linux", "RHEL"],
    "centos:centos": ["CentOS"],
    "microsoft:windows_server": ["Windows Server"],
    # Analytics / monitoring
    "grafana:grafana": ["Grafana"],
    "elastic:kibana": ["Kibana"],
}


class ImpactCorrelator:
    """Cross-references CVE CPE data with the Wappalyzer tech inventory.

    Usage:
        correlator = ImpactCorrelator(wappalyzer_scanner.get_inventory())
        result = correlator.correlate("CVE-2024-1234", nvd_client.get_cve_products("CVE-2024-1234"))
    """

    def __init__(self, tech_inventory: dict):
        # tech_inventory: {url: {TechName: {version, confidence, categories, ...}}}
        self.inventory = tech_inventory
        self._tech_index = self._build_index()

    def correlate(self, cve_id: str, cpe_products: list[dict]) -> dict:
        """Return impact analysis for one CVE.

        Returns:
            {
                "cve": str,
                "impacted_urls": [str, ...],
                "matches": [{"url", "tech_name", "detected_version", "cpe"}, ...],
                "summary": str,
            }
        """
        impacted_urls: set[str] = set()
        matches: list[dict] = []

        for product in cpe_products:
            wapp_names = self._resolve(product)
            for wapp_name in wapp_names:
                for url in self._tech_index.get(wapp_name.lower(), []):
                    detected = self.inventory[url].get(wapp_name, {})
                    detected_version = detected.get("version", "")
                    if self._in_range(detected_version, product):
                        impacted_urls.add(url)
                        matches.append({
                            "url": url,
                            "tech_name": wapp_name,
                            "detected_version": detected_version or "desconocida",
                            "cpe": product.get("cpe", ""),
                        })

        summary = self._build_summary(cve_id, impacted_urls, matches)
        return {
            "cve": cve_id,
            "impacted_urls": sorted(impacted_urls),
            "matches": matches,
            "summary": summary,
        }

    def correlate_many(self, cve_products_map: dict[str, list[dict]]) -> dict:
        """Correlate multiple CVEs at once.

        cve_products_map: {cve_id: [cpe_product, ...]}
        Returns: {cve_id: correlate_result}
        """
        return {cve: self.correlate(cve, products) for cve, products in cve_products_map.items()}

    def format_report(self, correlations: dict) -> str:
        """Build Spanish-language comment block from correlate_many results."""
        lines = ["[WEB TECH IMPACT]"]
        any_impact = False

        for cve_id, result in correlations.items():
            if result["impacted_urls"]:
                any_impact = True
                lines.append(f"  [!] {cve_id} -> IMPACTO DETECTADO EN:")
                for m in result["matches"]:
                    ver = f" v{m['detected_version']}" if m["detected_version"] != "desconocida" else ""
                    lines.append(f"       * {m['url']} ({m['tech_name']}{ver})")
            else:
                lines.append(f"  [OK] {cve_id} -> Sin tecnologias web afectadas en el inventario")

        if not any_impact:
            lines.append("  Ningun activo web del inventario usa tecnologias afectadas por este boletin.")

        return "\n".join(lines)

    # ── Internals ─────────────────────────────────────────────────────────────

    def _build_index(self) -> dict[str, list[str]]:
        """Inverted index: lowercase tech name → list of URLs."""
        idx: dict[str, list[str]] = {}
        for url, techs in self.inventory.items():
            for tech_name in techs:
                idx.setdefault(tech_name.lower(), []).append(url)
        return idx

    def _resolve(self, product: dict) -> list[str]:
        """Map a CPE product dict to Wappalyzer technology names."""
        vendor = product.get("vendor", "").lower()
        prod = product.get("product", "").lower()

        # Exact vendor:product match
        key = f"{vendor}:{prod}"
        if key in CPE_TO_WAPPALYZER:
            return CPE_TO_WAPPALYZER[key]

        # Partial match on product part only
        for cpe_key, wapp_names in CPE_TO_WAPPALYZER.items():
            if cpe_key.split(":")[-1] == prod:
                return wapp_names

        # Fuzzy fallback: check if CPE product words appear in any known tech name
        prod_clean = re.sub(r"[_\-]", " ", prod).lower()
        found: list[str] = []
        for tech_lower in self._tech_index:
            tech_clean = re.sub(r"[_\-]", " ", tech_lower).lower()
            if prod_clean in tech_clean or tech_clean in prod_clean:
                # Recover original casing from inventory
                for url, techs in self.inventory.items():
                    for t in techs:
                        if t.lower() == tech_lower and t not in found:
                            found.append(t)
        return found

    def _in_range(self, detected: str, product: dict) -> bool:
        """Return True if detected version falls within the CPE version range."""
        if not detected:
            return True  # Version unknown → assume potentially affected

        v_exact = product.get("version")
        v_start = product.get("version_start")
        v_end = product.get("version_end")

        if v_exact and v_exact not in ("*", "-", ""):
            return self._ver_lte(v_exact, detected) and self._ver_lte(detected, v_exact)

        if not v_start and not v_end:
            return True  # All versions affected

        try:
            ok_start = self._ver_lte(v_start, detected) if v_start else True
            ok_end = self._ver_lte(detected, v_end) if v_end else True
            return ok_start and ok_end
        except Exception:
            return True

    @staticmethod
    def _ver_lte(a: str, b: str) -> bool:
        def parts(v):
            return [int(x) for x in re.split(r"[.\-]", str(v)) if x.isdigit()]
        try:
            return parts(a) <= parts(b)
        except Exception:
            return True

    @staticmethod
    def _build_summary(cve_id: str, impacted_urls: set, matches: list) -> str:
        if not impacted_urls:
            return f"{cve_id}: sin impacto detectado en activos web"
        techs = list({m["tech_name"] for m in matches})
        return f"{cve_id}: impacta {len(impacted_urls)} URL(s) via {', '.join(techs)}"
