import json
import logging
import os
import re
import concurrent.futures

import requests
from requests.packages.urllib3.exceptions import InsecureRequestWarning

requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

logger = logging.getLogger(__name__)

DEFAULT_CACHE = os.path.join(os.path.dirname(__file__), "..", "data", "tech_inventory.json")

# Header/body fingerprints: pattern → (tech_name, category)
_HEADER_FINGERPRINTS = [
    # Server header
    (r"apache(?:[/ ]([\d.]+))?",           "Server",  "Apache",         ["Web servers"]),
    (r"nginx(?:[/ ]([\d.]+))?",            "Server",  "Nginx",          ["Web servers"]),
    (r"microsoft-iis(?:[/ ]([\d.]+))?",    "Server",  "IIS",            ["Web servers"]),
    (r"litespeed",                         "Server",  "LiteSpeed",      ["Web servers"]),
    (r"openresty(?:[/ ]([\d.]+))?",        "Server",  "OpenResty",      ["Web servers"]),
    (r"tomcat(?:[/ ]([\d.]+))?",           "Server",  "Tomcat",         ["Web servers"]),
    (r"jboss(?:[/ ]([\d.]+))?",            "Server",  "JBoss",          ["Web servers"]),
    (r"weblogic(?:[/ ]([\d.]+))?",         "Server",  "WebLogic",       ["Web servers"]),
    (r"websphere",                         "Server",  "WebSphere",      ["Web servers"]),
    # X-Powered-By
    (r"php(?:[/ ]([\d.]+))?",              "X-Powered-By", "PHP",        ["Programming languages"]),
    (r"asp\.net",                          "X-Powered-By", "ASP.NET",    ["Web frameworks"]),
    (r"express",                           "X-Powered-By", "Express",    ["Web frameworks"]),
    (r"next\.js",                          "X-Powered-By", "Next.js",    ["Web frameworks"]),
    (r"undertow",                          "X-Powered-By", "Undertow",   ["Web servers"]),
    # Dedicated headers
    (r"([\d.]+)",                          "X-AspNet-Version",    "ASP.NET",  ["Web frameworks"]),
    (r"([\d.]+)",                          "X-AspNetMvc-Version", "ASP.NET MVC", ["Web frameworks"]),
    (r".*",                                "X-Drupal-Cache",      "Drupal",   ["CMS"]),
    (r".*",                                "X-Generator",         None,       ["CMS"]),  # value becomes name
    (r".*",                                "X-Joomla-Version",    "Joomla",   ["CMS"]),
]

_COOKIE_FINGERPRINTS = [
    (r"JSESSIONID",      "Java / Tomcat",  ["Web frameworks"]),
    (r"PHPSESSID",       "PHP",            ["Programming languages"]),
    (r"ASP\.NET_Session","ASP.NET",        ["Web frameworks"]),
    (r"laravel_session", "Laravel",        ["Web frameworks"]),
    (r"ci_session",      "CodeIgniter",    ["Web frameworks"]),
    (r"rack\.session",   "Ruby on Rails",  ["Web frameworks"]),
    (r"_cfuid|cf_clearance", "Cloudflare", ["CDN"]),
    (r"__cfduid",        "Cloudflare",     ["CDN"]),
    (r"_ga",             "Google Analytics",["Analytics"]),
]

_HTML_FINGERPRINTS = [
    (r'<meta[^>]+generator[^>]+content=["\']([^"\']+)["\']', "meta-generator"),
    (r'wp-content|wp-includes',          "WordPress"),
    (r'/sites/default/files',            "Drupal"),
    (r'Joomla!',                         "Joomla"),
    (r'data-reactroot|__NEXT_DATA__',    "React / Next.js"),
    (r'ng-version=|angular\.js',         "Angular"),
    (r'__nuxt|nuxtjs',                   "Nuxt.js"),
    (r'<div id=["\']app["\']',           "Vue.js"),
    (r'jquery[.-]([\d.]+)\.min\.js',     "jQuery"),
    (r'bootstrap[.-]([\d.]+)',           "Bootstrap"),
]


class WappalyzerScanner:
    """Detects technology stacks on URLs.

    Primary method: wappalyzer-next (browser-based, most accurate).
    Fallback method: HTTP header + HTML fingerprinting (no browser needed,
    works behind firewalls/VPNs as long as the host returns any HTTP response).

    Install for primary method:
        pip install wappalyzer
        python -m playwright install chromium
    """

    def __init__(self, cache_path: str = None, timeout: int = 30, workers: int = 3):
        self.cache_path = cache_path or DEFAULT_CACHE
        self.timeout = timeout
        self.workers = min(workers, 3)
        self._inventory: dict = self._load_cache()
        self._available: bool = self._check_install()

    # ── Public API ────────────────────────────────────────────────────────────

    def scan_url(self, url: str, force: bool = False) -> dict:
        """Scan one URL. Returns {tech_name: {version, confidence, categories}}."""
        url = self._normalize(url)
        if not force and url in self._inventory:
            logger.info(f"[Wappalyzer] Cache hit: {url}")
            return self._inventory[url]

        techs = {}

        if self._available:
            try:
                from wappalyzer import analyze
                logger.info(f"[Wappalyzer] Scanning {url} ...")
                result = analyze(url=url, scan_type="full", timeout=self.timeout)
                techs = result.get(url, {})
            except Exception as exc:
                logger.debug(f"[Wappalyzer] Browser scan failed for {url}: {exc}")

        if not techs:
            logger.info(f"[HTTPScan] Falling back to header scan for {url}")
            techs = self._http_fingerprint(url)

        if techs:
            self._inventory[url] = techs
            self._save_cache()

        logger.info(f"[Scanner] {url} → {list(techs.keys())}")
        return techs

    def scan_many(self, urls: list[str], force: bool = False) -> dict:
        """Scan a batch of URLs. Uses cache for already-known entries."""
        urls = [self._normalize(u) for u in urls]
        to_scan = [u for u in urls if force or u not in self._inventory]

        if to_scan:
            browser_failed: list[str] = []

            # Try browser-based wappalyzer first
            if self._available:
                try:
                    from wappalyzer import Wappalyzer
                    logger.info(f"[Wappalyzer] Batch scanning {len(to_scan)} URLs ...")
                    with Wappalyzer(workers=self.workers, timeout=self.timeout) as scanner:
                        new = scanner.analyze_many(to_scan)

                    for url, techs in new.items():
                        if techs:
                            self._inventory[url] = techs
                            logger.info(f"[Wappalyzer] {url} → {list(techs.keys())}")
                        else:
                            browser_failed.append(url)
                except Exception as exc:
                    logger.warning(f"[Wappalyzer] Batch scan error: {exc}")
                    browser_failed = to_scan
            else:
                browser_failed = to_scan

            # Fallback: HTTP header scan for anything the browser couldn't detect
            if browser_failed:
                logger.info(f"[HTTPScan] Header-scanning {len(browser_failed)} URL(s) that browser scan missed...")
                with concurrent.futures.ThreadPoolExecutor(max_workers=10) as pool:
                    futures = {pool.submit(self._http_fingerprint, u): u for u in browser_failed}
                    for future in concurrent.futures.as_completed(futures):
                        url = futures[future]
                        try:
                            techs = future.result()
                        except Exception:
                            techs = {}
                        if techs:
                            self._inventory[url] = techs
                            logger.info(f"[HTTPScan] {url} → {list(techs.keys())}")
                        else:
                            logger.debug(f"[HTTPScan] {url} → no response or no fingerprints matched")

            self._save_cache()

        return {u: self._inventory.get(u, {}) for u in urls}

    def get_inventory(self) -> dict:
        return self._inventory

    def is_available(self) -> bool:
        return True  # HTTP fallback is always available

    # ── HTTP Fingerprinting ───────────────────────────────────────────────────

    def _http_fingerprint(self, url: str) -> dict:
        """Detect technologies from HTTP headers and HTML body."""
        techs: dict = {}
        try:
            resp = requests.get(
                url,
                timeout=self.timeout,
                verify=False,  # internal certs are often self-signed
                allow_redirects=True,
                headers={"User-Agent": "Mozilla/5.0 (compatible; SecurityScanner/1.0)"},
            )
        except requests.exceptions.ConnectionError:
            logger.debug(f"[HTTPScan] Connection refused / host unreachable: {url}")
            return {}
        except requests.exceptions.Timeout:
            logger.debug(f"[HTTPScan] Timeout: {url}")
            return {}
        except Exception as exc:
            logger.debug(f"[HTTPScan] Error: {url} — {exc}")
            return {}

        headers = {k.lower(): v for k, v in resp.headers.items()}
        body = ""
        try:
            body = resp.text[:50_000]  # first 50 KB is enough
        except Exception as exc:
            logger.warning(f"[HTTPScan] No se pudo leer el body de {url}: {exc}")

        # Header fingerprints
        for pattern, header_name, tech_name, categories in _HEADER_FINGERPRINTS:
            value = headers.get(header_name.lower(), "")
            if not value:
                continue
            m = re.search(pattern, value, re.I)
            if m:
                name = tech_name or value.strip()  # X-Generator: use the value itself
                version = m.group(1) if m.lastindex and m.lastindex >= 1 else ""
                techs[name] = {"version": version, "confidence": 75, "categories": categories}

        # Cookie fingerprints
        cookie_header = headers.get("set-cookie", "")
        for pattern, tech_name, categories in _COOKIE_FINGERPRINTS:
            if re.search(pattern, cookie_header, re.I):
                if tech_name not in techs:
                    techs[tech_name] = {"version": "", "confidence": 60, "categories": categories}

        # HTML body fingerprints
        if body:
            for item in _HTML_FINGERPRINTS:
                pattern, name = item[0], item[1]
                m = re.search(pattern, body, re.I)
                if m:
                    if name == "meta-generator" and m.lastindex:
                        name = m.group(1).strip()
                    version_match = re.search(r"([\d.]+)", name)
                    version = version_match.group(1) if version_match else ""
                    if name not in techs:
                        techs[name] = {"version": version, "confidence": 80, "categories": ["CMS / Framework"]}

        return techs

    # ── Internals ─────────────────────────────────────────────────────────────

    def _check_install(self) -> bool:
        try:
            import wappalyzer  # noqa: F401
            return True
        except ImportError:
            logger.info(
                "[Wappalyzer] Browser-based scanner not installed. "
                "Using HTTP header fallback. "
                "For full detection: pip install wappalyzer && python -m playwright install chromium"
            )
            return False

    def _load_cache(self) -> dict:
        if os.path.exists(self.cache_path):
            try:
                with open(self.cache_path, encoding="utf-8") as f:
                    return json.load(f)
            except Exception as exc:
                logger.warning(f"[Wappalyzer] Cache corrupta o ilegible, se ignora: {exc}")
        return {}

    def _save_cache(self):
        os.makedirs(os.path.dirname(self.cache_path), exist_ok=True)
        try:
            with open(self.cache_path, "w", encoding="utf-8") as f:
                json.dump(self._inventory, f, indent=2, ensure_ascii=False)
        except Exception as exc:
            logger.error(f"[Wappalyzer] Cache save failed: {exc}")

    @staticmethod
    def _normalize(url: str) -> str:
        url = url.strip()
        if not url.startswith(("http://", "https://")):
            return f"https://{url}"
        return url
