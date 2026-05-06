import base64
import logging
import os
import re
import tempfile
import time
from datetime import datetime, timedelta

import pandas as pd
import requests
import streamlit as st
import yaml
from dotenv import load_dotenv
from yaml.loader import SafeLoader

import streamlit_authenticator as stauth

from src.email_reader import EmailReader
from src.ai_analyzer import AIAnalyzer
from src.virustotal import VirusTotalAnalyzer
from src.excel_manager import ExcelManager
from src.tenable_client import TenableClient, format_tenable_comment
from src.nvd_client import NVDClient
from src.wappalyzer_scanner import WappalyzerScanner
from src.impact_correlator import ImpactCorrelator

load_dotenv()

# ── Persistent report path (used for local dev; cloud uses GitHub) ─────────────
REPORT_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data", "Informe_Amenazas.xlsx")

# ── Audit log ─────────────────────────────────────────────────────────────────
_audit_handler = logging.FileHandler("security_audit.log", encoding="utf-8")
_audit_handler.setFormatter(logging.Formatter("%(asctime)s | %(message)s"))
_audit_log = logging.getLogger("security_audit")
_audit_log.setLevel(logging.INFO)
_audit_log.addHandler(_audit_handler)
_audit_log.propagate = False


def audit(username: str, action: str, detail: str = "") -> None:
    _audit_log.info(f"user={username!r} | action={action} | {detail}")


# ── Secret resolution: Streamlit Cloud first, then .env ───────────────────────
def get_secret(key: str, default=None) -> str | None:
    try:
        val = st.secrets.get(key)
        if val is not None:
            return str(val)
    except Exception:
        pass
    return os.getenv(key, default)


def load_auth_config() -> dict:
    """Load auth config from Streamlit secrets (cloud) or auth_config.yaml (local)."""
    try:
        if "auth_config_yaml" in st.secrets:
            return yaml.safe_load(st.secrets["auth_config_yaml"])
    except Exception:
        pass
    auth_file = os.path.join(os.path.dirname(__file__), "auth_config.yaml")
    if not os.path.exists(auth_file):
        st.error(
            "No se encontró `auth_config.yaml`. "
            "Ejecuta `python setup_auth.py` o configura `auth_config_yaml` en los secretos de Streamlit."
        )
        st.stop()
    with open(auth_file) as f:
        return yaml.load(f, Loader=SafeLoader)


# ── GitHub persistence ────────────────────────────────────────────────────────
def _gh_headers() -> dict:
    return {
        "Authorization": f"Bearer {get_secret('GITHUB_TOKEN')}",
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
    }


def download_excel_from_github() -> tuple[bytes | None, str | None]:
    """Returns (file_bytes, sha) or (None, None) if not found."""
    repo = get_secret("GITHUB_REPO")
    path = get_secret("GITHUB_EXCEL_PATH", "data/Informe_Amenazas.xlsx")
    branch = get_secret("GITHUB_BRANCH", "main")
    try:
        r = requests.get(
            f"https://api.github.com/repos/{repo}/contents/{path}",
            headers=_gh_headers(),
            params={"ref": branch},
            timeout=15,
        )
        if r.status_code == 200:
            data = r.json()
            return base64.b64decode(data["content"]), data["sha"]
    except Exception as e:
        _audit_log.warning(f"GitHub download failed: {e}")
    return None, None


def upload_excel_to_github(excel_bytes: bytes, sha: str | None) -> bool:
    """Upload Excel to GitHub repo. Returns True on success."""
    repo = get_secret("GITHUB_REPO")
    path = get_secret("GITHUB_EXCEL_PATH", "data/Informe_Amenazas.xlsx")
    branch = get_secret("GITHUB_BRANCH", "main")
    payload = {
        "message": f"chore: update threat report [{datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')}]",
        "content": base64.b64encode(excel_bytes).decode(),
        "branch": branch,
    }
    if sha:
        payload["sha"] = sha
    try:
        r = requests.put(
            f"https://api.github.com/repos/{repo}/contents/{path}",
            headers=_gh_headers(),
            json=payload,
            timeout=30,
        )
        return r.status_code in (200, 201)
    except Exception as e:
        _audit_log.error(f"GitHub upload failed: {e}")
        return False


USE_GITHUB = bool(get_secret("GITHUB_TOKEN") and get_secret("GITHUB_REPO"))

# ── Security constants ────────────────────────────────────────────────────────
MAX_LOGIN_ATTEMPTS = 5
LOCKOUT_DURATION = timedelta(minutes=15)
MAX_FILE_SIZE_MB = 20
MAX_FILES = 10
PDF_MAGIC = b"%PDF"


def check_lockout() -> None:
    st.session_state.setdefault("login_attempts", 0)
    st.session_state.setdefault("locked_until", None)
    locked_until = st.session_state["locked_until"]
    if locked_until and datetime.now() < locked_until:
        remaining = int((locked_until - datetime.now()).total_seconds())
        mins, secs = divmod(remaining, 60)
        st.error(f"Cuenta bloqueada. Vuelve a intentarlo en {mins}m {secs}s.")
        audit("UNKNOWN", "LOGIN_BLOCKED", f"remaining={remaining}s")
        st.stop()
    elif locked_until and datetime.now() >= locked_until:
        st.session_state["locked_until"] = None
        st.session_state["login_attempts"] = 0


def register_failed_login() -> None:
    st.session_state["login_attempts"] += 1
    attempts = st.session_state["login_attempts"]
    audit("UNKNOWN", "LOGIN_FAILED", f"attempt={attempts}/{MAX_LOGIN_ATTEMPTS}")
    if attempts >= MAX_LOGIN_ATTEMPTS:
        st.session_state["locked_until"] = datetime.now() + LOCKOUT_DURATION
        st.error(f"Demasiados intentos fallidos. Acceso bloqueado por {int(LOCKOUT_DURATION.total_seconds() // 60)} minutos.")
        st.stop()
    st.error(f"Usuario o contraseña incorrectos. {MAX_LOGIN_ATTEMPTS - attempts} intento(s) restante(s).")
    st.stop()


def safe_filename(name: str) -> str:
    name = os.path.basename(name)
    return re.sub(r"[^\w\-_. ]", "_", name)[:200]


def validate_upload(file) -> str | None:
    raw = file.getbuffer()
    size_mb = len(raw) / (1024 * 1024)
    if size_mb > MAX_FILE_SIZE_MB:
        return f"**{file.name}**: excede el límite de {MAX_FILE_SIZE_MB} MB ({size_mb:.1f} MB)."
    if bytes(raw[:4]) != PDF_MAGIC:
        return f"**{file.name}**: no es un PDF válido."
    return None


def validate_env() -> list[str]:
    return [f"GROQ_API_KEY (IA)" for k in ["GROQ_API_KEY"] if not get_secret(k)]


# ── Page config ───────────────────────────────────────────────────────────────
st.set_page_config(page_title="Security Bulletin Analyzer", page_icon="🛡️", layout="wide")

# ── Auth ──────────────────────────────────────────────────────────────────────
config = load_auth_config()
authenticator = stauth.Authenticate(
    config["credentials"],
    config["cookie"]["name"],
    config["cookie"]["key"],
    config["cookie"]["expiry_days"],
)

check_lockout()
authenticator.login()

auth_status = st.session_state.get("authentication_status")
if auth_status is False:
    register_failed_login()
if auth_status is None:
    st.info("Ingresa tu usuario y contraseña para acceder.")
    st.stop()

# ── Post-login ────────────────────────────────────────────────────────────────
username = st.session_state.get("username", "unknown")
name = st.session_state.get("name", username)

if not st.session_state.get("_login_logged"):
    audit(username, "LOGIN_SUCCESS")
    st.session_state["_login_logged"] = True
if st.session_state.get("login_attempts", 0) > 0:
    st.session_state["login_attempts"] = 0
    st.session_state["locked_until"] = None

# ── Sidebar ───────────────────────────────────────────────────────────────────
with st.sidebar:
    st.title("🛡️ Security Bulletin")
    st.write(f"👤 **{name}**")
    if authenticator.logout("Cerrar sesión", "sidebar"):
        audit(username, "LOGOUT")
    st.divider()
    storage_label = "☁️ GitHub" if USE_GITHUB else "💾 Local"
    st.caption(f"Almacenamiento: {storage_label}")
    st.caption("Sube PDFs → el sistema analiza con IA, VirusTotal y Tenable → genera Excel acumulado.")

# ── Env check ─────────────────────────────────────────────────────────────────
missing = validate_env()
if missing:
    st.error("Faltan variables críticas:\n\n" + "\n".join(f"- `{v}`" for v in missing))
    st.stop()

# ── Main ──────────────────────────────────────────────────────────────────────
st.title("📋 Analizador de Boletines de Seguridad")

uploaded_files = st.file_uploader(
    "Arrastra aquí los boletines en PDF",
    type=["pdf"],
    accept_multiple_files=True,
    help=f"Máximo {MAX_FILES} archivos · Máximo {MAX_FILE_SIZE_MB} MB por archivo.",
)

if not uploaded_files:
    st.info("Sube al menos un PDF para comenzar.")
    st.stop()

if len(uploaded_files) > MAX_FILES:
    st.error(f"Máximo {MAX_FILES} archivos por envío. Seleccionaste {len(uploaded_files)}.")
    st.stop()

errors = [e for f in uploaded_files if (e := validate_upload(f))]
if errors:
    for err in errors:
        st.error(err)
    st.stop()

st.success(f"✅ {len(uploaded_files)} archivo(s) válido(s) y listo(s) para procesar.")

if not st.button("🚀 Procesar boletines", type="primary", use_container_width=True):
    st.stop()

# ── Processing ────────────────────────────────────────────────────────────────
reports: list[dict] = []
excel_bytes: bytes | None = None
filenames_processed: list[str] = []

with st.status("Iniciando procesamiento...", expanded=True) as status:
    try:
        os.makedirs(os.path.dirname(REPORT_PATH), exist_ok=True)

        # ── 1. Fetch accumulated Excel from GitHub (cloud) or use local file ──
        excel_sha = None
        if USE_GITHUB:
            st.write("☁️ Descargando informe acumulado desde GitHub...")
            existing_bytes, excel_sha = download_excel_from_github()
            if existing_bytes:
                with open(REPORT_PATH, "wb") as f:
                    f.write(existing_bytes)
                st.write("✅ Informe existente cargado desde GitHub.")
            else:
                st.write("📄 Primera ejecución: se creará el informe desde cero.")

        with tempfile.TemporaryDirectory() as tmpdir:
            pdf_paths = []
            for uf in uploaded_files:
                sname = safe_filename(uf.name)
                dest = os.path.join(tmpdir, sname)
                with open(dest, "wb") as f:
                    f.write(uf.getbuffer())
                pdf_paths.append(dest)
                filenames_processed.append(sname)
                st.write(f"📁 **{sname}** guardado.")

            st.write("⚙️ Inicializando módulos...")
            email_reader = EmailReader(
                host=get_secret("EMAIL_HOST"),
                user=get_secret("EMAIL_USER"),
                password=get_secret("EMAIL_PASS"),
            )
            ai_analyzer = AIAnalyzer(api_key=get_secret("GROQ_API_KEY"))
            vt_analyzer = VirusTotalAnalyzer(api_key=get_secret("VT_API_KEY"))

            tenable_client = None
            if get_secret("TENABLE_ACCESS_KEY") and get_secret("TENABLE_SECRET_KEY"):
                tenable_client = TenableClient(
                    access_key=get_secret("TENABLE_ACCESS_KEY"),
                    secret_key=get_secret("TENABLE_SECRET_KEY"),
                )
                st.write("🔒 Cliente Tenable inicializado.")

            nvd_client = NVDClient(api_key=get_secret("NVD_API_KEY"))
            wapp_scanner = WappalyzerScanner(timeout=int(get_secret("WAPP_TIMEOUT", "30")))

            extra_urls = [u.strip() for u in (get_secret("WAPP_EXTRA_URLS") or "").split(",") if u.strip()]
            if tenable_client and wapp_scanner.is_available():
                asset_urls = tenable_client.get_asset_urls()
                all_urls = list(dict.fromkeys(asset_urls + extra_urls))
                if all_urls:
                    st.write(f"🌐 Escaneando {len(all_urls)} URL(s) con Wappalyzer...")
                    wapp_scanner.scan_many(all_urls)
            elif extra_urls and wapp_scanner.is_available():
                wapp_scanner.scan_many(extra_urls)

            excel_manager = ExcelManager(output_path=REPORT_PATH)

            for i, pdf_path in enumerate(pdf_paths):
                filename = os.path.basename(pdf_path)
                st.write(f"📄 **[{i+1}/{len(pdf_paths)}] {filename}**")

                text = email_reader.extract_text_from_pdf(pdf_path)
                if not text.strip():
                    st.warning(f"⚠️ {filename}: sin texto extraíble. Saltando.")
                    continue

                st.write("🤖 Analizando con IA (Groq)...")
                threat_data = ai_analyzer.analyze_bulletin(text)

                m = re.search(r"(\d+)", filename)
                if m:
                    fid = m.group(1)
                    if not threat_data.get("id") or threat_data.get("id") != fid:
                        threat_data["id"] = fid

                iocs = threat_data.get("iocs", [])
                if iocs:
                    st.write(f"🔍 Consultando VirusTotal ({len(iocs)} IOC(s))...")
                    threat_data["vt_results"] = vt_analyzer.check_iocs(iocs)

                if tenable_client:
                    st.write("🔒 Consultando Tenable...")
                    try:
                        tenable_result = tenable_client.check_bulletin(text)
                        threat_data["soc_comments"] = format_tenable_comment(tenable_result)
                        affected = tenable_result.get("affected", [])
                        if affected:
                            st.write(f"⚠️ Tenable: {len(affected)} CVE(s) afectan la empresa.")
                        else:
                            st.write("✅ Tenable: ningún CVE afecta activos propios.")
                    except Exception:
                        _audit_log.error("Tenable error", exc_info=True)
                        st.warning("Tenable no disponible. Continuando sin esos datos.")
                        threat_data["soc_comments"] = "[TENABLE] Error al consultar la API."

                cves = list(dict.fromkeys(
                    c.upper() for c in re.findall(r"CVE-\d{4}-\d{4,7}", text, re.I)
                ))
                if cves and wapp_scanner.get_inventory():
                    st.write(f"🌐 Correlacionando {len(cves)} CVE(s) con tecnologías web...")
                    cve_products_map = {}
                    for cve in cves:
                        products = nvd_client.get_cve_products(cve)
                        if products:
                            cve_products_map[cve] = products
                    if cve_products_map:
                        correlator = ImpactCorrelator(wapp_scanner.get_inventory())
                        web_correlations = correlator.correlate_many(cve_products_map)
                        web_report = correlator.format_report(web_correlations)
                        existing = threat_data.get("soc_comments", "")
                        threat_data["soc_comments"] = (existing + "\n\n" + web_report).strip()

                reports.append(threat_data)
                excel_manager.add_record(threat_data)

                if i < len(pdf_paths) - 1:
                    st.write("⏳ Esperando 8s (límite de velocidad de Groq)...")
                    time.sleep(8)

            # ── 2. Save Excel and push to GitHub ──────────────────────────────
            if reports:
                excel_manager.save()
                with open(REPORT_PATH, "rb") as f:
                    excel_bytes = f.read()

                if USE_GITHUB:
                    st.write("☁️ Guardando informe actualizado en GitHub...")
                    ok = upload_excel_to_github(excel_bytes, excel_sha)
                    if ok:
                        st.write("✅ Informe guardado en GitHub.")
                    else:
                        st.warning("⚠️ No se pudo guardar en GitHub. Descarga el archivo manualmente.")
                        _audit_log.error(f"GitHub upload failed for user={username}")

                audit(username, "BULLETINS_PROCESSED", f"count={len(reports)} files={filenames_processed}")
                status.update(
                    label=f"✅ Completado: {len(reports)} boletín(es) añadido(s) al informe acumulado",
                    state="complete",
                )
            else:
                status.update(label="⚠️ No se procesó ningún boletín.", state="error")

    except Exception:
        _audit_log.error(f"Processing error user={username!r} files={filenames_processed}", exc_info=True)
        status.update(label="❌ Error durante el procesamiento", state="error")
        st.error("Ocurrió un error interno. Contacta al administrador e indica la hora aproximada del fallo.")

# ── Results ───────────────────────────────────────────────────────────────────
if reports:
    st.divider()
    st.subheader(f"📊 Resumen — {len(reports)} boletín(es) añadidos")

    rows = []
    for r in reports:
        title = r.get("title") or r.get("titulo") or r.get("name") or "—"
        severity = r.get("severity") or r.get("severidad") or "—"
        cve_count = len(re.findall(r"CVE-\d{4}-\d{4,7}", str(r), re.I))
        rows.append({
            "ID": r.get("id", "—"),
            "Título": title[:80],
            "Severidad": severity,
            "IOCs": len(r.get("iocs", [])),
            "CVEs": cve_count,
        })
    st.dataframe(pd.DataFrame(rows), use_container_width=True, hide_index=True)

    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    st.download_button(
        label="⬇️ Descargar informe completo (acumulado)",
        data=excel_bytes,
        file_name=f"Informe_Amenazas_{ts}.xlsx",
        mime="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        type="primary",
        use_container_width=True,
    )
