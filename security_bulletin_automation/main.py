"""
CARONTE — Pipeline principal de procesamiento de boletines de seguridad.
Flujo: PDF → Extracción texto → Análisis Groq → VirusTotal → Tenable → Excel
"""
import logging
import os
import shutil
import sys
import time
from pathlib import Path

from dotenv import load_dotenv

load_dotenv()

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%H:%M:%S",
    stream=sys.stdout,
)
logger = logging.getLogger(__name__)

BULLETINS_DIR = Path(os.getenv("DATA_DIR", str(Path(__file__).parent / "data"))).resolve()
PROCESSED_DIR = BULLETINS_DIR / "Procesados"
PAUSE_SECS    = 8   # Respeta límite 12k TPM de Groq


def extract_text(pdf_path: Path) -> str:
    import pdfplumber
    logger.info(f"Processing: {pdf_path.name}")
    text_parts = []
    with pdfplumber.open(pdf_path) as pdf:
        for page in pdf.pages:
            t = page.extract_text()
            if t:
                text_parts.append(t)
    full = "\n".join(text_parts)
    logger.info(f"--- Extracted {len(full)} chars from {pdf_path.name}")
    return full


def process_pdf(pdf_path: Path):
    from src.ai_analyzer import AIAnalyzer
    from src.virustotal  import VirusTotalClient

    logger.info(f"=== Starting: {pdf_path.name} ===")

    # 1. Extract text
    text = extract_text(pdf_path)
    if not text.strip():
        logger.warning(f"No text extracted from {pdf_path.name}, skipping.")
        return

    # 2. AI analysis
    logger.info(f"Analyzing with IA: {pdf_path.name}")
    analyzer = AIAnalyzer()
    analysis = analyzer.analyze(text, pdf_path.name)
    logger.info(f"Analizando completado para {pdf_path.name}")

    # 3. VirusTotal scoring on IoCs
    iocs = analysis.get("iocs_detalle", [])
    if iocs:
        logger.info(f"VirusTotal: scoring {len(iocs)} IoCs for {pdf_path.name}")
        vt = VirusTotalClient()
        vt_results = vt.score_iocs(iocs, delay=1.5)
        analysis["_vt_scores"] = vt_results
        logger.info(f"VirusTotal done for {pdf_path.name}")
    else:
        logger.info(f"VirusTotal: no IoCs found in {pdf_path.name}")

    # 4. Tenable check
    logger.info(f"Tenable: checking vulnerabilities for {pdf_path.name}")
    try:
        from src.tenable_client import TenableClient, format_tenable_comment
        access_key = os.getenv("TENABLE_ACCESS_KEY")
        secret_key = os.getenv("TENABLE_SECRET_KEY")
        if access_key and secret_key:
            tc = TenableClient(access_key=access_key, secret_key=secret_key)
            tenable_result = tc.check_bulletin(text)
            analysis["_tenable_comment"] = format_tenable_comment(tenable_result)

            # ¿Afecta Activos? (Tenable) — resumen corto para la celda
            if not tenable_result.get("cves_found"):
                analysis["_tenable_afecta"] = "NO APLICA"
            elif tenable_result.get("affected"):
                total_hosts = sum(len(v) for v in tenable_result["hosts"].values())
                analysis["_tenable_afecta"] = f"SÍ — {total_hosts} activo(s)"
            else:
                analysis["_tenable_afecta"] = "NO"

            # Solo sobreescribir probabilidad si Tenable encontró CVEs para analizar.
            # Si el boletín no tiene CVEs (malware, phishing, APT), conservar la valoración de la IA.
            if tenable_result.get("cves_found"):
                analysis["probabilidad"] = tenable_result.get("probabilidad", analysis.get("probabilidad", ""))
            logger.info(f"Tenable done for {pdf_path.name}: {len(tenable_result.get('affected', []))} CVE(s) afectan activos — PROBABILIDAD={analysis['probabilidad']}")
        else:
            logger.warning("Tenable skipped: TENABLE_ACCESS_KEY / TENABLE_SECRET_KEY no configuradas")
    except Exception as e:
        logger.warning(f"Tenable skipped: {e}")

    # 5. NVD CPE lookup — compartido por Wappalyzer e Inventario de Activos
    import re as _re
    _CVE_RE = _re.compile(r'CVE-\d{4}-\d{4,7}', _re.IGNORECASE)
    cves_in_bulletin = sorted(set(m.upper() for m in _CVE_RE.findall(text)))
    cve_products_map: dict = {}

    wapp_urls_raw = os.getenv("WAPP_EXTRA_URLS", "").strip()
    asset_api_key  = os.getenv("ASSET_INVENTORY_API_KEY", "").strip()
    needs_nvd = bool((wapp_urls_raw or asset_api_key) and cves_in_bulletin)

    if needs_nvd:
        try:
            from src.nvd_client import NVDClient
            nvd = NVDClient(api_key=os.getenv("NVD_API_KEY") or None)
            for cve in cves_in_bulletin:
                products = nvd.get_cve_products(cve)
                if products:
                    cve_products_map[cve] = products
                else:
                    logger.debug(f"NVD: sin productos CPE para {cve}")
            logger.info(f"NVD: {len(cve_products_map)}/{len(cves_in_bulletin)} CVEs con datos CPE")
        except Exception as exc:
            logger.warning(f"NVD skipped: {exc}")

    # 6. Wappalyzer → correlación de impacto en servidores web propios
    if wapp_urls_raw:
        try:
            from src.wappalyzer_scanner import WappalyzerScanner
            from src.impact_correlator import ImpactCorrelator

            urls = [u.strip() for u in wapp_urls_raw.split(",") if u.strip()]
            if cves_in_bulletin and urls:
                logger.info(f"Wappalyzer: escaneando {len(urls)} URL(s) contra {len(cves_in_bulletin)} CVE(s)")

                scanner = WappalyzerScanner(timeout=int(os.getenv("WAPP_TIMEOUT", 30)))
                inventory = scanner.scan_many(urls)

                if cve_products_map:
                    correlator = ImpactCorrelator(inventory)
                    correlations = correlator.correlate_many(cve_products_map)
                    wapp_report = correlator.format_report(correlations)

                    prev = analysis.get("_tenable_comment", "")
                    analysis["_tenable_comment"] = f"{prev}\n\n{wapp_report}".strip() if prev else wapp_report

                    impacted_urls = sorted(set(
                        url for r in correlations.values() for url in r["impacted_urls"]
                    ))
                    if impacted_urls:
                        prev_afecta = analysis.get("_tenable_afecta", "")
                        suffix = f"WEB: {len(impacted_urls)} servidor(es) afectado(s)"
                        analysis["_tenable_afecta"] = f"{prev_afecta} | {suffix}".lstrip(" | ") if prev_afecta else f"SÍ — {suffix}"
                        logger.info(f"Wappalyzer: impacto detectado en {impacted_urls}")
                    else:
                        logger.info("Wappalyzer: ningún servidor propio afectado")
                else:
                    logger.info("Wappalyzer: NVD no devolvió productos CPE para los CVEs del boletín")
            else:
                logger.info(
                    "Wappalyzer: omitido — "
                    + ("sin CVEs en el boletín" if not cves_in_bulletin else "WAPP_EXTRA_URLS vacío")
                )
        except Exception as exc:
            logger.warning(f"Wappalyzer skipped: {exc}")
    else:
        logger.info("Wappalyzer: WAPP_EXTRA_URLS no configurado, paso omitido")

    # 7. Inventario interno de activos → correlación contra servidores del CMDB
    if asset_api_key:
        try:
            from src.asset_inventory_client import AssetInventoryClient

            asset_url = os.getenv("ASSET_INVENTORY_URL", "http://172.16.0.216/api/external")
            asset_client = AssetInventoryClient(api_key=asset_api_key, base_url=asset_url)

            if cve_products_map:
                inv_result = asset_client.correlate(cve_products_map, bulletin_text=text)
            elif cves_in_bulletin:
                # Sin CPE data de NVD, usar sólo coincidencias de texto (OS keywords)
                empty_map = {cve: [] for cve in cves_in_bulletin}
                inv_result = asset_client.correlate(empty_map, bulletin_text=text)
            else:
                inv_result = {"affected_servers": {}, "by_server": {}, "summary": "Sin CVEs en el boletín"}

            inv_report = asset_client.format_report(inv_result)
            prev = analysis.get("_tenable_comment", "")
            analysis["_tenable_comment"] = f"{prev}\n\n{inv_report}".strip() if prev else inv_report

            affected_by_cve = inv_result.get("affected_servers", {})
            if affected_by_cve:
                total_srvs = len(inv_result.get("by_server", {}))
                prev_afecta = analysis.get("_tenable_afecta", "")
                suffix = f"INVENTARIO: {total_srvs} servidor(es)"
                analysis["_tenable_afecta"] = f"{prev_afecta} | {suffix}".lstrip(" | ") if prev_afecta else f"SÍ — {suffix}"

            logger.info(f"AssetInventory: {inv_result['summary']}")
        except Exception as exc:
            logger.warning(f"AssetInventory skipped: {exc}")
    else:
        logger.info("AssetInventory: ASSET_INVENTORY_API_KEY no configurado, paso omitido")

    # 8. Save record (Oracle o Excel según USE_ORACLE)
    if os.getenv("USE_ORACLE", "false").lower() == "true":
        logger.info(f"Report updated: saving {pdf_path.name} to Oracle")
        from db.oracle_manager import OracleManager
        record_id = OracleManager().add_record(analysis, pdf_path.name)
    else:
        logger.info(f"Report updated: saving {pdf_path.name} to Excel")
        from src.excel_manager import add_record
        record_id = add_record(analysis, pdf_path.name)
    logger.info(f"add_record: ID={record_id} for {pdf_path.name}")

    # 9. Move PDF to Procesados
    PROCESSED_DIR.mkdir(parents=True, exist_ok=True)
    dest = PROCESSED_DIR / pdf_path.name
    if dest.exists():
        ts = time.strftime("%Y%m%d_%H%M%S")
        dest = PROCESSED_DIR / f"{ts}_{pdf_path.name}"
    shutil.move(str(pdf_path.resolve()), str(dest))
    logger.info(f"Moved {pdf_path.name} -> Procesados/")

    logger.info(f"=== Done: {pdf_path.name} (ID={record_id}) ===")


def main():
    BULLETINS_DIR.mkdir(parents=True, exist_ok=True)
    pdfs = sorted(BULLETINS_DIR.glob("*.pdf"))

    if not pdfs:
        logger.info("No PDFs found in Casos_inteligencia_de_amenazas/. Nothing to process.")
        logger.info("Process finished")
        return

    logger.info(f"Found {len(pdfs)} PDF(s) to process.")

    for i, pdf in enumerate(pdfs):
        try:
            process_pdf(pdf)
        except Exception as e:
            logger.error(f"Error processing {pdf.name}: {e}", exc_info=True)

        if i < len(pdfs) - 1:
            logger.info(f"Waiting {PAUSE_SECS}s before next bulletin (Groq TPM limit)…")
            time.sleep(PAUSE_SECS)

    logger.info("finalizado — todos los boletines procesados.")
    logger.info("Process finished")


if __name__ == "__main__":
    main()
