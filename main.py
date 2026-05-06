import os
import sys
import re
import time
import logging
import subprocess
import ctypes
from windows_toasts import Toast, WindowsToaster, ToastAudio
from datetime import datetime
from dotenv import load_dotenv

from src.email_reader import EmailReader
from src.ai_analyzer import AIAnalyzer
from src.virustotal import VirusTotalAnalyzer
from src.excel_manager import ExcelManager
from src.email_sender import EmailSender
from src.tenable_client import TenableClient, format_tenable_comment
from src.nvd_client import NVDClient
from src.wappalyzer_scanner import WappalyzerScanner
from src.impact_correlator import ImpactCorrelator

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def speak(text):
    """Voice notification (Natural AI voice using edge-tts)."""
    try:
        # Generate audio file
        audio_file = os.path.join(os.environ.get('TEMP', ''), 'notification.mp3')
        
        # We use a natural sounded male voice for Latin America (Jorge)
        voice = "es-MX-JorgeNeural" 
        subprocess.run([sys.executable, "-m", "edge_tts", "-t", text, "--voice", voice, "--write-media", audio_file],
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        
        # Play the audio natively
        if os.path.exists(audio_file):
            winmm = ctypes.windll.winmm
            winmm.mciSendStringW(f'open "{audio_file}" type mpegvideo alias notify_sound', None, 0, None)
            winmm.mciSendStringW('play notify_sound wait', None, 0, None)
            winmm.mciSendStringW('close notify_sound', None, 0, None)
            os.remove(audio_file)
    except Exception as e:
        logging.warning(f"Voice notification failed: {e}")

def notify(title, msg, voice_text=None):
    """Native Windows notification using windows-toasts + Optional Voice."""
    # 1. Visual Notification
    try:
        toaster = WindowsToaster("Security Automation")
        newToast = Toast()
        newToast.text_fields = [title, msg]
        
        # Disable the default windows ding if we are going to speak
        if voice_text:
            newToast.audio = ToastAudio(silent=True)
            
        toaster.show_toast(newToast)
    except Exception as e:
        logging.debug(f"Visual notification failed: {e}")

    # 2. Voice Notification
    if voice_text:
        speak(voice_text)

def main():
    load_dotenv()
    logging.info("Starting security bulletin automation...")
    notify("Security Automation", "Iniciando analisis de boletines.", "Jefe, el análisis de boletines de seguridad ha comenzado.")

    # Config: User Documents folder
    BULLETINS_DIR = os.path.expanduser(r"~\Documents\Casos_inteligencia_de_amenazas")
    PROCESSED_DIR = os.path.join(BULLETINS_DIR, "Procesados")
    os.makedirs(PROCESSED_DIR, exist_ok=True)

    # Initialize modules
    email_reader = EmailReader(
        host=os.getenv("EMAIL_HOST"),
        user=os.getenv("EMAIL_USER"),
        password=os.getenv("EMAIL_PASS")
    )
    # Using Groq as requested
    ai_analyzer = AIAnalyzer(api_key=os.getenv("GROQ_API_KEY"))
    vt_analyzer = VirusTotalAnalyzer(api_key=os.getenv("VT_API_KEY"))

    tenable_client = None
    if os.getenv("TENABLE_ACCESS_KEY") and os.getenv("TENABLE_SECRET_KEY"):
        tenable_client = TenableClient(
            access_key=os.getenv("TENABLE_ACCESS_KEY"),
            secret_key=os.getenv("TENABLE_SECRET_KEY"),
        )
        logging.info("Tenable client initialized.")

    # NVD + Wappalyzer + Correlator setup
    nvd_client = NVDClient(api_key=os.getenv("NVD_API_KEY"))
    wapp_scanner = WappalyzerScanner(timeout=int(os.getenv("WAPP_TIMEOUT", 30)))

    # Seed tech inventory: Tenable assets + any manually configured URLs
    extra_urls = [u.strip() for u in os.getenv("WAPP_EXTRA_URLS", "").split(",") if u.strip()]
    if tenable_client and wapp_scanner.is_available():
        asset_urls = tenable_client.get_asset_urls()
        all_urls = list(dict.fromkeys(asset_urls + extra_urls))
        if all_urls:
            logging.info(f"Scanning {len(all_urls)} asset(s) with Wappalyzer (cached results reused)...")
            wapp_scanner.scan_many(all_urls)
    elif extra_urls and wapp_scanner.is_available():
        wapp_scanner.scan_many(extra_urls)

    correlator = ImpactCorrelator(wapp_scanner.get_inventory())
    
    report_path = os.path.join(BULLETINS_DIR, "Informe_Amenazas.xlsx")
    excel_manager = ExcelManager(output_path=report_path)
    
    company_techs = os.getenv("COMPANY_TECHS", "").split(",")
    email_sender = EmailSender(
        smtp_host=os.getenv("SMTP_HOST"),
        smtp_port=int(os.getenv("SMTP_PORT", 587)),
        user=os.getenv("EMAIL_USER"),
        password=os.getenv("EMAIL_PASS"),
        company_techs=company_techs
    )

    # 1. Fetch Bulletins
    logging.info(f"Checking for bulletins in: {BULLETINS_DIR}")
    
    # Optional IMAP sync (won't crash if fails)
    if os.getenv("EMAIL_USER") and os.getenv("EMAIL_PASS"):
        try:
            email_reader.download_bulletins(download_folder=BULLETINS_DIR)
        except Exception:
            logging.info("IMAP sync skipped (Corporate policy prevents automated login). Using local folder.")

    # Scan the folder for all PDFs
    local_files = [
        os.path.join(BULLETINS_DIR, f) 
        for f in os.listdir(BULLETINS_DIR) 
        if f.lower().endswith(".pdf")
    ]
    
    if not local_files:
        logging.info("No bulletins to process today.")
        notify("Security Automation", "No hay nuevos boletines.", "Jefe, no se han detectado nuevos boletines en la carpeta.")
        return

    reports = []
    # 2. Extract and analyze per PDF
    for pdf_path in local_files:
        filename = os.path.basename(pdf_path)
        logging.info(f"--- Processing: {filename} ---")
        
        text = email_reader.extract_text_from_pdf(pdf_path)
        if not text.strip():
            logging.warning(f"Empty text in {filename}. Skipping.")
            continue
            
        logging.info("Analyzing with IA (Groq)...")
        threat_data = ai_analyzer.analyze_bulletin(text)
        
        # 2b. Extract ID from filename as reliable source
        filename_id_match = re.search(r'(\d+)', filename)
        if filename_id_match:
            filename_id = filename_id_match.group(1)
            # Use filename ID if AI failed or to enforce sequence consistency
            if not threat_data.get("id") or threat_data.get("id") != filename_id:
                threat_data["id"] = filename_id
        
        # 3. Query VirusTotal for IOCs
        iocs = threat_data.get("iocs", [])
        if iocs:
            logging.info(f"Querying VirusTotal for {len(iocs)} IOCs...")
            vt_results = vt_analyzer.check_iocs(iocs)
            threat_data["vt_results"] = vt_results

        # 4. Query Tenable for CVEs found in this bulletin
        tenable_result = None
        if tenable_client:
            logging.info("Querying Tenable for CVEs in bulletin...")
            try:
                tenable_result = tenable_client.check_bulletin(text)
                threat_data["soc_comments"] = format_tenable_comment(tenable_result)
                if tenable_result.get("affected"):
                    logging.info(f"Tenable: {len(tenable_result['affected'])} CVE(s) afectan la empresa → {tenable_result['affected']}")
                else:
                    logging.info("Tenable: Ningún CVE del boletín afecta activos de la empresa.")
            except Exception as e:
                logging.error(f"[Tenable] Unexpected error: {e}")
                threat_data["soc_comments"] = "[TENABLE] Error al consultar la API."

        # 5. Web tech impact via NVD + Wappalyzer
        cves_in_text = sorted(set(re.findall(r'CVE-\d{4}-\d{4,7}', text, re.I)))
        all_cves = list(dict.fromkeys([c.upper() for c in cves_in_text]))

        if all_cves and wapp_scanner.get_inventory():
            logging.info(f"Querying NVD for {len(all_cves)} CVE(s) to assess web tech impact...")
            cve_products_map = {}
            for cve in all_cves:
                products = nvd_client.get_cve_products(cve)
                if products:
                    cve_products_map[cve] = products

            if cve_products_map:
                # Rebuild correlator with current inventory (it may have grown)
                correlator = ImpactCorrelator(wapp_scanner.get_inventory())
                web_correlations = correlator.correlate_many(cve_products_map)
                web_report = correlator.format_report(web_correlations)
                # Append web impact to the soc_comments
                existing = threat_data.get("soc_comments", "")
                threat_data["soc_comments"] = (existing + "\n\n" + web_report).strip()
                affected_by_web = [r["cve"] for r in web_correlations.values() if r["impacted_urls"]]
                if affected_by_web:
                    logging.info(f"[WebTech] {len(affected_by_web)} CVE(s) impactan activos web: {affected_by_web}")
                else:
                    logging.info("[WebTech] Ningún CVE afecta tecnologías web detectadas en el inventario.")
        elif all_cves and not wapp_scanner.get_inventory():
            logging.info("[WebTech] Inventario de tecnologías vacío. Instala wappalyzer o configura WAPP_EXTRA_URLS.")

        reports.append(threat_data)
        excel_manager.add_record(threat_data)
        time.sleep(8)  # Evitar rate limit de Groq (12k TPM)

        # Move to /Procesados
        try:
            dest = os.path.join(PROCESSED_DIR, filename)
            if os.path.exists(dest):
                dest = os.path.join(PROCESSED_DIR, f"{datetime.now().strftime('%Y%m%d_%H%M%S')}_{filename}")
            os.rename(pdf_path, dest)
            logging.info(f"Moved {filename} to /Procesados")
        except Exception as e:
            logging.error(f"Error moving {filename}: {e}")

    # 4. Save Excel, Draft Emails, and Send Report
    if reports:
        excel_manager.save()
        logging.info(f"Report updated at: {report_path}")
        email_sender.create_drafts(reports)

        # Send the Excel report by email
        report_to = os.getenv("REPORT_TO_EMAIL")
        report_from = os.getenv("REPORT_FROM_EMAIL")
        report_pass = os.getenv("REPORT_EMAIL_PASS")
        if report_to and report_from and report_pass:
            sent = email_sender.send_excel_report(
                excel_path=report_path,
                to_email=report_to,
                from_email=report_from,
                app_password=report_pass,
                num_reports=len(reports)
            )
            if sent:
                notify("Security Automation", f"Informe enviado a {report_to}", f"Jefe, el informe ha sido enviado a su correo.")
            else:
                notify("Security Automation", "Error al enviar el correo", "Jefe, no se pudo enviar el informe por correo. Revise los logs.")
        else:
            logging.warning("REPORT_TO_EMAIL / REPORT_FROM_EMAIL / REPORT_EMAIL_PASS not set. Skipping email delivery.")

    logging.info("Process finished successfully.")
    notify("Security Automation", "Proceso completado.", f"Jefe, el análisis ha finalizado. He procesado {len(reports)} boletines y actualizado la bitácora.")

if __name__ == "__main__":
    main()
