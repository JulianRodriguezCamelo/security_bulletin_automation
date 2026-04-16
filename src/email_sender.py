import smtplib
import logging
from email.message import EmailMessage
from email.mime.multipart import MIMEMultipart
from email.mime.base import MIMEBase
from email.mime.text import MIMEText
from email import encoders
import os


class EmailSender:
    def __init__(self, smtp_host, smtp_port, user, password, company_techs):
        self.smtp_host = smtp_host
        self.smtp_port = smtp_port
        self.user = user
        self.password = password
        self.company_techs = [tech.lower() for tech in company_techs]

    def create_drafts(self, reports):
        for idx, report in enumerate(reports):
            desc = report.get("description", "").lower()

            # Filter relevance
            relevant = any(tech in desc for tech in self.company_techs)

            if relevant:
                msg = EmailMessage()
                msg.set_content(f"Vulnerabilidad relevante:\n\n{report.get('description')}\nRiesgo: {report.get('risk')}")
                msg['Subject'] = f"Borrador: Alerta {report.get('threat_type')}"
                msg['From'] = self.user if self.user else "bot@empresa.com"
                msg['To'] = "equipo@empresa.com"

                draft_path = f"draft_report_{idx}.eml"
                with open(draft_path, "wb") as f:
                    f.write(bytes(msg))
                print(f"Created draft email: {draft_path}")

    def send_excel_report(self, excel_path: str, to_email: str, from_email: str, app_password: str, num_reports: int):
        """Send the Excel report as email attachment via Gmail SMTP."""
        if not os.path.exists(excel_path):
            logging.error(f"Excel file not found, cannot send: {excel_path}")
            return False

        subject = f"Informe de Amenazas de Seguridad — {num_reports} boletín(es) procesado(s)"
        body = (
            f"Hola,\n\n"
            f"Se adjunta el informe actualizado de inteligencia de amenazas.\n"
            f"Boletines procesados en esta ejecución: {num_reports}\n\n"
            f"Este correo fue generado automáticamente por el sistema de automatización de boletines de seguridad.\n\n"
            f"Saludos,\nSistema de Seguridad"
        )

        msg = MIMEMultipart()
        msg['Subject'] = subject
        msg['From'] = from_email
        msg['To'] = to_email
        msg.attach(MIMEText(body, 'plain', 'utf-8'))

        # Attach the Excel file
        filename = os.path.basename(excel_path)
        with open(excel_path, 'rb') as f:
            part = MIMEBase('application', 'vnd.openxmlformats-officedocument.spreadsheetml.sheet')
            part.set_payload(f.read())
        encoders.encode_base64(part)
        part.add_header('Content-Disposition', f'attachment; filename="{filename}"')
        msg.attach(part)

        try:
            logging.info(f"Connecting to Gmail SMTP to send report to {to_email}...")
            with smtplib.SMTP('smtp.gmail.com', 587) as server:
                server.ehlo()
                server.starttls()
                server.ehlo()
                server.login(from_email, app_password)
                server.sendmail(from_email, to_email, msg.as_bytes())
            logging.info(f"Report successfully sent to {to_email}")
            return True
        except smtplib.SMTPAuthenticationError:
            logging.error(
                "Gmail authentication failed. If you have 2-Step Verification enabled, "
                "you need to use an App Password instead of your regular password. "
                "Go to: Google Account → Security → App Passwords"
            )
            return False
        except Exception as e:
            logging.error(f"Failed to send email report: {e}")
            return False
