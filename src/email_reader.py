import imaplib
import email
import os
import logging
import PyPDF2
from email.header import decode_header

logger = logging.getLogger(__name__)


class EmailReader:
    def __init__(self, host, user, password):
        self.host = host
        self.user = user
        self.password = password

   

    def download_bulletins(
        self,
        subject_filter="Boletines de Seguridad Digital",
        download_folder="./data",
        mark_as_read: bool = False,
    ) -> list[str]:
        """
        Connects via IMAP SSL and downloads PDF attachments from emails
        matching subject_filter. Returns a list of local PDF file paths.
        Set mark_as_read=True to mark messages as SEEN after processing.
        """
        os.makedirs(download_folder, exist_ok=True)
        pdf_files: list[str] = []

        try:
            logger.info(f"Connecting to IMAP host: {self.host}")
            mail = imaplib.IMAP4_SSL(self.host)
            mail.login(self.user, self.password)
            mail.select("inbox")
            logger.info("IMAP login successful.")

            # Search ALL matching emails (read + unread) for testing
            status, message_ids = mail.search(
                None, f'(SUBJECT "{subject_filter}")'
            )

            if status != "OK" or not message_ids[0]:
                logger.info("No matching bulletins found in inbox.")
                mail.logout()
                return pdf_files

            ids = message_ids[0].split()
            logger.info(f"Found {len(ids)} bulletin email(s).")

            for msg_id in ids:
                status, msg_data = mail.fetch(msg_id, "(RFC822)")
                if status != "OK":
                    continue

                raw_email = msg_data[0][1]
                msg = email.message_from_bytes(raw_email)

                subject = self._decode_str(msg.get("Subject", ""))
                logger.info(f"Processing: [{subject}]")

                for part in msg.walk():
                    content_type = part.get_content_type()
                    disposition = str(part.get("Content-Disposition", ""))

                    if "attachment" in disposition and (
                        content_type == "application/pdf"
                        or part.get_filename("").lower().endswith(".pdf")
                    ):
                        filename = self._decode_str(
                            part.get_filename(f"attachment_{msg_id.decode()}.pdf")
                        )
                        safe_name = "".join(
                            c if c.isalnum() or c in (" ", "-", "_", ".") else "_"
                            for c in filename
                        )
                        filepath = os.path.join(download_folder, safe_name)

                        with open(filepath, "wb") as f:
                            f.write(part.get_payload(decode=True))
                        logger.info(f"Downloaded PDF: {filepath}")
                        pdf_files.append(filepath)

                if mark_as_read:
                    mail.store(msg_id, "+FLAGS", "\\Seen")

            mail.logout()

        except imaplib.IMAP4.error as e:
            logger.debug(f"IMAP error: {e}")
        except Exception as e:
            logger.error(f"Unexpected error in download_bulletins: {e}")

        return pdf_files

    def extract_text_from_pdf(self, pdf_path: str) -> str:
        """Extract all text from a PDF file using PyPDF2."""
        text = ""
        try:
            with open(pdf_path, "rb") as file:
                reader = PyPDF2.PdfReader(file)
                for page in reader.pages:
                    extracted = page.extract_text()
                    if extracted:
                        text += extracted + "\n"
        except Exception as e:
            logger.error(f"Error reading {pdf_path}: {e}")
        return text

    # ── Helpers ───────────────────────────────────────────────────────────

    @staticmethod
    def _decode_str(value) -> str:
        """Decode encoded email header strings."""
        if not value:
            return ""
        decoded_parts = decode_header(value)
        result = ""
        for part, encoding in decoded_parts:
            if isinstance(part, bytes):
                result += part.decode(encoding or "utf-8", errors="replace")
            else:
                result += str(part)
        return result
