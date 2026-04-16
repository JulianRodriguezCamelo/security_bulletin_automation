import PyPDF2
import os

pdf_path = r"C:\Users\Usuario\Documents\Casos_inteligencia_de_amenazas\Procesados\134. Boletin_seguridad.pdf"

def extract_text(path):
    text = ""
    try:
        with open(path, "rb") as file:
            reader = PyPDF2.PdfReader(file)
            for page in reader.pages:
                extracted = page.extract_text()
                if extracted:
                    text += extracted + "\n"
    except Exception as e:
        print(f"Error: {e}")
    return text

if os.path.exists(pdf_path):
    print(f"Extracted from {pdf_path}:")
    print("-" * 20)
    print(extract_text(pdf_path)[:1000]) # First 1000 chars
    print("-" * 20)
else:
    print(f"File not found: {pdf_path}")
