import os
import json
import logging
from groq import Groq, RateLimitError

logger = logging.getLogger(__name__)

_MODEL  = "llama-3.3-70b-versatile"
_PROMPT = """Eres un analista experto en ciberseguridad de un SOC colombiano.
Analiza el siguiente boletín de seguridad y extrae la información estructurada.

REGLAS PARA IDENTIFICAR LA FUENTE ("fuente"):
- Si el texto contiene "COLCERT" → fuente = "COLCERT"
- Si el texto contiene "BOLETIN CSIRT CYWEX" o "CSIRT CYWEX" → fuente = "BOLETIN CSIRT CYWEX"
- Si el texto contiene "Octapus" o "octapus.io" → fuente = "Octapus"
- Si el texto contiene "CERT-CO" → fuente = "CERT-CO"
- Si no coincide con ninguno anterior → extrae el nombre real del vendor/organización emisora del boletín

REGLAS PARA "vulnerabilidad":
- Si el boletín trata una sola CVE → usar esa CVE (ej: "CVE-2026-45585")
- Si trata múltiples CVEs → usar el nombre de la campaña/malware/amenaza principal
- Si es un reporte semanal de inteligencia → usar el título corto
- Si es una alerta de malware específico → usar el nombre del malware

REGLAS PARA "tipo_amenaza":
- Vulnerabilidad: boletines de CVEs, parches, actualizaciones de seguridad
- Malware: troyanos, spyware, adware
- Ransomware: cuando el actor principal es ransomware
- Phishing: campañas de phishing o credential harvesting
- APT: grupos de amenaza persistente avanzada
- Campaña: campañas activas mixtas
- Amenaza/Vulnerabilidad: cuando combina ambas
- Otro: reportes generales o inteligencia semanal

REGLAS PARA IoCs:
- Extraer TODOS los indicadores:
  - IPs
  - dominios
  - hashes
  - URLs
  - emails
  - nombres de archivos maliciosos
- Para hashes:
  - 32 caracteres = MD5
  - 40 caracteres = SHA1
  - 64 caracteres = SHA256
- No incluir URLs bibliográficas o referencias
- Limpiar defang:
  - hxxp → http
  - [.] → .

REGLAS PARA TTPs:
- Extraer técnicas MITRE ATT&CK si aparecen explícitamente
- Formato:
  - T1566.001 Spearphishing Attachment
  - T1059 Command and Scripting Interpreter
- Separar múltiples TTPs por coma

REGLAS PARA CRITICIDAD:
- Crítica: explotación activa, ransomware, RCE crítica, impacto masivo
- Alta: vulnerabilidad severa o malware con alto impacto
- Media: riesgo moderado o requiere condiciones específicas
- Baja: impacto limitado o difícil explotación
- Informativa: inteligencia sin impacto directo

REGLAS PARA PROBABILIDAD:
- Alta: explotación activa o muy probable
- Media: posible explotación
- Baja: baja probabilidad o sin evidencia activa

REGLAS PARA "cves":
- Extraer TODOS los identificadores CVE del boletín (ej: CVE-2024-12345)
- Separar múltiples CVEs por coma
- Si no hay CVEs → cadena vacía ""

REGLAS PARA "nombre":
- Solo aplica si tipo_amenaza = "Vulnerabilidad"
- Usar el nombre del producto/software afectado (ej: "Microsoft Windows", "Apache Log4j 2.x")
- Si tipo_amenaza NO es "Vulnerabilidad" → dejar como cadena vacía "" (el sistema pondrá "NO APLICA")

REGLAS PARA CAMPOS ADICIONALES:
- "estado":
  - Por defecto: "Pendiente"
- "comentarios_soc":
  - Resumen técnico corto para analistas SOC
- "comentarios_fidu":
  - Observaciones ejecutivas o administrativas
- "area_responsable_remediacion":
  - Identificar área probable:
    - Infraestructura
    - Redes
    - Seguridad
    - Desarrollo
    - Usuarios
    - SOC
    - Cloud
    - Endpoint
- "fecha_escalamiento":
  - Solo si el boletín indica escalamiento
  - Formato YYYY-MM-DD
  - Si no existe → vacío

REGLAS PARA EL ID:
- Generar un ID corto único tipo:
  - THREAT-2026-0001
  - IOC-2026-0045

REGLAS PARA "numero_boletin":
- Buscar el número o identificador propio del boletín en el texto.
- Patrones comunes: "Boletín N° 251", "Boletin #251", "ID: WX-251", "No. 2024-047", "CSIRT-2024-001"
- Extraer solo la parte numérica o alfanumérica del identificador (ej: "251", "2024-047")
- Si el boletín es de CSIRT CYWEX / WEXLER → es obligatorio intentar extraerlo
- Si no se encuentra → cadena vacía ""

REGLAS PARA FECHAS:
- fecha_deteccion:
  - Extraer fecha del boletín si existe
  - Formato YYYY-MM-DD
  - Si no existe usar fecha actual

Responde ÚNICAMENTE con un JSON válido con esta estructura exacta:

{
  "id": "<ID generado>",
  "fecha_deteccion": "<YYYY-MM-DD>",
  "tipo_amenaza": "<Vulnerabilidad | Malware | Ransomware | Phishing | APT | Campaña | Amenaza/Vulnerabilidad | Otro>",
  "fuente": "<fuente identificada>",
  "vulnerabilidad": "<nombre corto>",
  "descripcion": "<descripción técnica concisa en español, máx 300 caracteres>",
  "riesgo": "<descripción del riesgo, máx 200 caracteres>",
  "criticidad": "<Crítica | Alta | Media | Baja | Informativa>",
  "probabilidad": "<Alta | Media | Baja>",
  "impacto": "<productos/sistemas/versiones afectadas>",
  "cves": "<CVE-XXXX-XXXXX, CVE-XXXX-XXXXX o vacío>",
  "nombre": "<producto/software afectado, solo si es Vulnerabilidad, si no vacío>",
  "iocs": "<IoCs separados por coma>",
  "ttps": "<MITRE ATT&CK>",
  "accion": "<acción recomendada para el SOC>",
  "comentarios_soc": "<comentario técnico SOC>",
  "estado": "<Pendiente | En análisis | Escalado | Mitigado | Cerrado>",
  "fecha_escalamiento": "<YYYY-MM-DD o vacío>",
  "area_responsable_remediacion": "<área responsable>",
  "comentarios_fidu": "<comentario ejecutivo>",
  "numero_boletin": "<número/ID del boletín extraído del texto, o vacío>",
  "iocs_detalle": [
    {
      "tipo": "<IP|Dominio|Hash MD5|Hash SHA1|Hash SHA256|URL|Email|Archivo>",
      "valor": "<ioc limpio>"
    }
  ]
}

Texto del boletín:
"""

class AIAnalyzer:
    def __init__(self):
        keys = [k for k in [
            os.getenv("GROQ_API_KEY"),
            os.getenv("GROQ_API_KEY_2"),
        ] if k]
        if not keys:
            raise RuntimeError("Se requiere al menos una GROQ_API_KEY en las variables de entorno.")
        self._clients  = [Groq(api_key=k) for k in keys]
        self._next_idx = 0

    def _call_groq(self, content: str) -> str:
        """Intenta cada clave en round-robin; si una está rate-limited usa la siguiente."""
        start = self._next_idx
        for attempt in range(len(self._clients)):
            idx    = (start + attempt) % len(self._clients)
            client = self._clients[idx]
            try:
                resp = client.chat.completions.create(
                    model=_MODEL,
                    messages=[{"role": "user", "content": content}],
                    temperature=0.1,
                    max_tokens=2500,
                )
                # Avanza el puntero para balancear carga en la siguiente llamada
                self._next_idx = (idx + 1) % len(self._clients)
                return resp.choices[0].message.content.strip()
            except RateLimitError:
                logger.warning(f"Groq key {idx + 1} alcanzó el límite, intentando siguiente clave…")
        raise RateLimitError("Todas las claves de Groq han alcanzado el límite de tokens.")

    def analyze(self, text: str, filename: str = "") -> dict:
        logger.info(f"Analyzing with IA: {filename}")
        truncated = text[:16000]

        try:
            raw = self._call_groq(_PROMPT + truncated)

            # Strip markdown fences if present
            if raw.startswith("```"):
                raw = raw.split("```")[1]
                if raw.startswith("json"):
                    raw = raw[4:]
            raw = raw.strip()

            result = json.loads(raw)
            logger.info(f"AI analysis done for {filename}")
            return result

        except json.JSONDecodeError as e:
            logger.warning(f"JSON parse error for {filename}: {e}. Using fallback.")
            return self._fallback(filename)
        except Exception as e:
            logger.error(f"Groq error for {filename}: {e}")
            raise

    @staticmethod
    def _fallback(filename: str) -> dict:
        return {
        "id": "ERROR-0001",
        "fecha_deteccion": "",
        "tipo_amenaza": "Otro",
        "fuente": "Desconocida",
        "vulnerabilidad": filename.replace(".pdf", ""),
        "descripcion": "Error al analizar el boletín con IA.",
        "riesgo": "Sin clasificar",
        "criticidad": "Informativa",
        "probabilidad": "Baja",
        "impacto": "",
        "cves": "",
        "nombre": "",
        "iocs": "",
        "ttps": "",
        "accion": "Revisar manualmente",
        "comentarios_soc": "",
        "estado": "Pendiente",
        "fecha_escalamiento": "",
        "area_responsable_remediacion": "",
        "comentarios_fidu": "",
        "numero_boletin": "",
        "iocs_detalle": [],
        }
