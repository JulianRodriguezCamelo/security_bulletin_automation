import json
import logging
from groq import Groq

logger = logging.getLogger(__name__)

class AIAnalyzer:
    def __init__(self, api_key):
        self.api_key = api_key
        # Initialize Groq client
        self.client = Groq(api_key=self.api_key)
        # Using Llama 3.3 70B for high-quality extraction
        self.model_id = 'llama-3.3-70b-versatile'

    def analyze_bulletin(self, text):
        """
        Sends text to Groq to extract all threat fields for the security report.
        Returns a dict with all 16 structured fields.
        """
        prompt = f"""Eres un analista experto en ciberseguridad. Analiza el siguiente boletín de seguridad y extrae la información en formato JSON estricto con exactamente estas claves:

- "id": ID o número de boletín que aparece en la parte superior (string)
- "threat_type": Tipo de amenaza o vulnerabilidad (string)
- "source": Fuente de detección, ej: BOLETIN CSIRT CYWEX (string)
- "vulnerability_name": Debe ser estrictamente uno de los siguientes valores: "Vulnerabilidad", "Amenaza", o "Amenaza/Vulnerabilidad". Usa "Vulnerabilidad" si el boletín trata principalmente una falla técnica explotable. Usa "Amenaza" si trata principalmente de un actor malicioso o campaña activa. Usa "Amenaza/Vulnerabilidad" si combina ambos elementos (string)
- "description": Descripción técnica detallada (string)
- "risk_description": Descripción del riesgo (string)
- "possible_impact": SI o NO dependiendo si hay impacto potencial confirmado (string)
- "iocs": Lista de indicadores de compromiso como IPs, hashes, dominios (array de strings, vacío si no hay)
- "ttps": Técnicas, tácticas y procedimientos en formato MITRE ATT&CK ej: T1566 (array de strings, vacío si no hay)
- "recommended_action": Pasos de mitigación y acción recomendada (string)
- "reporter": Siempre debe ser exactamente "WEXLER" (string)
- "soc_comments": Deja vacío string (string)
- "status": Estado inicial: Gestionado (string)
- "fidu_comments": Deja vacío string (string)
- "antivirus_block": NO APLICA (string)
- "firewall_block": NO APLICA (string)
- "firewall_case": NO APLICA (string)

Responde ÚNICAMENTE con el JSON puro, sin bloques de código ```json o texto adicional.

Texto del boletín:
{text}
"""

        try:
            logger.info(f"Calling Groq model: {self.model_id}")
            chat_completion = self.client.chat.completions.create(
                messages=[
                    {
                        "role": "user",
                        "content": prompt,
                    }
                ],
                model=self.model_id,
                response_format={"type": "json_object"}
            )
            raw = chat_completion.choices[0].message.content.strip()
            return json.loads(raw)
        except Exception as e:
            logger.error(f"[AIAnalyzer] Error calling Groq API: {e}")
            return {}
