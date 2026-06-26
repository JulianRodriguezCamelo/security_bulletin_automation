# Security Bulletin Automation

Sistema automatizado de inteligencia de amenazas que procesa boletines de seguridad en PDF, enriquece los datos con APIs externas y genera reportes Excel estructurados para equipos SOC.

## Flujo general

```
[Email IMAP] → [PDF] → [Extracción de texto]
                              ↓
                    [Análisis con Groq LLM]
                              ↓
              ┌───────────────┼───────────────┐
              ↓               ↓               ↓
        [VirusTotal]    [Tenable API]   [NVD + Wappalyzer]
        (IoC scoring)  (Activos afect.) (Correlación CVE)
              └───────────────┼───────────────┘
                              ↓
                  [Informe_Amenazas.xlsx]
                              ↓
              [Email SMTP + Notificación Windows]
```

## Requisitos

- Python 3.11+
- Windows (para notificaciones Toast y TTS)
- Acceso a los servicios externos configurados (ver sección de configuración)

## Instalación

### 1. Clonar el repositorio

```bash
git clone <url-del-repositorio>
cd security_bulletin_automation
```

### 2. Crear y activar entorno virtual

```bash
python -m venv venv
venv\Scripts\activate
```

### 3. Instalar dependencias

```bash
pip install -r requirements.txt
```

### 4. Instalar Playwright (requerido para Wappalyzer)

```bash
python -m playwright install chromium
```

> Si Playwright no está disponible, el sistema cae en modo fallback usando fingerprinting por cabeceras HTTP.

### 5. Configurar variables de entorno

Copia el archivo de ejemplo y completa los valores:

```bash
cp .env.example .env
```

Edita `.env` con tus credenciales reales (ver sección siguiente).

## Configuración

### Variables de entorno (`.env`)

```env
# ── Correo entrante (IMAP) ──────────────────────────────────────────
EMAIL_HOST=outlook.office365.com
EMAIL_USER=tu_correo@empresa.com
EMAIL_PASS=tu_contraseña

# ── Correo saliente (SMTP) ──────────────────────────────────────────
SMTP_HOST=smtp.office365.com
SMTP_PORT=587

# ── API Keys ────────────────────────────────────────────────────────
GROQ_API_KEY=gsk_...               # https://console.groq.com
VT_API_KEY=...                     # https://www.virustotal.com/gui/my-apikey
TENABLE_ACCESS_KEY=...             # Tenable.io → Settings → API Keys
TENABLE_SECRET_KEY=...
NVD_API_KEY=                       # Opcional: https://nvd.nist.gov/developers/request-an-api-key

# ── Entrega del reporte ─────────────────────────────────────────────
REPORT_TO_EMAIL=destinatario@gmail.com
REPORT_FROM_EMAIL=remitente@gmail.com
REPORT_EMAIL_PASS=xxxx xxxx xxxx xxxx   # Contraseña de aplicación Gmail

# ── Configuración de la aplicación ─────────────────────────────────
COMPANY_TECHS=Google Chrome,Windows,Fortinet,Oracle,WordPress
DATA_DIR=./data
WAPP_EXTRA_URLS=https://portal.empresa.com,https://intranet.empresa.com
WAPP_TIMEOUT=30
```

#### Obtener las API Keys

| Servicio | Cómo obtenerla |
|---|---|
| **Groq** | Regístrate en [console.groq.com](https://console.groq.com) → API Keys |
| **VirusTotal** | Cuenta gratuita en [virustotal.com](https://www.virustotal.com) → My API Key |
| **Tenable** | Tenable.io → Settings → My Account → API Keys |
| **NVD** | Solicitud gratuita en [nvd.nist.gov](https://nvd.nist.gov/developers/request-an-api-key) |
| **Gmail SMTP** | Google Account → Security → App Passwords (requiere 2FA activo) |

## Uso

### Ejecución principal

```bash
python main.py
```

El script:
1. Conecta al correo por IMAP y descarga PDFs de la carpeta `Boletines de Seguridad Digital`
2. También procesa PDFs locales en `~/Documents/Casos_inteligencia_de_amenazas/`
3. Analiza cada PDF con Groq (Llama 3.3 70B)
4. Consulta VirusTotal, Tenable y NVD para enriquecer los datos
5. Genera el reporte en `~/Documents/Casos_inteligencia_de_amenazas/Informe_Amenazas.xlsx`
6. Envía el reporte por correo y muestra notificación Windows con TTS

### Scripts auxiliares

```bash
# Re-clasificar el campo "Vulnerabilidad / Amenaza" con IA en el Excel existente
python reanalyze_vuln_field.py

# Inspeccionar estructura del Excel generado
python check_excel.py

# Probar extracción de texto de un PDF específico
python test_extract.py
```

## Estructura del proyecto

```
security_bulletin_automation/
├── main.py                    # Punto de entrada principal
├── requirements.txt
├── .env.example               # Plantilla de configuración
│
├── src/
│   ├── ai_analyzer.py         # Análisis con Groq LLM
│   ├── email_reader.py        # Cliente IMAP + extracción PDF
│   ├── email_sender.py        # Envío SMTP + creación de borradores
│   ├── excel_manager.py       # Generación de reporte Excel
│   ├── virustotal.py          # Cliente VirusTotal v3
│   ├── tenable_client.py      # Cliente Tenable Vulnerability Management
│   ├── nvd_client.py          # Cliente NVD para datos de CVE
│   ├── wappalyzer_scanner.py  # Fingerprinting de tecnologías web
│   └── impact_correlator.py   # Motor de correlación CVE ↔ tecnología
│
├── data/
│   ├── tech_inventory.json    # Caché de resultados Wappalyzer
│   └── Informe_Amenazas.xlsx  # Reporte generado (ubicación alternativa)
│
├── reanalyze_vuln_field.py    # Utilidad: re-clasificar campo de amenaza
├── check_excel.py             # Utilidad: depurar Excel
└── test_extract.py            # Utilidad: probar extracción PDF
```

## Reporte Excel generado

**Hoja 1 — Registro de Amenazas** (18 columnas):
ID, Fecha Detección, Tipo de Amenaza, Fuente, Vulnerabilidad/Amenaza, Descripción, Descripción del Riesgo, Posible Impacto, Indicadores (IoC), TTP (MITRE ATT&CK), Acción Recomendada, Reportó, Comentarios SOC, Estado, Comentarios FIDU, Bloqueo Antivirus, Bloqueo Firewall, Caso Firewall.

**Hoja 2 — Detalle de IoCs** (6 columnas):
Tipo de IoC, IoC, Fecha, Antivirus, Firewall, Caso Firewall.

## Dev Container

El proyecto incluye configuración para VS Code Dev Containers con Python 3.11:

```bash
# Abrir en VS Code y seleccionar "Reopen in Container"
code .
```

## Notas importantes

- El sistema introduce una pausa de 8 segundos entre boletines para respetar el límite de 12k TPM de Groq.
- Los PDFs procesados se mueven automáticamente a la subcarpeta `Procesados/`.
- El caché de Wappalyzer (`tech_inventory.json`) evita re-escanear URLs ya procesadas.
- La clave NVD es opcional pero mejora significativamente los límites de tasa.
