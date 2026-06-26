"""
Gestor de base de datos Oracle 21c para CARONTE/ARGOS.
Usa python-oracledb en modo thin (sin Oracle Client instalado).

Variables de entorno requeridas:
    ORACLE_USER      — usuario Oracle (ej: caronte)
    ORACLE_PASSWORD  — contraseña
    ORACLE_HOST      — host (default: localhost)
    ORACLE_PORT      — puerto (default: 1521)
    ORACLE_SERVICE   — service name (ej: XEPDB1 para Oracle XE)
"""
import os
import logging
from contextlib import contextmanager
from typing import Optional

logger = logging.getLogger(__name__)

# Columnas del Excel → columnas Oracle (threats)
_THREAT_COL_MAP = {
    "ID":                            "threat_id",
    "Fecha Detección":               "fecha_deteccion",
    "Fuente":                        "fuente",
    "V-A":                           "tipo_va",
    "CVE(s) Identificados":          "cves_identificados",
    "NOMBRE":                        "nombre",
    "Descripción Técnica":           "descripcion_tecnica",
    "Descripción del Riesgo":        "descripcion_riesgo",
    "TTPs (MITRE ATT&CK)":           "ttps",
    "Probabilidad":                  "probabilidad",
    "Impacto":                       "impacto",
    "Critcidad":                     "criticidad",
    "Acción Recomendada":            "accion_recomendada",
    "Área Responsable Remediación":  "area_responsable",
    "Fecha Escalamiento al Área":    "fecha_escalamiento",
    "¿Afecta Activos? (Tenable)":   "afecta_activos",
    "Comentarios Tenable":           "comentarios_tenable",
    "Bloqueo Antivirus":             "bloqueo_antivirus",
    "Bloqueo Firewall":              "bloqueo_firewall",
    "Caso Firewall":                 "caso_firewall",
}
_THREAT_COL_MAP_INV = {v: k for k, v in _THREAT_COL_MAP.items()}

_IOC_COL_MAP = {
    "ID Amenaza":       "threat_id",
    "Tipo de IoC":      "tipo_ioc",
    "Indicador (IoC)":  "indicador",
    "Bloqueo Antivirus": "bloqueo_antivirus",
    "Bloqueo Firewall":  "bloqueo_firewall",
}
_IOC_COL_MAP_INV = {v: k for k, v in _IOC_COL_MAP.items()}


class OracleManager:
    def __init__(self):
        self._user     = os.environ["ORACLE_USER"]
        self._password = os.environ["ORACLE_PASSWORD"]
        self._host     = os.getenv("ORACLE_HOST", "localhost")
        self._port     = int(os.getenv("ORACLE_PORT", "1521"))
        self._service  = os.getenv("ORACLE_SERVICE", "XEPDB1")
        self._dsn      = f"{self._host}:{self._port}/{self._service}"
        self._verify_connection()

    def _verify_connection(self):
        try:
            import oracledb
            with oracledb.connect(user=self._user, password=self._password, dsn=self._dsn) as conn:
                conn.ping()
            logger.info(f"Oracle connection OK → {self._dsn}")
        except Exception as exc:
            logger.error(f"Oracle connection failed: {exc}")
            raise

    @contextmanager
    def _conn(self):
        import oracledb
        conn = oracledb.connect(user=self._user, password=self._password, dsn=self._dsn)
        try:
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()

    # ── Users ────────────────────────────────────────────────────────────────

    def has_users(self) -> bool:
        with self._conn() as conn:
            cur = conn.cursor()
            cur.execute("SELECT COUNT(*) FROM caronte_users")
            return cur.fetchone()[0] > 0

    def user_exists(self, username: str) -> bool:
        with self._conn() as conn:
            cur = conn.cursor()
            cur.execute("SELECT COUNT(*) FROM caronte_users WHERE username = :1", [username])
            return cur.fetchone()[0] > 0

    def create_user(self, username: str, password_hash: str, role: str = "user"):
        with self._conn() as conn:
            cur = conn.cursor()
            cur.execute(
                "INSERT INTO caronte_users (username, password_hash, role) VALUES (:1, :2, :3)",
                [username, password_hash, role],
            )
        logger.info(f"Usuario creado: {username} (role={role})")

    def get_user(self, username: str) -> Optional[dict]:
        with self._conn() as conn:
            cur = conn.cursor()
            cur.execute(
                "SELECT username, password_hash, totp_secret, role FROM caronte_users WHERE username = :1",
                [username],
            )
            row = cur.fetchone()
            if not row:
                return None
            return {"username": row[0], "password_hash": row[1], "totp_secret": row[2], "role": row[3]}

    def list_users(self) -> list[dict]:
        with self._conn() as conn:
            cur = conn.cursor()
            cur.execute("SELECT username, role, created_at FROM caronte_users ORDER BY created_at")
            return [{"username": r[0], "role": r[1], "created_at": str(r[2])} for r in cur.fetchall()]

    def update_totp_secret(self, username: str, secret: str):
        with self._conn() as conn:
            cur = conn.cursor()
            cur.execute(
                "UPDATE caronte_users SET totp_secret = :1 WHERE username = :2",
                [secret, username],
            )

    def update_password(self, username: str, password_hash: str):
        with self._conn() as conn:
            cur = conn.cursor()
            cur.execute(
                "UPDATE caronte_users SET password_hash = :1 WHERE username = :2",
                [password_hash, username],
            )

    # ── Threats ──────────────────────────────────────────────────────────────

    def add_threat(self, threat: dict) -> str:
        """Inserta una amenaza. Acepta claves en formato Excel o en formato Oracle."""
        row = self._normalize_threat(threat)
        cols = list(row.keys())
        placeholders = [f":{i+1}" for i in range(len(cols))]
        sql = f"INSERT INTO caronte_threats ({', '.join(cols)}) VALUES ({', '.join(placeholders)})"
        with self._conn() as conn:
            cur = conn.cursor()
            cur.execute(sql, list(row.values()))
        return row.get("threat_id", "")

    def get_threats(self) -> list[dict]:
        with self._conn() as conn:
            cur = conn.cursor()
            cur.execute(
                "SELECT threat_id, fecha_deteccion, fuente, tipo_va, cves_identificados, nombre, "
                "descripcion_tecnica, descripcion_riesgo, ttps, probabilidad, impacto, criticidad, "
                "accion_recomendada, area_responsable, fecha_escalamiento, afecta_activos, "
                "comentarios_tenable, bloqueo_antivirus, bloqueo_firewall, caso_firewall "
                "FROM caronte_threats ORDER BY created_at"
            )
            cols = [d[0].lower() for d in cur.description]
            rows = cur.fetchall()
        return [self._to_excel_threat(dict(zip(cols, r))) for r in rows]

    def update_threat(self, threat_id: str, threat: dict):
        row = self._normalize_threat(threat)
        row.pop("threat_id", None)
        if not row:
            return
        set_clause = ", ".join(f"{k} = :{i+1}" for i, k in enumerate(row))
        values = list(row.values()) + [threat_id]
        sql = f"UPDATE caronte_threats SET {set_clause} WHERE threat_id = :{len(values)}"
        with self._conn() as conn:
            cur = conn.cursor()
            cur.execute(sql, values)

    def upsert_threat(self, threat: dict):
        """Inserta o actualiza una amenaza según si el threat_id ya existe."""
        row = self._normalize_threat(threat)
        tid = row.get("threat_id")
        if tid and self._threat_exists(tid):
            self.update_threat(tid, threat)
        else:
            self.add_threat(threat)

    def _threat_exists(self, threat_id: str) -> bool:
        with self._conn() as conn:
            cur = conn.cursor()
            cur.execute("SELECT COUNT(*) FROM caronte_threats WHERE threat_id = :1", [threat_id])
            return cur.fetchone()[0] > 0

    def save_threats_bulk(self, threats: list[dict]):
        """Borra y reescribe todas las amenazas (usado por PUT /api/archive/threats)."""
        with self._conn() as conn:
            cur = conn.cursor()
            cur.execute("DELETE FROM caronte_threats")
            for t in threats:
                row = self._normalize_threat(t)
                cols = list(row.keys())
                placeholders = [f":{i+1}" for i in range(len(cols))]
                sql = f"INSERT INTO caronte_threats ({', '.join(cols)}) VALUES ({', '.join(placeholders)})"
                cur.execute(sql, list(row.values()))

    # ── IoCs ──────────────────────────────────────────────────────────────────

    def add_ioc(self, ioc: dict):
        row = self._normalize_ioc(ioc)
        cols = list(row.keys())
        placeholders = [f":{i+1}" for i in range(len(cols))]
        sql = f"INSERT INTO caronte_iocs ({', '.join(cols)}) VALUES ({', '.join(placeholders)})"
        with self._conn() as conn:
            cur = conn.cursor()
            cur.execute(sql, list(row.values()))

    def get_iocs(self) -> list[dict]:
        with self._conn() as conn:
            cur = conn.cursor()
            cur.execute(
                "SELECT threat_id, tipo_ioc, indicador, bloqueo_antivirus, bloqueo_firewall "
                "FROM caronte_iocs ORDER BY ioc_id"
            )
            cols = [d[0].lower() for d in cur.description]
            rows = cur.fetchall()
        return [self._to_excel_ioc(dict(zip(cols, r))) for r in rows]

    def save_iocs_bulk(self, iocs: list[dict]):
        """Borra y reescribe todos los IoCs."""
        with self._conn() as conn:
            cur = conn.cursor()
            cur.execute("DELETE FROM caronte_iocs")
            for ioc in iocs:
                row = self._normalize_ioc(ioc)
                cols = list(row.keys())
                placeholders = [f":{i+1}" for i in range(len(cols))]
                sql = f"INSERT INTO caronte_iocs ({', '.join(cols)}) VALUES ({', '.join(placeholders)})"
                cur.execute(sql, list(row.values()))

    def add_record(self, analysis: dict, pdf_name: str) -> str:
        """
        Equivalente Oracle de excel_manager.add_record.
        Genera el ID, inserta la amenaza y sus IoCs en una sola transacción.
        """
        from datetime import datetime as _dt

        source         = analysis.get("fuente", "")
        numero_boletin = str(analysis.get("numero_boletin", "")).strip()
        src_lower      = source.lower().strip()

        _WEXLER = {"boletin csirt cywex", "csirt cywex", "wexler"}
        _PREFIX = {
            "colcert": "COL", "boletin csirt cywex": "WX",
            "csirt cywex": "WX", "wexler": "WX",
            "octapus": "OCT", "octopus": "OCT",
        }
        prefix = next((p for k, p in _PREFIX.items() if k in src_lower), "WX")

        if numero_boletin and any(k in src_lower for k in _WEXLER):
            candidate = f"WX-{numero_boletin}"
            if not self._threat_exists(candidate):
                threat_id = candidate
            else:
                suffix = 2
                while self._threat_exists(f"{candidate}-{suffix}"):
                    suffix += 1
                threat_id = f"{candidate}-{suffix}"
        else:
            threat_id = self.get_next_threat_id(prefix)

        today = _dt.now().strftime("%Y-%m-%d")
        tipo  = analysis.get("tipo_amenaza", "Otro")
        nombre = analysis.get("nombre", "") if tipo == "Vulnerabilidad" else "NO APLICA"

        threat = {
            "ID":                             threat_id,
            "Fecha Detección":               today,
            "Fuente":                         analysis.get("fuente", "CARONTE"),
            "V-A":                            tipo,
            "CVE(s) Identificados":           analysis.get("cves", ""),
            "NOMBRE":                         nombre,
            "Descripción Técnica":            analysis.get("descripcion", ""),
            "Descripción del Riesgo":         analysis.get("riesgo", ""),
            "TTPs (MITRE ATT&CK)":            analysis.get("ttps", ""),
            "Probabilidad":                   analysis.get("probabilidad", ""),
            "Impacto":                        analysis.get("impacto", ""),
            "Critcidad":                      analysis.get("criticidad", ""),
            "Acción Recomendada":             analysis.get("accion", ""),
            "Área Responsable Remediación":   analysis.get("area_responsable_remediacion", ""),
            "Fecha Escalamiento al Área":     analysis.get("fecha_escalamiento", ""),
            "¿Afecta Activos? (Tenable)":    analysis.get("_tenable_afecta", ""),
            "Comentarios Tenable":            analysis.get("_tenable_comment", ""),
            "Bloqueo Antivirus": "",
            "Bloqueo Firewall":  "",
            "Caso Firewall":     "",
        }
        self.upsert_threat(threat)

        for ioc in analysis.get("iocs_detalle", []):
            if ioc.get("valor"):
                self.add_ioc({
                    "ID Amenaza":       threat_id,
                    "Tipo de IoC":      ioc.get("tipo", ""),
                    "Indicador (IoC)":  ioc.get("valor", ""),
                    "Bloqueo Antivirus": "",
                    "Bloqueo Firewall":  "",
                })

        logger.info(f"add_record (Oracle): ID={threat_id} ({pdf_name})")
        return threat_id

    def get_next_threat_id(self, prefix: str = "WX") -> str:
        """Genera el siguiente ID secuencial para el prefijo dado."""
        import re
        pattern = f"^{re.escape(prefix)}-"
        with self._conn() as conn:
            cur = conn.cursor()
            cur.execute(
                "SELECT threat_id FROM caronte_threats WHERE REGEXP_LIKE(threat_id, :1) ORDER BY threat_id",
                [pattern],
            )
            rows = cur.fetchall()
        nums = []
        for (tid,) in rows:
            m = __import__("re").match(rf"{re.escape(prefix)}-(\d+)$", tid)
            if m:
                n = int(m.group(1))
                if n < 90000:
                    nums.append(n)
        nxt = (max(nums) + 1) if nums else 1
        return f"{prefix}-{nxt:03d}"

    # ── Helpers ───────────────────────────────────────────────────────────────

    @staticmethod
    def _normalize_threat(threat: dict) -> dict:
        """Convierte claves Excel → Oracle y elimina las desconocidas."""
        result = {}
        for k, v in threat.items():
            oracle_key = _THREAT_COL_MAP.get(k, k if k in _THREAT_COL_MAP_INV else None)
            if oracle_key:
                result[oracle_key] = v if v not in (None, "") else None
        return result

    @staticmethod
    def _to_excel_threat(row: dict) -> dict:
        """Convierte claves Oracle → Excel para la API."""
        return {_THREAT_COL_MAP_INV.get(k, k): v for k, v in row.items()}

    @staticmethod
    def _normalize_ioc(ioc: dict) -> dict:
        result = {}
        for k, v in ioc.items():
            oracle_key = _IOC_COL_MAP.get(k, k if k in _IOC_COL_MAP_INV else None)
            if oracle_key:
                result[oracle_key] = v if v not in (None, "") else None
        return result

    @staticmethod
    def _to_excel_ioc(row: dict) -> dict:
        return {_IOC_COL_MAP_INV.get(k, k): v for k, v in row.items()}
