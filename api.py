import base64
import json
import os
import subprocess
import sys
from datetime import datetime
from functools import wraps
from pathlib import Path

import pandas as pd
from dotenv import load_dotenv
from flask import Flask, Response, jsonify, request, send_file, session
from flask_cors import CORS

load_dotenv()

sys.path.insert(0, str(Path(__file__).parent))
from auth_manager import AuthManager

DIST = Path(__file__).parent / "frontend" / "dist"
app = Flask(__name__, static_folder=str(DIST), static_url_path="")
app.secret_key = os.getenv("SECRET_KEY", "argos-dev-secret-change-in-prod")
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
app.config["SESSION_COOKIE_HTTPONLY"] = True

CORS(app, supports_credentials=True, origins=["http://localhost:5173", "http://127.0.0.1:5173"])

BULLETINS_DIR = Path.home() / "Documents" / "Casos_inteligencia_de_amenazas"
EXCEL_PATH    = BULLETINS_DIR / "Informe_Amenazas.xlsx"
MAIN_SCRIPT   = Path(__file__).parent / "main.py"

auth = AuthManager()


# ── Auth guard ────────────────────────────────────────────────────────────────
def require_auth(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if not session.get("authenticated"):
            return jsonify({"error": "Unauthorized"}), 401
        return f(*args, **kwargs)
    return wrapper


# ── Auth ──────────────────────────────────────────────────────────────────────
@app.route("/api/auth/login", methods=["POST"])
def login():
    data     = request.get_json()
    username = data.get("username", "").strip()
    password = data.get("password", "")

    if not auth.has_users():
        auth.create_user(username, password)
        session["temp_username"] = username
        secret = auth.generate_totp_secret(username)
        qr     = auth.get_qr_image(username, secret)
        return jsonify({
            "step":   "totp_setup",
            "qr":     base64.b64encode(qr).decode(),
            "secret": secret,
        })

    if not auth.verify_password(username, password):
        return jsonify({"error": "Credenciales incorrectas"}), 401

    session["temp_username"] = username

    if not auth.has_totp(username):
        secret = auth.generate_totp_secret(username)
        qr     = auth.get_qr_image(username, secret)
        return jsonify({
            "step":   "totp_setup",
            "qr":     base64.b64encode(qr).decode(),
            "secret": secret,
        })

    return jsonify({"step": "totp"})


@app.route("/api/auth/totp/verify", methods=["POST"])
def verify_totp():
    data     = request.get_json()
    username = session.get("temp_username")
    code     = data.get("code", "").strip()

    if not username:
        return jsonify({"error": "No hay sesión pendiente"}), 400

    if auth.verify_totp(username, code):
        session.pop("temp_username", None)
        session["authenticated"] = True
        session["username"]      = username
        return jsonify({"step": "done", "username": username})

    return jsonify({"error": "Código incorrecto"}), 401


@app.route("/api/auth/logout", methods=["POST"])
def logout():
    session.clear()
    return jsonify({"ok": True})


@app.route("/api/auth/me")
def me():
    if session.get("authenticated"):
        return jsonify({"authenticated": True, "username": session["username"]})
    return jsonify({"authenticated": False})


# ── Files ─────────────────────────────────────────────────────────────────────
@app.route("/api/files", methods=["GET"])
@require_auth
def list_files():
    BULLETINS_DIR.mkdir(parents=True, exist_ok=True)
    files = sorted(BULLETINS_DIR.glob("*.pdf"))
    return jsonify([{"name": f.name, "size": f.stat().st_size} for f in files])


@app.route("/api/files", methods=["POST"])
@require_auth
def upload_files():
    BULLETINS_DIR.mkdir(parents=True, exist_ok=True)
    uploaded = []
    for file in request.files.getlist("files"):
        dest = BULLETINS_DIR / file.filename
        if dest.exists():
            ts   = datetime.now().strftime("%Y%m%d_%H%M%S")
            dest = BULLETINS_DIR / f"{ts}_{file.filename}"
        file.save(dest)
        uploaded.append(dest.name)
    return jsonify({"uploaded": uploaded})


@app.route("/api/files/<name>", methods=["DELETE"])
@require_auth
def delete_file(name):
    path = BULLETINS_DIR / name
    if path.exists() and path.suffix.lower() == ".pdf":
        path.unlink()
        return jsonify({"ok": True})
    return jsonify({"error": "Archivo no encontrado"}), 404


# ── Process (SSE streaming) ───────────────────────────────────────────────────
# EventSource only supports GET, so we accept GET here.
@app.route("/api/process", methods=["GET"])
@require_auth
def process():
    def generate():
        try:
            proc = subprocess.Popen(
                [sys.executable, str(MAIN_SCRIPT)],
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                encoding="utf-8",
                errors="replace",
                cwd=str(MAIN_SCRIPT.parent),
            )
            for line in proc.stdout:
                line = line.rstrip()
                if line:
                    yield f"data: {json.dumps({'line': line})}\n\n"
            proc.wait()
            yield f"data: {json.dumps({'done': True, 'code': proc.returncode})}\n\n"
        except Exception as exc:
            yield f"data: {json.dumps({'error': str(exc)})}\n\n"

    return Response(
        generate(),
        mimetype="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


# ── Archive ───────────────────────────────────────────────────────────────────
def _read_sheet(sheet_name: str):
    import json as _json
    df = pd.read_excel(EXCEL_PATH, sheet_name=sheet_name, engine="openpyxl")
    return _json.loads(df.to_json(orient="records", force_ascii=False, date_format="iso"))


def _write_sheet(sheet_name: str, records: list):
    from openpyxl import Workbook, load_workbook
    df = pd.DataFrame(records)
    if EXCEL_PATH.exists():
        wb = load_workbook(EXCEL_PATH)
    else:
        EXCEL_PATH.parent.mkdir(parents=True, exist_ok=True)
        wb = Workbook()
    if sheet_name in wb.sheetnames:
        del wb[sheet_name]
    ws = wb.create_sheet(sheet_name)
    ws.append(list(df.columns))
    for row in df.itertuples(index=False):
        ws.append([None if isinstance(v, float) and pd.isna(v) else v for v in row])
    if "Sheet" in wb.sheetnames and len(wb.sheetnames) > 1:
        del wb["Sheet"]
    wb.save(EXCEL_PATH)


@app.route("/api/archive/threats", methods=["GET"])
@require_auth
def get_threats():
    if not EXCEL_PATH.exists():
        return jsonify([])
    try:
        return jsonify(_read_sheet("Registro de Amenazas"))
    except Exception as exc:
        return jsonify({"error": str(exc)}), 500


@app.route("/api/archive/threats", methods=["PUT"])
@require_auth
def update_threats():
    try:
        _write_sheet("Registro de Amenazas", request.get_json())
        return jsonify({"ok": True})
    except Exception as exc:
        return jsonify({"error": str(exc)}), 500


@app.route("/api/archive/iocs", methods=["GET"])
@require_auth
def get_iocs():
    if not EXCEL_PATH.exists():
        return jsonify([])
    try:
        return jsonify(_read_sheet("Detalle de IoCs"))
    except Exception as exc:
        return jsonify({"error": str(exc)}), 500


@app.route("/api/archive/iocs", methods=["PUT"])
@require_auth
def update_iocs():
    try:
        _write_sheet("Detalle de IoCs", request.get_json())
        return jsonify({"ok": True})
    except Exception as exc:
        return jsonify({"error": str(exc)}), 500


@app.route("/api/archive/download")
@require_auth
def download_excel():
    if not EXCEL_PATH.exists():
        return jsonify({"error": "Sin archivo Excel"}), 404
    return send_file(EXCEL_PATH, as_attachment=True, download_name="Informe_Amenazas.xlsx")


# ── Config ────────────────────────────────────────────────────────────────────
_CONFIG_KEYS = {
    "GROQ_API_KEY":       "CRITICAL",
    "VT_API_KEY":         "HIGH",
    "TENABLE_ACCESS_KEY": "HIGH",
    "TENABLE_SECRET_KEY": "HIGH",
    "EMAIL_USER":         "MEDIUM",
    "SMTP_HOST":          "LOW",
    "REPORT_TO_EMAIL":    "LOW",
    "COMPANY_TECHS":      "LOW",
}


@app.route("/api/config", methods=["GET"])
@require_auth
def get_config():
    result = {}
    for key, severity in _CONFIG_KEYS.items():
        val = os.getenv(key, "")
        result[key] = {
            "severity": severity,
            "set":      bool(val),
            "masked":   val[:4] + "••••••••" if len(val) > 4 else "",
        }
    return jsonify({
        "keys":         result,
        "groq_model":   "llama-3.3-70b-versatile",
        "company_techs": os.getenv("COMPANY_TECHS", ""),
        "report_to":    os.getenv("REPORT_TO_EMAIL", ""),
    })


@app.route("/", defaults={"path": ""})
@app.route("/<path:path>")
def serve_spa(path: str):
    """Serve the React SPA for all non-API routes."""
    full = DIST / path
    if full.exists() and full.is_file():
        return app.send_static_file(path)
    return app.send_static_file("index.html")


if __name__ == "__main__":
    # use_reloader=False prevents the reloader from killing SSE streams mid-flight
    app.run(debug=True, port=5000, threaded=True, use_reloader=False)
