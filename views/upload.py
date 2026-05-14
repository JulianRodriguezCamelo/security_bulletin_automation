import subprocess
import sys
from datetime import datetime
from pathlib import Path

import streamlit as st

BULLETINS_DIR = Path.home() / "Documents" / "Casos_inteligencia_de_amenazas"
MAIN_SCRIPT   = Path(__file__).parent.parent / "main.py"

_STAGES = [
    ("Inicializando módulos",   None),
    ("Extrayendo texto PDF",    ["Processing:", "---"]),
    ("Análisis IA (Groq)",      ["Analyzing with IA", "Analizando"]),
    ("Consultando VirusTotal",  ["VirusTotal", "virustotal"]),
    ("Verificando Tenable",     ["Tenable", "tenable"]),
    ("Generando Excel",         ["Report updated", "excel_manager", "add_record"]),
    ("Completado",              ["Process finished", "finalizado"]),
]


def _detect_stage(lines: list[str]) -> int:
    reached = 0
    for i, (_, kws) in enumerate(_STAGES):
        if kws is None:
            continue
        if any(any(k.lower() in l.lower() for k in kws) for l in lines):
            reached = max(reached, i)
    return reached


def render_upload():
    BULLETINS_DIR.mkdir(parents=True, exist_ok=True)

    if "saved_file_ids" not in st.session_state:
        st.session_state.saved_file_ids = set()

    pending = sorted(BULLETINS_DIR.glob("*.pdf"))

    st.markdown("""
    <div style="background:#FFFFFF;border:1px solid #EAD8DE;border-radius:20px;
        overflow:hidden;max-width:800px;margin:0 auto;
        box-shadow:0 4px 32px rgba(74,14,36,0.09);">
        <div style="padding:18px 26px;
            border-bottom:1px solid #F0E4E8;
            background:linear-gradient(90deg,rgba(193,41,74,0.04),transparent);
            display:flex;align-items:center;gap:12px;">
            <div style="width:36px;height:36px;
                background:linear-gradient(135deg,#C1294A,#8B1A33);
                border-radius:10px;display:flex;align-items:center;justify-content:center;
                font-size:17px;box-shadow:0 2px 10px rgba(193,41,74,0.28);">📄</div>
            <div>
                <span style="font-size:14px;font-weight:700;color:#1C0A0F;">Cargar Reporte de Vulnerabilidades</span>
                <p style="font-size:11px;color:#A07080;margin:2px 0 0;">Soporta múltiples PDFs · máx. 200 MB c/u</p>
            </div>
        </div>
        <div style="padding:28px 26px 22px;">
    """, unsafe_allow_html=True)

    uploaded = st.file_uploader(
        "drop",
        type=["pdf"],
        accept_multiple_files=True,
        label_visibility="collapsed",
    )

    if uploaded:
        new_files = [f for f in uploaded if f.file_id not in st.session_state.saved_file_ids]
        if new_files:
            for f in new_files:
                dest = BULLETINS_DIR / f.name
                if dest.exists():
                    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
                    dest = BULLETINS_DIR / f"{ts}_{f.name}"
                dest.write_bytes(f.read())
                st.session_state.saved_file_ids.add(f.file_id)
            st.success(f"✓ {len(new_files)} archivo(s) guardado(s)")
            st.rerun()

    pending = sorted(BULLETINS_DIR.glob("*.pdf"))
    processed = list((BULLETINS_DIR / "Procesados").glob("*.pdf")) if (BULLETINS_DIR / "Procesados").exists() else []
    total_processed = len(processed)

    hist_col1, hist_col2 = st.columns([6, 1])
    with hist_col1:
        st.markdown(
            f"""
            <div style="margin-top:12px;display:flex;align-items:center;gap:6px;">
                <span style="font-size:12px;color:#C4A8B2;">🕐</span>
                <span style="font-size:12px;color:#B09AA5;">
                    {total_processed} reporte{"s" if total_processed != 1 else ""} procesado{"s" if total_processed != 1 else ""} en total
                </span>
            </div>
            """,
            unsafe_allow_html=True,
        )
    if total_processed:
        with hist_col2:
            st.markdown('<div style="margin-top:6px;">', unsafe_allow_html=True)
            if st.button("ver historial →", key="go_archive", type="secondary"):
                st.session_state.page = "archive"
                st.rerun()
            st.markdown('</div>', unsafe_allow_html=True)

    st.markdown("</div></div>", unsafe_allow_html=True)

    if pending:
        st.markdown("<div style='height:22px'></div>", unsafe_allow_html=True)
        st.markdown(f"""
        <div style="display:flex;align-items:center;justify-content:space-between;
            max-width:780px;margin:0 auto 12px;">
            <span style="font-size:11px;font-weight:700;color:#8A5060;
                text-transform:uppercase;letter-spacing:0.09em;">PDFs PENDIENTES</span>
            <span style="font-size:11px;
                background:linear-gradient(135deg,rgba(193,41,74,0.10),rgba(249,115,22,0.08));
                color:#C1294A;border:1px solid rgba(193,41,74,0.22);
                padding:2px 10px;border-radius:99px;font-weight:700;">{len(pending)}</span>
        </div>
        """, unsafe_allow_html=True)

        for p in pending:
            size_kb = p.stat().st_size // 1024
            name = p.name if len(p.name) <= 44 else p.name[:41] + "..."
            st.markdown(f"""
            <div style="display:flex;align-items:center;gap:12px;
                padding:12px 16px;background:#FFFFFF;
                border:1px solid #EAD8DE;border-radius:12px;
                margin:0 auto 6px;max-width:780px;
                box-shadow:0 1px 5px rgba(74,14,36,0.06);
                transition:box-shadow 150ms;">
                <div style="width:36px;height:36px;background:rgba(193,41,74,0.07);
                    border:1px solid rgba(193,41,74,0.16);border-radius:9px;
                    display:flex;align-items:center;justify-content:center;font-size:16px;flex-shrink:0;">📄</div>
                <div style="flex:1;min-width:0;">
                    <div style="font-size:13px;font-weight:600;color:#1C0A0F;
                        white-space:nowrap;overflow:hidden;text-overflow:ellipsis;"
                        title="{p.name}">{name}</div>
                    <div style="font-size:11px;color:#B09AA5;margin-top:2px;">{size_kb} KB</div>
                </div>
                <span style="font-size:10px;font-weight:700;
                    background:rgba(193,41,74,0.07);color:#C1294A;
                    padding:3px 9px;border-radius:6px;border:1px solid rgba(193,41,74,0.18);
                    flex-shrink:0;">PDF</span>
            </div>
            """, unsafe_allow_html=True)

        st.markdown("<div style='height:18px'></div>", unsafe_allow_html=True)

        col_c, _ = st.columns([2.4, 3])
        with col_c:
            run = st.button("▶  Procesar Boletines", use_container_width=True, type="primary")

        if run:
            st.markdown("<div style='height:16px'></div>", unsafe_allow_html=True)
            _run(pending)
    else:
        st.markdown("<div style='height:20px'></div>", unsafe_allow_html=True)
        st.markdown("""
        <div style="text-align:center;padding:8px 0;max-width:780px;margin:0 auto;">
            <span style="font-size:12px;color:#C4A8B2;">
                Sube un PDF para habilitar el procesamiento
            </span>
        </div>
        """, unsafe_allow_html=True)


def _run(pending):
    st.markdown("""
    <div style="background:#FFFFFF;border:1px solid #EAD8DE;border-radius:18px;
        overflow:hidden;max-width:780px;margin:0 auto;
        box-shadow:0 4px 24px rgba(74,14,36,0.09);">
        <div style="padding:14px 22px;border-bottom:1px solid #F0E4E8;
            background:linear-gradient(90deg,rgba(193,41,74,0.04),transparent);
            display:flex;align-items:center;gap:10px;">
            <div style="width:30px;height:30px;
                background:linear-gradient(135deg,#C1294A,#8B1A33);
                border-radius:8px;display:flex;align-items:center;justify-content:center;
                font-size:14px;box-shadow:0 2px 8px rgba(193,41,74,0.28);">⚡</div>
            <span style="font-size:13px;font-weight:700;color:#1C0A0F;">Ejecutando automatización</span>
        </div>
        <div style="padding:20px 24px;">
    """, unsafe_allow_html=True)

    stages_ph   = st.empty()
    progress_ph = st.empty()

    st.markdown("</div></div>", unsafe_allow_html=True)

    st.markdown("""
    <div style="max-width:780px;margin:14px auto 0;">
        <p style="font-size:10px;font-weight:700;color:#B09AA5;text-transform:uppercase;
            letter-spacing:0.09em;margin-bottom:6px;">LOG</p>
    </div>
    """, unsafe_allow_html=True)
    log_ph = st.empty()

    logs: list[str] = []

    def _render_stages(current: int):
        rows = ""
        for i, (lbl, _) in enumerate(_STAGES):
            if i < current:
                dot_cls, col = "done",    "#22c55e"
                icon          = "✓"
                text_color    = "#3A1520"
            elif i == current:
                dot_cls, col = "active",  "#C1294A"
                icon          = "◉"
                text_color    = "#1C0A0F"
            else:
                dot_cls, col = "pending", "#E0CDD3"
                icon          = "○"
                text_color    = "#C4A8B2"
            rows += f"""
            <div class="stage-row">
                <span style="font-size:12px;color:{col};width:16px;text-align:center;">{icon}</span>
                <span style="font-size:12px;color:{text_color};font-weight:{'600' if i == current else '400'};">{lbl}</span>
            </div>"""
        stages_ph.markdown(rows, unsafe_allow_html=True)

    _render_stages(0)
    progress_ph.progress(0, text="Iniciando…")

    try:
        proc = subprocess.Popen(
            [sys.executable, str(MAIN_SCRIPT)],
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            text=True, encoding="utf-8", errors="replace",
            cwd=str(MAIN_SCRIPT.parent),
        )
        for line in proc.stdout:
            line = line.rstrip()
            if not line:
                continue
            logs.append(line)
            cur = _detect_stage(logs)
            _render_stages(cur)
            pct = int(cur / (len(_STAGES) - 1) * 100)
            progress_ph.progress(pct, text=_STAGES[cur][0])
            log_ph.code("\n".join(logs[-40:]), language="text")
        proc.wait()
    except Exception as exc:
        st.error(f"Error al iniciar el proceso: {exc}")
        return

    if proc.returncode == 0:
        _render_stages(len(_STAGES) - 1)
        progress_ph.progress(100, text="Completado")
        st.success("✓ Automatización completada — revisa el **Historial**")
    else:
        st.error(f"✗ Terminó con errores (código {proc.returncode}) — revisa los logs")
