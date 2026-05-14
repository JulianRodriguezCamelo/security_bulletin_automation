import os
from pathlib import Path

import streamlit as st
from dotenv import load_dotenv

load_dotenv()

_GROQ_MODEL = "llama-3.3-70b-versatile"

_SEV_BADGES = {
    "CRITICAL": ("#DC2626", "rgba(220,38,38,0.08)"),
    "HIGH":     ("#C1294A", "rgba(193,41,74,0.08)"),
    "MEDIUM":   ("#D97706", "rgba(217,119,6,0.08)"),
    "LOW":      ("#2563EB", "rgba(37,99,235,0.08)"),
}

_KEYS = {
    "GROQ_API_KEY":         "CRITICAL",
    "VT_API_KEY":           "HIGH",
    "TENABLE_ACCESS_KEY":   "HIGH",
    "TENABLE_SECRET_KEY":   "HIGH",
}


def _section(icon: str, title: str):
    st.markdown(f"""
    <div style="display:flex;align-items:center;gap:10px;margin-bottom:16px;">
        <div style="width:32px;height:32px;
            background:linear-gradient(135deg,rgba(193,41,74,0.10),rgba(249,115,22,0.10));
            border:1px solid rgba(193,41,74,0.18);border-radius:8px;
            display:flex;align-items:center;justify-content:center;font-size:15px;">{icon}</div>
        <span style="font-size:15px;font-weight:700;color:#1C0A0F;">{title}</span>
    </div>
    """, unsafe_allow_html=True)


def _card_open():
    st.markdown(
        '<div style="background:#FFFFFF;border:1px solid #EAD8DE;border-radius:16px;'
        'padding:22px 24px;margin-bottom:16px;box-shadow:0 2px 12px rgba(74,14,36,0.07);">',
        unsafe_allow_html=True,
    )


def _card_close():
    st.markdown('</div>', unsafe_allow_html=True)


def _badge(label: str):
    color, bg = _SEV_BADGES.get(label, ("#8A5060", "rgba(138,80,96,0.08)"))
    return (
        f'<span style="display:inline-block;padding:2px 9px;border-radius:99px;'
        f'font-size:11px;font-weight:700;color:{color};background:{bg};">{label}</span>'
    )


def _key_row(env_key: str, severity: str):
    val = os.getenv(env_key, "")
    masked = val[:4] + "••••••••" if len(val) > 4 else "No configurada"
    is_set = bool(val)
    check = (
        '<span style="color:#16a34a;font-size:15px;font-weight:700;">✓</span>'
        if is_set else
        '<span style="color:#DC2626;font-size:15px;font-weight:700;">✗</span>'
    )
    return f"""
    <div style="display:flex;align-items:center;gap:10px;padding:10px 0;
        border-bottom:1px solid #F5EEF1;">
        {_badge(severity)}
        <span style="font-size:12px;color:#8A5060;font-family:monospace;flex:1;">
            {env_key}
            <span style="color:#C4A8B2;"> = {masked}</span>
        </span>
        {check}
    </div>"""


def render_config():
    _card_open()
    _section("🖥️", "Conexión Backend")

    st.markdown('<p style="font-size:12px;color:#8A5060;font-weight:500;margin:0 0 8px;">URL del servidor API</p>', unsafe_allow_html=True)

    col_in, col_btn = st.columns([5, 1])
    with col_in:
        st.text_input("api_url", value="http://localhost:8000",
                      label_visibility="collapsed", key="cfg_api_url")
    with col_btn:
        st.button("↗", key="cfg_open_url", type="secondary", use_container_width=True)

    st.markdown("""
    <div style="display:flex;align-items:center;gap:8px;margin-top:10px;
        background:rgba(22,163,74,0.06);border:1px solid rgba(22,163,74,0.20);
        border-radius:8px;padding:8px 12px;">
        <div style="width:8px;height:8px;background:#22c55e;border-radius:50%;
            box-shadow:0 0 6px rgba(34,197,94,0.5);flex-shrink:0;"></div>
        <span style="font-size:12px;color:#166534;font-weight:600;">Backend: Conectado</span>
        <span style="font-size:12px;color:#A07080;margin-left:4px;">http://localhost:8000</span>
    </div>
    """, unsafe_allow_html=True)

    _card_close()

    _card_open()
    _section("⚡", "Modelo de IA (Groq)")

    st.markdown(f"""
    <p style="font-size:12px;color:#8A5060;font-weight:500;margin:0 0 8px;">Modelo activo</p>
    <div style="background:linear-gradient(135deg,rgba(193,41,74,0.05),rgba(249,115,22,0.05));
        border:1px solid rgba(193,41,74,0.15);border-radius:10px;
        padding:12px 16px;margin-bottom:12px;display:flex;align-items:center;gap:10px;">
        <span style="font-size:16px;">🤖</span>
        <span style="font-size:13px;font-weight:600;color:#1C0A0F;">{_GROQ_MODEL}</span>
    </div>
    <p style="font-size:11px;color:#B09AA5;margin:0 0 16px;">
        El modelo se usa en <code style="background:rgba(193,41,74,0.06);padding:1px 5px;
        border-radius:4px;color:#8A5060;">ai_analyzer.py</code>
        → <code style="background:rgba(193,41,74,0.06);padding:1px 5px;
        border-radius:4px;color:#8A5060;">GROQ_API_KEY</code>.
        Edita el <code style="background:rgba(193,41,74,0.06);padding:1px 5px;
        border-radius:4px;color:#8A5060;">.env</code> para persistir cambios.
    </p>
    <p style="font-size:11px;font-weight:700;color:#8A5060;text-transform:uppercase;
        letter-spacing:0.08em;margin-bottom:10px;">API Keys por severidad</p>
    """, unsafe_allow_html=True)

    rows_html = "".join(_key_row(k, sev) for k, sev in _KEYS.items())
    st.markdown(
        f'<div style="border:1px solid #EAD8DE;border-radius:10px;padding:4px 14px;'
        f'background:#FDFAFA;">{rows_html}</div>',
        unsafe_allow_html=True,
    )
    st.markdown("""
    <p style="font-size:11px;color:#C4A8B2;margin:12px 0 0;">
        Para cambiar las keys, edita
        <code style="background:rgba(193,41,74,0.06);padding:1px 5px;border-radius:4px;
        color:#8A5060;">.env</code> en la raíz del proyecto.
    </p>
    """, unsafe_allow_html=True)

    _card_close()

    _card_open()
    _section("⚙️", "Preferencias")

    st.markdown("""
    <div style="display:flex;align-items:center;justify-content:space-between;
        padding:10px 0;border-bottom:1px solid #F5EEF1;">
        <div>
            <p style="font-size:13px;color:#1C0A0F;margin:0;font-weight:600;">Descarga automática al finalizar</p>
            <p style="font-size:11px;color:#B09AA5;margin:4px 0 0;">Descarga el Excel inmediatamente cuando el procesamiento termine</p>
        </div>
    </div>
    """, unsafe_allow_html=True)

    st.toggle("auto_download", value=False, label_visibility="hidden", key="cfg_auto_dl")

    techs = os.getenv("COMPANY_TECHS", "")
    st.markdown('<p style="font-size:11px;color:#8A5060;font-weight:600;text-transform:uppercase;letter-spacing:0.06em;margin:14px 0 6px;">TECNOLOGÍAS DE LA EMPRESA</p>', unsafe_allow_html=True)
    st.text_input("cfg_techs", value=techs, label_visibility="collapsed",
                  placeholder="Google Chrome, Windows, Fortinet…", key="cfg_techs_input",
                  disabled=True)
    st.caption("Edita el archivo .env para modificar esta lista.")

    _card_close()

    _card_open()
    _section("📧", "Entrega de Informes")

    report_to = os.getenv("REPORT_TO_EMAIL", "No configurado")
    configured = report_to != "No configurado"
    st.markdown(f"""
    <div style="display:flex;align-items:center;gap:10px;padding:10px 0;">
        <div style="width:8px;height:8px;background:{'#22c55e' if configured else '#E0CDD3'};
            border-radius:50%;flex-shrink:0;
            {'box-shadow:0 0 6px rgba(34,197,94,0.5);' if configured else ''}"></div>
        <span style="font-size:12px;color:#8A5060;">Destinatario: </span>
        <span style="font-size:12px;color:#1C0A0F;font-weight:600;">{report_to}</span>
    </div>
    """, unsafe_allow_html=True)

    _card_close()
