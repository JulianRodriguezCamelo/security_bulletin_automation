import sys
from datetime import datetime
from pathlib import Path

import streamlit as st
from dotenv import load_dotenv

load_dotenv()
sys.path.insert(0, str(Path(__file__).parent))

from auth_manager import AuthManager

st.set_page_config(
    page_title="ARGOS",
    layout="wide",
    initial_sidebar_state="expanded",
)

# ── Global CSS ─────────────────────────────────────────────────────────────────
st.markdown("""
<style>
@import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;800&display=swap');

*, *::before, *::after { box-sizing: border-box; }

html, body, .stApp {
    background: #F7F0EC !important;
    color: #1C0A0F !important;
    font-family: 'Inter', system-ui, sans-serif !important;
    -webkit-font-smoothing: antialiased;
}

/* ── Hide Streamlit chrome ── */
[data-testid="stDecoration"]  { display:none!important; }
[data-testid="stHeader"]      { display:none!important; }
[data-testid="stToolbar"]     { display:none!important; }
#MainMenu, footer             { display:none!important; }
[data-testid="stStatusWidget"]{ display:none!important; }

/* ── Main container ── */
[data-testid="stAppViewContainer"],
[data-testid="stMain"]        { background-color:transparent!important; }
.main .block-container        { padding:0!important; max-width:100%!important; }

/* ── Sidebar ── */
[data-testid="stSidebar"] {
    background: linear-gradient(180deg, #4A0E24 0%, #360A1A 100%) !important;
    border-right: none !important;
    min-width: 180px !important;
    max-width: 224px !important;
    box-shadow: 4px 0 24px rgba(74,14,36,0.18) !important;
}
[data-testid="stSidebarContent"] { padding: 0 !important; }
[data-testid="stSidebarNav"]     { display: none !important; }

/* ── Responsive ── */
@media (max-width: 600px) {
    [data-testid="stDataFrame"] { font-size: 11px !important; }
    [data-testid="stSidebar"] { min-width: 56px !important; max-width: 56px !important; }
}

/* ── Inputs ── */
.stTextInput input {
    background: #FFFFFF !important;
    border: 1.5px solid #E0CDD3 !important;
    border-radius: 10px !important;
    color: #1C0A0F !important;
    font-family: 'Inter', sans-serif !important;
    font-size: 14px !important;
    padding: 11px 14px !important;
    transition: border-color 150ms, box-shadow 150ms !important;
    box-shadow: 0 1px 3px rgba(74,14,36,0.07) !important;
}
.stTextInput input:focus {
    border-color: #C1294A !important;
    box-shadow: 0 0 0 3px rgba(193,41,74,0.10) !important;
    outline: none !important;
}
.stTextInput input::placeholder { color: #C4A8B2 !important; }
.stTextInput label { display:none!important; }

/* ── Buttons ── */
.stButton > button {
    font-family: 'Inter', sans-serif !important;
    font-weight: 600 !important;
    font-size: 14px !important;
    border-radius: 10px !important;
    border: none !important;
    transition: all 200ms !important;
    cursor: pointer !important;
}
.stButton > button[kind="primary"] {
    background: linear-gradient(135deg, #C1294A 0%, #8B1A33 100%) !important;
    color: #fff !important;
    padding: 12px 24px !important;
    box-shadow: 0 2px 14px rgba(193,41,74,0.30) !important;
}
.stButton > button[kind="primary"]:hover:not(:disabled) {
    background: linear-gradient(135deg, #D42E52 0%, #9E1E3A 100%) !important;
    box-shadow: 0 4px 22px rgba(193,41,74,0.40) !important;
    transform: translateY(-1px) !important;
}
.stButton > button[kind="primary"]:disabled {
    opacity: 0.45 !important;
    cursor: not-allowed !important;
}
.stButton > button[kind="secondary"] {
    background: #FFFFFF !important;
    color: #7A3045 !important;
    border: 1.5px solid #E0CDD3 !important;
    box-shadow: 0 1px 4px rgba(74,14,36,0.07) !important;
}
.stButton > button[kind="secondary"]:hover {
    color: #C1294A !important;
    border-color: #C1294A !important;
    background: #FEF5F7 !important;
    box-shadow: 0 2px 10px rgba(193,41,74,0.14) !important;
}

/* ── Selectbox ── */
.stSelectbox [data-baseweb="select"] > div {
    background: #FFFFFF !important;
    border: 1.5px solid #E0CDD3 !important;
    border-radius: 10px !important;
    color: #1C0A0F !important;
    box-shadow: 0 1px 3px rgba(74,14,36,0.07) !important;
}
.stSelectbox label {
    color: #8A5060 !important;
    font-size: 11px !important;
    font-weight: 600 !important;
    text-transform: uppercase;
    letter-spacing: 0.06em;
}

/* ── Tabs ── */
[data-baseweb="tab-list"] {
    background: transparent !important;
    border-bottom: 2px solid #EAD8DE !important;
    gap: 4px !important;
}
[data-baseweb="tab"] {
    background: transparent !important;
    color: #A07080 !important;
    font-size: 13px !important;
    font-weight: 500 !important;
    padding: 10px 20px !important;
    border-bottom: 2px solid transparent !important;
    margin-bottom: -2px !important;
}
[data-baseweb="tab"]:hover { color: #C1294A !important; }
[aria-selected="true"][data-baseweb="tab"] {
    color: #C1294A !important;
    border-bottom-color: #C1294A !important;
    background: transparent !important;
    font-weight: 700 !important;
}
[data-testid="stTabsContent"] { padding-top: 24px !important; }

/* ── Alerts ── */
.stSuccess  { background:rgba(34,197,94,0.07)!important; border:1px solid rgba(34,197,94,0.28)!important; color:#166534!important; border-radius:10px!important; }
.stError    { background:rgba(193,41,74,0.07)!important; border:1px solid rgba(193,41,74,0.25)!important; color:#881337!important; border-radius:10px!important; }
.stWarning  { background:rgba(249,115,22,0.07)!important; border:1px solid rgba(249,115,22,0.25)!important; color:#C2410C!important; border-radius:10px!important; }
.stInfo     { background:rgba(99,102,241,0.07)!important; border:1px solid rgba(99,102,241,0.25)!important; color:#3730A3!important; border-radius:10px!important; }

/* ── File uploader ── */
[data-testid="stFileUploader"] {
    background: #FFFFFF !important;
    border: 2px dashed #E0CDD3 !important;
    border-radius: 14px !important;
    transition: border-color 200ms, background 200ms !important;
    box-shadow: 0 1px 6px rgba(74,14,36,0.06) !important;
}
[data-testid="stFileUploader"]:hover {
    border-color: #C1294A !important;
    background: rgba(193,41,74,0.02) !important;
}
[data-testid="stFileUploaderDropzone"] {
    background: transparent !important;
    min-height: 140px !important;
    display: flex !important;
    align-items: center !important;
    justify-content: center !important;
}

/* ── Metrics ── */
[data-testid="stMetric"] {
    background: #FFFFFF !important;
    border: 1px solid #EAD8DE !important;
    border-radius: 12px !important;
    padding: 16px 18px !important;
    box-shadow: 0 1px 6px rgba(74,14,36,0.07) !important;
}
[data-testid="stMetricLabel"] > div {
    color: #8A5060 !important;
    font-size: 10px !important;
    text-transform: uppercase;
    letter-spacing: 0.07em;
    font-weight: 600 !important;
}
[data-testid="stMetricValue"] { color: #1C0A0F !important; font-size: 24px !important; font-weight: 700 !important; }

/* ── Dataframe ── */
[data-testid="stDataFrame"] {
    border: 1px solid #EAD8DE !important;
    border-radius: 12px !important;
    overflow: hidden !important;
    box-shadow: 0 1px 6px rgba(74,14,36,0.06) !important;
}

/* ── Code / log terminal ── */
[data-testid="stCode"] pre, .stCodeBlock pre {
    background: #1C0A0F !important;
    border: 1px solid #3D1020 !important;
    border-radius: 10px !important;
    font-size: 11px !important;
    color: #FFB8C6 !important;
}

/* ── Progress bar ── */
[data-testid="stProgressBar"] > div {
    background: #EAD8DE !important;
    border-radius: 6px !important;
}
[data-testid="stProgressBar"] > div > div {
    background: linear-gradient(90deg, #C1294A, #F97316) !important;
    border-radius: 6px !important;
}

/* ── Divider ── */
hr { border-color: #EAD8DE !important; }

/* ── Scrollbar ── */
::-webkit-scrollbar { width:5px; height:5px; }
::-webkit-scrollbar-track { background:#F7F0EC; }
::-webkit-scrollbar-thumb { background:#E0CDD3; border-radius:4px; }
::-webkit-scrollbar-thumb:hover { background:#C1294A; }

/* ── Skeleton shimmer ── */
@keyframes shimmer {
    0%   { background-position: -600px 0; }
    100% { background-position: 600px 0; }
}
.skeleton {
    background: linear-gradient(90deg,
        rgba(193,41,74,0.04) 25%,
        rgba(249,115,22,0.08) 50%,
        rgba(193,41,74,0.04) 75%);
    background-size: 600px 100%;
    animation: shimmer 1.6s infinite linear;
    border-radius: 10px;
}

/* ── Page-load bar ── */
@keyframes loadBar {
    0%   { width: 0%;   opacity: 1; }
    80%  { width: 90%;  opacity: 1; }
    100% { width: 100%; opacity: 0; }
}
#page-loader {
    position: fixed; top: 0; left: 0; right: 0;
    height: 3px; z-index: 9999;
    background: rgba(193,41,74,0.10);
    pointer-events: none;
}
#page-loader-fill {
    height: 100%; width: 0;
    background: linear-gradient(90deg, #C1294A, #F97316);
    border-radius: 0 2px 2px 0;
    animation: loadBar 1000ms ease-out 50ms forwards;
}

/* ── Animations ── */
@keyframes fadeUp {
    from { opacity:0; transform:translateY(8px); }
    to   { opacity:1; transform:translateY(0); }
}
.fade-up { animation: fadeUp 240ms ease both; }

@keyframes pulse-dot {
    0%,100% { opacity:1; transform:scale(1); }
    50%     { opacity:0.4; transform:scale(0.65); }
}

/* ── Sidebar download button ── */
[data-testid="stSidebar"] [data-testid="stDownloadButton"] > button {
    background: rgba(249,115,22,0.14) !important;
    color: #FFBA88 !important;
    border: 1px solid rgba(249,115,22,0.38) !important;
    border-radius: 10px !important;
    font-size: 12px !important;
    font-weight: 600 !important;
    padding: 9px 12px !important;
    transition: all 200ms !important;
}
[data-testid="stSidebar"] [data-testid="stDownloadButton"] > button:hover {
    background: rgba(249,115,22,0.24) !important;
    border-color: rgba(249,115,22,0.58) !important;
    box-shadow: 0 0 16px rgba(249,115,22,0.20) !important;
}

/* ── Sidebar nav buttons (inactive) ── */
[data-testid="stSidebar"] .stButton > button {
    background: transparent !important;
    color: rgba(255,255,255,0.42) !important;
    border: none !important;
    border-left: 3px solid transparent !important;
    border-radius: 0 8px 8px 0 !important;
    text-align: left !important;
    justify-content: flex-start !important;
    padding: 10px 14px 10px 13px !important;
    margin: 1px 0 !important;
    font-size: 13px !important;
    font-weight: 500 !important;
    width: calc(100% - 8px) !important;
    box-shadow: none !important;
}
[data-testid="stSidebar"] .stButton > button:hover {
    background: rgba(255,255,255,0.07) !important;
    color: rgba(255,255,255,0.85) !important;
    border-left-color: rgba(255,255,255,0.30) !important;
    box-shadow: none !important;
}

/* ── Stage indicator ── */
.stage-row {
    display:flex; align-items:center; gap:12px;
    padding:9px 0; border-bottom:1px solid #F0E4E8;
}
.stage-dot { width:7px; height:7px; border-radius:50%; flex-shrink:0; }
.stage-dot.done    { background:#22c55e; }
.stage-dot.active  { background:#C1294A; animation:pulse-dot 1.2s infinite; }
.stage-dot.pending { background:#E0CDD3; }
</style>
""", unsafe_allow_html=True)

# ── Auth & session ─────────────────────────────────────────────────────────────
auth = AuthManager()

_DEFAULTS = {
    "authenticated": False,
    "username": None,
    "auth_step": "password",
    "temp_username": None,
    "pending_totp_secret": None,
    "page": "archive",
}
for _k, _v in _DEFAULTS.items():
    if _k not in st.session_state:
        st.session_state[_k] = _v

# ── Route ─────────────────────────────────────────────────────────────────────
st.markdown('<div id="page-loader"><div id="page-loader-fill"></div></div>', unsafe_allow_html=True)

if not st.session_state.authenticated:
    from views.login import render_login
    render_login(auth)
else:
    from views.upload import render_upload
    from views.archive import render_archive
    from views.config import render_config

    username = st.session_state.username
    pending_count = len(list(
        (Path.home() / "Documents" / "Casos_inteligencia_de_amenazas").glob("*.pdf")
    )) if (Path.home() / "Documents" / "Casos_inteligencia_de_amenazas").exists() else 0

    # ── Sidebar: branding + status only (navigation moved to top navbar) ──────
    with st.sidebar:
        st.markdown("""
        <div style="padding:28px 18px 20px;border-bottom:1px solid rgba(255,255,255,0.08);
            text-align:center;">
            <div style="width:52px;height:52px;margin:0 auto 12px;
                background:linear-gradient(135deg,rgba(249,115,22,0.22),rgba(193,41,74,0.22));
                border:1px solid rgba(249,115,22,0.40);border-radius:14px;
                display:flex;align-items:center;justify-content:center;font-size:26px;">🛡️</div>
            <div style="font-size:17px;font-weight:800;color:#FFFFFF;letter-spacing:0.12em;">ARGOS</div>
            <div style="font-size:10px;color:rgba(255,255,255,0.28);margin-top:4px;line-height:1.5;">
                Sistema de Inteligencia<br>de Vulnerabilidades
            </div>
        </div>
        """, unsafe_allow_html=True)

        EXCEL_PATH = Path.home() / "Documents" / "Casos_inteligencia_de_amenazas" / "Informe_Amenazas.xlsx"
        st.markdown('<div style="padding:16px 12px 8px;">', unsafe_allow_html=True)
        if EXCEL_PATH.exists():
            with open(EXCEL_PATH, "rb") as _fh:
                st.download_button(
                    label="⬇  Descargar Informe",
                    data=_fh.read(),
                    file_name=EXCEL_PATH.name,
                    mime="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
                    use_container_width=True,
                    key="sidebar_dl",
                )
        else:
            st.markdown("""
            <div style="padding:10px 13px;background:rgba(255,255,255,0.04);
                border:1px dashed rgba(255,255,255,0.12);
                border-radius:10px;text-align:center;">
                <span style="font-size:11px;color:rgba(255,255,255,0.22);">Sin informe generado</span>
            </div>
            """, unsafe_allow_html=True)
        st.markdown('</div>', unsafe_allow_html=True)

        st.markdown("""
        <div style="position:fixed;bottom:0;left:0;width:224px;
            padding:14px 18px;
            background:rgba(30,5,15,0.80);backdrop-filter:blur(8px);
            border-top:1px solid rgba(255,255,255,0.07);">
            <div style="display:flex;align-items:center;gap:9px;">
                <span style="font-size:15px;">⚡</span>
                <div style="flex:1;min-width:0;">
                    <div style="font-size:11px;font-weight:700;color:rgba(255,255,255,0.80);
                        letter-spacing:0.04em;">GROQ IA</div>
                    <div style="font-size:10px;color:rgba(255,255,255,0.28);margin-top:1px;
                        overflow:hidden;text-overflow:ellipsis;white-space:nowrap;">
                        llama-3.3-70b-versatile</div>
                </div>
                <div style="display:flex;align-items:center;gap:4px;flex-shrink:0;">
                    <div style="width:6px;height:6px;background:#22c55e;border-radius:50%;
                        box-shadow:0 0 6px rgba(34,197,94,0.7);"></div>
                    <span style="font-size:10px;color:#4ade80;font-weight:600;">Online</span>
                </div>
            </div>
        </div>
        """, unsafe_allow_html=True)

    # ── Top bar + Navbar ─────────────────────────────────────────────────────
    current_page = st.session_state.page
    now_str = datetime.now().strftime("%H:%M")
    initial = username[0].upper() if username else "U"

    nav_items = [
        ("upload",  "📤", "Procesar",      pending_count if pending_count else None),
        ("archive", "📊", "Historial",      None),
        ("config",  "⚙️", "Configuración",  None),
    ]

    st.markdown("""
    <style>
    /* ── Layout ── */
    .page-content { padding:28px 28px 48px; max-width:1200px; width:100%; }
    @media (max-width:640px) { .page-content { padding:16px 12px 48px; } }

    /* ── Top bar ── */
    .topbar {
        display:flex; align-items:center; justify-content:space-between;
        padding:10px 24px; background:#FFFFFF;
        border-bottom:1px solid #EAD8DE;
        box-shadow:0 1px 6px rgba(74,14,36,0.07);
        flex-wrap:wrap; gap:8px;
    }
    .topbar-brand { display:flex; align-items:center; gap:10px; }
    .topbar-user  { display:flex; align-items:center; gap:10px; flex-wrap:wrap; }

    /* ── Navbar strip ── */
    .navbar-strip {
        background:#FFFFFF;
        border-bottom:2px solid #EAD8DE;
        padding:0 24px;
        display:flex; align-items:stretch; gap:0;
    }

    /* ── Navbar Streamlit buttons ── */
    div[data-testid="stHorizontalBlock"].navbar-row {
        gap:0 !important;
        background:#FFFFFF;
        border-bottom:2px solid #EAD8DE;
        padding:0 20px;
        margin:0 !important;
    }
    div[data-testid="stHorizontalBlock"].navbar-row > div {
        flex:0 0 auto !important;
        width:auto !important;
        min-width:0 !important;
    }

    /* ── Nav buttons base ── */
    .stButton.nav-btn > button {
        background: transparent !important;
        color: #A07080 !important;
        border: none !important;
        border-bottom: 2px solid transparent !important;
        border-radius: 0 !important;
        font-size: 13px !important;
        font-weight: 500 !important;
        padding: 12px 18px !important;
        margin-bottom: -2px !important;
        box-shadow: none !important;
        transition: color 150ms, border-color 150ms !important;
        white-space: nowrap !important;
    }
    .stButton.nav-btn > button:hover {
        color: #C1294A !important;
        border-bottom-color: rgba(193,41,74,0.35) !important;
        background: rgba(193,41,74,0.03) !important;
    }
    /* Active nav item */
    .stButton.nav-btn-active > button {
        background: transparent !important;
        color: #C1294A !important;
        border: none !important;
        border-bottom: 2px solid #C1294A !important;
        border-radius: 0 !important;
        font-size: 13px !important;
        font-weight: 700 !important;
        padding: 12px 18px !important;
        margin-bottom: -2px !important;
        box-shadow: none !important;
    }

    /* ── Logout button ── */
    .stButton.logout-btn > button {
        background: transparent !important;
        color: #A07080 !important;
        border: 1px solid #E0CDD3 !important;
        border-radius: 8px !important;
        font-size: 12px !important;
        font-weight: 600 !important;
        padding: 6px 14px !important;
        box-shadow: none !important;
    }
    .stButton.logout-btn > button:hover {
        color: #C1294A !important;
        border-color: #C1294A !important;
        background: #FEF5F7 !important;
    }

    @media (max-width:640px) {
        .stButton.nav-btn > button,
        .stButton.nav-btn-active > button { padding:10px 10px !important; font-size:11px !important; }
        .topbar { padding:8px 14px; }
    }
    </style>
    """, unsafe_allow_html=True)

    # ── Topbar HTML ───────────────────────────────────────────────────────────
    st.markdown(f"""
    <div class="topbar">
        <div class="topbar-brand">
            <div style="width:32px;height:32px;
                background:linear-gradient(135deg,#C1294A,#8B1A33);
                border-radius:9px;display:flex;align-items:center;justify-content:center;
                font-size:16px;box-shadow:0 2px 8px rgba(193,41,74,0.30);">🛡️</div>
            <span style="font-size:15px;font-weight:800;color:#1C0A0F;letter-spacing:0.06em;">ARGOS</span>
        </div>
        <div class="topbar-user">
            <span style="font-size:11px;color:#B09AA5;font-weight:500;">{now_str}</span>
            <div style="display:flex;align-items:center;gap:8px;">
                <div style="width:28px;height:28px;
                    background:linear-gradient(135deg,#C1294A,#8B1A33);
                    border-radius:50%;display:flex;align-items:center;justify-content:center;
                    font-size:11px;font-weight:700;color:#fff;
                    box-shadow:0 2px 8px rgba(193,41,74,0.30);">{initial}</div>
                <span style="font-size:13px;font-weight:600;color:#3A1520;">JC Rodríguez</span>
            </div>
        </div>
    </div>
    """, unsafe_allow_html=True)

    # ── Navbar row (Streamlit buttons styled as tabs) ─────────────────────────
    st.markdown(
        '<div style="background:#FFFFFF;border-bottom:2px solid #EAD8DE;'
        'padding:0 20px;display:flex;align-items:stretch;">',
        unsafe_allow_html=True,
    )
    nav_cols = st.columns([1, 1, 1, 6, 1])  # 3 nav items | spacer | logout
    for idx, (page_id, icon, label, badge) in enumerate(nav_items):
        is_active = current_page == page_id
        badge_str = f" · {badge}" if badge else ""
        btn_label = f"{icon}  {label}{badge_str}"
        css_class = "nav-btn-active" if is_active else "nav-btn"
        with nav_cols[idx]:
            st.markdown(f'<div class="stButton {css_class}">', unsafe_allow_html=True)
            if st.button(btn_label, key=f"navbar_{page_id}"):
                st.session_state.page = page_id
                st.rerun()
            st.markdown('</div>', unsafe_allow_html=True)

    with nav_cols[4]:
        st.markdown('<div class="stButton logout-btn" style="display:flex;align-items:center;justify-content:flex-end;height:100%;padding:8px 0;">', unsafe_allow_html=True)
        if st.button("→ Salir", key="logout_btn"):
            for k in list(st.session_state.keys()):
                if k not in ("saved_file_ids",):
                    del st.session_state[k]
            st.rerun()
        st.markdown('</div>', unsafe_allow_html=True)

    st.markdown('</div>', unsafe_allow_html=True)

    # ── Page content ──────────────────────────────────────────────────────────
    st.markdown('<div class="page-content">', unsafe_allow_html=True)

    if current_page == "upload":
        render_upload()
    elif current_page == "archive":
        render_archive()
    elif current_page == "config":
        render_config()

    st.markdown('</div>', unsafe_allow_html=True)
