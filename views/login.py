import streamlit as st

_EMAIL_HINT = "usuario@fiduprevisora.com.co"
_COMPANY    = "Fiduprevisora S.A."
_YEAR       = "2025"


def _complete_login(username: str):
    st.session_state.authenticated  = True
    st.session_state.username        = username
    st.session_state.auth_step       = "password"
    st.session_state.temp_username   = None
    st.session_state.pending_totp_secret = None
    st.rerun()


def render_login(auth):
    st.markdown("""
    <style>
    .stApp {
        background: linear-gradient(135deg, #F7F0EC 0%, #F0E4EA 50%, #F5EDE8 100%) !important;
    }
    .main .block-container { padding:0 !important; max-width:100% !important; }
    </style>
    """, unsafe_allow_html=True)

    st.markdown("""
    <div style="position:fixed;top:0;left:0;right:0;z-index:200;
        padding:18px 28px;display:flex;align-items:center;gap:11px;
        background:rgba(247,240,236,0.85);backdrop-filter:blur(10px);
        border-bottom:1px solid rgba(193,41,74,0.10);">
        <div style="width:32px;height:32px;
            background:linear-gradient(135deg,#C1294A,#8B1A33);
            border-radius:9px;display:flex;align-items:center;justify-content:center;
            font-size:16px;box-shadow:0 2px 10px rgba(193,41,74,0.30);">🛡️</div>
        <span style="font-size:14px;font-weight:800;color:#1C0A0F;letter-spacing:0.10em;">ARGOS</span>
    </div>
    """, unsafe_allow_html=True)

    step = st.session_state.auth_step

    if not auth.has_users():
        _render_setup(auth)
        return

    if step == "password":
        _render_step1(auth)
    elif step == "setup_totp":
        _render_setup_totp(auth)
    elif step == "totp":
        _render_step2(auth)

    st.markdown(f"""
    <div style="position:fixed;bottom:20px;left:0;right:0;text-align:center;">
        <span style="font-size:11px;color:#C4A8B2;">
            © {_YEAR} {_COMPANY} — Dirección de Ciberseguridad
        </span>
    </div>
    """, unsafe_allow_html=True)


def _render_setup(auth):
    _, col, _ = st.columns([1, 1.1, 1])
    with col:
        st.markdown("<div style='height:90px'></div>", unsafe_allow_html=True)
        st.markdown("""
        <div style="text-align:center;margin-bottom:32px;">
            <div style="display:inline-flex;align-items:center;gap:6px;
                background:rgba(193,41,74,0.08);border:1px solid rgba(193,41,74,0.22);
                border-radius:99px;padding:5px 14px;margin-bottom:18px;">
                <div style="width:6px;height:6px;background:#C1294A;border-radius:50%;"></div>
                <span style="font-size:11px;font-weight:600;color:#C1294A;">Primera configuración</span>
            </div>
            <h1 style="font-size:2.1rem;font-weight:800;color:#1C0A0F;margin:0;">Bienvenido a</h1>
            <h1 style="font-size:2.1rem;font-weight:800;
                background:linear-gradient(135deg,#C1294A,#F97316);
                -webkit-background-clip:text;-webkit-text-fill-color:transparent;margin:0;">ARGOS</h1>
            <p style="font-size:13px;color:#A07080;margin:10px 0 0;">Crea la cuenta de administrador</p>
        </div>
        """, unsafe_allow_html=True)

        st.markdown('<div style="background:#FFFFFF;border:1px solid #EAD8DE;border-radius:18px;padding:28px 26px;box-shadow:0 4px 30px rgba(74,14,36,0.10);">', unsafe_allow_html=True)
        with st.form("setup_form"):
            _label("USUARIO")
            u = st.text_input("u", placeholder="nombre_usuario", label_visibility="collapsed")
            _label("CONTRASEÑA", mt=14)
            p = st.text_input("p", type="password", placeholder="Mínimo 8 caracteres", label_visibility="collapsed")
            _label("CONFIRMAR CONTRASEÑA", mt=14)
            p2 = st.text_input("p2", type="password", placeholder="Repite la contraseña", label_visibility="collapsed")
            st.markdown("<br>", unsafe_allow_html=True)
            if st.form_submit_button("Crear cuenta", use_container_width=True, type="primary"):
                if not u or not p:
                    st.error("Completa todos los campos.")
                elif p != p2:
                    st.error("Las contraseñas no coinciden.")
                elif len(p) < 8:
                    st.error("La contraseña debe tener al menos 8 caracteres.")
                else:
                    auth.create_user(u, p)
                    st.success("Cuenta creada. Inicia sesión.")
                    st.rerun()
        st.markdown('</div>', unsafe_allow_html=True)


def _render_step1(auth):
    left, right = st.columns([1, 1.05])

    with left:
        st.markdown("""
        <div style="height:100vh;display:flex;align-items:center;justify-content:center;
            padding:40px 40px 40px 60px;">
            <div>
                <div style="width:64px;height:64px;
                    background:linear-gradient(135deg,#C1294A,#8B1A33);
                    border-radius:18px;display:flex;align-items:center;justify-content:center;
                    font-size:32px;margin-bottom:28px;
                    box-shadow:0 8px 32px rgba(193,41,74,0.35);">🛡️</div>
                <h1 style="font-size:2.8rem;font-weight:800;color:#1C0A0F;margin:0;line-height:1.1;">
                    Vigilancia<br>inteligente
                </h1>
                <p style="font-size:14px;color:#A07080;margin:16px 0 32px;max-width:320px;line-height:1.7;">
                    Procesamiento automatizado de boletines de seguridad con análisis de IA,
                    VirusTotal y Tenable.
                </p>
                <div style="display:flex;flex-direction:column;gap:12px;max-width:280px;">
                    <div style="display:flex;align-items:center;gap:10px;">
                        <div style="width:32px;height:32px;background:rgba(193,41,74,0.08);
                            border:1px solid rgba(193,41,74,0.18);border-radius:8px;
                            display:flex;align-items:center;justify-content:center;font-size:14px;">⚡</div>
                        <span style="font-size:12px;color:#6B3040;font-weight:500;">IA con Groq llama-3.3-70b</span>
                    </div>
                    <div style="display:flex;align-items:center;gap:10px;">
                        <div style="width:32px;height:32px;background:rgba(249,115,22,0.08);
                            border:1px solid rgba(249,115,22,0.18);border-radius:8px;
                            display:flex;align-items:center;justify-content:center;font-size:14px;">🔍</div>
                        <span style="font-size:12px;color:#6B3040;font-weight:500;">Correlación con VirusTotal</span>
                    </div>
                    <div style="display:flex;align-items:center;gap:10px;">
                        <div style="width:32px;height:32px;background:rgba(193,41,74,0.08);
                            border:1px solid rgba(193,41,74,0.18);border-radius:8px;
                            display:flex;align-items:center;justify-content:center;font-size:14px;">📊</div>
                        <span style="font-size:12px;color:#6B3040;font-weight:500;">Reportes Excel automáticos</span>
                    </div>
                </div>
            </div>
        </div>
        """, unsafe_allow_html=True)

    with right:
        st.markdown("<div style='height:110px'></div>", unsafe_allow_html=True)

        st.markdown("""
        <div style="margin-bottom:30px;">
            <div style="display:inline-flex;align-items:center;gap:6px;
                background:rgba(34,197,94,0.08);border:1px solid rgba(34,197,94,0.22);
                border-radius:99px;padding:5px 13px;margin-bottom:18px;">
                <div style="width:6px;height:6px;background:#22c55e;border-radius:50%;
                    box-shadow:0 0 6px rgba(34,197,94,0.6);animation:pulse-dot 2s infinite;"></div>
                <span style="font-size:11px;font-weight:600;color:#166534;">Sistema activo</span>
            </div>
            <h1 style="font-size:2rem;font-weight:800;color:#1C0A0F;margin:0;line-height:1.1;">Iniciar sesión</h1>
            <p style="font-size:13px;color:#A07080;margin:8px 0 0;">Accede al sistema de inteligencia de amenazas</p>
        </div>
        """, unsafe_allow_html=True)

        st.markdown('<div style="background:#FFFFFF;border:1px solid #EAD8DE;border-radius:18px;padding:28px 26px 22px;box-shadow:0 4px 30px rgba(74,14,36,0.10);max-width:420px;">', unsafe_allow_html=True)

        with st.form("login_form"):
            _label("Correo electrónico")
            username_val = st.text_input("usr", placeholder=_EMAIL_HINT, label_visibility="collapsed")
            _label("Contraseña", mt=14)
            password_val = st.text_input("pwd", type="password", placeholder="••••••••", label_visibility="collapsed")

            st.markdown("<div style='height:6px'></div>", unsafe_allow_html=True)
            submit = st.form_submit_button("Acceder al sistema", use_container_width=True, type="primary")

        st.markdown("""
        <p style="text-align:center;font-size:11px;color:#C4A8B2;margin:14px 0 4px;">
            ¿Olvidaste tus credenciales? Contacta al administrador
        </p>
        """, unsafe_allow_html=True)

        st.markdown('</div>', unsafe_allow_html=True)

        if submit:
            if auth.verify_password(username_val, password_val):
                st.session_state.temp_username = username_val
                if auth.has_totp(username_val):
                    st.session_state.auth_step = "totp"
                else:
                    st.session_state.auth_step = "setup_totp"
                    st.session_state.pending_totp_secret = auth.generate_totp_secret(username_val)
                st.rerun()
            else:
                st.error("Correo o contraseña incorrectos.")


def _render_setup_totp(auth):
    username = st.session_state.temp_username
    secret   = st.session_state.pending_totp_secret

    _, col, _ = st.columns([1, 1.2, 1])
    with col:
        st.markdown("<div style='height:70px'></div>", unsafe_allow_html=True)

        st.markdown("""
        <div style="text-align:center;margin-bottom:24px;">
            <h1 style="font-size:1.8rem;font-weight:800;color:#1C0A0F;margin:0;">Configura</h1>
            <h1 style="font-size:1.8rem;font-weight:800;
                background:linear-gradient(135deg,#C1294A,#F97316);
                -webkit-background-clip:text;-webkit-text-fill-color:transparent;margin:0;">Autenticación 2FA</h1>
            <p style="font-size:13px;color:#A07080;margin:8px 0 0;">Vincula tu dispositivo autenticador</p>
        </div>
        """, unsafe_allow_html=True)

        st.markdown('<div style="background:#FFFFFF;border:1px solid #EAD8DE;border-radius:18px;padding:28px 26px;box-shadow:0 4px 30px rgba(74,14,36,0.10);">', unsafe_allow_html=True)

        st.markdown("""
        <div style="text-align:center;margin-bottom:16px;">
            <div style="width:54px;height:54px;
                background:linear-gradient(135deg,rgba(193,41,74,0.12),rgba(249,115,22,0.12));
                border:1px solid rgba(193,41,74,0.22);border-radius:14px;
                display:inline-flex;align-items:center;justify-content:center;font-size:26px;">🔑</div>
        </div>
        """, unsafe_allow_html=True)

        qr_bytes = auth.get_qr_image(username, secret)
        c1, c2, c3 = st.columns([1, 1.6, 1])
        with c2:
            st.image(qr_bytes, use_container_width=True)

        st.markdown(f"""
        <p style="text-align:center;font-size:13px;color:#7A4A55;margin:12px 0 16px;line-height:1.6;">
            Abre <strong style="color:#1C0A0F;">Microsoft Authenticator</strong> e ingresa el código
            de 6 dígitos de la cuenta <strong style="color:#C1294A;">ARGOS</strong>.
        </p>
        """, unsafe_allow_html=True)

        with st.expander("Ingresar clave manualmente"):
            st.code(secret, language=None)
            st.caption("TOTP · SHA-1 · 6 dígitos · 30 s")

        _label("Código de verificación", mt=8)
        with st.form("totp_setup_form"):
            code = st.text_input("c", max_chars=6, placeholder="0  0  0  0  0  0",
                                 label_visibility="collapsed")
            st.markdown("<div style='height:4px'></div>", unsafe_allow_html=True)
            if st.form_submit_button("Confirmar código", use_container_width=True, type="primary"):
                if auth.verify_totp(username, code):
                    _complete_login(username)
                else:
                    st.error("Código incorrecto.")

        if st.button("← Volver al inicio de sesión", type="secondary", use_container_width=True):
            st.session_state.auth_step = "password"
            st.session_state.temp_username = None
            st.rerun()

        st.markdown('</div>', unsafe_allow_html=True)


def _render_step2(auth):
    username = st.session_state.temp_username

    _, col, _ = st.columns([1, 1.2, 1])
    with col:
        st.markdown("<div style='height:70px'></div>", unsafe_allow_html=True)

        st.markdown("""
        <div style="text-align:center;margin-bottom:24px;">
            <div style="display:inline-flex;align-items:center;gap:6px;
                background:rgba(34,197,94,0.08);border:1px solid rgba(34,197,94,0.22);
                border-radius:99px;padding:5px 13px;margin-bottom:16px;">
                <div style="width:6px;height:6px;background:#22c55e;border-radius:50%;"></div>
                <span style="font-size:11px;font-weight:600;color:#166534;">Sistema activo</span>
            </div>
            <h1 style="font-size:1.8rem;font-weight:800;color:#1C0A0F;margin:0;">Verificación</h1>
            <h1 style="font-size:1.8rem;font-weight:800;
                background:linear-gradient(135deg,#C1294A,#F97316);
                -webkit-background-clip:text;-webkit-text-fill-color:transparent;margin:0;">en dos pasos</h1>
        </div>
        """, unsafe_allow_html=True)

        st.markdown('<div style="background:#FFFFFF;border:1px solid #EAD8DE;border-radius:18px;padding:28px 26px;box-shadow:0 4px 30px rgba(74,14,36,0.10);">', unsafe_allow_html=True)

        st.markdown("""
        <div style="text-align:center;margin-bottom:16px;">
            <div style="width:54px;height:54px;
                background:linear-gradient(135deg,rgba(193,41,74,0.12),rgba(249,115,22,0.12));
                border:1px solid rgba(193,41,74,0.22);border-radius:14px;
                display:inline-flex;align-items:center;justify-content:center;font-size:26px;">🔑</div>
        </div>
        <p style="text-align:center;font-size:13px;color:#7A4A55;margin:0 0 18px;line-height:1.6;">
            Abre <strong style="color:#1C0A0F;">Microsoft Authenticator</strong> e ingresa el código
            de 6 dígitos de la cuenta <strong style="color:#C1294A;">ARGOS</strong>.
        </p>
        """, unsafe_allow_html=True)

        _label("Código de verificación")
        with st.form("totp_form"):
            code = st.text_input("code", max_chars=6, placeholder="0  0  0  0  0  0",
                                 label_visibility="collapsed")
            st.markdown("<div style='height:4px'></div>", unsafe_allow_html=True)
            if st.form_submit_button("Confirmar código", use_container_width=True, type="primary"):
                if auth.verify_totp(username, code):
                    _complete_login(username)
                else:
                    st.error("Código incorrecto o expirado.")

        if st.button("← Volver al inicio de sesión", type="secondary", use_container_width=True):
            st.session_state.auth_step = "password"
            st.session_state.temp_username = None
            st.rerun()

        st.markdown('</div>', unsafe_allow_html=True)


def _label(text: str, mt: int = 0):
    st.markdown(
        f'<p style="font-size:11px;color:#8A5060;font-weight:600;text-transform:uppercase;'
        f'letter-spacing:0.06em;margin:{mt}px 0 6px;">{text}</p>',
        unsafe_allow_html=True,
    )
