"""
Run this script once to create auth_config.yaml with hashed passwords.
Usage: python setup_auth.py
"""
import getpass
import re
import secrets
import sys

import bcrypt
import yaml

MIN_PASSWORD_LENGTH = 12


def hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt(rounds=12)).decode()


def validate_password(password: str) -> list[str]:
    """Return a list of unmet requirements (empty = valid)."""
    issues = []
    if len(password) < MIN_PASSWORD_LENGTH:
        issues.append(f"Mínimo {MIN_PASSWORD_LENGTH} caracteres (tiene {len(password)}).")
    if not re.search(r"[A-Z]", password):
        issues.append("Debe incluir al menos una letra MAYÚSCULA.")
    if not re.search(r"[a-z]", password):
        issues.append("Debe incluir al menos una letra minúscula.")
    if not re.search(r"\d", password):
        issues.append("Debe incluir al menos un número.")
    if not re.search(r"[^A-Za-z0-9]", password):
        issues.append("Debe incluir al menos un símbolo (ej. !@#$%).")
    return issues


def ask(prompt: str) -> str:
    value = input(f"  {prompt}: ").strip()
    if not value:
        print("  ❌ No puede estar vacío.")
        sys.exit(1)
    return value


def ask_password(prompt: str) -> str:
    while True:
        password = getpass.getpass(f"  {prompt}: ").strip()
        issues = validate_password(password)
        if not issues:
            confirm = getpass.getpass("  Confirmar contraseña: ").strip()
            if password != confirm:
                print("  ❌ Las contraseñas no coinciden. Intenta de nuevo.\n")
                continue
            return password
        print("  ❌ Contraseña débil:")
        for issue in issues:
            print(f"     • {issue}")
        print()


def configure_user(label: str) -> tuple[str, dict]:
    print(f"\n👤 {label}:")
    username = ask("Nombre de usuario (sin espacios)").lower().replace(" ", "_")
    name = ask("Nombre completo")
    email = ask("Email")
    password = ask_password("Contraseña")
    return username, {
        "name": name,
        "email": email,
        "password": hash_password(password),
    }


def main():
    print("=" * 55)
    print("  Configuración de usuarios — Security Bulletin Analyzer")
    print("=" * 55)
    print(f"\nRequisitos de contraseña:")
    print(f"  • Mínimo {MIN_PASSWORD_LENGTH} caracteres")
    print(f"  • Al menos una mayúscula, una minúscula, un número y un símbolo\n")

    u1, data1 = configure_user("Usuario 1 (administrador / tú)")
    u2, data2 = configure_user("Usuario 2 (colega)")

    if u1 == u2:
        print("\n❌ Los nombres de usuario deben ser diferentes.")
        sys.exit(1)

    config = {
        "credentials": {
            "usernames": {
                u1: data1,
                u2: data2,
            }
        },
        "cookie": {
            # Sessions expire after 7 days; reduce here if you want stricter control
            "expiry_days": 7,
            # Cryptographically random 64-hex-char key — never share this
            "key": secrets.token_hex(32),
            "name": "sec_bulletin_auth",
        },
    }

    with open("auth_config.yaml", "w", encoding="utf-8") as f:
        yaml.dump(config, f, default_flow_style=False, allow_unicode=True)

    print(f"\n auth_config.yaml creado correctamente.")
    print(f"   Usuarios: {u1}, {u2}")
    print(f"   Sesiones expiran en: {config['cookie']['expiry_days']} días")
    print("\n   IMPORTANTE: auth_config.yaml contiene contraseñas hasheadas.")
    print("   No lo subas a Git (ya está en .gitignore).\n")
    print("▶  Inicia la app con:")
    print("   streamlit run app.py\n")


if __name__ == "__main__":
    main()
