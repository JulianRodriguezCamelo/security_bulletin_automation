import io
import os
from pathlib import Path

import bcrypt
import pyotp
import qrcode
import yaml

USERS_FILE = Path(__file__).parent / "users.yaml"
APP_NAME   = "ARGOS - Seg. Vulnerabilidades"   # Nombre que aparece en Microsoft Authenticator


class AuthManager:
    """
    Gestiona autenticación de usuarios y TOTP (compatible con Microsoft Authenticator).
    Backend: Oracle 21c cuando USE_ORACLE=true, YAML en caso contrario.
    """

    def __init__(self):
        self._use_oracle = os.getenv("USE_ORACLE", "false").lower() == "true"
        if self._use_oracle:
            from db.oracle_manager import OracleManager
            self._db = OracleManager()
        else:
            if not USERS_FILE.exists():
                USERS_FILE.write_text("users: {}\n", encoding="utf-8")

    # ── Internal YAML helpers (solo cuando USE_ORACLE=false) ─────────────────

    def _load(self) -> dict:
        with open(USERS_FILE, encoding="utf-8") as f:
            return yaml.safe_load(f) or {"users": {}}

    def _save(self, data: dict):
        with open(USERS_FILE, "w", encoding="utf-8") as f:
            yaml.dump(data, f, allow_unicode=True)

    # ── Public API ────────────────────────────────────────────────────────────

    def has_users(self) -> bool:
        if self._use_oracle:
            return self._db.has_users()
        return bool(self._load().get("users"))

    def user_exists(self, username: str) -> bool:
        if self._use_oracle:
            return self._db.user_exists(username)
        return username in self._load().get("users", {})

    def create_user(self, username: str, password: str, role: str = "user"):
        hashed = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()
        if self._use_oracle:
            self._db.create_user(username, hashed, role=role)
        else:
            data = self._load()
            data["users"][username] = {
                "password_hash": hashed,
                "totp_secret": None,
                "role": role,
            }
            self._save(data)

    def get_user_role(self, username: str) -> str:
        """Devuelve 'admin' o 'user'."""
        if self._use_oracle:
            user = self._db.get_user(username)
            return user["role"] if user else "user"
        users = self._load().get("users", {})
        return users.get(username, {}).get("role", "user")

    def list_users(self) -> list[dict]:
        if self._use_oracle:
            return self._db.list_users()
        users = self._load().get("users", {})
        return [
            {
                "username": u,
                "role": info.get("role", "user"),
                "has_totp": bool(info.get("totp_secret")),
            }
            for u, info in users.items()
        ]

    def delete_user(self, username: str):
        if self._use_oracle:
            self._db.delete_user(username)
        else:
            data = self._load()
            data["users"].pop(username, None)
            self._save(data)

    def reset_totp(self, username: str):
        if self._use_oracle:
            self._db.update_totp_secret(username, None)
        else:
            data = self._load()
            if username in data["users"]:
                data["users"][username]["totp_secret"] = None
                self._save(data)

    def verify_password(self, username: str, password: str) -> bool:
        if self._use_oracle:
            user = self._db.get_user(username)
            if not user:
                return False
            return bcrypt.checkpw(password.encode(), user["password_hash"].encode())
        users = self._load().get("users", {})
        if username not in users:
            return False
        return bcrypt.checkpw(password.encode(), users[username]["password_hash"].encode())

    def has_totp(self, username: str) -> bool:
        if self._use_oracle:
            user = self._db.get_user(username)
            return bool(user and user.get("totp_secret"))
        users = self._load().get("users", {})
        return bool(users.get(username, {}).get("totp_secret"))

    def generate_totp_secret(self, username: str) -> str:
        secret = pyotp.random_base32()
        if self._use_oracle:
            self._db.update_totp_secret(username, secret)
        else:
            data = self._load()
            data["users"][username]["totp_secret"] = secret
            self._save(data)
        return secret

    def get_qr_image(self, username: str, secret: str) -> bytes:
        """
        Genera el QR code compatible con Microsoft Authenticator (y cualquier app TOTP).
        Parámetros explícitos en el URI: algorithm=SHA1, digits=6, period=30.
        """
        totp = pyotp.TOTP(secret, digits=6, interval=30)
        uri  = totp.provisioning_uri(
            name=username,
            issuer_name=APP_NAME,
        )
        img = qrcode.make(uri)
        buf = io.BytesIO()
        img.save(buf, format="PNG")
        return buf.getvalue()

    def verify_totp(self, username: str, code: str) -> bool:
        if self._use_oracle:
            user = self._db.get_user(username)
            secret = user.get("totp_secret") if user else None
        else:
            users  = self._load().get("users", {})
            secret = users.get(username, {}).get("totp_secret")
        if not secret:
            return False
        return pyotp.TOTP(secret, digits=6, interval=30).verify(code.strip(), valid_window=1)
