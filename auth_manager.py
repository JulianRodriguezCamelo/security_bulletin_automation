import io
from pathlib import Path

import bcrypt
import pyotp
import qrcode
import yaml

USERS_FILE = Path(__file__).parent / "users.yaml"
APP_NAME = "Security Bulletins"


class AuthManager:
    def __init__(self):
        if not USERS_FILE.exists():
            USERS_FILE.write_text("users: {}\n", encoding="utf-8")

    def _load(self) -> dict:
        with open(USERS_FILE, encoding="utf-8") as f:
            return yaml.safe_load(f) or {"users": {}}

    def _save(self, data: dict):
        with open(USERS_FILE, "w", encoding="utf-8") as f:
            yaml.dump(data, f, allow_unicode=True)

    def has_users(self) -> bool:
        return bool(self._load().get("users"))

    def user_exists(self, username: str) -> bool:
        return username in self._load().get("users", {})

    def create_user(self, username: str, password: str):
        data = self._load()
        hashed = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()
        data["users"][username] = {"password_hash": hashed, "totp_secret": None}
        self._save(data)

    def verify_password(self, username: str, password: str) -> bool:
        users = self._load().get("users", {})
        if username not in users:
            return False
        stored = users[username]["password_hash"].encode()
        return bcrypt.checkpw(password.encode(), stored)

    def has_totp(self, username: str) -> bool:
        users = self._load().get("users", {})
        return bool(users.get(username, {}).get("totp_secret"))

    def generate_totp_secret(self, username: str) -> str:
        secret = pyotp.random_base32()
        data = self._load()
        data["users"][username]["totp_secret"] = secret
        self._save(data)
        return secret

    def get_qr_image(self, username: str, secret: str) -> bytes:
        totp = pyotp.TOTP(secret)
        uri = totp.provisioning_uri(name=username, issuer_name=APP_NAME)
        img = qrcode.make(uri)
        buf = io.BytesIO()
        img.save(buf, format="PNG")
        return buf.getvalue()

    def verify_totp(self, username: str, code: str) -> bool:
        users = self._load().get("users", {})
        secret = users.get(username, {}).get("totp_secret")
        if not secret:
            return False
        return pyotp.TOTP(secret).verify(code.strip(), valid_window=1)
