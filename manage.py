"""Comandos de recuperação. Uso: docker compose exec app python manage.py <comando>"""
import secrets
import sys

import models
from appsettings import store
from database import SessionLocal
from security import get_password_hash


def main(cmd: str) -> int:
    db = SessionLocal()
    try:
        admin = db.query(models.Usuario).filter(models.Usuario.username == "admin").first()
        if cmd == "reset-admin-password":
            if not admin:
                print("Usuário admin não existe.")
                return 1
            senha = "Aa1!" + secrets.token_urlsafe(12)
            admin.password_hash = get_password_hash(senha)
            db.commit()
            print(f"Nova senha do admin: {senha}")
        elif cmd == "reset-admin-2fa":
            if not admin:
                print("Usuário admin não existe.")
                return 1
            admin.is_2fa_enabled, admin.totp_secret = False, None
            db.commit()
            print("2FA do admin redefinido. Será reconfigurado no próximo login.")
        elif cmd == "disable-recaptcha":
            store.load(db)
            store.save(db, {"recaptcha_enabled": "false"})
            print("reCAPTCHA desativado.")
        else:
            print("Comandos: reset-admin-password | reset-admin-2fa | disable-recaptcha")
            return 2
        return 0
    finally:
        db.close()


if __name__ == "__main__":
    sys.exit(main(sys.argv[1] if len(sys.argv) > 1 else ""))
