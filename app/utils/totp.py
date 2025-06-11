import pyotp
import qrcode
import base64
from io import BytesIO


def generate_totp_secret() -> str:
    return pyotp.random_base32()


def get_otpauth_url(secret: str, username: str, issuer: str = "MultipleAuth") -> str:
    totp = pyotp.TOTP(secret)
    return totp.provisioning_uri(name=username, issuer_name=issuer)


def verify_totp_token(secret: str, token: str) -> bool:
    totp = pyotp.TOTP(secret)
    return totp.verify(token, valid_window=1)  # 👈 tolerância de uma janela (~30s antes/depois)


def generate_qrcode_base64(otpauth_url: str) -> str:
    qr = qrcode.make(otpauth_url)
    buffered = BytesIO()
    qr.save(buffered, format="PNG")
    return base64.b64encode(buffered.getvalue()).decode("utf-8")
