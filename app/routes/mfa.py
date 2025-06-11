import os
import pyotp
from fastapi import APIRouter, HTTPException
from fastapi.responses import StreamingResponse, HTMLResponse
from app.schemas.mfa import GenerateRequest, GenerateResponse, VerifyTokenRequest
from app.utils.totp import (
    generate_totp_secret,
    get_otpauth_url,
    verify_totp_token,
    generate_qrcode_base64
)
from qrcode.constants import ERROR_CORRECT_L
from qrcode.main import QRCode
from io import BytesIO
from time import time


router = APIRouter(prefix="/mfa", tags=["MFA"])
# Armazenamento temporário em memória (dict de usuário → secret)
mfa_secrets: dict[str, str] = {}


@router.post("/generate", response_model=GenerateResponse)
def generate(data: GenerateRequest):
    issuer = os.getenv("ISSUER_NAME", "MultipleAuth")
    secret = generate_totp_secret()
    otpauth_url = get_otpauth_url(secret, data.username, issuer)
    qrcode_base64 = generate_qrcode_base64(otpauth_url)
    qrcode_html = f'<img src="data:image/png;base64,{qrcode_base64}"/>'
    qrcode_preview = f"data:image/png;base64,{qrcode_base64}"

    # Armazena secret por username
    mfa_secrets[data.username] = secret

    return GenerateResponse(
        secret=secret,
        otpauth_url=otpauth_url,
        qrcode_base64=qrcode_base64,
        qrcode_html=qrcode_html,
        qrcode_preview=qrcode_preview
    )


@router.post("/verify-token")
def verify_token(data: VerifyTokenRequest):
    secret = mfa_secrets.get(data.username)
    if not secret:
        raise HTTPException(status_code=404, detail="Secret não encontrado para o usuário")

    valid = verify_totp_token(secret, data.token)

    totp = pyotp.TOTP(secret)
    expected_token = totp.now()

    now = int(time())
    interval = 30  # padrão do TOTP
    timecodes = [now - interval, now, now + interval]

    tokens_validos = [totp.at(t) for t in timecodes]

    print("------ DEBUG VERIFY TOKEN ------")
    print("username:", data.username)
    print("secret armazenado:", secret)
    print("token recebido:", data.token)
    print("token atual esperado:", expected_token)
    print("tokens válidos (±30s):", tokens_validos)
    print("validação com valid_window=1:", totp.verify(data.token, valid_window=1))
    print("--------------------------------")

    return {"username": data.username, "valid": valid}


@router.get("/qrcode-image", summary="QR Code renderizável para autenticação MFA")
def get_qrcode_image(
    username: str = "demo",
    issuer: str = os.getenv("ISSUER_NAME", "MultipleAuth"),
    box_size: int = 10,
):
    """
    Gera e retorna a imagem do QR Code (image/png) e armazena o secret para uso posterior.
    Visualizável diretamente via Swagger ou navegador.
    """
    secret = generate_totp_secret()
    otpauth_url = get_otpauth_url(secret, username, issuer)

    # 💾 Salva o secret para o username
    mfa_secrets[username] = secret

    qr = QRCode(
        version=1,
        error_correction=ERROR_CORRECT_L,
        box_size=box_size,
        border=2,
    )
    qr.add_data(otpauth_url)
    qr.make(fit=True)

    img = qr.make_image(fill_color="black", back_color="white")
    img_io = BytesIO()
    img.save(img_io, format="PNG")
    img_io.seek(0)

    return StreamingResponse(img_io, media_type="image/png")


@router.get("/demo", response_class=HTMLResponse, summary="Página HTML com QR Code")
def mfa_demo(username: str = "demo"):
    issuer = os.getenv("ISSUER_NAME", "MultipleAuth")
    secret = generate_totp_secret()
    otpauth_url = get_otpauth_url(secret, username, issuer)
    qrcode_base64 = generate_qrcode_base64(otpauth_url)

    return f"""
    <html>
        <body style="font-family: sans-serif; text-align: center; padding: 2em">
            <h2>MFA QR Code para <code>{username}</code></h2>
            <p>Secret: <code>{secret}</code></p>
            <p><img src="data:image/png;base64,{qrcode_base64}" /></p>
            <p><small>Escaneie com Microsoft Authenticator ou Google Authenticator.</small></p>
        </body>
    </html>
    """
