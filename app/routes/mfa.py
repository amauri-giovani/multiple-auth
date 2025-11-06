from fastapi import APIRouter, HTTPException, Query, Form
from fastapi.responses import StreamingResponse, HTMLResponse, RedirectResponse
from qrcode.image.pil import PilImage
from sqlmodel import Session
from app.schemas.mfa import GenerateRequest, GenerateResponse, VerifyTokenRequest
from app.utils.totp import generate_totp_secret, get_otpauth_url, generate_qrcode_base64, verify_totp_token
from app.models import MFASecret
from app.db import engine
from qrcode.constants import ERROR_CORRECT_L
from qrcode.main import QRCode
from io import BytesIO
import os


router = APIRouter(prefix="/mfa", tags=["MFA"])


@router.post("/setup-mfa", response_model=GenerateResponse)
def mfa_setup(data: GenerateRequest):
    issuer = os.getenv("ISSUER_NAME", "MultipleAuth")
    secret = generate_totp_secret()
    otpauth_url = get_otpauth_url(secret, data.username, issuer)
    qrcode_base64 = generate_qrcode_base64(otpauth_url)
    qrcode_html = f'<img src="data:image/png;base64,{qrcode_base64}" />'
    qrcode_preview = f"data:image/png;base64,{qrcode_base64}"

    with Session(engine) as session:
        existing = session.get(MFASecret, data.username)
        if existing:
            existing.secret = secret
        else:
            session.add(MFASecret(username=data.username, secret=secret))
        session.commit()

    return GenerateResponse(
        secret=secret,
        otpauth_url=otpauth_url,
        qrcode_base64=qrcode_base64,
        qrcode_html=qrcode_html,
        qrcode_preview=qrcode_preview
    )

@router.post("/verify-token")
def verify_token(data: VerifyTokenRequest):
    with Session(engine) as session:
        secret_entry = session.get(MFASecret, data.username)
        if not secret_entry:
            raise HTTPException(status_code=404, detail="Usuário não encontrado")

        valid = verify_totp_token(secret_entry.secret, data.token)
        return {"username": data.username, "valid": valid}


@router.get("/qrcode-image", summary="QR Code renderizável para autenticação MFA")
def get_qrcode_image(
    username: str = "demo",
    issuer: str = os.getenv("ISSUER_NAME", "MultipleAuth"),
    box_size: int = 10,
):
    secret = generate_totp_secret()
    otpauth_url = get_otpauth_url(secret, username, issuer)

    with Session(engine) as session:
        existing = session.get(MFASecret, username)
        if existing:
            existing.secret = secret
        else:
            session.add(MFASecret(username=username, secret=secret))
        session.commit()

    qr = QRCode(
        version=1,
        error_correction=ERROR_CORRECT_L,
        box_size=box_size,
        border=2,
    )
    qr.add_data(otpauth_url)
    qr.make(fit=True)

    img = qr.make_image(fill_color="black", back_color="white", image_factory=PilImage)
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

    with Session(engine) as session:
        existing = session.get(MFASecret, username)
        if existing:
            existing.secret = secret
        else:
            session.add(MFASecret(username=username, secret=secret))
        session.commit()

    return f"""
    <html>
        <body style="font-family: sans-serif; text-align: center; padding: 2em">
            <h2>MFA QR Code para <code>{username}</code></h2>
            <p>Secret: <code>{secret}</code></p>
            <p><img src=\"data:image/png;base64,{qrcode_base64}\" /></p>
            <p><small>Escaneie com Microsoft Authenticator ou Google Authenticator.</small></p>
        </body>
    </html>
    """


@router.get("/status")
def check_mfa_status(username: str = Query(...)):
    with Session(engine) as session:
        secret_entry = session.get(MFASecret, username)
        return {"registered": secret_entry is not None}

@router.get("/start", response_class=HTMLResponse)
def mfa_start(username: str = Query(...), next: str = Query("/")):
    issuer = os.getenv("ISSUER_NAME", "MultipleAuth")
    with Session(engine) as session:
        secret_entry = session.get(MFASecret, username)

        if not secret_entry:
            secret = generate_totp_secret()
            otpauth_url = get_otpauth_url(secret, username, issuer)
            qrcode_base64 = generate_qrcode_base64(otpauth_url)

            session.add(MFASecret(username=username, secret=secret))
            session.commit()

            return f"""
            <html><body style='font-family:sans-serif; text-align:center'>
                <h2>Configure o MFA</h2>
                <p>Escaneie o QR Code com seu autenticador</p>
                <img src='data:image/png;base64,{qrcode_base64}' />
                <p>Após escanear, volte e acesse novamente o sistema.</p>
            </body></html>
            """

        return f"""
        <html><body style='font-family:sans-serif; text-align:center'>
            <h2>Digite seu código de autenticação</h2>
            <form method='post' action='/mfa/validate'>
                <input type='hidden' name='username' value='{username}' />
                <input type='hidden' name='next' value='{next}' />
                <input type='text' name='token' placeholder='Código MFA' required />
                <button type='submit'>Validar</button>
            </form>
        </body></html>
        """

@router.post("/validate")
def validate_token(username: str = Form(...), token: str = Form(...), next: str = Form("/")):
    with Session(engine) as session:
        secret_entry = session.get(MFASecret, username)
        if not secret_entry:
            return HTMLResponse("<h3>Erro: MFA não encontrado.</h3>", status_code=404)

        is_valid = verify_totp_token(secret_entry.secret, token)

    callback_url = f"/mfa/callback?username={username}&status={'success' if is_valid else 'fail'}&next={next}"
    return RedirectResponse(callback_url, status_code=302)
