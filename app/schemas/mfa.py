from pydantic import BaseModel


class GenerateRequest(BaseModel):
    username: str

class GenerateResponse(BaseModel):
    secret: str
    otpauth_url: str
    qrcode_base64: str
    qrcode_html: str
    qrcode_preview: str


class VerifyTokenRequest(BaseModel):
    username: str
    token: str
