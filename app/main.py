from fastapi import FastAPI
from dotenv import load_dotenv
from app.routes import mfa


# Carrega variáveis do .env
load_dotenv()

app = FastAPI(title="Multiple Auth API")

# Registra as rotas
app.include_router(mfa.router)

@app.get("/")
def root():
    return {"message": "API de autenticação multifator (MFA) ativa."}
