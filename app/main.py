from fastapi import FastAPI
from dotenv import load_dotenv
from contextlib import asynccontextmanager
from app.routes import mfa
from app.db import create_db_and_tables


load_dotenv()


@asynccontextmanager
async def lifespan(app: FastAPI):
    create_db_and_tables()
    yield

app = FastAPI(title="Multiple Auth API", lifespan=lifespan)
app.include_router(mfa.router)

@app.get("/")
def root():
    return {"message": "API de autenticação multifator (MFA) ativa."}
