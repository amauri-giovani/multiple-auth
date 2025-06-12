from sqlmodel import SQLModel, Field


class MFASecret(SQLModel, table=True):
    username: str = Field(primary_key=True)
    secret: str
