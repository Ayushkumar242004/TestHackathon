# app/settings.py
from pydantic_settings import BaseSettings, SettingsConfigDict
from typing import Optional
class Settings(BaseSettings):
    ADMIN_API_KEY: str = "0x94803bf3032ccf8c7605e96213c0b5f884cad8cfbc32365a71e959de891c1877"
    DEPLOYER_PK: str | None = None
    RPC_URL: str
    CONTRACT_ADDRESS: str
    CHAIN_ID: int = 31337
    ADMIN_PK: str
    SUBMITTER_PK: str
    INSPECTOR_PK: str | None = None

    PINATA_JWT: str | None = None
    PINATA_API_KEY: str | None = None
    PINATA_API_SECRET: str | None = None

    DATABASE_URL: str = "sqlite:///./data.db"
    HOST: str = "127.0.0.1"
    PORT: int = 8000
    AUTO_REVOKE_DAYS_BEFORE: int = 7

    class Config:
        env_file = ".env"

settings = Settings()
