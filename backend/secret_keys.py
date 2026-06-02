from pydantic_settings import BaseSettings
from dotenv import load_dotenv

load_dotenv()

class SecretKeys(BaseSettings):
    GOOGLE_CLIENT_ID: str = ""
    DATABASE_URL: str = ""
    REDIS_URL: str = "redis://localhost:6379/0"
    SESSION_TTL_MINUTES: int = 1440
