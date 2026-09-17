from pydantic_settings import BaseSettings, SettingsConfigDict

class Settings(BaseSettings):
    REDIS_URL: str = "redis://localhost:6379"
    DATABASE_URL: str = "postgresql+asyncpg://scanzero:scanzero@localhost:5432/scanzero"
    
    SHODAN_API_KEY: str = ""
    HIBP_API_KEY: str = ""
    DEHASHED_API_KEY: str = ""
    CENSYS_API_ID: str = ""
    CENSYS_API_SECRET: str = ""
    GITHUB_TOKEN: str = ""
    INTELX_API_KEY: str = ""
    GEMINI_API_KEY: str = ""
    
    CACHE_TTL_HOURS: int = 6
    SCAN_TIMEOUT_SECONDS: int = 30
    SECRET_KEY: str = "supersecretkey"

    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")

settings = Settings()
