from pydantic_settings import BaseSettings, SettingsConfigDict

class Settings(BaseSettings):
    REDIS_URL: str = "redis://localhost:6379"
    DATABASE_URL: str = "postgresql+asyncpg://scanzero:scanzero@localhost:5432/scanzero"
    
    # Core Active Keys
    SHODAN_API_KEY: str = ""
    GEMINI_API_KEY: str = ""
    SECRET_KEY: str = "supersecretkey"

    # World-Class Free Alternative Threat Intel API Keys
    VIRUSTOTAL_API_KEY: str = ""   # Alternative to Censys (Free: virustotal.com)
    URLSCAN_API_KEY: str = ""      # Alternative to IntelX (Free: urlscan.io)
    LEAKCHECK_API_KEY: str = ""    # Alternative to DeHashed & HIBP (Free: leakcheck.io)
    OTX_API_KEY: str = ""          # Alternative to Censys (AlienVault OTX Free: otx.alienvault.com)

    ZAP_API_URL: str = ""
    ZAP_API_KEY: str = ""

    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")

settings = Settings()
