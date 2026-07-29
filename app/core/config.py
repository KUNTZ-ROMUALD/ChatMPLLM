from pydantic_settings import BaseSettings, SettingsConfigDict

class Settings(BaseSettings) :
    model_config=SettingsConfigDict(env_file=".env",extra="ignore")
    app_name: str ="ChatMPLLM"
    environment: str = "local"
    DATABASE_URL : str
    redis_url : str ="redis://redis:6379/0"
    cors_origins : list[str] = ["http://localhost:4200"]

settings=Settings()
