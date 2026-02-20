from pydantic_settings import BaseSettings
from typing import Optional


class Settings(BaseSettings):
    elasticsearch_url: str = "http://localhost:9200"
    slack_bot_token: Optional[str] = None
    slack_channel_id: Optional[str] = None
    openai_api_key: Optional[str] = None
    
    class Config:
        env_file = ".env"
        case_sensitive = False


settings = Settings()
