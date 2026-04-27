from pydantic import BaseModel


class Settings(BaseModel):
    app_name: str = "Hallucination Firewall API"
    app_version: str = "0.1.0"
    frontend_origin: str = "http://localhost:5173"


settings = Settings()
