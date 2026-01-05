import os


class Settings:

    SECRET_KEY: str = os.getenv("SECRET_KEY", "default_secret_key_change_this")
    MASTER_KEY: str = os.getenv("MASTER_KEY", "default_master_key_32_bytes_here")
    PEPPER_KEY: str = os.getenv("PEPPER_KEY", "")

    ACCESS_TOKEN_EXPIRE_MINUTES: int = 15
    try:
        ACCESS_TOKEN_EXPIRE_MINUTES = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", "15"))
    except (ValueError, TypeError):
        ACCESS_TOKEN_EXPIRE_MINUTES = 15

    DATABASE_URL: str = os.getenv(
        "DATABASE_URL",
        "postgresql://tcc_user:tcc_password_secure@postgres:5432/tcc_health_db"
    )

    ADMIN_PASSWORD: str = os.getenv("ADMIN_PASSWORD", "AdminSenha123!")
    DOCTOR_PASSWORD: str = os.getenv("DOCTOR_PASSWORD", "MedicoSenha123!")


    DATA_RETENTION_DAYS: int = 2190
    try:
        DATA_RETENTION_DAYS = int(os.getenv("DATA_RETENTION_DAYS", "2190"))
    except (ValueError, TypeError):
        DATA_RETENTION_DAYS = 2190


    LOG_LEVEL: str = os.getenv("LOG_LEVEL", "INFO")
    LOG_SENSITIVE_DATA: bool = os.getenv("LOG_SENSITIVE_DATA", "false").lower() == "true"


    COMPLIANCE_FRAMEWORKS: list = ["LGPD", "ANVISA"]

    @property
    def log_level(self) -> str:
        return self.LOG_LEVEL

    @property
    def log_sensitive_data(self) -> bool:
        return self.LOG_SENSITIVE_DATA

    @property
    def is_production(self) -> bool:
        return os.getenv("ENVIRONMENT", "development").lower() == "production"


settings = Settings()