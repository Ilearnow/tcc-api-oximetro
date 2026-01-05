from sqlalchemy import create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
import os
from app.config import settings  

#DATABASE_URL = "postgresql://tcc_user:tcc_password_secure@localhost:65432/tcc_health_db"

#DATABASE_URL = os.getenv(
#    "DATABASE_URL",
#    "postgresql://tcc_user:tcc_password_secure@postgres:5432/tcc_health_db",
#)

DATABASE_URL = settings.DATABASE_URL

engine = create_engine(DATABASE_URL)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

Base = declarative_base()

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()