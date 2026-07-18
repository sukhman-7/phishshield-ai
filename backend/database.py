from sqlalchemy import create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker

# SQLite database file path
SQLALCHEMY_DATABASE_URL = "sqlite:///./phishshield.db"

# connect_args={"check_same_thread": False} is required ONLY for SQLite 
engine = create_engine(
    SQLALCHEMY_DATABASE_URL, connect_args={"check_same_thread": False}
)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

Base = declarative_base()

# Dependency to open/close DB connections per API request securely
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()