from sqlalchemy import create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker

SQLALCHEMY_DATABASE_URL = "sqlite:///./lms.db"
engine = create_engine(SQLALCHEMY_DATABASE_URL, connect_args={"check_same_thread": False})

engine = create_engine(
    SQLALCHEMY_DATABASE_URL,
    pool_size=20, 
    max_overflow=10,
    pool_timeout=30, 
    pool_recycle=1800,  
    echo=True  
)

SessionLocal = sessionmaker(
    autocommit=False, 
    autoflush=False,  
    bind=engine  
)

Base = declarative_base()
from models import User, Branch, Group, StudentGroup
Base.metadata.create_all(bind=engine)

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()