from sqlalchemy import create_engine, Column, String, Float, Integer, DateTime, Text, Boolean, ForeignKey
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, Session, relationship
from datetime import datetime
import uuid

from app.core.config import settings

# Create engine
engine = create_engine(
    settings.DATABASE_URL,
    connect_args={"check_same_thread": False}
)


SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

Base = declarative_base()

def get_db():
    """Dependency to get database session"""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

def generate_uuid() -> str:
    """Generate a unique ID"""
    return str(uuid.uuid4())

class User(Base):
    __tablename__ = "users"
    
    id = Column(String, primary_key=True, default=generate_uuid)
    email = Column(String, unique=True, index=True, nullable=False)
    hashed_password = Column(String, nullable=False)
    full_name = Column(String, nullable=True)
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    
    # Relationships
    analyses = relationship("Analysis", back_populates="user")
    api_keys = relationship("APIKey", back_populates="user")

class Analysis(Base):
    __tablename__ = "analyses"
    
    id = Column(String, primary_key=True, default=generate_uuid)
    user_id = Column(String, ForeignKey("users.id"), nullable=True)
    filename = Column(String, nullable=False)
    format = Column(String, nullable=False)
    components_count = Column(Integer, default=0)
    vulnerabilities_count = Column(Integer, default=0)
    risk_score = Column(Float, default=0.0)
    status = Column(String, default="completed")
    result_json = Column(Text, nullable=True)  
    ai_insights_json = Column(Text, nullable=True)
    analyzed_at = Column(DateTime, default=datetime.utcnow)
    
    # Relationships
    user = relationship("User", back_populates="analyses")

class APIKey(Base):
    __tablename__ = "api_keys"
    
    id = Column(String, primary_key=True, default=generate_uuid)
    user_id = Column(String, ForeignKey("users.id"), nullable=False)
    name = Column(String, nullable=False)
    key_hash = Column(String, nullable=False)
    key_prefix = Column(String, nullable=False)  # First 8 chars for display
    created_at = Column(DateTime, default=datetime.utcnow)
    expires_at = Column(DateTime, nullable=False)
    last_used = Column(DateTime, nullable=True)
    is_active = Column(Boolean, default=True)
    
    # Relationships
    user = relationship("User", back_populates="api_keys")

# Create all tables
def init_db():
    """Initialize database tables"""
    Base.metadata.create_all(bind=engine)

