from sqlalchemy import Column, Integer, String, DateTime, Float, ForeignKey, JSON
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.sql import func

Base = declarative_base()

class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True, nullable=False)
    hashed_password = Column(String, nullable=False)
    created_at = Column(DateTime(timezone=True), server_default=func.now())

class RiskLog(Base):
    __tablename__ = "risk_logs"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"))
    ip_address = Column(String)
    device_info = Column(String)
    rba_score = Column(Float)  # 환경 위험 점수
    ai_score = Column(Float)   # 타건 리듬 일치 점수
    status = Column(String)    # ALLOWED, MFA_REQUIRED, DENIED
    attempted_at = Column(DateTime(timezone=True), server_default=func.now())