from sqlalchemy import Column, Integer, String, DateTime, Float, ForeignKey, Boolean, JSON, BigInteger
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.sql import func
from sqlalchemy.orm import relationship

Base = declarative_base()

class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True, nullable=False)
    hashed_password = Column(String, nullable=False)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    
    last_ip = Column(String, nullable=True)        
    last_device = Column(String, nullable=True)    
    
    logs = relationship("RiskLog", back_populates="owner", primaryjoin="User.id == RiskLog.user_id", foreign_keys="RiskLog.user_id")
    sessions = relationship("UserSession", back_populates="owner")


class UserSession(Base):
    __tablename__ = "user_sessions"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"))
    session_token = Column(String, unique=True)
    socket_id = Column(String, nullable=True) 
    ip_address = Column(String)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    
    owner = relationship("User", back_populates="sessions")


class RiskLog(Base):
    __tablename__ = "risk_logs"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True) 
    user_id = Column(BigInteger, index=True) # 💡 DB 아키텍처 튜닝: 거대 해시 ID 수용을 위한 BIGINT 매핑 (외래키 제약 제거 반영)
    login_timestamp = Column(DateTime(timezone=True), server_default=func.now(), index=True) 
    rtt = Column(Float, nullable=True) # 💡 DB 아키텍처 튜닝: 소수점(.0) 포함 데이터 수용을 위한 Float 매핑
    ip_address = Column(String, index=True)                                
    
    owner = relationship("User", back_populates="logs", primaryjoin="User.id == RiskLog.user_id", foreign_keys="RiskLog.user_id")

    country = Column(String, default="Unknown")                            
    region = Column(String, default="Unknown")                             
    city = Column(String, default="Unknown")                               
    asn = Column(String, default="Unknown")                                
    
    user_agent_string = Column(String, nullable=False)                     
    browser_name_version = Column(String, nullable=True)                   
    os_name_version = Column(String, nullable=True)                        
    device_type = Column(String, nullable=True)                            
    
    login_successful = Column(Boolean, default=True)                       
    resolution = Column(String, nullable=True)                             
    language = Column(String, nullable=True)                               
    
    status = Column(String)                                                
    rba_score = Column(Float, default=0.0)                       
    ai_score = Column(Float, default=0.0)                        

    owner = relationship("User", primaryjoin="RiskLog.user_id==User.id", foreign_keys=[user_id], remote_side=[User.id], viewonly=True)
    keystroke_data = relationship("KeystrokeLog", back_populates="log_reference", uselist=False)


class KeystrokeLog(Base):
    __tablename__ = "keystroke_logs"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    risk_log_id = Column(Integer, ForeignKey("risk_logs.id"), unique=True, index=True) 
    keystroke_timing = Column(JSON, nullable=False) 
    created_at = Column(DateTime(timezone=True), server_default=func.now())

    log_reference = relationship("RiskLog", back_populates="keystroke_data")


# =========================================================================
# 🚀 [MINSUNG'S REQUEST] 유민성 요청 반영 AI 학습 고속화용 미니 캐시 테이블
# =========================================================================
class RBAReadyToTrain(Base):
    __tablename__ = "rba_ready_to_train"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    login_timestamp = Column(BigInteger, index=True) # 💡 데이터셋 내부의 다양한 에포크 타임 조회를 위한 인덱싱
    user_id = Column(BigInteger, index=True)         # 💡 민성님 규격 거대 해시 수용용 BIGINT 적용
    rtt = Column(Float, nullable=True)               # 💡 소수점 매핑
    ip_address = Column(String(255))
    country = Column(String(100), default="Unknown")
    region = Column(String(100), default="Unknown")
    city = Column(String(100), default="Unknown")
    asn = Column(String(100), default="Unknown")
    user_agent_string = Column(String, nullable=True)
    browser_name_version = Column(String(255))
    os_name_version = Column(String(255))
    device_type = Column(String(50))
    login_successful = Column(Boolean, default=True)
    resolution = Column(String(50))
    language = Column(String(50))