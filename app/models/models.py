from sqlalchemy import Column, Integer, String, DateTime, Float, ForeignKey, Boolean, JSON
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
    
    logs = relationship("RiskLog", back_populates="owner")
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

    # 피드백 주신 17가지 내역 명확하게 컬럼 매핑
    id = Column(Integer, primary_key=True, index=True, autoincrement=True) # index (부모 고유 PK)
    user_id = Column(Integer, ForeignKey("users.id"), index=True)          # User ID
    login_timestamp = Column(DateTime(timezone=True), server_default=func.now(), index=True) # Login Timestamp
    rtt = Column(Integer, nullable=True)                                   # Round-Trip Time [ms]
    ip_address = Column(String, index=True)                                # IP Address
    
    # [Phase 4 보강 데이터] 위치 정보 영역
    country = Column(String, default="Unknown")                            # Country
    region = Column(String, default="Unknown")                             # Region
    city = Column(String, default="Unknown")                               # City
    asn = Column(String, default="Unknown")                                # ASN
    
    # [Phase 3 파싱 데이터] 기기 정보 영역
    user_agent_string = Column(String, nullable=False)                     # User Agent String
    browser_name_version = Column(String, nullable=True)                   # Browser Name and Version
    os_name_version = Column(String, nullable=True)                        # OS Name and Version
    device_type = Column(String, nullable=True)                            # Device Type
    
    # [Phase 2 프론트 수집 데이터] 및 기타 상태
    login_successful = Column(Boolean, default=True)                       # Login Successful
    resolution = Column(String, nullable=True)                             # 해상도
    language = Column(String, nullable=True)                               # 언어
    
    # 내부 제어용 점수 및 상태 필드
    status = Column(String)                                                # ALLOWED, KICKED_OUT 등
    rba_score = Column(Float, default=0.0)                       
    ai_score = Column(Float, default=0.0)                        

    owner = relationship("User", back_populates="logs")
    
    # 🎯 키스트로크 분리 테이블과의 관계선언 (1:1 구조 매핑)
    keystroke_data = relationship("KeystrokeLog", back_populates="log_reference", uselist=False)


class KeystrokeLog(Base):
    __tablename__ = "keystroke_logs"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    
    # 부모 RiskLog의 고유 id(index)를 참조하는 외래키 구조화
    risk_log_id = Column(Integer, ForeignKey("risk_logs.id"), unique=True, index=True) 
    
    # 🎯 키스트로크 데이터 실제 격리 저장소 (배열 형식을 유연하게 담는 JSON 타입 선언)
    keystroke_timing = Column(JSON, nullable=False) 
    created_at = Column(DateTime(timezone=True), server_default=func.now())

    log_reference = relationship("RiskLog", back_populates="keystroke_data")