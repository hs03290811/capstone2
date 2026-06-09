from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy.orm import Session
from datetime import datetime
import redis
import os
import asyncio
import json
from pydantic import BaseModel, Field
from typing import Optional

# 외부 분리한 실전형 AI 보안 엔진 및 미니 캐시 적재 함수 임포트
from app.api.security_engine import verify_security_payload, insert_and_manage_rba_cache

# 키스트로크 수집용 스키마 임포트
from app.api.schemas import UserRegisterWithKeystrokeDTO

from app.core.database import get_db
# DB 모델 임포트

from app.models.models import (
    User,
    RiskLog,
    UserSession,
    KeystrokeLog,
    UserKeystrokeProfile,
    RBAReadyToTrain
)

from app.core.security import (
    get_password_hash, 
    verify_password, 
    create_access_token
)
from user_agents import parse

# ========================================================
# 🚀 [교정 완료] 프론트엔드 수집 데이터 스키마 (시연 확장 규격 반영)
# ========================================================
class LoginRequest(BaseModel):
    username: str = Field(..., description="사용자 아이디")
    password: str = Field(..., description="사용자 비밀번호")
    language: str = Field(..., description="브라우저 언어 설정 (navigator.language)")
    resolution: str = Field(..., description="화면 해상도 (e.g., '1920x1080')")
    rtt: int = Field(..., description="측정된 네트워크 왕복 시간 (ms)")
    keystroke: list[int] = Field(default=[], description="키스트로크 데이터 타이밍 배열")
    ip_address: Optional[str] = Field(None, description="시연용 IP 주소")
    country: Optional[str] = Field(None, description="시연용 수집 국가")
    region: Optional[str] = Field(None, description="시연용 수집 지역")
    city: Optional[str] = Field(None, description="시연용 수집 도시")
    asn: Optional[str] = Field(None, description="시연용 수집 ASN")
    user_agent_string: Optional[str] = Field(None, description="시연용 수집 User-Agent")
    browser_name_version: Optional[str] = Field(None, description="시연용 수집 브라우저")
    os_name_version: Optional[str] = Field(None, description="시연용 수집 OS")
    device_type: Optional[str] = Field(None, description="시연용 수집 디바이스")


redis_client = redis.from_url(os.getenv("REDIS_URL", "redis://redis:6379/0"), decode_responses=True)
router = APIRouter(prefix="/auth", tags=["Authentication"])

def convert_to_feature_vector(events):

    ignore_keys = {
        "Backspace",
        "Shift",
        "Control",
        "Alt",
        "Meta",
        "CapsLock",
        "Tab"
    }

    filtered = [
        e for e in events
        if e.key not in ignore_keys
    ]

    keydown_times = []
    keyup_times = []

    for e in filtered:

        if e.event.lower() in ["keydown", "down"]:
            keydown_times.append(e.time)

        elif e.event.lower() in ["keyup", "up"]:
            keyup_times.append(e.time)

    pair_count = min(len(keydown_times), len(keyup_times))

    # H (Hold Time)
    holds = [
        keyup_times[i] - keydown_times[i]
        for i in range(pair_count)
    ]

    # DD (Down-Down)
    dd = [
        keydown_times[i + 1] - keydown_times[i]
        for i in range(len(keydown_times) - 1)
    ]

    # UD (Up-Down)
    ud = [
        keydown_times[i + 1] - keyup_times[i]
        for i in range(pair_count - 1)
    ]

    return holds + dd + ud

# ========================================================
# 🛠️ 키스트로크 15회 연동형 회원가입 API
# ========================================================
@router.post("/signup")
def signup(
    payload: UserRegisterWithKeystrokeDTO, 
    db: Session = Depends(get_db)
):
    existing_user = db.query(User).filter(User.username == payload.username).first()
    if existing_user:
        db.query(User).filter(User.username == payload.username).delete()
        db.commit()
    
    hashed_pw = get_password_hash(payload.password)
    new_user = User(username=payload.username, hashed_password=hashed_pw)
    
    db.add(new_user)
    db.commit()
    db.refresh(new_user)
    
    for session in payload.keystroke_profiles:

        feature_vector = convert_to_feature_vector(session)

        db_profile = UserKeystrokeProfile(
            user_id=new_user.id,
            raw_profile_data=json.dumps(feature_vector)
        )

        db.add(db_profile)

    db.flush()
    
    db.commit()

    new_rba = RBAReadyToTrain(
        login_timestamp=int(datetime.now().timestamp()),
        user_id=new_user.id,
        rtt=float(payload.rtt),
        ip_address=payload.ip_address,
        country=payload.country,
        region=payload.region,
        city=payload.city,
        asn=payload.asn,
        user_agent_string=payload.user_agent_string,
        browser_name_version=payload.browser_name_version,
        os_name_version=payload.os_name_version,
        device_type=payload.device_type,
        login_successful=True,
        resolution=payload.resolution,
        language=payload.language
    )

    db.add(new_rba)
    db.commit()
    
    return {
        "message": "회원가입 및 15회 타이핑 지문 프로필 등록 성공!", 
        "user_id": new_user.id
    }


# ========================================================
# 🔐 로그인 API (하드코딩 오버라이트 억까 원천 청소 완료)
# ========================================================
@router.post("/login")
async def login(
    payload: LoginRequest, 
    request: Request, 
    db: Session = Depends(get_db)
):
    username = payload.username
    password = payload.password

    user = db.query(User).filter(User.username == username).first()
    if not user or not verify_password(password, user.hashed_password):
        raise HTTPException(status_code=400, detail="아이디 또는 비밀번호가 틀렸습니다.")

    forwarded_for = request.headers.get("X-Forwarded-For")
    current_ip = payload.ip_address if payload.ip_address else (forwarded_for.split(",")[0].strip() if forwarded_for else request.client.host)
    user_agent_str = payload.user_agent_string if payload.user_agent_string else request.headers.get("User-Agent", "Unknown")

    ua = parse(user_agent_str)
    
    # 💡 [정품 패치] 시연용 박스에 입력한 값이 존재하면 최우선으로 엔진에 반영! (오염 방지)
    detected_country = payload.country if payload.country else "South Korea"
    detected_region = payload.region if payload.region else "Seoul"
    detected_city = payload.city if payload.city else "Seoul"
    detected_asn = payload.asn if payload.asn else "AS9318 (SK Broadband)"
    browser_info = payload.browser_name_version if payload.browser_name_version else f"{ua.browser.family} {ua.browser.version_string}".strip()
    os_info = payload.os_name_version if payload.os_name_version else f"{ua.os.family} {ua.os.version_string}".strip()
    device_type = payload.device_type if payload.device_type else ("Mobile" if ua.is_mobile else ("Tablet" if ua.is_tablet else "Desktop"))
    
    incoming_context = {
        "rtt": payload.rtt,
        "country": detected_country,
        "region": detected_region,
        "city": detected_city,
        "asn": detected_asn,
        "browser_name_version": browser_info,
        "os_name_version": os_info,
        "device_type": device_type,
        "resolution": payload.resolution,
        "language": payload.language,
        "Hour": datetime.now().hour
    }

    security_result = verify_security_payload(
        user_id=user.id,
        incoming_keystroke=payload.keystroke,
        incoming_context=incoming_context,
        db=db,
        k=2.5
    )
    
    login_status = security_result["status"]
    ai_score = security_result["ai_score"]

    

    existing_sid = redis_client.get(f"user_sid:{username}")
    is_kicked = False

    if existing_sid and login_status == "ALLOWED":
        is_kicked = True
        login_status = "KICKED_OUT"
        try:
            from app.main import sio
            asyncio.create_task(sio.emit('kick_out', {
                'message': '다른 기기나 브라우저에서 로그인이 감지되어 접속을 종료합니다.',
                'new_ip': current_ip,
                'time': datetime.now().strftime('%H:%M:%S'),
                'reason': 'Duplicate Login Detected'
            }, to=existing_sid))
            redis_client.delete(f"user_sid:{username}")
        except Exception as e:
            print(f"❌ 킥아웃 발송 중 에러: {e}")

    try:
        # 필드 검증: RiskLog 테이블에 실제로 존재하는 컬럼만 명시
        new_log = RiskLog(
            user_id=user.id,
            rtt=float(payload.rtt),
            ip_address=current_ip,
            country=detected_country,
            region=detected_region,
            city=detected_city,
            asn=detected_asn,
            user_agent_string=user_agent_str,
            browser_name_version=browser_info,
            os_name_version=os_info,
            device_type=device_type,
            login_successful=(login_status in ["ALLOWED", "KICKED_OUT", "MFA_REQUIRED"]),
            status=login_status,
            ai_score=ai_score
        )
        db.add(new_log)
        db.flush()

        new_keystroke_log = KeystrokeLog(
            risk_log_id=new_log.id,             
            keystroke_timing=json.dumps(payload.keystroke) if isinstance(payload.keystroke, list) else payload.keystroke
        )
        db.add(new_keystroke_log)
        
        user.last_ip = current_ip
        user.last_device = f"{os_info} / {browser_info}"
        
        db.commit()
        

        if login_status in ["ALLOWED", "KICKED_OUT"]:
            cache_payload = {
                "login_timestamp": int(datetime.now().timestamp()),
                "user_id": user.id,
                "rtt": float(payload.rtt),
                "ip_address": current_ip,
                "country": detected_country,
                "region": detected_region,
                "city": detected_city,
                "asn": detected_asn,
                "user_agent_string": user_agent_str,
                "browser_name_version": browser_info,
                "os_name_version": os_info,
                "device_type": device_type,
                "login_successful": True,
                "resolution": payload.resolution,
                "language": payload.language
            }
            insert_and_manage_rba_cache(user_id=user.id, payload=cache_payload, db=db)
        
    except Exception as db_err:
        db.rollback()
        # 💡 [필수 패치] 진짜 에러 메시지를 뿜도록 변경하여 억까 방지
        raise HTTPException(status_code=500, detail=f"DB 적재 실패: {str(db_err)}")
        
    telemetry_data = security_result.get("telemetry", {})
    
    keystroke_info = telemetry_data.get("keystroke", {})
    is_key_success = keystroke_info.get("success", True)
    keystroke_status = "ALLOW" if is_key_success else "BLOCK"
    
    rba_info = telemetry_data.get("rba", {})
    rba_prob_str = rba_info.get("genuine_probability", "100.0%")
    
    try:
        if isinstance(rba_prob_str, str):
            rba_match_percentage = float(rba_prob_str.replace("%", "").strip())
        else:
            rba_match_percentage = float(rba_prob_str)
    except Exception:
        rba_match_percentage = 100.0
    
    if keystroke_status == "ALLOW" and rba_match_percentage >= 80.0:
        reason_flag = "CLEAN"
    elif keystroke_status == "BLOCK" and rba_match_percentage < 30.0:
        reason_flag = "BOTH_RISK"
    elif keystroke_status == "ALLOW" and rba_match_percentage < 80.0:
        reason_flag = "CONTEXT_RISK"
    else:
        reason_flag = "KEYSTROKE_MISMATCH"
        
    security_analysis_payload = {
        "status": login_status,
        "primary_risk_factor": reason_flag,
        "keystroke_result": keystroke_status,
        "rba_match_probability": rba_match_percentage
    }

    if login_status == "MFA_REQUIRED":
        return {
            "access_token": None,
            "token_type": "bearer",
            "message": security_result["message"],
            "security_analysis": security_analysis_payload,
            "telemetry": telemetry_data
        }

    if login_status == "DENIED":
        return {
            "access_token": None,
            "token_type": "bearer",
            "message": security_result["message"],
            "security_analysis": security_analysis_payload,
            "telemetry": telemetry_data
        }

    access_token = create_access_token(data={"sub": user.username})
    return {
        "access_token": access_token,
        "token_type": "bearer",
        "message": f"{username}님, 환영합니다!",
        "security_analysis": security_analysis_payload,
        "telemetry": telemetry_data,
        "debug_info": {
            "ip": current_ip,
            "device": f"{os_info} / {browser_info}",
            "device_type": device_type,
            "language": payload.language,
            "resolution": payload.resolution,
            "rtt": f"{payload.rtt}ms",
            "previous_session_detected": is_kicked,
            "telemetry": telemetry_data
        }
    }
