from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy.orm import Session
from datetime import datetime
import redis
import os
import asyncio
import json
from pydantic import BaseModel, Field

# 💡 외부 분리한 실전형 AI 보안 엔진 및 희서님이 만든 미니 캐시 적재 함수 임포트
from app.api.security_engine import verify_security_payload, insert_and_manage_rba_cache

from app.core.database import get_db
from app.models.models import User, RiskLog, UserSession, KeystrokeLog
from app.core.security import (
    get_password_hash, 
    verify_password, 
    create_access_token
)
from user_agents import parse

# ========================================================
# 🚀 프론트엔드 수집 데이터 스키마
# ========================================================
class LoginRequest(BaseModel):
    username: str = Field(..., description="사용자 아이디")
    password: str = Field(..., description="사용자 비밀번호")
    language: str = Field(..., description="브라우저 언어 설정 (navigator.language)")
    resolution: str = Field(..., description="화면 해상도 (e.g., '1920x1080')")
    rtt: int = Field(..., description="측정된 네트워크 왕복 시간 (ms)")
    keystroke: list[int] = Field(default=[], description="키스트로크 데이터 타이밍 배열")


redis_client = redis.from_url(os.getenv("REDIS_URL", "redis://redis:6379/0"), decode_responses=True)
router = APIRouter(prefix="/auth", tags=["Authentication"])

# --- 회원가입 API ---
@router.post("/signup")
def signup(username: str, password: str, db: Session = Depends(get_db)):
    existing_user = db.query(User).filter(User.username == username).first()
    if existing_user:
        raise HTTPException(status_code=400, detail="이미 존재하는 아이디입니다.")
    
    hashed_pw = get_password_hash(password)
    new_user = User(username=username, hashed_password=hashed_pw)
    
    db.add(new_user)
    db.commit()
    db.refresh(new_user)
    return {"message": "회원가입 성공!", "user_id": new_user.id}


# --- 로그인 API ---
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

    # [수집 및 파싱] 네트워크/환경 변수 가로채기
    forwarded_for = request.headers.get("X-Forwarded-For")
    current_ip = forwarded_for.split(",")[0].strip() if forwarded_for else request.client.host
    user_agent_str = request.headers.get("User-Agent", "Unknown")

    ua = parse(user_agent_str)
    browser_info = f"{ua.browser.family} {ua.browser.version_string}".strip()
    os_info = f"{ua.os.family} {ua.os.version_string}".strip()
    device_type = "Mobile" if ua.is_mobile else ("Tablet" if ua.is_tablet else "Desktop")

    # 위협 인텔리전스 위치 추적 보강 (내부 가공 정보)
    detected_country = "South Korea"
    detected_region = "Seoul"
    detected_city = "Seoul"
    detected_asn = "AS9318 (SK Broadband)"
    
    # AI 엔진 입력 딕셔너리 구조 생성
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

    # ========================================================
    # 🔥 실제 DB 세션을 주입하여 외부 AI 보안 엔진 구동
    # ========================================================
    security_result = verify_security_payload(
        user_id=user.id,
        incoming_keystroke=payload.keystroke,
        incoming_context=incoming_context,
        db=db,
        k=2.5
    )
    
    login_status = security_result["status"]  # ALLOWED / DENIED / MFA_REQUIRED
    ai_score = security_result["ai_score"]

    # 만약 고위험군 차단(`DENIED`)이 떴다면 가차 없이 403 차단 리턴
    if login_status == "DENIED":
        raise HTTPException(status_code=403, detail=security_result["message"])

    # ========================================================
    # 🚀 Single Session 관리 (실시간 킥아웃 발송)
    # ========================================================
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

    # ========================================================
    # 💾 이원화 테이블 구조 트랜잭션 실시간 적재
    # ========================================================
    try:
        new_log = RiskLog(
            user_id=user.id,
            rtt=payload.rtt,
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
            resolution=payload.resolution,
            language=payload.language,
            status=login_status,
            rba_score=float(1.0 - ai_score), 
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
        print(f"💾 [Postgres] RBA AI 분석 데이터 및 키스트로크 분리 이원화 적재 완료! (상태: {login_status})")

        # ========================================================
        # 🎯 [희서님의 긴급 미션] 정상 로그인 성공 시 민성님 미니 캐시 테이블 적재 가동!
        # ========================================================
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
            # 슬라이딩 윈도우 스케일링 오토 트리거 시동!
            insert_and_manage_rba_cache(user_id=user.id, payload=cache_payload, db=db)
            print(f"🚀 [Cache Window] 민성님 전용 AI 미니 캐시 테이블 적재 및 300개 스케일링 마감 완료!")
        
    except Exception as db_err:
        db.rollback()
        print(f"❌ [DB 트랜잭션 에러] 적재 실패: {db_err}")
        raise HTTPException(status_code=500, detail="서버 내부 데이터베이스 처리 오류")

    # 2차 인증 필요 시 토큰 발급을 우회하고 프론트엔드에 상태 전달
    if login_status == "MFA_REQUIRED":
        return {
            "access_token": None,
            "token_type": "bearer",
            "message": security_result["message"],
            "debug_info": {"status": "MFA_REQUIRED", "telemetry": security_result["telemetry"]}
        }

    access_token = create_access_token(data={"sub": user.username})
    return {
        "access_token": access_token,
        "token_type": "bearer",
        "message": f"{username}님, 환영합니다!",
        "debug_info": {
            "ip": current_ip,
            "device": f"{os_info} / {browser_info}",
            "device_type": device_type,
            "language": payload.language,
            "resolution": payload.resolution,
            "rtt": f"{payload.rtt}ms",
            "previous_session_detected": is_kicked,
            "status": login_status,
            "telemetry": security_result["telemetry"] 
        }
    }