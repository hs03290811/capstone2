# app/main.py

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware  # CORS 해결을 위한 임포트
from fastapi_socketio import SocketManager
from app.core.database import engine, settings

# 🚀 [핵심 보완] Base뿐만 아니라 정의한 모델들을 명시적으로 다 불러와야 DB에 테이블이 생성됩니다!
from app.models.models import Base, User, RiskLog, UserSession, KeystrokeLog

from sqlalchemy import create_engine
import os
import redis
import urllib.parse

# --- 1. 앱 생성 및 기초 설정 ---
app = FastAPI(title="Guardian SSG Server")

# --- 2. CORS 설정 (프론트엔드 연결 허용) ---
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # 모든 도메인 허용 (테스트 환경)
    allow_credentials=True,
    allow_methods=["*"],  # GET, POST, OPTIONS 등 모든 메서드 허용
    allow_headers=["*"],  # 모든 헤더 허용
)

# Redis 연결
redis_client = redis.from_url(os.getenv("REDIS_URL", "redis://redis:6379/0"), decode_responses=True)

# --- 3. 웹소켓 설정 ---
sio = SocketManager(
    app=app, 
    mount_location='/socket.io', 
    cors_allowed_origins="*"  # 웹소켓용 CORS 허용
)

# --- 4. 라우터 연결 ---
# 의존성 순환 참조 문제를 예방하기 위해 스크립트 실행 시점에 임포트
from app.api import auth
app.include_router(auth.router)

# --- 5. DB 초기화 ---
try:
    # 이제 모든 모델 클래스가 위에 로드되었으므로 risk_logs와 keystroke_logs 테이블이 정상 빌드됩니다.
    Base.metadata.create_all(bind=engine)
    print("✅ DB 테이블 생성 완료!")
except Exception as e:
    print(f"❌ DB 초기화 실패: {e}")

@app.get("/")
def root():
    return {"message": "Guardian Server is Running", "status": "healthy"}

# --- 6. 실시간 웹소켓 이벤트 핸들러 ---

@sio.on('connect')
async def handle_connect(sid, environ, auth_data=None):
    try:
        # ASGI scope에서 쿼리 스트링 추출 (이름표 찾기)
        raw_query = environ.get('query_string') or environ.get('QUERY_STRING') or b''
        
        if isinstance(raw_query, bytes):
            query_str = raw_query.decode()
        else:
            query_str = str(raw_query)

        params = urllib.parse.parse_qs(query_str)
        username = params.get('username', [None])[0]

        # 디버깅용 로그
        print(f"🔎 [DEBUG] 접속 SID: {sid}")
        print(f"🔎 [DEBUG] 들어온 파라미터: {params}")

        # 1순위: 쿼리 파라미터에서 username 확인
        if username:
            redis_client.set(f"user_sid:{username}", sid)
            print(f"✅ [등록 완료] {username} -> SID: {sid}")
            return

        # 2순위: auth_data(Socket.io 인증 객체)에서 확인
        if auth_data and isinstance(auth_data, dict):
            username = auth_data.get('username')
            if username:
                redis_client.set(f"user_sid:{username}", sid)
                print(f"✅ [Auth 데이터 발견] {username} -> SID: {sid}")
                return

        print(f"❌ [실패] username을 찾을 수 없음 (익명 기기)")
            
    except Exception as e:
        print(f"🚨 [연결 에러] {e}")

@sio.on('disconnect')
async def handle_disconnect(sid):
    print(f"❌ 연결 해제 (SID: {sid})")

# --- 7. 유저 제어 함수 (외부 호출용) ---
async def kick_out_user(username: str):
    """특정 유저의 기존 세션을 찾아 킥아웃 명령 전송"""
    sid = redis_client.get(f"user_sid:{username}")
    if sid:
        from datetime import datetime
        await sio.emit('kick_out', {
          'message': '다른 기기에서 로그인이 감지되어 접속을 종료합니다.',
          'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S') # 보안 표준 표기로 고도화
        }, to=sid)
        print(f"🚀 {username} 킥아웃 완료 (SID: {sid})")
        return True
    return False