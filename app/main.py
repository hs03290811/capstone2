from fastapi import FastAPI
import redis
from sqlalchemy import create_engine
from sqlalchemy.orm import Session
from fastapi.middleware.cors import CORSMiddleware  # CORS 필수!

# 우리가 만든 파일들에서 가져오기
from app.core.config import settings
from app.models.models import Base
from app.core.database import engine
from app.api import auth

# 1. 딱 한 번만 선언합니다!
app = FastAPI(title=settings.PROJECT_NAME)

# 2. CORS 설정 (이게 있어야 친구가 접속 가능해요)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# 3. 라우터 연결 (auth 기능을 인식하게 함)
app.include_router(auth.router)

# 4. 서버 시작 시 실행될 로직
@app.on_event("startup")
def startup_event():
    print("\n" + "="*30)
    print("🔍 인프라 연결 테스트 시작...")
    print("="*30)

    try:
        r = redis.from_url(settings.REDIS_URL, socket_timeout=5)
        r.ping()
        print("✅ Redis 연결 성공!")
    except Exception as e:
        print(f"❌ Redis 연결 실패: {e}")

    try:
        temp_engine = create_engine(
            settings.POSTGRES_URL, 
            connect_args={'connect_timeout': 5}
        )
        with temp_engine.connect() as conn:
            print("✅ Postgres 연결 성공!")
        
        Base.metadata.create_all(bind=engine)
        print("✅ DB 테이블 생성 완료!")
    except Exception as e:
        print(f"❌ Postgres 연결 실패: {e}")

    print("="*30)
    print("🚀 Guardian 서버가 8001번 포트에서 준비되었습니다!")
    print("="*30 + "\n")

# 5. 기본 홈 화면 주소
@app.get("/")
def root():
    return {"message": "Guardian Server is Running", "status": "healthy"}