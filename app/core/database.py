from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, Session
from app.core.config import settings

# DB 엔진 생성
engine = create_engine(settings.POSTGRES_URL)

# DB 세션을 생성하는 팩토리
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

# 의존성 주입(Dependency Injection)을 위한 함수
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()