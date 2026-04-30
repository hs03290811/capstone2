from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

# 우리가 만든 모듈들 가져오기
from app.core.database import get_db
from app.models.models import User
from app.core.security import (
    get_password_hash, 
    verify_password, 
    create_access_token
)

router = APIRouter(prefix="/auth", tags=["Authentication"])

# --- 1. 회원가입 API ---
@router.post("/signup")
def signup(username: str, password: str, db: Session = Depends(get_db)):
    # 1. 중복 유저 체크
    existing_user = db.query(User).filter(User.username == username).first()
    if existing_user:
        raise HTTPException(status_code=400, detail="이미 존재하는 아이디입니다.")
    
    # 2. 비밀번호 암호화 및 유저 생성
    hashed_pw = get_password_hash(password)
    new_user = User(username=username, hashed_password=hashed_pw)
    
    # 3. DB 저장
    db.add(new_user)
    db.commit()
    db.refresh(new_user)
    
    return {"message": "회원가입 성공!", "user_id": new_user.id}


# --- 2. 로그인 API ---
@router.post("/login")
def login(username: str, password: str, db: Session = Depends(get_db)):
    # 1. 유저 존재 여부 확인
    user = db.query(User).filter(User.username == username).first()
    if not user:
        raise HTTPException(status_code=400, detail="아이디 또는 비밀번호가 틀렸습니다.")

    # 2. 비밀번호 일치 여부 확인 (bcrypt 직접 비교)
    if not verify_password(password, user.hashed_password):
        raise HTTPException(status_code=400, detail="아이디 또는 비밀번호가 틀렸습니다.")

    # 3. 로그인 성공 시 JWT 토큰 발급
    # sub(Subject) 클레임에 유저의 이름을 담아 보냅니다.
    access_token = create_access_token(data={"sub": user.username})
    
    return {
        "access_token": access_token,
        "token_type": "bearer",
        "message": f"{username}님, 환영합니다!"
    }