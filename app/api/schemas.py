from pydantic import BaseModel
from typing import List

# 1. 단일 키스트로크 이벤트 규격
class KeystrokeEventDTO(BaseModel):
    key: str
    event: str  # "down" 또는 "up"
    time: int   # 밀리초(ms) 단위 타임스탬프

# 2. 회원가입 요청 전체 규격 (15세트 수용)
class UserRegisterWithKeystrokeDTO(BaseModel):
    username: str
    password: str
    keystroke_profiles: List[List[KeystrokeEventDTO]] # ✅ 2차원 리스트 정상 매핑