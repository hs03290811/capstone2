from pydantic import BaseModel
from typing import List, Dict, Any

class KeystrokeEvent(BaseModel):
    key: str
    event: str
    time: int

class UserRegisterWithKeystrokeDTO(BaseModel):
    username: str
    password: str
    keystroke_profiles: List[List[KeystrokeEvent]] # 👈 객체 배열 구조로 통일