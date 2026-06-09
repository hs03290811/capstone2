from pydantic import BaseModel
from typing import List, Dict, Any, Optional

class KeystrokeEvent(BaseModel):
    key: str
    event: str
    time: int

class UserRegisterWithKeystrokeDTO(BaseModel):
    username: str
    password: str

    language: str
    resolution: str
    rtt: int

    ip_address: Optional[str] = None
    country: Optional[str] = None
    region: Optional[str] = None
    city: Optional[str] = None
    asn: Optional[str] = None
    user_agent_string: Optional[str] = None
    browser_name_version: Optional[str] = None
    os_name_version: Optional[str] = None
    device_type: Optional[str] = None

    keystroke_profiles: List[List[KeystrokeEvent]]