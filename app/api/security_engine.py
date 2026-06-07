import pandas as pd
import numpy as np
import json
from datetime import datetime
from sqlalchemy.orm import Session
from scipy.spatial.distance import cityblock
from sqlalchemy import Column, Integer, String, BigInteger, Float, Boolean
from sklearn.preprocessing import StandardScaler

try:
    from sqlalchemy.orm import declarative_base
except ImportError:
    from sqlalchemy.ext.declarative import declarative_base

Base = declarative_base()

class RBAReadyToTrain(Base):
    __tablename__ = "rba_ready_to_train"
    __table_args__ = {'extend_existing': True}

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    login_timestamp = Column(BigInteger, index=True) 
    user_id = Column(BigInteger, index=True)         
    rtt = Column(Float, nullable=True)               
    ip_address = Column(String(255))
    country = Column(String(100), default="Unknown")
    region = Column(String(100), default="Unknown")
    city = Column(String(100), default="Unknown")
    asn = Column(String(100), default="Unknown")
    user_agent_string = Column(String, nullable=True)
    browser_name_version = Column(String(255))
    os_name_version = Column(String(255))
    device_type = Column(String(50))
    login_successful = Column(Boolean, default=True)
    resolution = Column(String(50))
    language = Column(String(50))

def fetch_past_keystrokes_from_db(user_id: int, db: Session, incoming_len: int = 9):
    try:
        query = f"SELECT raw_profile_data FROM user_keystroke_profiles WHERE user_id = {user_id} ORDER BY id DESC LIMIT 1;"
        df_prof = pd.read_sql_query(query, db.bind)
        if not df_prof.empty:
            raw_string = df_prof['raw_profile_data'].iloc[0]
            profiles_dict = json.loads(raw_string)
            processed_dataset = []
            for session in profiles_dict:
                if isinstance(session, list):
                    timestamps = [event.get('time', 0) if isinstance(event, dict) else event for event in session]
                    # 고정된 길이로 패딩 처리
                    data = list(timestamps)
                    if len(data) < incoming_len: data.extend([0] * (incoming_len - len(data)))
                    processed_dataset.append(data[:incoming_len])
            if processed_dataset:
                return np.array(processed_dataset)
    except Exception as e:
        print(f"DEBUG: 파싱 에러 {e}")
    return np.array([[100, 210, 305, 420, 515, 630, 725, 840, 950]] * 15)

def verify_security_payload(user_id: int, incoming_keystroke: list, incoming_context: dict, db: Session, k=3):
    try:
        if not incoming_keystroke: incoming_keystroke = [100, 210, 305, 420, 515, 630, 725, 840, 950]
        
        # 1. 학습 데이터 로드
        X_train_key = fetch_past_keystrokes_from_db(user_id, db, incoming_len=len(incoming_keystroke))
        
        # 2. 데이터 패딩 처리 (resize 대신)
        target_len = X_train_key.shape[1]
        processed_input = np.zeros(target_len)
        input_data = np.array(incoming_keystroke)
        processed_input[:min(len(input_data), target_len)] = input_data[:min(len(input_data), target_len)]
        X_test_key = processed_input.reshape(1, -1)
            
        # 3. 고정된 기준점 기반 스케일링 (fit_transform 후 transform 사용)
        key_scaler = StandardScaler()
        X_train_key_scaled = key_scaler.fit_transform(X_train_key)
        X_test_key_scaled = key_scaler.transform(X_test_key)
        
        # 4. 거리 계산 (안정적 연산)
        scaled_mean = np.mean(X_train_key_scaled, axis=0)
        current_key_dist = cityblock(X_test_key_scaled[0], scaled_mean) / target_len
        
        train_distances = [cityblock(row, scaled_mean) / target_len for row in X_train_key_scaled]
        dynamic_threshold = np.mean(train_distances) + (k * np.std(train_distances) if np.std(train_distances) > 0 else 1.0)
        
        keystroke_success = bool(current_key_dist <= dynamic_threshold)

        # 5. RBA 계산
        match_count = sum([
            1 if incoming_context.get("country") in ["South Korea", "KR"] else 0,
            1 if incoming_context.get("region") == "Seoul" else 0,
            1 if incoming_context.get("city") == "Seoul" else 0,
            1 if any(x in incoming_context.get("asn", "") for x in ["SK Broadband", "AS9318"]) else 0,
            1 if "Chrome" in incoming_context.get("browser_name_version", "") else 0,
            1 if "Mac OS X" in incoming_context.get("os_name_version", "") else 0,
            1 if incoming_context.get("device_type") == "Desktop" else 0,
            1 if incoming_context.get("resolution") == "1920x1080" else 0,
            1 if incoming_context.get("language") == "ko-KR" else 0
        ])
        
        rtt_val = float(incoming_context.get("rtt", 45))
        rtt_score = 1.0 if rtt_val <= 60 else (0.5 if rtt_val <= 150 else 0.0)
        rba_prob = ((match_count + rtt_score + 1.0) / 11.0) * 100.0
        
        if rba_prob >= 80.0: rba_tier = "안전(저위험군)"
        elif rba_prob >= 30.0: rba_tier = "애매(중위험군)"
        else: rba_tier = "불안전(고위험군)"

        # 6. 6가지 시나리오 기반 의사결정 매트릭스
        if keystroke_success:
            final_status = "ALLOWED" if rba_tier != "불안전(고위험군)" else "MFA_REQUIRED"
        else:
            if rba_tier == "안전(저위험군)": final_status = "ALLOWED"
            elif rba_tier == "애매(중위험군)": final_status = "MFA_REQUIRED"
            else: final_status = "DENIED"

        return {
            "status": final_status,
            "message": "보안 연산 완료",
            "ai_score": float(round(rba_prob / 100.0, 2)),
            "telemetry": {
                "keystroke": {
                    "success": keystroke_success,
                    "current_distance": float(round(current_key_dist, 4)),
                    "dynamic_threshold": float(round(dynamic_threshold, 4)),
                    "k_value": float(k)
                },
                "rba": {"risk_tier": rba_tier, "genuine_probability": f"{rba_prob:.1f}%"}
            }
        }
    except Exception as e:
        return {"status": "MFA_REQUIRED", "message": f"Error: {e}"}

def insert_and_manage_rba_cache(user_id: int, payload: dict, db: Session):
    try:
        new_cache = RBAReadyToTrain(
            login_timestamp=payload["login_timestamp"], user_id=user_id,
            rtt=payload["rtt"], ip_address=payload["ip_address"],
            country=payload["country"], region=payload["region"],
            city=payload["city"], asn=payload["asn"],
            user_agent_string=payload["user_agent_string"],
            browser_name_version=payload["browser_name_version"],
            os_name_version=payload["os_name_version"],
            device_type=payload["device_type"],
            login_successful=payload["login_successful"],
            resolution=payload["resolution"],
            language=payload["language"]
        )
        db.add(new_cache)
        db.flush()
        db.commit()
    except Exception:
        db.rollback()