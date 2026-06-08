import pandas as pd
import numpy as np
import json
from datetime import datetime
from sqlalchemy.orm import Session
from scipy.spatial.distance import cityblock
from sqlalchemy import Column, Integer, String, BigInteger, Float, Boolean
from sklearn.preprocessing import StandardScaler
from sklearn.ensemble import RandomForestClassifier  # [추가] RBA 랜덤포레스트 모델용
from sklearn.preprocessing import LabelEncoder  # [추가] RBA 범주형 데이터 인코딩용

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


######################################################################################################################
# 이 전까지 수정 금지
######################################################################################################################

def fetch_past_keystrokes_from_db(
        user_id: int,
        db: Session,
        incoming_len: int
):
    """
    학습 데이터 구성

    1. 회원가입 시 저장한 15회 프로필
    2. 로그인 성공 이력(keystroke_logs)
    3. 둘을 합쳐 최대 100개 유지
    """
    # incoming_len 값의 유효성 검증 (하드코딩 방지 및 명시적 에러 발생)
    if incoming_len is None or incoming_len <= 0:
        raise ValueError("incoming_len은 0보다 큰 정수값이어야 합니다.")

    processed_dataset = []

    # ==================================================
    # 1차: 회원가입 프로필(기본 15회)
    # ==================================================
    try:
        query = f"""
        SELECT raw_profile_data
        FROM user_keystroke_profiles
        WHERE user_id = {user_id}
        ORDER BY id DESC
        LIMIT 1;
        """

        df_prof = pd.read_sql_query(query, db.bind)

        if not df_prof.empty:

            raw_string = df_prof["raw_profile_data"].iloc[0]
            profiles_dict = json.loads(raw_string)

            for session in profiles_dict:

                if not isinstance(session, list):
                    continue

                timestamps = [
                    event.get("time", 0)
                    if isinstance(event, dict)
                    else event
                    for event in session
                ]

                data = list(timestamps)

                if len(data) < incoming_len:
                    data.extend([0] * (incoming_len - len(data)))

                processed_dataset.append(data[:incoming_len])

    except Exception as e:
        print(f"DEBUG: 회원가입 프로필 로드 실패 {e}")

    # ==================================================
    # 2차: 로그인 성공 이력 추가
    # ==================================================
    try:
        query = f"""
        SELECT kl.keystroke_timing
        FROM keystroke_logs kl
        JOIN risk_logs rl
            ON kl.risk_log_id = rl.id
        WHERE rl.user_id = {user_id}
          AND rl.login_successful = true
        ORDER BY kl.created_at DESC
        LIMIT 85;
        """

        df_logs = pd.read_sql_query(query, db.bind)

        for raw_data in df_logs["keystroke_timing"]:

            try:
                if isinstance(raw_data, str):
                    data = json.loads(raw_data)
                else:
                    data = raw_data

                if not isinstance(data, list):
                    continue

                # dict 형태 방어
                data = [
                    item.get("time", 0)
                    if isinstance(item, dict)
                    else item
                    for item in data
                ]

                if len(data) < incoming_len:
                    data.extend([0] * (incoming_len - len(data)))

                processed_dataset.append(data[:incoming_len])

            except Exception:
                continue

    except Exception as e:
        print(f"DEBUG: 로그인 이력 로드 실패 {e}")

    # ==================================================
    # 최대 100개 유지
    # ==================================================
    if processed_dataset:

        if len(processed_dataset) > 100:
            processed_dataset = processed_dataset[:15] + processed_dataset[-85:]

        print(
            f"DEBUG: user {user_id} "
            f"학습 데이터 {len(processed_dataset)}건 사용"
        )

        return np.array(processed_dataset)

    raise ValueError(
        f"user_id={user_id} 의 키스트로크 학습 데이터를 찾을 수 없습니다."
    )


def verify_security_payload(user_id: int, incoming_keystroke: list, incoming_context: dict, db: Session, k=3):
    try:
        # 데이터 부재 혹은 예외 발생 시 하단의 RBA 의사결정 및 Telemetry 딕셔너리가 정상 작동하도록 기본값 선언
        keystroke_success = False
        current_key_dist = -1.0
        dynamic_threshold = -1.0

        # =====================================================================================================
        # [수정 영역] 하드코딩 제거, 에러 처리 강화 및 맨해튼 거리 기반 동적 임계값 알고리즘 반영
        # =====================================================================================================

        # 1. [하드코딩 제거] 검증할 현재 입력 데이터가 없는 경우 실패(False) 처리 후 RBA로 통과
        if not incoming_keystroke or len(incoming_keystroke) == 0:
            print(f"DEBUG: user_id={user_id} - 입력된 현재 키스트로크 데이터가 없어 실패(False) 처리합니다.")

        else:
            try:
                # 2. DB로부터 과거 성공 이력 데이터(최대 100개) 로드
                X_train_key = fetch_past_keystrokes_from_db(user_id, db, incoming_len=len(incoming_keystroke))

                # 3. [에러 처리] DB에 과거 데이터가 아예 존재하지 않는 경우 하드코딩 없이 실패(False) 처리
                if X_train_key is None or len(X_train_key) == 0:
                    print(f"DEBUG: user_id={user_id} - DB 내 학습 데이터가 존재하지 않아 키스트로크 실패(False) 처리합니다.")

                else:
                    # 4. 데이터 패딩 처리 및 피처 개수(비밀번호 길이) 동적 추출
                    num_features = X_train_key.shape[1]  # 제공 예시의 num_features 역할
                    processed_input = np.zeros(num_features)
                    input_data = np.array(incoming_keystroke)

                    # 입력 데이터가 학습 피처 수보다 길거나 짧을 때를 대비한 안전한 슬라이싱 및 패딩
                    processed_input[:min(len(input_data), num_features)] = input_data[
                        :min(len(input_data), num_features)]
                    X_test_key = processed_input.reshape(1, -1)

                    # 5. 정규화 (StandardScaler 수행)
                    key_scaler = StandardScaler()
                    X_train_key_scaled = key_scaler.fit_transform(X_train_key)
                    X_test_key_scaled = key_scaler.transform(X_test_key)

                    # 6. 맨해튼 거리 및 통계량(mu, sigma) 계산 (제공 예시 코드 흐름과 연산 일치)
                    from scipy.spatial.distance import cdist

                    # 학습 데이터의 평균 벡터 계산 (1, num_features 형태로 명시적 변환)
                    mean_vector = np.mean(X_train_key_scaled, axis=0).reshape(1, -1)

                    # 학습 데이터 자체의 '피처당 평균 맨해튼 거리' 계산 (피처 개수로 정규화)
                    train_distances = cdist(X_train_key_scaled, mean_vector,
                                            metric='cityblock').flatten() / num_features

                    # 학습 데이터 거리의 평균(mu)과 표준편차(sigma) 계산
                    mu = np.mean(train_distances)
                    sigma = np.std(train_distances)

                    # 7. k 기반 동적 임계값(Threshold) 결정
                    # [에러 처리] 모든 학습 데이터가 완전 동일하여 표준편차가 0일 경우, 나누기/오버플로우 방지를 위해 기본 임계 스페이스(1.0) 부여
                    dynamic_threshold = mu + (float(k) * sigma if sigma > 0 else 1.0)

                    # 8. 테스트 데이터(현재 입력) 거리 계산 (피처 개수로 정규화)
                    current_distances = cdist(X_test_key_scaled, mean_vector,
                                              metric='cityblock').flatten() / num_features
                    current_distances = cdist(X_test_key_scaled, mean_vector,
                                              metric='cityblock').flatten() / num_features
                    current_key_dist = float(current_distances[0])

                    # 9. 최종 임계값 판별 및 변수 업데이트 (임계값 이하면 성공)
                    keystroke_success = bool(current_key_dist <= dynamic_threshold)

            except Exception as math_error:
                # 연산 중 예측하지 못한 수학적 예외(데이터 차원 불일치 등)가 발생해도 실패 처리 후 안전하게 RBA로 우회시킴
                print(f"DEBUG: 키스트로크 수치 연산 중 예외 발생 ({math_error}) - 실패(False) 처리 후 RBA를 진행합니다.")
                keystroke_success = False
        # =====================================================================================================
        # 이 전까지 수정 금지
        # =====================================================================================================

        # 5. RBA 계산 (참고 코드를 기반으로 랜덤 포레스트 모델 머신러닝 연산 구현)

        # [주석 처리] 백엔드 연동 영역: RBAReadyToTrain 테이블에서 유저별 최대 300개의 데이터셋 로드 필요
        # 예시 기틀:
        # query = f"SELECT * FROM rba_ready_to_train WHERE user_id = {user_id} OR ... LIMIT 300"
        # df_rba = pd.read_sql_query(query, db.bind)

        # 백엔드 연동 전까지 정상적인 빌드 및 방어 코드가 작동할 수 있도록 임시 빈 데이터프레임 구조 선언
        df_rba = pd.DataFrame(columns=[
            'user_id', 'login_timestamp', 'rtt', 'ip_address', 'country', 'region', 'city',
            'asn', 'user_agent_string', 'browser_name_version', 'os_name_version',
            'device_type', 'login_successful', 'resolution', 'language'
        ])

        # 현재 로그인 시도를 요청한 타겟 사용자의 기존 RBA 학습 데이터 건수 확인
        target_user_cnt = len(df_rba[df_rba['user_id'] == user_id])

        # Top 4의 중요한 판단 속성을 상시 저장해두기 위한 리스트 변수 초기화
        top_4_features = []

        if target_user_cnt == 0:
            # [조건 반영] 데이터 개수가 0개라면 RBA 무조건 실패 처리 (확률 0.0 -> 고위험군 유도)
            rba_prob = 0.0
            print(f"DEBUG: user_id={user_id} - RBA 데이터가 0건이므로 무조건 실패 처리합니다.")
        elif target_user_cnt <= 10:
            # [조건 반영] 데이터 개수가 10개 이하라면 무조건 애매 단계 처리 (확률 50.0 -> 중위험군 유도)
            rba_prob = 50.0
            print(f"DEBUG: user_id={user_id} - RBA 데이터가 10건 이하({target_user_cnt}건)이므로 애매 단계로 처리합니다.")
        else:
            try:
                # [수정 부분] 요청하신 10가지 특정 핵심 보안 속성만 엄격하게 누락 여부 검사
                required_fields = [
                    "country", "region", "city", "asn", "browser_name_version",
                    "os_name_version", "device_type", "resolution", "language", "rtt"
                ]

                # 지정된 핵심 속성 중 하나라도 값이 없거나 빈 문자열("")이면 예외 발생 -> RBA 실패 처리
                for field in required_fields:
                    val = incoming_context.get(field)
                    if val is None or val == "":
                        print(f"DEBUG: user_id={user_id} - 필수 보안 데이터 누락 발견: '{field}'")
                        raise ValueError(f"필수 컨텍스트 속성 '{field}' 데이터가 누락되었습니다.")

                # 검증을 통과한 핵심 데이터는 incoming_context에서 가져오고, 제외된 필드는 안전하게 기본값 처리
                current_time_epoch = incoming_context.get("login_timestamp", int(datetime.utcnow().timestamp()))
                current_row = pd.DataFrame([{
                    'user_id': user_id,
                    'login_timestamp': current_time_epoch,
                    'rtt': float(incoming_context["rtt"]),
                    'ip_address': incoming_context.get("ip_address", ""),  # 검증 제외 필드는 fallback 적용
                    'country': incoming_context["country"],
                    'region': incoming_context["region"],
                    'city': incoming_context["city"],
                    'asn': incoming_context["asn"],
                    'user_agent_string': incoming_context.get("user_agent_string", ""),  # 검증 제외 필드
                    'browser_name_version': incoming_context["browser_name_version"],
                    'os_name_version': incoming_context["os_name_version"],
                    'device_type': incoming_context["device_type"],
                    'login_successful': bool(incoming_context.get("login_successful", True)),  # 검증 제외 필드
                    'resolution': incoming_context["resolution"],
                    'language': incoming_context["language"]
                }])

                # 일관성 있는 라벨 인코딩을 위해 과거 데이터셋 맨 끝에 현재 시도 데이터를 일시 병합
                df_ml = pd.concat([df_rba, current_row], ignore_index=True)

                # Feature Engineering: 에폭 형태인 'login_timestamp'를 변환하여 'Hour(시간)' 속성 추출
                df_ml['Hour'] = pd.to_datetime(df_ml['login_timestamp'], unit='s', errors='coerce').dt.hour.fillna(
                    0).astype(int)

                # 범주형 데이터 전처리: 라벨 인코딩 일괄 수행
                cat_cols = ['country', 'region', 'city', 'asn', 'device_type', 'os_name_version',
                            'browser_name_version', 'user_agent_string', 'login_successful', 'resolution', 'language']
                for col in cat_cols:
                    le = LabelEncoder()
                    df_ml[col] = le.fit_transform(df_ml[col].astype(str))

                # 이진 분류를 위한 타겟 라벨링 기법 적용: 현재 타겟 사용자는 1(정상), 타 사용자는 0(공격자군)
                df_ml['Target'] = (df_ml['user_id'] == user_id).astype(int)

                # 분석에서 제외할 고유 식별 필드 및 타겟 드롭
                drop_columns = ['user_id', 'Target', 'login_timestamp', 'ip_address']
                X_all = df_ml.drop(columns=drop_columns, errors='ignore')
                y_all = df_ml['Target']

                # 과거 데이터(학습용)와 방금 들어온 마지막 로우(예측 대상 테스트용) 분리
                X_train = X_all.iloc[:-1]
                y_train = y_all.iloc[:-1]
                X_test = X_all.iloc[-1:]

                # 랜덤 포레스트 모델 빌드 및 지도 학습 실행
                rf = RandomForestClassifier(n_estimators=100, random_state=42)
                rf.fit(X_train, y_train)

                # 클래스별 예측 확률값 연산 추출 (proba_results -> [[공격자일 확률, 정상 사용자일 확률]])
                proba_results = rf.predict_proba(X_test)

                # 정상 사용자(인덱스 1)에 매칭되는 확률을 가져와 하단 가이드에 맞춰 100배 스케일링 수행
                rba_prob = float(proba_results[0][1] * 100.0)

                # [요구사항 반영] 현재 코드에 기록을 유지하기 위한 Top 4 중요 속성(Feature Importance) 추출 및 변수 할당
                importances = pd.Series(rf.feature_importances_, index=X_train.columns)
                top_4_features = importances.sort_values(ascending=False).head(4).index.tolist()
                print(f"DEBUG: user_id={user_id} - RBA RF 산출 확률: {rba_prob:.2f}%, Top 4 기여 속성: {top_4_features}")

            except Exception as ml_error:
                # 데이터 누락 에러 및 예기치 못한 모델 에러 발생 시 방어적으로 무조건 실패(확률 0.0) 처리
                print(f"DEBUG: RBA 머신러닝 모델 수행 중 예외 발생 ({ml_error}) - 안전을 위해 불안전 단계로 처리합니다.")
                rba_prob = 0.0

        ###########################################################################################################
        # 이 이후로 수정 금지
        ###########################################################################################################
        ###########################################################################################################
        # RBA 기준 이 내용은 수정하지 말 것 수치는 직접 조정할거임
        if rba_prob >= 75.0:
            rba_tier = "안전(저위험군)"
        elif rba_prob >= 40.0:
            rba_tier = "애매(중위험군)"
        else:
            rba_tier = "불안전(고위험군)"
        ##########################################################################################################
        # 6. 6가지 시나리오 기반 의사결정 매트릭스
        if keystroke_success:
            # [시나리오 1] 키스트로크 성공인 경우
            if rba_tier == "안전(저위험군)" or rba_tier == "애매(중위험군)":
                final_status = "ALLOWED"
            else:  # 불안전(고위험군)
                final_status = "MFA_REQUIRED"
        else:
            # [시나리오 2] 키스트로크 실패인 경우
            if rba_tier == "안전(저위험군)":
                final_status = "ALLOWED"
            elif rba_tier == "애매(중위험군)":
                final_status = "MFA_REQUIRED"
            else:  # 불안전(고위험군)
                final_status = "DENIED"

        ###########################################################################################################
        # 이 이후로 수정 금지
        ###########################################################################################################
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