import pandas as pd
from sqlalchemy import create_engine

# 🌐 도커 컴포즈에 세팅된 PostgreSQL 연결 엔진 생성
# 형식: postgresql://유저명:비밀번호@호스트:포트/디비명
# 현재 내부에 뜬 포트가 5432이므로 localhost:5432로 찌르면 다이렉트로 꽂힙니다.
DATABASE_URL = "postgresql://postgres:postgres@localhost:5432/capstone"
engine = create_engine(DATABASE_URL)

def migrate_csv_to_db():
    try:
        print("⏳ 1. CSV 파일(rba_clean.csv) 로드 중...")
        df = pd.read_csv("rba_clean.csv")
        
        # 💡 중요: CSV의 컬럼명과 DB 테이블(RBAReadyToTrain)의 컬럼명을 완벽하게 일치시키는 매핑 작업
        # 민성님 csv 스펙의 한글/대문자 컬럼들을 희서님이 파놓은 오피셜 DB 컬럼명으로 치환합니다.
        column_mapping = {
            'Login Timestamp': 'login_timestamp',
            'User ID': 'user_id',
            'Round-Trip Time [ms]': 'rtt',
            'IP Address': 'ip_address',
            'Country': 'country',
            'Region': 'region',
            'City': 'city',
            'ASN': 'asn',
            'User Agent String': 'user_agent_string',
            'Browser Name and Version': 'browser_name_version',
            'OS Name and Version': 'os_name_version',
            'Device Type': 'device_type',
            'Login Successful': 'login_successful',
            '해상도': 'resolution',
            '언어': 'language'
        }
        df = df.rename(columns=column_mapping)
        
        # 만약 id 컬럼이 csv에 존재한다면 DB의 자동 증가(Autoincrement)와 충돌을 방지하기 위해 드롭합니다.
        if 'id' in df.columns:
            df = df.drop(columns=['id'])

        print(f"⏳ 2. 실제 PostgreSQL DB의 'rba_ready_to_train' 테이블로 {len(df)}개의 데이터 적재 시작...")
        
        # 🚀 pandas의 to_sql을 활용해 고속 데이터 마이그레이션 격발
        # if_exists="append"를 주어야 기존 테이블 스키마를 부수지 않고 알맹이만 쏙 들어갑니다.
        df.to_sql(
            name="rba_ready_to_train",
            con=engine,
            if_exists="append",
            index=False
        )
        
        print("✅ 3. 대성공! 모든 CSV 데이터가 AI 임시 캐시 테이블에 적재되었습니다!")
        
    except FileNotFoundError:
        print("❌ 에러: 현재 디렉토리에 'rba_clean.csv' 파일이 존재하지 않습니다. 경로를 확인해 주세요.")
    except Exception as e:
        print(f"❌ 데이터 적재 중 오류 발생: {e}")

if __name__ == "__main__":
    migrate_csv_to_db()
