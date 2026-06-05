import requests
import json
import random
import time

url = "http://localhost:8001/auth/login"
headers = {"Content-Type": "application/json"}

print("🚀 RBA 미니 캐시 및 AI 학습 데이터 자동 주입 시작...")

for i in range(1, 31):
    # AI 모델이 다양하게 학습할 수 있도록 약간의 데이터 변동성(난수) 부여
    payload = {
        "username": "testuser",
        "password": "testpassword",
        "language": "ko-KR",
        "resolution": "1920x1080",
        "rtt": random.randint(35, 55),
        "keystroke": [random.randint(100, 160) for _ in range(34)]
    }
    
    response = requests.post(url, headers=headers, data=json.dumps(payload))
    print(f"[{i}/30] 데이터 주입 상태 코드: {response.status_code}")
    time.sleep(0.1) # 서버 과부하 방지용 미세 딜레이

print("✅ 총 30개의 청정 행위 데이터가 성공적으로 적재되었습니다!")
