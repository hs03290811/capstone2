# 1. 파이썬 환경 설정
FROM python:3.11-slim

# 2. 작업 디렉토리 생성
WORKDIR /app

# 3. 필요한 라이브러리 설치 파일 복사 및 설치
# (requirements.txt가 폴더에 있는지 꼭 확인하세요!)
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# 4. 전체 코드 복사
COPY . .

# 5. 서버 실행 (8001번 포트)
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8001"]
