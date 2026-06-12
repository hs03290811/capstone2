# Guardian Login System

키스트로크 다이내믹스(Keystroke Dynamics)와 위험 기반 인증(Risk-Based Authentication, RBA)을 결합한 적응형 사용자 인증 시스템입니다.

## 프로젝트 개요

본 프로젝트는 기존 ID/PW 인증 방식의 보안 취약점을 보완하기 위해 개발되었습니다.

사용자의 타이핑 패턴과 로그인 환경 정보를 함께 분석하여 정상 사용자 여부를 판단하며, 필요 시 추가 인증(MFA)을 수행합니다.

### 주요 기능

* 회원가입 및 로그인
* 키스트로크 다이내믹스 기반 사용자 인증
* RBA(Risk-Based Authentication)
* 적응형 인증(Adaptive Authentication)
* MFA(다중 인증) 화면 제공
* 로그인 이력 관리

---

## 시스템 구조

```text
Frontend
   │
   ▼
FastAPI Backend
   │
   ├── PostgreSQL
   ├── Redis
   └── Authentication Engine
```

---

## 기술 스택

### Frontend

* HTML
* CSS
* JavaScript
* Chart.js

### Backend

* Python
* FastAPI
* SQLAlchemy
* PostgreSQL
* Redis

### Deployment

* Docker
* Docker Compose
* AWS EC2

---

## 프로젝트 구조

```text
project/
├── frontend/
│   ├── index.html
│   ├── signup.html
│   └── script.js
│
├── backend/
│   ├── app/
│   ├── requirements.txt
│   └── Dockerfile
│
├── docs/
│   ├── Final_Report.pdf
│   ├── User_Manual.pdf
│   └── Presentation.pdf
│
├── docker-compose.yml
└── README.md
```

---

## 실행 방법

### 1. 프로젝트 다운로드

```bash
git clone [repository-url]
cd [repository-name]
```

### 2. Docker 실행

```bash
docker compose up -d
```

### 3. 프론트엔드 실행

현재 프론트엔드는 별도 서버에 배포되어 있지 않으며 로컬 환경에서 실행합니다.

VS Code Live Server 또는 브라우저를 이용하여 실행합니다.

```text
http://127.0.0.1:5500/index.html
```

회원가입 페이지

```text
http://127.0.0.1:5500/signup.html
```

---

## 시연 시나리오

### ALLOWED

* 정상 사용자
* 정상 환경

결과

```text
ALLOWED
```

### MFA_REQUIRED

* 환경 정보 일부 변경
* 추가 인증 필요

결과

```text
MFA_REQUIRED
```

### DENIED

* 타이핑 패턴 불일치
* 위험 환경 접속

결과

```text
DENIED
```

---

## 문서

프로젝트 관련 문서는 docs 폴더에서 확인할 수 있습니다.

* Final_Report.pdf
* User_Manual.pdf
* Presentation.pdf

---

## 개발 팀

Capstone Design Project

* Frontend : 20232110 최윤서
* Backend : 20231900 김희서
* AI : 20206830 유민성
