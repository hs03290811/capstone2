let lastKeyUpTime = 0;
let holdTimes = [];
let flightTimes = [];
let timerInterval;

// [로드맵 Phase 2] RTT 측정을 위한 초기 로드 시간 계산
let estimatedRTT = 0;
window.addEventListener('load', () => {
    const navEntries = performance.getEntriesByType("navigation");
    if (navEntries.length > 0) {
        // 응답 종료 시간 - 요청 시작 시간으로 대략적인 RTT 계산
        estimatedRTT = Math.round(navEntries[0].responseEnd - navEntries[0].requestStart);
        console.log("측정된 네트워크 RTT:", estimatedRTT + "ms");
    }
});

const passwordInput = document.getElementById('password');

// 키스트로크 수집 로직 (기존 유지)
passwordInput.addEventListener('keydown', (e) => {
    if (e.repeat) return; 
    const now = performance.now();
    passwordInput.dataset.lastDownTime = now;
    if (lastKeyUpTime !== 0) {
        flightTimes.push(Math.round(now - lastKeyUpTime));
    }
});

passwordInput.addEventListener('keyup', (e) => {
    const now = performance.now();
    const lastDownTime = parseFloat(passwordInput.dataset.lastDownTime);
    if (lastDownTime) {
        holdTimes.push(Math.round(now - lastDownTime));
    }
    lastKeyUpTime = now;
});

// 로그인 함수 (백엔드 팀원 명세서 규격으로 완전히 전면 수정)
async function login() {
    const username = document.getElementById('username').value;
    const password = passwordInput.value;

    // 💡 변경포인트 1: 백엔드 요청대로 holdTimes와 flightTimes를 1차원 숫자 배열로 합침
    const combinedKeystroke = [...holdTimes, ...flightTimes]; 

    // 💡 변경포인트 2: 백엔드 팀원이 정의한 핑크색 JSON Body 양식과 100% 일치시킴
    // (User-Agent, Timestamp 등은 백엔드가 직접 낚아채므로 제거하여 프론트 일거리 단축)
    const securityPayload = {
        "username": username,
        "password": password,
        "language": navigator.language,
        "resolution": `${window.screen.width}x${window.screen.height}`,
        "rtt": estimatedRTT, 
        "keystroke": combinedKeystroke
    };

    console.log("🚀 백엔드 전송 새 규격 데이터:", securityPayload);

    // 💡 변경포인트 3: 새로운 백엔드 서버 IP 주소 반영
    const url = 'http://211.244.28.177:8001/auth/login';

    try {
        // 💡 변경포인트 4: URL 주소창 쿼리 스트링 방식 제거하고, Body에 JSON을 싣고 전송
        const response = await fetch(url, {
            method: 'POST',
            headers: { 
                'Content-Type': 'application/json' 
            },
            body: JSON.stringify(securityPayload)
        });

        const result = await response.json();

        // 1. 완전 성공 (FLOW 03): 알림창 띄우고 종료
        if (response.ok) {
            alert("로그인 성공! 환영합니다.");
            document.getElementById('mfa-section').style.display = 'none';
        } 
        // 2. 실패 또는 2차 인증 필요 (FLOW 01, 02, 04)
        else {
            alert("보안 위협이 감지되었거나 정보가 틀립니다. 2차 인증을 진행합니다.");
            showMfaSection(username); // QR 띄우기
        }
    } catch (error) {
        console.error("통신 에러:", error);
        alert("서버 연결 실패! 테스트를 위해 QR을 띄웁니다.");
        showMfaSection(username);
    }
}

// QR 및 타이머 로직 (기존 유지)
function showMfaSection(username) {
    const mfaSection = document.getElementById('mfa-section');
    const qrImage = document.getElementById('qr-image');
    
    // 1. 일단 섹션부터 보여주기
    mfaSection.style.display = 'block';

    // 2. 안정적인 api.qrserver.com 사용 
    const myIp = "172.20.10.14"; 
    const authUrl = `http://${myIp}:5500/cap/mfa.html?user=${username}`;
    
    qrImage.src = `https://api.qrserver.com/v1/create-qr-code/?size=200x200&data=${encodeURIComponent(authUrl)}`;
    
    console.log("🚀 QR 생성 완료!");

    startTimer();
}

function startTimer() {
    let timeLeft = 180;
    const timerDisplay = document.getElementById('timer');
    if (timerInterval) clearInterval(timerInterval);
    timerInterval = setInterval(() => {
        const min = Math.floor(timeLeft / 60);
        const sec = timeLeft % 60;
        timerDisplay.textContent = `남은 시간: 0${min}:${sec < 10 ? '0' + sec : sec}`;
        if (timeLeft <= 0) clearInterval(timerInterval);
        else timeLeft--;
    }, 1000);
}