let lastKeyUpTime = 0;
let holdTimes = [];
let flightTimes = [];
let timerInterval;

const passwordInput = document.getElementById('password');

// 1. 키스트로크 데이터 수집 (프론트 핵심 과제)
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

// 타이머 함수
function startTimer() {
    let timeLeft = 180;
    const timerDisplay = document.getElementById('timer');
    if (timerInterval) clearInterval(timerInterval);
    timerInterval = setInterval(() => {
        const minutes = Math.floor(timeLeft / 60);
        const seconds = timeLeft % 60;
        timerDisplay.textContent = `남은 시간: 0${minutes}:${seconds < 10 ? '0' + seconds : seconds}`;
        if (timeLeft <= 0) {
            clearInterval(timerInterval);
            timerDisplay.textContent = "시간 만료";
        } else {
            timeLeft--;
        }
    }, 1000);
}

// 2. 로그인 버튼 클릭 (서버 통신 및 결과 처리)
async function login() {
    const username = document.getElementById('username').value;
    const password = passwordInput.value;

    // 희서님 서버 방식(Query Parameter)에 맞춘 주소 생성
    const url = new URL('http://34.207.73.29:8001/auth/login');
    url.searchParams.append('username', username);
    url.searchParams.append('password', password);

    // 본문에 담을 추가 데이터 (RBA + Keystroke)
    const extraData = {
        "keystroke_data": [holdTimes, flightTimes],
        "resolution": `${window.screen.width}x${window.screen.height}`
    };

    try {
        const response = await fetch(url.toString(), {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(extraData)
        });

        const result = await response.json();
        console.log("서버 응답 데이터:", result);

        // [핵심] 서버 응답 결과에 따른 분기 처리
        if (response.ok) {
            // 서버가 성공(200)을 보냈을 때
            alert("로그인 성공!");
        } else if (response.status === 400) {
            // 아이디/비번이 틀렸을 때 (방금 확인한 에러)
            alert("로그인 실패: " + (result.detail || "아이디 또는 비밀번호를 확인하세요."));
        } else if (response.status === 422) {
            alert("데이터 형식이 맞지 않습니다. (422 에러)");
        } else {
            // 위험 점수가 높아서 MFA가 필요한 경우 (서버 설계에 따라 status 확인)
            alert("보안 인증이 필요합니다. QR 코드를 스캔하세요.");
            showMfaSection(username);
        }
    } catch (error) {
        console.error("연결 에러:", error);
        alert("서버와 통신할 수 없습니다.");
    }
}

function showMfaSection(username) {
    const qrImage = document.getElementById('qr-image');
    const mfaSection = document.getElementById('mfa-section');
    mfaSection.style.display = 'block';

    const myIp = "172.20.10.14"; // 윤서님 현재 IP 주소
    const authUrl = `http://${myIp}:5500/cap/mfa.html?user=${username}`;
    
    qrImage.src = `https://api.qrserver.com/v1/create-qr-code/?size=150x150&data=${encodeURIComponent(authUrl)}`;
    startTimer();
}