let lastKeyUpTime = 0;
let holdTimes = [];
let flightTimes = [];
let timerInterval; // 타이머 변수를 밖으로 빼서 관리합니다.

const passwordInput = document.getElementById('password');

// 1. 키를 누를 때 (Hold 시작)
passwordInput.addEventListener('keydown', (e) => {
    if (e.repeat) return; 

    const now = performance.now();
    passwordInput.dataset.lastDownTime = now;

    if (lastKeyUpTime !== 0) {
        const flightTime = now - lastKeyUpTime;
        flightTimes.push(Math.round(flightTime));
    }
});

// 2. 키를 뗄 때 (Hold 종료)
passwordInput.addEventListener('keyup', (e) => {
    const now = performance.now();
    const lastDownTime = parseFloat(passwordInput.dataset.lastDownTime);
    
    if (lastDownTime) {
        const holdTime = now - lastDownTime;
        holdTimes.push(Math.round(holdTime));
    }
    
    lastKeyUpTime = now;
});

// 타이머 함수 (정리 및 최적화)
function startTimer() {
    let timeLeft = 180; // 3분
    const timerDisplay = document.getElementById('timer');

    if (timerInterval) clearInterval(timerInterval);

    timerInterval = setInterval(() => {
        const minutes = Math.floor(timeLeft / 60);
        const seconds = timeLeft % 60;
        const displaySeconds = seconds < 10 ? '0' + seconds : seconds;
        
        timerDisplay.textContent = `남은 시간: 0${minutes}:${displaySeconds}`;

        if (timeLeft <= 0) {
            clearInterval(timerInterval);
            timerDisplay.textContent = "시간이 만료되었습니다. 다시 시도하세요.";
            document.getElementById('qr-image').style.opacity = "0.2";
        } else {
            timeLeft--;
        }
    }, 1000);
}

// 3. 로그인 버튼 눌렀을 때
function login() {
    const username = document.getElementById('username').value;
    const password = passwordInput.value;

    // JSON 데이터 생성 (콘솔 확인용)
    const loginData = {
        username: username,
        password: password,
        keystroke: {
            hold_times: holdTimes,
            flight_times: flightTimes
        },
        context: {
            device: navigator.userAgent.split(' ')[0],
            location_hint: "Gwanghwamun"
        }
    };

    console.log("--- 서버 전송 데이터 ---");
    console.log(JSON.stringify(loginData, null, 2));

    // UI 요소 제어
    const qrImage = document.getElementById('qr-image');
    const mfaSection = document.getElementById('mfa-section');
    mfaSection.style.display = 'block';

   const myIp = "172.20.10.14"; 
    // 중간에 /cap/ 경로를 추가해줍니다.
    const authUrl = `http://${myIp}:5500/cap/mfa.html?user=${username}`;
    
    // QR 코드 생성 API 호출
    qrImage.src = `https://api.qrserver.com/v1/create-qr-code/?size=150x150&data=${encodeURIComponent(authUrl)}`;
    
    qrImage.onload = function() {
        qrImage.style.display = 'block';
    };

    alert("데이터 수집 완료! 아이폰으로 QR 코드를 스캔하세요.");
    startTimer();
}