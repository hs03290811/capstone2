let lastKeyUpTime = 0;
let holdTimes = [];
let flightTimes = [];

const passwordInput = document.getElementById('password');

// 1. 키를 누를 때 (Hold 시작)
passwordInput.addEventListener('keydown', (e) => {
    // 키를 처음 눌렀을 때만 시간 기록 (꾹 누르고 있을 때 중복 기록 방지)
    if (e.repeat) return; 

    const now = performance.now();
    passwordInput.dataset.lastDownTime = now;

    // Flight Time 계산: 이전 키를 뗀 시점부터 지금 누른 시점까지의 간격
    if (lastKeyUpTime !== 0) {
        const flightTime = now - lastKeyUpTime;
        flightTimes.push(Math.round(flightTime));
    }
});

// 2. 키를 뗄 때 (Hold 종료)
passwordInput.addEventListener('keyup', (e) => {
    const now = performance.now();
    const lastDownTime = parseFloat(passwordInput.dataset.lastDownTime);
    
    // Hold Time 계산: 키를 누르고 있었던 시간
    if (lastDownTime) {
        const holdTime = now - lastDownTime;
        holdTimes.push(Math.round(holdTime));
    }
    
    lastKeyUpTime = now;
});

// 3. 로그인 버튼 눌렀을 때 (서버 전송용 데이터 완성)
function login() {
    const username = document.getElementById('username').value;
    const password = passwordInput.value;

    // API 가이드에 명시된 JSON 규격 완성!
    const loginData = {
        username: username,
        password: password,
        keystroke: {
            hold_times: holdTimes,
            flight_times: flightTimes
        },
        context: {
            device: navigator.userAgent.split(' ')[0], // 대략적인 기기 정보
            location_hint: "Gwanghwamun" // 이건 나중에 GPS 연동 가능
        }
    };

    console.log("--- 서버로 보낼 데이터 ---");
    console.log(JSON.stringify(loginData, null, 2));
    
    document.getElementById('mfa-section').style.display = 'block';
    alert("데이터 수집 완료! F12를 눌러 콘솔창을 확인하세요.");
    
    // 여기서 실제로 서버에 데이터를 쏘는 fetch() 코드를 넣으면 됩니다.

    const qrImage = document.getElementById('qr-image');
    const mfaSection = document.getElementById('mfa-section');

    // 1. MFA 섹션을 보여줌
    mfaSection.style.display = 'block';

    // 2. 임시로 '인증용 주소'를 QR 코드로 만듭니다. (나중에 백엔드에서 줄 주소)
    // 구글 API를 사용해서 "인증 완료"라는 텍스트를 QR로 만드는 예시입니다.
    const authUrl = "https://your-project-auth.com/verify?user=" + username;
    qrImage.src = `https://api.qrserver.com/v1/create-qr-code/?size=150x150&data=${encodeURIComponent(authUrl)}`;
    qrImage.style.display = 'block'; // 이미지 보이기

    let timerInterval; // 타이머를 멈추기 위해 변수를 미리 만듭니다.

    function startTimer() {
        let timeLeft = 180; // 3분 = 180초
        const timerDisplay = document.getElementById('timer');

        // 혹시 이미 돌아가고 있는 타이머가 있다면 초기화
        clearInterval(timerInterval);

        timerInterval = setInterval(() => {
            const minutes = Math.floor(timeLeft / 60);
            const seconds = timeLeft % 60;

            // 숫자가 10보다 작으면 앞에 0을 붙여서 '05'처럼 보이게 함
            const displaySeconds = seconds < 10 ? '0' + seconds : seconds;
            timerDisplay.textContent = `남은 시간: 0${minutes}:${displaySeconds}`;

            if (timeLeft <= 0) {
                clearInterval(timerInterval);
                timerDisplay.textContent = "시간이 만료되었습니다. 다시 시도하세요.";
                document.getElementById('qr-image').style.opacity = "0.2"; // QR코드 흐리게
            } else {
                timeLeft--;
            }
        }, 1000); // 1초(1000ms)마다 실행
    }

    startTimer();

}