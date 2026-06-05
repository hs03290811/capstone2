let currentSessionEvents = []; 
const finalKeystrokeProfiles = []; 
let successCount = 0;
const TARGET_SUCCESS_COUNT = 15; 

const passwordInput = document.getElementById('password');
const keystrokeInput = document.getElementById('keystroke-input');
const successCountDisplay = document.getElementById('success-count');
const registerBtn = document.getElementById('register-btn');

keystrokeInput.addEventListener('keydown', (e) => {
    if (e.repeat) return; 
    if (e.key === 'Enter') return; 

    currentSessionEvents.push({
        "key": e.key,
        "type": "keydown",
        "time": performance.now()
    });
});

keystrokeInput.addEventListener('keyup', (e) => {
    if (e.key === 'Enter') {
        checkSentenceValidation();
        return;
    }

    currentSessionEvents.push({
        "key": e.key,
        "type": "keyup",
        "time": performance.now()
    });
});

function checkSentenceValidation() {
    const targetPhrase = passwordInput.value; 
    const userInput = keystrokeInput.value;

    if (!targetPhrase) {
        alert("위의 비밀번호(PW) 입력란을 먼저 채워주세요!");
        currentSessionEvents = [];
        keystrokeInput.value = "";
        passwordInput.focus();
        return;
    }

    if (userInput !== targetPhrase) {
        alert("비밀번호가 일치하지 않습니다. 다시 입력해 주세요.");
        currentSessionEvents = [];
        keystrokeInput.value = ""; 
        keystrokeInput.focus();
        return;
    }

    // 💡 [백엔드 AI 엔진 에러 원천 방어]: 백엔드 파이썬 소스코드 파싱 로직에 맞춤형 변환 가동!
    const keys = [];
    const downMap = {};
    for (let ev of currentSessionEvents) {
        if (ev.type === 'keydown') downMap[ev.key] = ev.time;
        else if (ev.type === 'keyup' && downMap[ev.key] !== undefined) {
            keys.push({ key: ev.key, down: downMap[ev.key], up: ev.time });
            delete downMap[ev.key];
        }
    }

    const combinedKeystroke = [];
    for (let i = 0; i < keys.length; i++) {
        combinedKeystroke.push(Math.round(keys[i].up - keys[i].down));
        if (i < keys.length - 1) {
            combinedKeystroke.push(Math.round(keys[i+1].down - keys[i].down));
            combinedKeystroke.push(Math.round(keys[i+1].down - keys[i].up));
        }
    }

    // 💡 백엔드가 422, 400 에러 안 나게 객체 리스트 스키마로 포장하되, 값은 순수 연산 숫자를 주입!
    const formattedProfile = combinedKeystroke.map((val) => ({
        "key": "num",
        "event": "keydown",
        "time": val
    }));

    successCount++;
    successCountDisplay.textContent = successCount;
    finalKeystrokeProfiles.push(formattedProfile);

    currentSessionEvents = [];
    keystrokeInput.value = "";
    keystrokeInput.focus();

    if (successCount >= TARGET_SUCCESS_COUNT) {
        registerBtn.disabled = false; 
        keystrokeInput.disabled = true; 
        alert(`🎉 총 ${TARGET_SUCCESS_COUNT}회의 비밀번호 타자 지문 등록이 완료되었습니다! 회원가입 완료 버튼을 눌러주세요.`);
    }
}

async function submitSignup() {
    const username = document.getElementById('username').value.trim();
    const password = passwordInput.value;

    const signupPayload = {
        "username": username,
        "password": password,
        "keystroke_profiles": finalKeystrokeProfiles
    };

    const url = 'http://32.197.121.164:8001/auth/signup';
    try {
        const response = await fetch(url, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(signupPayload)
        });
        const result = await response.json();
        if (response.ok) {
            alert("🎉 회원가입 및 타건 등록 성공!"); 
            window.location.href = 'index.html'; 
        } else {
            alert("❌ 회원가입 실패: " + (result.detail || "서버 오류"));
        }
    } catch (error) {
        alert("백엔드 서버 연결 실패!");
    }
}