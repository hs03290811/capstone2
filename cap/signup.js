let currentSessionEvents = []; 
const finalKeystrokeProfiles = []; 
let successCount = 0;
const TARGET_SUCCESS_COUNT = 15; 

const passwordInput = document.getElementById('password');
const keystrokeInput = document.getElementById('keystroke-input');
const successCountDisplay = document.getElementById('success-count');
const registerBtn = document.getElementById('register-btn');

// 🌐 [추가] 백엔드가 가입 시 요구하는 RTT 측정을 위한 초기 시간 연산
let estimatedRTT = 0;
window.addEventListener('load', () => {
    const navEntries = performance.getEntriesByType("navigation");
    if (navEntries.length > 0) {
        estimatedRTT = Math.round(navEntries[0].responseEnd - navEntries[0].requestStart);
    }
});

if (keystrokeInput) {
    keystrokeInput.addEventListener('keydown', (e) => {
        if (e.repeat) return; 
        if (e.key === 'Enter') return; 

        // 💡 백엔드 schemas.py (KeystrokeEvent) 정품 규격 그대로 주입
        currentSessionEvents.push({
            "key": e.key,
            "event": "keydown", // 백엔드 검증용 소문자 통일
            "time": Math.round(performance.now())
        });
    });

    keystrokeInput.addEventListener('keyup', (e) => {
        if (e.key === 'Enter') {
            checkSentenceValidation();
            return;
        }

        // 💡 백엔드 schemas.py (KeystrokeEvent) 정품 규격 그대로 주입
        currentSessionEvents.push({
            "key": e.key,
            "event": "keyup", // 백엔드 검증용 소문자 통일
            "time": Math.round(performance.now())
        });
    });
}

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

    successCount++;
    if (successCountDisplay) successCountDisplay.textContent = successCount;
    
    // 💡 [핵심 교정]: 프론트에서 야매 가공하던 로직을 전면 철거하고, 
    // 백엔드 파이썬 소스코드 파싱 로직에 맞게 순수 날것(Raw)의 객체 로그 리스트를 그대로 적재합니다!
    finalKeystrokeProfiles.push(currentSessionEvents);

    currentSessionEvents = [];
    keystrokeInput.value = "";
    keystrokeInput.focus();

    console.log(`👍 세트 등록 성공! 현재 카운트: ${successCount}/${TARGET_SUCCESS_COUNT}`);

    if (successCount >= TARGET_SUCCESS_COUNT) {
        if (registerBtn) registerBtn.disabled = false; 
        keystrokeInput.disabled = true; 
        alert(`🎉 총 ${TARGET_SUCCESS_COUNT}회의 비밀번호 타자 지문 등록이 완료되었습니다! 회원가입 완료 버튼을 눌러주세요.`);
    }
}

async function submitSignup() {
    const username = document.getElementById('username').value.trim();
    const password = passwordInput.value;

    if (!username || !password) {
        alert("아이디와 비밀번호를 먼저 입력해 주세요.");
        return;
    }

    // 💡 [완벽 매싱 패치]: schemas.py의 UserRegisterWithKeystrokeDTO 스펙 누락 방지 9대 환경 인자 전면 추가 주입!
    const signupPayload = {
        "username": username,
        "password": password,
        "language": navigator.language || "ko-KR",
        "resolution": `${window.screen.width}x${window.screen.height}`,
        "rtt": estimatedRTT || 0,
        "ip_address": "219.255.207.24",
        "country": "South Korea",
        "region": "Seoul",
        "city": "Seoul",
        "asn": "AS9318 (SK Broadband)",
        "user_agent_string": navigator.userAgent,
        "browser_name_version": "Chrome 120.0.0.0",
        "os_name_version": "Mac OS X 10.15.7",
        "device_type": "Desktop",
        "keystroke_profiles": finalKeystrokeProfiles // 15세트 2차원 리스트 정상 매핑
    };

    console.log("🚀 백엔드 정품 DTO 검증단으로 쏘아 올릴 회원가입 데이터 패킷:", signupPayload);

    const url = 'http://32.197.121.164:8001/auth/signup';

    try {
        const response = await fetch(url, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(signupPayload)
        });

        const result = await response.json();

        if (response.ok) {
            alert("🎉 회원가입 및 15회 타이핑 지문 프로필 등록 성공!"); 
            window.location.href = 'index.html'; 
        } else {
            alert("❌ 회원가입 실패: " + (result.detail || "서버 규격 파싱 오류 발생"));
        }
    } catch (error) {
        console.error("통신 에러:", error);
        alert("백엔드 서버 연결 실패!");
    }
}