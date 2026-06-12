let currentSessionEvents = [];
const finalKeystrokeProfiles = [];
let successCount = 0;
const TARGET_SUCCESS_COUNT = 15;

const passwordInput = document.getElementById('password');
const keystrokeInput = document.getElementById('keystroke-input');
const successCountDisplay = document.getElementById('success-count');
const registerBtn = document.getElementById('register-btn');

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

        currentSessionEvents.push({
            key: e.key,
            event: "keydown",
            time: Math.round(performance.now())
        });
    });

    keystrokeInput.addEventListener('keyup', (e) => {
        if (e.key === 'Enter') {
            checkSentenceValidation();
            return;
        }

        currentSessionEvents.push({
            key: e.key,
            event: "keyup",
            time: Math.round(performance.now())
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

    if (finalKeystrokeProfiles.length < TARGET_SUCCESS_COUNT) {
        alert(`비밀번호 타자 지문을 ${TARGET_SUCCESS_COUNT}회 등록해 주세요.`);
        return;
    }

    const ua = navigator.userAgent;

    const osNameVersion =
        ua.includes("Windows NT 10.0") ? "Windows 10/11" :
        ua.includes("Windows NT 6.3") ? "Windows 8.1" :
        ua.includes("Windows NT 6.2") ? "Windows 8" :
        ua.includes("Windows NT 6.1") ? "Windows 7" :
        ua.includes("Mac OS X") ? "Mac OS X" :
        ua.includes("Android") ? "Android" :
        ua.includes("iPhone") || ua.includes("iPad") ? "iOS" :
        "Unknown OS";

    let browserNameVersion = "Unknown Browser";

    if (ua.includes("Edg/")) {
        browserNameVersion = ua.match(/Edg\/([\d.]+)/)?.[0] || "Edge";
    }
    else if (ua.includes("Chrome/")) {
        browserNameVersion = ua.match(/Chrome\/([\d.]+)/)?.[0] || "Chrome";
    }
    else if (ua.includes("Firefox/")) {
        browserNameVersion = ua.match(/Firefox\/([\d.]+)/)?.[0] || "Firefox";
    }
    else if (ua.includes("Safari/")) {
        browserNameVersion = ua.match(/Version\/([\d.]+)/)?.[0] || "Safari";
    }

    const deviceType =
        /Mobi|Android|iPhone|iPad/i.test(ua)
            ? "Mobile"
            : "Desktop";

    let geoData = {};

    try {
        const geoResponse = await fetch("https://ipapi.co/json/");
        geoData = await geoResponse.json();
        console.log("🌍 실제 위치 정보:", geoData);
    } catch (e) {
        console.error("위치 조회 실패:", e);
    }

    const signupPayload = {
        username,
        password,
        language: navigator.language || "ko-KR",
        resolution: `${window.screen.width}x${window.screen.height}`,
        rtt: estimatedRTT || 0,

        ip_address: geoData.ip || "",
        country: geoData.country_name || "",
        region: geoData.region || "",
        city: geoData.city || "",
        asn: geoData.org || "",

        user_agent_string: navigator.userAgent,
        browser_name_version: browserNameVersion,
        os_name_version: osNameVersion,
        device_type: deviceType,

        keystroke_profiles: finalKeystrokeProfiles
    };

    console.log("🚀 회원가입 데이터 패킷:", {
        ...signupPayload,
        password: "********"
    });

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