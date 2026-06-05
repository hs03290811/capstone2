let currentSessionEvents = []; // 이번 1회 타임라인 수집 배열
const finalKeystrokeProfiles = []; // 최종 백엔드로 보낼 세트들이 저장되는 2차원 배열
let successCount = 0;

// 💡 명세서 규칙대로 정확하게 15회 설정!
const TARGET_SUCCESS_COUNT = 15; 

const passwordInput = document.getElementById('password');
const keystrokeInput = document.getElementById('keystroke-input');
const successCountDisplay = document.getElementById('success-count');
const registerBtn = document.getElementById('register-btn');

// [1단계] 타자 칠 때마다 ms 단위로 기록 가로채기
keystrokeInput.addEventListener('keydown', (e) => {
    if (e.repeat) return; // 꾹 누름 방지
    if (e.key === 'Enter') return; // 엔터키 자체의 입력 기록은 제외

    currentSessionEvents.push({
        "key": e.key,
        "event": "down",
        "time": Math.round(performance.now())
    });
});

keystrokeInput.addEventListener('keyup', (e) => {
    if (e.key === 'Enter') {
        // [2단계] 엔터키 입력 시 유효성 및 자기 비번 일치 검사 작동
        checkSentenceValidation();
        return;
    }

    currentSessionEvents.push({
        "key": e.key,
        "event": "up",
        "time": Math.round(performance.now())
    });
});

// [2단계 분기 처리 함수]
function checkSentenceValidation() {
    const targetPhrase = passwordInput.value; 
    const userInput = keystrokeInput.value;

    // 예외 처리: 비밀번호를 입력 안 하고 밑에부터 치는 경우 방지
    if (!targetPhrase) {
        alert("위의 비밀번호(PW) 입력란을 먼저 채워주세요!");
        currentSessionEvents = [];
        keystrokeInput.value = "";
        passwordInput.focus();
        return;
    }

    // 조건 A: 위에 친 비번이랑 밑에 친 문장이 틀린 경우
    if (userInput !== targetPhrase) {
        alert("비밀번호가 일치하지 않습니다. 다시 입력해 주세요.");
        currentSessionEvents = [];
        keystrokeInput.value = ""; // 입력창 초기화
        keystrokeInput.focus();
        return;
    }

    // 조건 B: 유효성 검사 통과 (정품 확정 🎉)
    successCount++;
    successCountDisplay.textContent = successCount;

    // 이번에 수집된 키스트로크 배열을 최종 전송용 2차원 배열에 저장
    finalKeystrokeProfiles.push(currentSessionEvents);

    // 임시 저장소 및 입력창 비우고 다음 회차 유도
    currentSessionEvents = [];
    keystrokeInput.value = "";
    keystrokeInput.focus();

    console.log(`👍 세트 등록 성공! 현재 카운트: ${successCount}/${TARGET_SUCCESS_COUNT}`);

    // 정확히 15회 도달 시 처리
    if (successCount >= TARGET_SUCCESS_COUNT) {
        registerBtn.disabled = false; // 회원가입 완료 버튼 켜기 🔓
        keystrokeInput.disabled = true; // 더 이상 입력 못 하게 차단
        alert(`🎉 총 ${TARGET_SUCCESS_COUNT}회의 비밀번호 타자 지문 등록이 완료되었습니다! 회원가입 완료 버튼을 눌러주세요.`);
    }
}

// [3단계] 회원가입 완료 버튼 누를 때 백엔드로 대포 발사
async function submitSignup() {
    const username = document.getElementById('username').value;
    const password = passwordInput.value;

    if (!username || !password) {
        alert("아이디와 비밀번호를 먼저 입력해 주세요.");
        return;
    }

    // 💡 새 명세서의 Request Body JSON 스펙 변수명과 100% 일치화
    const signupPayload = {
        "username": username,
        "password": password,
        "keystroke_profiles": finalKeystrokeProfiles
    };

    console.log("🚀 백엔드로 대포 발사할 최종 회원가입 데이터:", signupPayload);

    // 💡 [최신 반영] 희서 가이드 문서에 적힌 공식 Base URL 및 회원가입 엔드포인트 주소
    const url = 'http://32.197.121.164:8001/auth/signup';

    try {
        const response = await fetch(url, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(signupPayload)
        });

        const result = await response.json();
        console.log("📥 서버 응답 결과:", result);

        // 💡 백엔드가 성공 시 주는 200 OK 메시지 분기 처리
        if (response.ok) {
            // "회원가입 및 15회 타이핑 지문 프로필 등록 성공!"
            alert("🎉 " + result.message); 
            window.location.href = 'index.html'; // 성공 시 로그인 메인화면으로 이동
        } else {
            // 400, 422 에러 등 실패 시 경고창
            alert("❌ 회원가입 실패: " + (result.detail || result.message || "서버 오류 발생"));
        }
    } catch (error) {
        console.error("통신 에러:", error);
        alert("백엔드 서버 연결 실패! 서버가 켜져 있는지 확인해 주세요.");
    }
}