let keyEvents = []; // 타이핑 이벤트(keydown, keyup)를 순서대로 담을 배열
let timerInterval;

// [로드맵 Phase 2] RTT 측정을 위한 초기 로드 시간 계산
let estimatedRTT = 0;
window.addEventListener('load', () => {
    const navEntries = performance.getEntriesByType("navigation");
    if (navEntries.length > 0) {
        estimatedRTT = Math.round(navEntries[0].responseEnd - navEntries[0].requestStart);
        console.log("측정된 네트워크 RTT:", estimatedRTT + "ms");
    }
});

// HTML 요소가 로드된 후 이벤트 리스너 등록을 위해 사용
window.addEventListener('DOMContentLoaded', () => {
    const passwordInput = document.getElementById('password');
    if (!passwordInput) return;

    // 키스트로크 수집 로직 (백스페이스 오타 처리 반영)
    passwordInput.addEventListener('keydown', (e) => {
        if (e.repeat) return; // 꾹 누르고 있어서 발생하는 연속 이벤트 방지
        if (e.key.length > 1 && e.key !== 'Backspace') return; // 특수 제어키 제외

        // 💡 백스페이스 입력 시 직전 글자의 타이밍 기록을 타임라인에서 제거(무시)
        if (e.key === 'Backspace') {
            if (keyEvents.length > 0) {
                let targetKey = null;
                // 가장 최근에 등록된 정상 키의 이름을 탐색
                for (let i = keyEvents.length - 1; i >= 0; i--) {
                    if (keyEvents[i].type === 'keydown') {
                        targetKey = keyEvents[i].key;
                        break;
                    }
                }
                // 해당 오타 키의 keydown, keyup 기록을 배열 끝에서부터 제거 (Undo 효과)
                if (targetKey) {
                    while (keyEvents.length > 0) {
                        let popped = keyEvents.pop();
                        if (popped.key === targetKey && popped.type === 'keydown') {
                            break;
                        }
                    }
                }
            }
            return; // 백스페이스 자체의 타이밍은 분석에 필요 없으므로 저장하지 않고 종료
        }

        // 정상 키는 타임라인에 기록
        keyEvents.push({
            key: e.key,
            type: 'keydown',
            time: performance.now()
        });
    });

    passwordInput.addEventListener('keyup', (e) => {
        if (e.key.length > 1) return; // 특수 제어키 제외

        keyEvents.push({
            key: e.key,
            type: 'keyup',
            time: performance.now()
        });
    });
});

// 로그인 및 CMU 규격 데이터 전송 함수
async function login() {
    try {
        const passwordInput = document.getElementById('password');
        const username = document.getElementById('username').value;
        const password = passwordInput ? passwordInput.value : '';

        if (!username || !password) {
            alert("아이디와 비밀번호를 모두 입력해 주세요.");
            return;
        }

        // 1차 정제: keyEvents 로그를 기반으로 글자별 [누른시간, 뗀시간] 객체 배열 생성
        const keys = [];
        const downMap = {};
        
        for (let ev of keyEvents) {
            if (ev.type === 'keydown') {
                downMap[ev.key] = ev.time;
            } else if (ev.type === 'keyup') {
                if (downMap[ev.key] !== undefined) {
                    keys.push({
                        key: ev.key,
                        down: downMap[ev.key],
                        up: ev.time
                    });
                    delete downMap[ev.key];
                }
            }
        }

        // 💡 AI 팀원이 요청한 CMU 데이터셋 규격 [H1, DD1, UD1, H2...] 배열 조립
        const combinedKeystroke = [];
        
        for (let i = 0; i < keys.length; i++) {
            // H (Hold Time): 본인 키 누른 시간 ~ 본인 키 뗀 시간
            const h = Math.round(keys[i].up - keys[i].down);
            combinedKeystroke.push(h);
            
            // 다음 글자가 존재할 때만 DD와 UD를 계산하여 삽입
            if (i < keys.length - 1) {
                // DD (Down-Down): 현재 키 누른 시간 ~ 다음 키 누른 시간
                const dd = Math.round(keys[i+1].down - keys[i].down);
                // UD (Up-Down): 현재 키 뗀 시간 ~ 다음 키 누른 시간
                const ud = Math.round(keys[i+1].down - keys[i].up);
                
                combinedKeystroke.push(dd);
                combinedKeystroke.push(ud);
            }
        }

        const securityPayload = {
            "username": username,
            "password": password,
            "language": navigator.language || "ko-KR",
            "resolution": `${window.screen.width}x${window.screen.height}`,
            "rtt": typeof estimatedRTT !== 'undefined' ? estimatedRTT : 0, 
            "keystroke": combinedKeystroke
        };

        console.log("🚀새 규격 데이터:", securityPayload);

        // 희서님(백엔드) 서버 주소 유지
        const url = 'http://34.207.73.29:8001/auth/login';

        const response = await fetch(url, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(securityPayload)
        });

        const result = await response.json();
        console.log("📥 서버 응답 결과:", result);

        if (response.ok) {
            alert("로그인 성공! 환영합니다.");
            document.getElementById('mfa-section').style.display = 'none';
        } else {
            alert("보안 위협이 감지되었거나 정보가 틀립니다. 2차 인증을 진행합니다.");
            showMfaSection(username); 
        }

    } catch (error) {
        console.error("오류 발생 원인:", error);
        alert("코드 실행 중 에러가 발생했습니다! " + error.message);
        const username = document.getElementById('username').value || 'test_user';
        showMfaSection(username);
    }
}

// QR 및 타이머 로직 (기존 유지)
function showMfaSection(username) {
    const mfaSection = document.getElementById('mfa-section');
    const qrImage = document.getElementById('qr-image');
    
    mfaSection.style.display = 'block';

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