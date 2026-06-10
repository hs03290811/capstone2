let keyEvents = []; // 타이핑 이벤트(keydown, keyup)를 담을 배열
let timerInterval;
let keystrokeChart = null; // Chart.js 인스턴스 전역 변수

// [로드맵 Phase 2] RTT 측정을 위한 초기 로드 시간 계산
let estimatedRTT = 0;
window.addEventListener('load', () => {
    const navEntries = performance.getEntriesByType("navigation");
    if (navEntries.length > 0) {
        estimatedRTT = Math.round(navEntries[0].responseEnd - navEntries[0].requestStart);
    }
});

window.addEventListener('DOMContentLoaded', () => {
    const passwordInput = document.getElementById('password');
    if (!passwordInput) return;

    passwordInput.addEventListener('focus', () => {
        keyEvents = [];
    });

    passwordInput.addEventListener('keydown', (e) => {
        if (e.repeat) return;

        if (e.key === 'Enter') {
            e.preventDefault();
            login();
            return;
        }

        if (e.key.length > 1 && e.key !== 'Backspace') return;

        if (e.key === 'Backspace') {
            keyEvents = [];
            return;
        }

        keyEvents.push({
            key: e.key,
            type: 'keydown',
            time: performance.now()
        });
    });

    passwordInput.addEventListener('keyup', (e) => {
        if (e.key === 'Enter') return;
        if (e.key.length > 1) return;

        keyEvents.push({
            key: e.key,
            type: 'keyup',
            time: performance.now()
        });
    });
});

async function login() {
    const passwordInput = document.getElementById('password');
    const username = document.getElementById('username').value.trim();
    const password = passwordInput ? passwordInput.value : '';

    if (!username || !password) {
        alert("아이디와 비밀번호를 모두 입력해 주세요.");
        return;
    }

    // 1차 정제: keyEvents 로그 기반 글자별 누른/뗀 시간 추출
    const keys = [];
    const downMap = {};

    for (let ev of keyEvents) {
        if (ev.type === 'keydown') {
            if (!downMap[ev.key]) downMap[ev.key] = [];
            downMap[ev.key].push(ev.time);
        } else if (ev.type === 'keyup') {
            if (downMap[ev.key] && downMap[ev.key].length > 0) {
                const downTime = downMap[ev.key].shift();
                keys.push({
                    key: ev.key,
                    down: downTime,
                    up: ev.time
                });
            }
        }
    }

    keys.sort((a, b) => a.down - b.down);

    // CMU 규격 1차원 정수 배열 조립
    const combinedKeystroke = [];
    for (let i = 0; i < keys.length; i++) {
        const h = Math.round(keys[i].up - keys[i].down);
        combinedKeystroke.push(h);

        if (i < keys.length - 1) {
            const dd = Math.round(keys[i + 1].down - keys[i].down);
            const ud = Math.round(keys[i + 1].down - keys[i].up);
            combinedKeystroke.push(dd);
            combinedKeystroke.push(ud);
        }
    }

    const securityPayload = {
        "username": username,
        "password": password,
        "language": navigator.language || "ko-KR",
        "resolution": `${window.screen.width}x${window.screen.height}`,
        "rtt": estimatedRTT || 0,
        "keystroke": combinedKeystroke,
        "ip_address": "219.255.207.24",
        "country": "South Korea",
        "region": "Seoul",
        "city": "Seoul",
        "asn": "AS9318 (SK Broadband)",
        "user_agent_string": navigator.userAgent,
        "browser_name_version": "Chrome 120.0.0.0",
        "os_name_version": "Mac OS X 10.15.7",
        "device_type": "Desktop"
    };

    console.log("🚀 백엔드 전송 규격 데이터 패킷:", securityPayload);

    try {
        const response = await fetch('http://32.197.121.164:8001/auth/login', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(securityPayload)
        });

        const result = await response.json();
        console.log("📥 서버 응답 결과:", result);

        // 백엔드가 주는 평균 정답선 벡터 낚아채기
        const meanVector = result.telemetry?.keystroke?.mean_vector || [110, 240, 130, 310, 95, 280, 120, 340, 115, 290];
        drawKeystrokeChart(combinedKeystroke, meanVector);

        const finalStatus = result.security_analysis?.status || result.status;

        if (response.ok && (finalStatus === "ALLOWED" || finalStatus === "ALLOW" || finalStatus === "KICKED_OUT")) {
            alert("🎉 로그인 성공! 환영합니다.");
            const mfaBox = document.getElementById('mfa-section');
            if (mfaBox) mfaBox.style.display = 'none';
        } 
        else if (response.ok && finalStatus === "MFA_REQUIRED") {
            const riskReason = result.security_analysis?.primary_risk_factor || "위협 감지";
            const distance = result.telemetry?.keystroke?.current_distance ?? "N/A";
            const threshold = result.telemetry?.keystroke?.dynamic_threshold ?? "N/A";

            alert(
                `🔒 보안 알림: [${riskReason}] 리스크로 인해 2차 인증을 가동합니다.\n` +
                `---------------------------------\n` +
                `• 타건 거리 (Distance): ${distance}\n` +
                `• 동적 임계치 (Threshold): ${threshold}\n` +
                `---------------------------------`
            );
            showMfaSection(username);
        } 
        else {
            alert("❌ 로그인 실패: " + (result.detail || result.message || "아이디 또는 비밀번호가 일치하지 않습니다."));
        }

    } catch (error) {
        console.error("에러 발생:", error);
        alert("통신 중 오류가 발생했습니다.");
        drawKeystrokeChart(combinedKeystroke, [110, 240, 130, 310, 95, 280, 120, 340, 115, 290]);
    } finally {
        keyEvents = [];
    }
}

function showMfaSection(username) {
    const mfaSection = document.getElementById('mfa-section');
    const qrImage = document.getElementById('qr-image');
    if (!mfaSection) return;

    mfaSection.style.display = 'block';
    const myIp = "172.20.10.14";
    const authUrl = `http://${myIp}:5500/cap/mfa.html?user=${encodeURIComponent(username)}`;

    if (qrImage) {
        qrImage.src = `https://api.qrserver.com/v1/create-qr-code/?size=200x200&data=${encodeURIComponent(authUrl)}`;
    }
    console.log("🚀 QR 생성 완료!");
    startTimer();
}

function startTimer() {
    let timeLeft = 180;
    const timerDisplay = document.getElementById('timer');
    if (!timerDisplay) return;
    if (timerInterval) clearInterval(timerInterval);

    timerInterval = setInterval(() => {
        const min = Math.floor(timeLeft / 60);
        const sec = timeLeft % 60;
        timerDisplay.textContent = `남은 시간: 0${min}:${sec < 10 ? '0' + sec : sec}`;
        if (timeLeft <= 0) clearInterval(timerInterval);
        else timeLeft--;
    }, 1000);
}

// 📊 문자열 텍스트 라벨 플러그인을 완전히 제거한 최종 정제 차트 엔진
function drawKeystrokeChart(currentData, targetVector) {
    const ctx = document.getElementById('keystrokeChart');
    if (!ctx) return;

    const currentPasswordValue = document.getElementById('password')?.value || '';
    const currentChars = currentPasswordValue.split('');

    function parseCmuToAbsoluteTimes(cmuArray, charList, yValue) {
        const points = [];
        if (!cmuArray || cmuArray.length === 0 || charList.length === 0) return points;

        let currentPressTime = 0;
        for (let i = 0; i < charList.length; i++) {
            const cmuIdx = i * 3;
            if (cmuIdx >= cmuArray.length) break;

            const holdTime = cmuArray[cmuIdx];
            const downDown = cmuArray[cmuIdx + 1];

            points.push({
                x: currentPressTime,
                y: yValue,
                pointType: 'press',
                charIdx: i
            });

            points.push({
                x: currentPressTime + holdTime,
                y: yValue,
                pointType: 'release',
                charIdx: i
            });

            if (downDown !== undefined) {
                currentPressTime += downDown;
            } else {
                break;
            }
        }
        return points;
    }

    function normalizePoints(points) {
        if (!points || points.length === 0) return [];

        const timeValues = points.map(pt => pt.x);
        const minX = Math.min(...timeValues);
        const maxX = Math.max(...timeValues);
        const range = maxX - minX || 1;

        const sorted = [...points].sort((a, b) => {
            if (a.charIdx !== b.charIdx) {
                return a.charIdx - b.charIdx;
            }
            return a.pointType === 'press' ? -1 : 1;
        });

        return sorted.map(pt => ({
            x: parseFloat(((pt.x - minX) / range).toFixed(2)),
            y: pt.y,
            pointType: pt.pointType
        }));
    }

    const rawCurrentPoints = parseCmuToAbsoluteTimes(currentData, currentChars, 1);

    let regChars = currentChars;
    if (targetVector && targetVector.length > 0) {
        const regCharCount = Math.floor((targetVector.length + 1) / 3);
        if (regCharCount !== currentChars.length) {
            regChars = Array.from({ length: regCharCount }, (_, i) => String(i + 1));
        }
    }

    const rawRegPoints = parseCmuToAbsoluteTimes(targetVector, regChars, 2);

    const datasetCurrent = normalizePoints(rawCurrentPoints);
    const datasetReg = normalizePoints(rawRegPoints);

    if (keystrokeChart) {
        keystrokeChart.data.datasets[0].data = datasetReg;
        keystrokeChart.data.datasets[1].data = datasetCurrent;
        keystrokeChart.update();
        return;
    }

    // 💡 문자열 텍스트 라벨 플러그인(textLabelsPlugin) 전면 삭제 완료
    keystrokeChart = new Chart(ctx, {
        type: 'scatter',
        data: {
            datasets: [
                { label: '등록 평균선', data: datasetReg, borderColor: '#9b59b6', backgroundColor: '#9b59b6', showLine: true, borderWidth: 2, pointRadius: 6 },
                { label: '현재 타건선', data: datasetCurrent, borderColor: '#3498db', backgroundColor: '#3498db', showLine: true, borderWidth: 2, pointRadius: 6 }
            ]
        },
        options: {
            responsive: true, maintainAspectRatio: false,
            layout: { padding: { top: 15, bottom: 10, left: 15, right: 15 } },
            plugins: { legend: { display: false } },
            scales: {
                x: { min: 0, max: 1, title: { display: true, text: 'Time Rate (0.0 ~ 1.0)' } },
                y: { min: 0.2, max: 2.8, ticks: { stepSize: 1, callback: function (v) { if (v === 1 || v === 2) return v; } } }
            }
        }
    });
}