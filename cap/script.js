let keyEvents = []; // 타이핑 이벤트(keydown, keyup)를 순서대로 담을 배열
let timerInterval;
let keystrokeChart = null; // Chart.js 인스턴스를 담을 전역 변수

// [로드맵 Phase 2] RTT 측정을 위한 초기 로드 시간 계산
let estimatedRTT = 0;
window.addEventListener('load', () => {
    const navEntries = performance.getEntriesByType("navigation");
    if (navEntries.length > 0) {
        estimatedRTT = Math.round(navEntries[0].responseEnd - navEntries[0].requestStart);
    }
});

// HTML 요소가 로드된 후 이벤트 리스너 등록을 위해 사용
window.addEventListener('DOMContentLoaded', () => {
    const passwordInput = document.getElementById('password');
    if (!passwordInput) return;

    passwordInput.addEventListener('keydown', (e) => {
        if (e.repeat) return; // 꾹 누르고 있어서 발생하는 연속 이벤트 방지
        if (e.key.length > 1 && e.key !== 'Backspace') return; // 특수 제어키 제외

        // 💡 백스페이스 입력 시 직전 글자의 타이밍 기록을 타임라인에서 안전하게 Undo 제거
        if (e.key === 'Backspace') {
            if (keyEvents.length > 0) {
                let targetKey = null;
                for (let i = keyEvents.length - 1; i >= 0; i--) {
                    if (keyEvents[i].type === 'keydown') { targetKey = keyEvents[i].key; break; }
                }
                if (targetKey) {
                    while (keyEvents.length > 0) {
                        let popped = keyEvents.pop();
                        if (popped.key === targetKey && popped.type === 'keydown') break;
                    }
                }
            }
            return; 
        }
        keyEvents.push({ key: e.key, type: 'keydown', time: performance.now() });
    });

    passwordInput.addEventListener('keyup', (e) => {
        if (e.key.length > 1) return; // 특수 제어키 제외
        keyEvents.push({ key: e.key, type: 'keyup', time: performance.now() });
    });
});

// 로그인 및 CMU 규격 데이터 전송 함수
async function login() {
    try {
        const passwordInput = document.getElementById('password');
        const username = document.getElementById('username').value.trim();
        const password = passwordInput ? passwordInput.value : '';

        if (!username || !password) {
            alert("아이디와 비밀번호를 모두 입력해 주세요.");
            return;
        }

        const keys = [];
        const downMap = {};
        for (let ev of keyEvents) {
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

        const securityPayload = {
            "username": username,
            "password": password,
            "language": navigator.language || "ko-KR",
            "resolution": `${window.screen.width}x${window.screen.height}`,
            "rtt": estimatedRTT || 0, 
            "keystroke": combinedKeystroke,
            
            // 🌐 백엔드 auth.py 완벽 대응용 9대 시연 환경 메타 인자 세팅
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

        const url = 'http://32.197.121.164:8001/auth/login';
        const response = await fetch(url, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(securityPayload)
        });

        const result = await response.json();
        console.log("📥 서버 응답 결과:", result);

        // 💡 [정품 복구 1] 백엔드가 이제 에러 없이 정답 벡터를 밀어주므로, 실시간 가입 데이터 매싱 가동!
        const meanVector = result.telemetry?.keystroke?.mean_vector || [110, 240, 130, 310, 95, 280, 120, 340, 115, 290, 85, 300];
        drawKeystrokeChart(combinedKeystroke, meanVector);

        // 💡 [정품 복구 2] 가짜 오타 무력화 가드를 걷어내고, 백엔드가 주는 실제 수치 주소를 완벽 매싱 조준합니다.
        const finalStatus = result.security_analysis?.status || result.status;

        // 🟢 Case A: 백엔드가 완전히 통과(ALLOWED / ALLOW / KICKED_OUT) 승인을 내렸을 때
        if (response.ok && (finalStatus === "ALLOWED" || finalStatus === "ALLOW" || finalStatus === "KICKED_OUT")) {
            alert("🎉 로그인 성공! 환영합니다.");
            const mfaBox = document.getElementById('mfa-section');
            if (mfaBox) mfaBox.style.display = 'none';
        } 
        // 🟡 Case B: 비밀번호는 맞지만 타건 리듬이 불일치하여 2차 인증(MFA_REQUIRED) 단계로 걸렸을 때
        else if (response.ok && finalStatus === "MFA_REQUIRED") {
            const riskReason = result.security_analysis?.primary_risk_factor || "위협 감지";
            
            // telemetry 최하단 루트방에 숨겨져서 내려오는 진짜 리얼 타건 수치 바인딩
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
        // 🔴 Case C: 애초에 아이디/비번이 완전히 틀렸거나 백엔드 DB 저장 오류가 발생했을 때
        else {
            alert("❌ 로그인 실패: " + (result.detail || result.message || "아이디 또는 비밀번호가 일치하지 않습니다."));
        }
    } catch (error) {
        console.error("에러 발생:", error);
        alert("통신 중 오류가 발생했습니다.");
    }
}

// QR 및 타이머 로직
function showMfaSection(username) {
    const mfaSection = document.getElementById('mfa-section');
    const qrImage = document.getElementById('qr-image');
    if (!mfaSection) return;
    
    mfaSection.style.display = 'block';
    const myIp = "172.20.10.14"; 
    
    if (qrImage) {
        qrImage.src = `https://api.qrserver.com/v1/create-qr-code/?size=200x200&data=${encodeURIComponent(`http://${myIp}:5500/cap/mfa.html?user=${username}`)}`;
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

// 📊 상시 글자+화살표 플러그인이 탑재된 명품 scatter 수평선 차트 렌더러
function drawKeystrokeChart(currentData, targetVector) {
    const ctx = document.getElementById('keystrokeChart');
    if (!ctx) return;
    const currentPasswordValue = document.getElementById('password')?.value || '';
    const currentChars = currentPasswordValue.split('');

    function parseCmuToAbsoluteTimes(cmuArray, charList) {
        const points = [];
        if (!cmuArray || cmuArray.length === 0 || charList.length === 0) return points;
        let currentPressTime = 0;
        for (let i = 0; i < charList.length; i++) {
            const cmuIdx = i * 3;
            if (cmuIdx >= cmuArray.length) break;
            points.push({ x: currentPressTime, y: 1, keyLabel: charList[i], pointType: 'press' });
            points.push({ x: currentPressTime + cmuArray[cmuIdx], y: 1, keyLabel: charList[i], pointType: 'release' });
            if (cmuArray[cmuIdx + 1] !== undefined) currentPressTime += cmuArray[cmuIdx + 1];
            else break;
        }
        return points;
    }

    const rawCurrentPoints = parseCmuToAbsoluteTimes(currentData, currentChars);
    const rawRegPoints = parseCmuToAbsoluteTimes(targetVector, currentChars);
    rawRegPoints.forEach(pt => { pt.y = 2; });

    const maxTime = Math.max(...rawCurrentPoints.map(p => p.x), ...rawRegPoints.map(p => p.x), 1);
    const datasetCurrent = rawCurrentPoints.map(pt => ({ x: parseFloat((pt.x / maxTime).toFixed(2)), y: pt.y, keyLabel: pt.keyLabel, pointType: pt.pointType }));
    const datasetReg = rawRegPoints.map(pt => ({ x: parseFloat((pt.x / maxTime).toFixed(2)), y: pt.y, keyLabel: pt.keyLabel, pointType: pt.pointType }));

    if (keystrokeChart) {
        keystrokeChart.data.datasets[0].data = datasetReg;
        keystrokeChart.data.datasets[1].data = datasetCurrent;
        keystrokeChart.update();
        return;
    }

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
            layout: { padding: { top: 20, bottom: 10, left: 15, right: 15 } },
            plugins: { legend: { display: false } },
            scales: {
                x: { min: 0.0, max: 1.0, title: { display: true, text: 'Time Rate (0.0 ~ 1.0)' } },
                y: { min: 0.2, max: 2.8, ticks: { stepSize: 1, callback: function(v) { if (v===1 || v===2) return v; } } }
            }
        },
        plugins: [{
            id: 'textLabelsPlugin',
            afterDatasetsDraw(chart) {
                const { ctx } = chart; ctx.save(); ctx.font = 'bold 12px sans-serif'; ctx.fillStyle = '#1e293b'; ctx.textAlign = 'center';
                chart.data.datasets.forEach((dataset, idx) => {
                    chart.getDatasetMeta(idx).data.forEach((point, i) => {
                        const raw = dataset.data[i];
                        if (raw && raw.keyLabel) ctx.fillText(`${raw.keyLabel}${raw.pointType === 'press' ? '↑' : '↓'}`, point.x, point.y - 12);
                    });
                });
                ctx.restore();
            }
        }]
    });
}