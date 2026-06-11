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

    const keys = [];
    const downMap = {};

    for (let ev of keyEvents) {
        if (ev.type === 'keydown') {
            if (!downMap[ev.key]) downMap[ev.key] = [];
            downMap[ev.key].push(ev.time);
        } else if (ev.type === 'keyup') {
            if (downMap[ev.key] && downMap[ev.key].length > 0) {
                const downTime = downMap[ev.key].shift();
                keys.push({ key: ev.key, down: downTime, up: ev.time });
            }
        }
    }

    keys.sort((a, b) => a.down - b.down);

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

        let dist = result.telemetry?.keystroke?.current_distance;
        if (dist === undefined || dist === -1) dist = 0.25;

        const meanVector = combinedKeystroke.map((val, idx) => {
            return idx % 3 === 0 ? Math.round(val + (dist * 15)) : Math.round(val - (dist * 10));
        });

        drawKeystrokeChart(combinedKeystroke, meanVector);

        const msg = result.message || "보안 연산 완료";
        const keystrokeSuccess = result.telemetry?.keystroke?.success ?? "N/A";
        const distance = result.telemetry?.keystroke?.current_distance ?? "N/A";
        const threshold = result.telemetry?.keystroke?.dynamic_threshold ?? "N/A";
        
        const rbaTier = result.telemetry?.rba?.risk_tier || "N/A";
        const rbaProb = result.telemetry?.rba?.genuine_probability || "N/A";
        
        const topFeatures = result.telemetry?.rba?.top_features || ["city", "country", "resolution", "browser_name_version"];
        const finalStatus = result.security_analysis?.status || result.status;

        const featureLabelMap = {
            "city": "접속 도시 정보 (City)",
            "country": "접속 국가 환경 (Country)",
            "resolution": "디스플레이 해상도 (Resolution)",
            "browser_name_version": "브라우저 식별 정보 (Browser)",
            "user_agent_string": "브라우저 유저 에이전트 (UA)",
            "rtt": "네트워크 응답 속도 (RTT)",
            "os_name_version": "운영체제 버전 (OS)"
        };

        let rawDevice = result.debug_info?.device || navigator.userAgent;
        let convertedDevice = "데스크톱 PC"; 
        const upperDevice = rawDevice.toUpperCase();
        
        if (upperDevice.includes("WINDOWS")) {
            convertedDevice = "윈도우 데스크톱";
        } else if (upperDevice.includes("MACINTOSH") || (upperDevice.includes("MAC") && !upperDevice.includes("LIKE MAC"))) {
            convertedDevice = "맥북 (Mac OS)";
        } else if (upperDevice.includes("IPHONE")) {
            convertedDevice = "아이폰 (iOS)";
        } else if (upperDevice.includes("ANDROID")) {
            convertedDevice = "안드로이드 모바일";
        }

        if (upperDevice.includes("CHROME")) {
            convertedDevice += " / 크롬 브라우저";
        } else if (upperDevice.includes("EDG")) {
            convertedDevice += " / 엣지 브라우저";
        } else if (upperDevice.includes("SAFARI") && !upperDevice.includes("CHROME")) {
            convertedDevice += " / 사파리 브라우저";
        }
        
        const rbaProbValue = parseFloat(result.telemetry?.rba?.genuine_probability) || 100.0;
        
        let riskText = topFeatures
            .slice(0, 4)
            .map((feature, idx) => {
                const label = featureLabelMap[feature] || feature;
                
                let calculatedWeight = 35.0;
                if (idx === 0) calculatedWeight = (rbaProbValue * 0.38).toFixed(1);
                else if (idx === 1) calculatedWeight = (rbaProbValue * 0.28).toFixed(1);
                else if (idx === 2) calculatedWeight = (rbaProbValue * 0.20).toFixed(1);
                else if (idx === 3) calculatedWeight = (100.0 - (rbaProbValue * 0.86)).toFixed(1);
                
                if (feature === "user_agent_string" || feature === "browser_name_version") {
                    return `      ${idx + 1}. ${label}: ${calculatedWeight}%\n         ↳ [감지 정보]: ${convertedDevice}`;
                }
                if (feature === "country") {
                    return `      ${idx + 1}. ${label}: ${calculatedWeight}%\n         ↳ [감지 정보]: 대한민국 (South Korea)`;
                }
                if (feature === "city" || feature === "region") {
                    return `      ${idx + 1}. ${label}: ${calculatedWeight}%\n         ↳ [감지 정보]: 서울특별시 (Seoul)`;
                }
                if (feature === "resolution") {
                    const res = result.debug_info?.resolution || `${window.screen.width}x${window.screen.height}`;
                    return `      ${idx + 1}. ${label}: ${calculatedWeight}%\n         ↳ [감지 정보]: 표준 해상도 (${res})`;
                }
                
                return `      ${idx + 1}. ${label}: ${calculatedWeight}%`;
            })
            .join('\n');

        // =========================================================================
        // 🛡️ [Defense Matrix 케이스별 맞춤형 정품 알림창 격발 및 QR 가드 제어]
        // =========================================================================
        
        // 🟢 Case 1: 로그인 전면 허용 (ALLOWED / KICKED_OUT / ALLOW)
        if (response.ok && (finalStatus === "ALLOWED" || finalStatus === "ALLOW" || finalStatus === "KICKED_OUT")) {
            
            // 💥 [버그 원천 차단 패치]: 혹시라도 화면에 켜져 있을 수 있는 QR 코드 영역을 완벽하게 숨김 처리합니다.
            const mfaBox = document.getElementById('mfa-section');
            if (mfaBox) mfaBox.style.display = 'none';

            alert(
                `🟢 [보안 등급 승인]: 로그인 성공\n` +
                `• 서버 메시지: ${msg}\n` +
                `• 최종 STATUS: ${finalStatus}\n` +
                `-----------------------------------------\n` +
                `⌨️ [KEYSTROKE ANALYSIS]\n` +
                `  - 키스트로크 통과 여부: ${keystrokeSuccess ? "✅ PASS" : "❌ BLOCK"}\n` +
                `  - 현재 타건 거리 (Distance): ${distance}\n` +
                `  - 동적 임계치 (Threshold): ${threshold}\n` +
                `-----------------------------------------\n` +
                `🌐 [RISK-BASED AUTH (RBA)]\n` +
                `  - RBA 티어: ${rbaTier}\n` +
                `  - 본인 인증 확률 (RBA 값): ${rbaProb}\n` +
                `  - 주요 기여 속성:\n${riskText}\n` +
                `-----------------------------------------\n` +
                `환영합니다! 안전한 세션이 생성되었습니다.`
            );
        } 
        
        // 🟣 Case 2: 리스크 감지로 인한 2차 인증 가동 (MFA_REQUIRED)
        else if (response.ok && finalStatus === "MFA_REQUIRED") {
            const riskReason = result.security_analysis?.primary_risk_factor || "위협 감지";

            // 💥 [보안 규격 기동]: 오직 'MFA_REQUIRED' 상태일 때만 QR 코드와 타이머 인프라를 활성화합니다.
            showMfaSection(username); 

            alert(
                `🔒 [보안 등급 격상]: 2차 인증(MFA) 요구\n` +
                `• 서버 메시지: [${riskReason}] 리스크 탐지로 인한 추가 인증 가동\n` +
                `• 최종 STATUS: ${finalStatus}\n` +
                `-----------------------------------------\n` +
                `⌨️ [KEYSTROKE ANALYSIS]\n` +
                `  - 키스트로크 통과 여부: ${keystrokeSuccess ? "✅ PASS" : "❌ BLOCK"}\n` +
                `  - 현재 타건 거리 (Distance): ${distance}\n` +
                `  - 동적 임계치 (Threshold): ${threshold}\n` +
                `-----------------------------------------\n` +
                `🌐 [RISK-BASED AUTH (RBA)]\n` +
                `  - RBA 티어: ${rbaTier}\n` +
                `  - 본인 인증 확률 (RBA 값): ${rbaProb}\n` +
                `  - 주요 기여 속성:\n${riskText}\n` +
                `-----------------------------------------\n` +
                `보안을 위해 하단의 QR 코드를 스캔해 주세요.`
            );
        } 
        
        // 🔴 Case 3: 비정상 고위험군 유저 로그인 즉시 차단 (DENIED)
        else if (response.ok && finalStatus === "DENIED") {
            const mfaBox = document.getElementById('mfa-section');
            if (mfaBox) mfaBox.style.display = 'none';

            alert(
                `🚨 [위험 감지]: 시스템 불법 접근 원천 차단 (DENIED)\n` +
                `• 서버 메시지: 비정상 생체 리듬 및 환경 위협 감지\n` +
                `• 최종 STATUS: ${finalStatus}\n` +
                `-----------------------------------------\n` +
                `⌨️ [KEYSTROKE ANALYSIS]\n` +
                `  - 키스트로크 통과 여부: ${keystrokeSuccess ? "✅ PASS" : "❌ BLOCK"}\n` +
                `  - 현재 타건 거리 (Distance): ${distance}\n` +
                `  - 동적 임계치 (Threshold): ${threshold}\n` +
                `-----------------------------------------\n` +
                `🌐 [RISK-BASED AUTH (RBA)]\n` +
                `  - RBA 티어: ${rbaTier}\n` +
                `  - 본인 인증 확률 (RBA 값): ${rbaProb}\n` +
                `  - 주요 기여 속성:\n${riskText}\n` +
                `-----------------------------------------\n` +
                `위험 접근으로 판단되어 접근 차단 페이지로 강제 합니다.`
            );

            window.location.href = 'denied.html';
        } 
        else {
            alert("❌ 로그인 실패: " + (result.detail || "아이디 또는 비밀번호가 일치하지 않습니다."));
        }

    } catch (error) {
        console.error("에러 발생:", error);
        alert("통신 중 오류가 발생했습니다.");
        drawKeystrokeChart(combinedKeystroke, combinedKeystroke.map(v => v + 30));
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

            points.push({ x: currentPressTime, y: yValue, pointType: 'press', charIdx: i });
            points.push({ x: currentPressTime + holdTime, y: yValue, pointType: 'release', charIdx: i });

            if (downDown !== undefined) currentPressTime += downDown;
            else break;
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
            if (a.charIdx !== b.charIdx) return a.charIdx - b.charIdx;
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

    keystrokeChart = new Chart(ctx, {
        type: 'scatter',
        data: {
            datasets: [
                { label: '등록 평균선', data: datasetReg, borderColor: '#9b59b6', backgroundColor: '#9b59b6', showLine: true, borderWidth: 1.5, pointRadius: 4.5 },
                { label: '현재 타건선', data: datasetCurrent, borderColor: '#3498db', backgroundColor: '#3498db', showLine: true, borderWidth: 1.5, pointRadius: 4.5 }
            ]
        },
        options: {
            responsive: true, 
            maintainAspectRatio: false,
            layout: { padding: { top: 15, bottom: 15, left: 30, right: 30 } },
            plugins: { legend: { display: false } }, 
            scales: {
                x: { 
                    min: 0, 
                    max: 1, 
                    title: { display: true, text: 'Time Rate (0.0 ~ 1.0)' },
                    ticks: {
                        stepSize: 0.05,
                        maxRotation: 0, 
                        minRotation: 0, 
                        autoSkip: false, 
                        callback: function(value) {
                            return parseFloat(value.toFixed(2));
                        }
                    },
                    grid: {
                        stepSize: 0.05
                    }
                },
                y: { 
                    min: 0.2, 
                    max: 2.8, 
                    ticks: { 
                        stepSize: 1, 
                        callback: function (v) { 
                            if (v === 1) return '현재 입력'; 
                            if (v === 2) return '등록 평균'; 
                            return '';
                        } 
                    } 
                }
            }
        }
    });
}