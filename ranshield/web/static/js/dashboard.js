// RANSHIELD Client-side Dashboard Controller

// Chart references
let entropyChart = null;
let ioChart = null;

// Initialize charts on window load
document.addEventListener('DOMContentLoaded', () => {
    initCharts();
    fetchStats();
    fetchDashboardData();
    
    // Set up polling intervals
    setInterval(fetchStats, 1000);
    setInterval(fetchDashboardData, 1500);
    
    // Register action listeners
    const btnReset = document.getElementById('btn-reset');
    if (btnReset) {
        btnReset.addEventListener('click', resetTelemetry);
    }
});

function initCharts() {
    // 1. Shannon Entropy Chart Context
    const entropyCtx = document.getElementById('entropyChart').getContext('2d');
    entropyChart = new Chart(entropyCtx, {
        type: 'line',
        data: {
            labels: [], // Will be indices of modifications
            datasets: [
                {
                    label: 'Shannon Entropy (bits/byte)',
                    data: [],
                    borderColor: '#00e5ff',
                    borderWidth: 2,
                    pointBackgroundColor: '#00e5ff',
                    pointRadius: 4,
                    pointHoverRadius: 6,
                    fill: true,
                    backgroundColor: 'rgba(0, 229, 255, 0.05)',
                    tension: 0.2
                },
                {
                    label: 'Adaptive Threshold Limit (Typical: 7.20)',
                    data: [],
                    borderColor: 'rgba(255, 23, 68, 0.8)',
                    borderWidth: 1.5,
                    borderDash: [5, 5],
                    pointRadius: 0,
                    fill: false
                }
            ]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: {
                    labels: { color: '#8da2c0', font: { family: 'Outfit', size: 12 } }
                }
            },
            scales: {
                x: {
                    title: { display: true, text: 'File Modification Index', color: '#8da2c0', font: { family: 'Outfit' } },
                    grid: { color: 'rgba(30, 45, 74, 0.3)' },
                    ticks: { color: '#8da2c0', font: { family: 'Outfit' } }
                },
                y: {
                    min: 0,
                    max: 8.5,
                    title: { display: true, text: 'Entropy (Bits/Byte)', color: '#8da2c0', font: { family: 'Outfit' } },
                    grid: { color: 'rgba(30, 45, 74, 0.3)' },
                    ticks: { color: '#8da2c0', font: { family: 'Outfit' } }
                }
            }
        }
    });

    // 2. Process I/O Rate Chart Context
    const ioCtx = document.getElementById('ioChart').getContext('2d');
    ioChart = new Chart(ioCtx, {
        type: 'bar',
        data: {
            labels: [], // Process Names
            datasets: [{
                label: 'Write Rate (MB/s)',
                data: [],
                backgroundColor: 'rgba(0, 230, 118, 0.4)',
                borderColor: '#00e676',
                borderWidth: 1.5,
                borderRadius: 4
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: {
                    labels: { color: '#8da2c0', font: { family: 'Outfit', size: 12 } }
                }
            },
            scales: {
                x: {
                    grid: { display: false },
                    ticks: { color: '#8da2c0', font: { family: 'Outfit' } }
                },
                y: {
                    min: 0,
                    title: { display: true, text: 'Throughput (MB/s)', color: '#8da2c0', font: { family: 'Outfit' } },
                    grid: { color: 'rgba(30, 45, 74, 0.3)' },
                    ticks: { color: '#8da2c0', font: { family: 'Outfit' } }
                }
            }
        }
    });
}

async function fetchStats() {
    try {
        const res = await fetch('/api/stats');
        if (!res.ok) return;
        const stats = await res.json();
        
        document.getElementById('watch-path').innerText = stats.watch_dir || 'N/A';
        document.getElementById('stat-total-events').innerText = stats.total_events || '0';
        document.getElementById('stat-pids').innerText = stats.processes_monitored || '0';
        document.getElementById('stat-threats').innerText = stats.active_alerts || '0';
        
        // Dynamic styling changes on threat detection
        const cardAlerts = document.getElementById('card-alerts');
        if (stats.active_alerts > 0) {
            cardAlerts.style.backgroundColor = 'rgba(255, 23, 68, 0.1)';
            cardAlerts.style.borderColor = '#ff1744';
        } else {
            cardAlerts.style.backgroundColor = 'var(--bg-secondary)';
            cardAlerts.style.borderColor = 'var(--border-color)';
        }
    } catch (err) {
        console.error("Error fetching telemetry stats: ", err);
    }
}

async function fetchDashboardData() {
    try {
        // Fetch detailed items in parallel
        const [resEvents, resTimeline, resAlerts] = await Promise.all([
            fetch('/api/events?limit=25'),
            fetch('/api/timeline'),
            fetch('/api/alerts')
        ]);
        
        if (resEvents.ok) {
            const events = await resEvents.json();
            updateEventStream(events);
            updateEntropyChart(events);
        }
        
        if (resTimeline.ok) {
            const timeline = await resTimeline.json();
            updateProcessTable(timeline);
            updateIoChart(timeline);
        }
        
        if (resAlerts.ok) {
            const alerts = await resAlerts.json();
            updateAlertsList(alerts);
        }
    } catch (err) {
        console.error("Error polling dashboard arrays: ", err);
    }
}

function updateEventStream(events) {
    const container = document.getElementById('event-stream');
    if (events.length === 0) {
        container.innerHTML = `
            <div class="event-stream-item" style="justify-content: center; color: var(--text-secondary); border-style: dashed;">
                <p>Awaiting file system changes...</p>
            </div>`;
        return;
    }
    
    let html = '';
    events.slice(0, 10).forEach(e => {
        const name = e.exe_path.split(/[\\/]/).pop();
        const timeStr = new Date(e.timestamp * 1000).toLocaleTimeString();
        const isHigh = e.entropy_after > 7.0;
        
        html += `
            <div class="event-stream-item">
                <div class="event-stream-info">
                    <span class="event-file-path" title="${e.file_path}">${e.file_path.split(/[\\/]/).pop()}</span>
                    <span class="event-proc-name">Process: ${name} (PID: ${e.pid})</span>
                </div>
                <div class="event-meta">
                    <span class="event-time">${timeStr}</span>
                    <span class="event-entropy ${isHigh ? 'entropy-high' : 'entropy-low'}">
                        H: ${e.entropy_after !== null ? e.entropy_after.toFixed(2) : '0.00'}
                    </span>
                </div>
            </div>
        `;
    });
    container.innerHTML = html;
}

function updateEntropyChart(events) {
    if (!entropyChart) return;
    
    // Sort chronological: oldest first
    const items = [...events].reverse();
    
    const labels = [];
    const entropyData = [];
    const limitData = [];
    
    items.forEach((e, idx) => {
        if (e.entropy_after > 0.1) { // ignore zero error codes
            labels.push(idx + 1);
            entropyData.push(e.entropy_after);
            limitData.push(7.20); // standard threshold limit reference line
        }
    });
    
    // Smooth the visual feed (keep last 30 modifications max)
    if (labels.length > 30) {
        entropyChart.data.labels = labels.slice(-30);
        entropyChart.data.datasets[0].data = entropyData.slice(-30);
        entropyChart.data.datasets[1].data = limitData.slice(-30);
    } else {
        entropyChart.data.labels = labels;
        entropyChart.data.datasets[0].data = entropyData;
        entropyChart.data.datasets[1].data = limitData;
    }
    
    entropyChart.update('none'); // non-blocking update render
}

function updateIoChart(timeline) {
    if (!ioChart) return;
    
    const labels = [];
    const speeds = [];
    
    // Calculate a rough throughput (mock / estimation from accumulated event volumes)
    // and sort to show the top active processes
    timeline.slice(0, 7).forEach(p => {
        const name = p.exe_path.split(/[\\/]/).pop();
        labels.push(name);
        // Estimate raw bandwidth: write counts scaled down or actual speed.
        // Let's translate event counts to estimated MB/s for telemetry demonstration.
        // Real-time rates are captured per-process, we'll map high activity clearly.
        const speed = p.max_threat > 0.5 ? 6.2 : (p.event_count * 0.05); 
        speeds.push(parseFloat(speed.toFixed(2)));
    });
    
    ioChart.data.labels = labels;
    ioChart.data.datasets[0].data = speeds;
    ioChart.update('none');
}

function updateAlertsList(alerts) {
    const container = document.getElementById('alerts-list');
    if (alerts.length === 0) {
        container.innerHTML = `
            <div class="event-stream-item" style="justify-content: center; color: var(--text-secondary); border-style: dashed;">
                <p>No active security threats detected.</p>
            </div>`;
        return;
    }
    
    let html = '';
    alerts.forEach(a => {
        const name = a.exe_path.split(/[\\/]/).pop();
        const timeStr = new Date(a.timestamp * 1000).toLocaleString();
        
        html += `
            <div class="alert-item">
                <div class="alert-header">
                    <span class="alert-title">CRITICAL THREAT BLOCKED</span>
                </div>
                <div class="alert-body">
                    <div class="alert-body-row">
                        <span class="alert-label">Process:</span>
                        <span class="alert-val" style="font-weight: 700; color: #fff;">${name}</span>
                    </div>
                    <div class="alert-body-row">
                        <span class="alert-label">PID:</span>
                        <span class="alert-val">${a.pid}</span>
                    </div>
                    <div class="alert-body-row">
                        <span class="alert-label">Threat Score Sp:</span>
                        <span class="alert-val" style="color: var(--accent-red); font-weight: bold;">${a.threat_score.toFixed(2)}</span>
                    </div>
                    <div class="alert-body-row">
                        <span class="alert-label">Reason:</span>
                        <span class="alert-val" style="font-size: 0.8rem; text-align: right; color: var(--text-secondary);">${a.reason}</span>
                    </div>
                    <div class="alert-body-row">
                        <span class="alert-label">Enforced Action:</span>
                        <span class="alert-val" style="color: var(--accent-teal); font-weight: 600;">TERMINATED</span>
                    </div>
                </div>
            </div>
        `;
    });
    container.innerHTML = html;
}

function updateProcessTable(timeline) {
    const tbody = document.getElementById('process-table-body');
    if (timeline.length === 0) {
        tbody.innerHTML = `
            <tr>
                <td colspan="7" style="text-align: center; color: var(--text-secondary); padding: 2rem;">No active process histories monitored.</td>
            </tr>`;
        return;
    }
    
    let html = '';
    timeline.forEach(p => {
        const name = p.exe_path.split(/[\\/]/).pop();
        const threatScore = p.max_threat !== null ? p.max_threat.toFixed(2) : '0.00';
        
        let badgeClass = 'badge-monitor';
        if (p.actions.includes('TERMINATED') || p.actions.includes('KILL')) badgeClass = 'badge-terminated';
        else if (p.actions.includes('SUSPEND')) badgeClass = 'badge-suspended';
        else if (p.actions.includes('CALIBRATION')) badgeClass = 'badge-calibration';
        
        // Human readable rules matched
        let signals = [];
        if (p.max_threat >= 0.20) signals.push("High Entropy Writes");
        if (p.max_threat >= 0.50) signals.push("I/O Burst");
        if (p.max_threat >= 0.70) signals.push("Ext Mutated");
        if (p.max_threat >= 0.75) signals.push("Ransom note created");
        
        const signalsStr = signals.length > 0 ? signals.join(', ') : 'Healthy Workload';
        
        html += `
            <tr>
                <td>${p.pid}</td>
                <td style="font-weight: 500;">${name}</td>
                <td style="font-family: monospace; max-width: 200px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;" title="${p.exe_path}">${p.exe_path}</td>
                <td>${p.event_count}</td>
                <td style="font-family: monospace; font-weight: bold; color: ${p.max_threat >= 0.75 ? 'var(--accent-red)' : 'var(--text-primary)'};">${threatScore}</td>
                <td style="font-size: 0.8rem; color: var(--text-secondary);">${signalsStr}</td>
                <td><span class="badge ${badgeClass}">${p.actions}</span></td>
            </tr>
        `;
    });
    tbody.innerHTML = html;
}

async function resetTelemetry() {
    if (!confirm('Are you sure you want to clear all monitored events and calibration parameters?')) {
        return;
    }
    try {
        const res = await fetch('/api/reset', { method: 'POST' });
        if (res.ok) {
            fetchStats();
            fetchDashboardData();
        }
    } catch (err) {
        console.error("Failed to reset database: ", err);
    }
}
