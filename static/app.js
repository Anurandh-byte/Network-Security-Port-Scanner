/**
 * CYBERPORT SCANNER PRO - CLIENT APPLICATION LOGIC
 * Real-time WebSocket telemetry, dynamic port matrix, radar simulation, and reporting.
 */

(function () {
    'use strict';

    // Application State
    const state = {
        ws: null,
        isScanning: false,
        activePreset: 'top20',
        target: '127.0.0.1',
        portsToScan: [],
        scannedCount: 0,
        totalPorts: 20,
        results: [],
        openPorts: [],
        matrixCells: new Map(), // port -> element
        scanStartTime: 0,
        scanTimerInterval: null,
        targetInfo: null,
        history: [],
        activeFilter: 'all',
        searchQuery: ''
    };

    // DOM Elements
    const elements = {
        connectionStatus: document.getElementById('connectionStatus'),
        targetInput: document.getElementById('targetInput'),
        btnResolve: document.getElementById('btnResolve'),
        btnStartScan: document.getElementById('btnStartScan'),
        btnStopScan: document.getElementById('btnStopScan'),
        presetButtons: document.querySelectorAll('.preset-btn'),
        chips: document.querySelectorAll('.chip'),
        customPortsGroup: document.getElementById('customPortsGroup'),
        customPortsInput: document.getElementById('customPortsInput'),
        portsQueuedBadge: document.getElementById('portsQueuedBadge'),
        
        // Advanced
        toggleAdvanced: document.getElementById('toggleAdvanced'),
        advancedBody: document.getElementById('advancedBody'),
        threadsSlider: document.getElementById('threadsSlider'),
        threadsVal: document.getElementById('threadsVal'),
        timeoutSlider: document.getElementById('timeoutSlider'),
        timeoutVal: document.getElementById('timeoutVal'),

        // Intel Card
        intelTarget: document.getElementById('intelTarget'),
        intelIp: document.getElementById('intelIp'),
        intelHost: document.getElementById('intelHost'),
        intelLatency: document.getElementById('intelLatency'),

        // Telemetry & Radar
        radarSweep: document.querySelector('.radar-sweep'),
        radarStatus: document.getElementById('radarStatus'),
        radarBlipsContainer: document.getElementById('radarBlipsContainer'),

        // Stats
        statScanned: document.getElementById('statScanned'),
        statTotal: document.getElementById('statTotal'),
        statProgressFill: document.getElementById('statProgressFill'),
        statOpen: document.getElementById('statOpen'),
        openRateBadge: document.getElementById('openRateBadge'),
        statSpeed: document.getElementById('statSpeed'),
        statElapsed: document.getElementById('statElapsed'),
        statRisk: document.getElementById('statRisk'),
        statRiskBreakdown: document.getElementById('statRiskBreakdown'),

        // Matrix & Table
        matrixGrid: document.getElementById('matrixGrid'),
        btnToggleMatrixView: document.getElementById('btnToggleMatrixView'),
        resultsTableBody: document.getElementById('resultsTableBody'),
        resultsCountBadge: document.getElementById('resultsCountBadge'),
        tableSearch: document.getElementById('tableSearch'),
        filterPills: document.querySelectorAll('.filter-pill'),
        countFilterAll: document.getElementById('countFilterAll'),
        countFilterOpen: document.getElementById('countFilterOpen'),
        countFilterRisk: document.getElementById('countFilterRisk'),

        // Modals & Drawers
        portModal: document.getElementById('portModal'),
        modalBody: document.getElementById('modalBody'),
        btnCloseModal: document.getElementById('btnCloseModal'),
        historyDrawer: document.getElementById('historyDrawer'),
        btnHistory: document.getElementById('btnHistory'),
        btnCloseHistory: document.getElementById('btnCloseHistory'),
        historyList: document.getElementById('historyList'),
        exportModal: document.getElementById('exportModal'),
        btnExport: document.getElementById('btnExport'),
        btnCloseExport: document.getElementById('btnCloseExport'),
        btnExportJSON: document.getElementById('btnExportJSON'),
        btnExportCSV: document.getElementById('btnExportCSV'),
        btnPrintReport: document.getElementById('btnPrintReport'),
        toastContainer: document.getElementById('toastContainer')
    };

    // Preset Port Counts / Data Map
    const PRESET_MAP = {
        top20: [21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 1433, 1521, 3306, 3389, 5432, 8080, 8443, 27017],
        standard: Array.from({ length: 1024 }, (_, i) => i + 1),
        web: [80, 81, 443, 2082, 2083, 3000, 4200, 5000, 5173, 8000, 8008, 8080, 8081, 8443, 8888, 9000, 9090, 9443],
        databases: [1433, 1521, 2181, 3306, 5432, 5672, 6379, 9042, 9092, 9200, 9300, 11211, 27017, 27018],
        remote_admin: [22, 23, 135, 139, 445, 623, 1080, 1194, 1723, 2222, 3389, 5900, 5901, 5985, 5986]
    };

    // Security Advisory database for common ports
    const SECURITY_ADVISORIES = {
        21: { risk: 'Medium', advice: 'FTP transmits credentials in plaintext. Replace with SFTP (SSH) or FTPS.' },
        23: { risk: 'High', advice: 'Telnet is unencrypted and vulnerable to packet sniffing and MITM attacks. Disable Telnet and enforce SSH.' },
        80: { risk: 'Low', advice: 'Cleartext HTTP. Enforce HTTPS redirection and HSTS headers.' },
        135: { risk: 'Medium', advice: 'Microsoft Windows RPC endpoint mapper. Exposing this port over WAN can allow remote enumeration and exploitation.' },
        139: { risk: 'High', advice: 'NetBIOS Session service. Frequently targeted for SMB relay and legacy Windows attacks.' },
        445: { risk: 'High', advice: 'SMB direct hosting. High vulnerability risk (e.g., EternalBlue, ransomware lateral movement). Restrict via firewall.' },
        1433: { risk: 'High', advice: 'Microsoft SQL Server. Do not expose directly to the internet; use VPN or SSH tunneling.' },
        3306: { risk: 'High', advice: 'MySQL Database server. Ensure root login is restricted to localhost and strong authentication is enforced.' },
        3389: { risk: 'High', advice: 'RDP Remote Desktop. Heavy target for brute-force attacks and BlueKeep CVEs. Enable NLA, MFA, or place behind VPN.' },
        5432: { risk: 'High', advice: 'PostgreSQL Database. Disallow public access and restrict pg_hba.conf.' },
        5900: { risk: 'High', advice: 'VNC Remote Desktop. Often weakly protected. Use SSH port forwarding instead.' },
        6379: { risk: 'Critical', advice: 'Redis cache/database. If unauthenticated, allows arbitrary file write and remote code execution (RCE).' },
        27017: { risk: 'Critical', advice: 'MongoDB NoSQL database. Ensure authentication is enabled to prevent unauthenticated data leaks.' }
    };

    // Initialize Application
    function init() {
        setupEventListeners();
        connectWebSocket();
        updatePresetUI('top20');
        resolveTargetInfo('127.0.0.1');
    }

    // Connect WebSocket
    function connectWebSocket() {
        const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
        const wsUrl = `${protocol}//${window.location.host}/ws/scan`;

        try {
            state.ws = new WebSocket(wsUrl);

            state.ws.onopen = () => {
                elements.connectionStatus.classList.remove('disconnected');
                elements.connectionStatus.querySelector('.status-text').textContent = 'WS CONNECTED';
            };

            state.ws.onmessage = (event) => {
                const data = JSON.parse(event.data);
                handleWebSocketMessage(data);
            };

            state.ws.onclose = () => {
                elements.connectionStatus.classList.add('disconnected');
                elements.connectionStatus.querySelector('.status-text').textContent = 'WS DISCONNECTED';
                // Try reconnect in 3s
                setTimeout(connectWebSocket, 3000);
            };

            state.ws.onerror = () => {
                elements.connectionStatus.classList.add('disconnected');
            };
        } catch (e) {
            console.error('WebSocket connection error:', e);
        }
    }

    // WebSocket Message Router
    function handleWebSocketMessage(msg) {
        if (msg.type === 'batch_update') {
            msg.events.forEach(ev => handleScanEvent(ev));
        } else {
            handleScanEvent(msg);
        }
    }

    // Handle Individual Scan Event
    function handleScanEvent(ev) {
        if (ev.type === 'scan_start') {
            onScanStarted(ev);
        } else if (ev.type === 'port_scanned') {
            onPortScanned(ev);
        } else if (ev.type === 'scan_complete') {
            onScanCompleted(ev);
        } else if (ev.type === 'scan_stopped') {
            onScanStopped();
        } else if (ev.type === 'error') {
            showToast(ev.message || 'An error occurred during scan.', 'error');
            resetScanUI();
        }
    }

    // Setup DOM Listeners
    function setupEventListeners() {
        // Start / Stop Scan
        elements.btnStartScan.addEventListener('click', startScan);
        elements.btnStopScan.addEventListener('click', stopScan);

        // Resolve Target
        elements.btnResolve.addEventListener('click', () => {
            resolveTargetInfo(elements.targetInput.value.trim());
        });

        // Quick Chips
        elements.chips.forEach(chip => {
            chip.addEventListener('click', () => {
                const target = chip.getAttribute('data-target');
                elements.targetInput.value = target;
                resolveTargetInfo(target);
            });
        });

        // Presets
        elements.presetButtons.forEach(btn => {
            btn.addEventListener('click', () => {
                const preset = btn.getAttribute('data-preset');
                updatePresetUI(preset);
            });
        });

        // Custom ports input change
        elements.customPortsInput.addEventListener('input', () => {
            if (state.activePreset === 'custom') {
                updateCustomPortsCount();
            }
        });

        // Advanced accordion toggle
        elements.toggleAdvanced.addEventListener('click', () => {
            const isHidden = elements.advancedBody.style.display === 'none';
            elements.advancedBody.style.display = isHidden ? 'flex' : 'none';
            elements.toggleAdvanced.querySelector('.toggle-arrow').classList.toggle('open', isHidden);
        });

        // Sliders
        elements.threadsSlider.addEventListener('input', (e) => {
            elements.threadsVal.textContent = e.target.value;
        });
        elements.timeoutSlider.addEventListener('input', (e) => {
            elements.timeoutVal.textContent = `${e.target.value}s`;
        });

        // Matrix Expand Toggle
        elements.btnToggleMatrixView.addEventListener('click', () => {
            elements.matrixGrid.classList.toggle('expanded');
            const icon = elements.btnToggleMatrixView.querySelector('i');
            if (elements.matrixGrid.classList.contains('expanded')) {
                icon.className = 'fa-solid fa-compress';
            } else {
                icon.className = 'fa-solid fa-expand';
            }
        });

        // Table Search & Filter
        elements.tableSearch.addEventListener('input', (e) => {
            state.searchQuery = e.target.value.toLowerCase().trim();
            renderTableRows();
        });

        elements.filterPills.forEach(pill => {
            pill.addEventListener('click', () => {
                elements.filterPills.forEach(p => p.classList.remove('active'));
                pill.classList.add('active');
                state.activeFilter = pill.getAttribute('data-filter');
                renderTableRows();
            });
        });

        // Modals & Drawers
        elements.btnCloseModal.addEventListener('click', () => elements.portModal.classList.remove('open'));
        elements.portModal.querySelector('.modal-backdrop').addEventListener('click', () => elements.portModal.classList.remove('open'));

        elements.btnHistory.addEventListener('click', () => elements.historyDrawer.classList.add('open'));
        elements.btnCloseHistory.addEventListener('click', () => elements.historyDrawer.classList.remove('open'));

        elements.btnExport.addEventListener('click', () => elements.exportModal.classList.add('open'));
        elements.btnCloseExport.addEventListener('click', () => elements.exportModal.classList.remove('open'));
        elements.exportModal.querySelector('.modal-backdrop').addEventListener('click', () => elements.exportModal.classList.remove('open'));

        // Export Options
        elements.btnExportJSON.addEventListener('click', exportJSON);
        elements.btnExportCSV.addEventListener('click', exportCSV);
        elements.btnPrintReport.addEventListener('click', printReport);
    }

    // Update Preset Selection
    function updatePresetUI(presetKey) {
        state.activePreset = presetKey;
        elements.presetButtons.forEach(btn => {
            btn.classList.toggle('active', btn.getAttribute('data-preset') === presetKey);
        });

        if (presetKey === 'custom') {
            elements.customPortsGroup.style.display = 'flex';
            updateCustomPortsCount();
        } else {
            elements.customPortsGroup.style.display = 'none';
            const ports = PRESET_MAP[presetKey] || [];
            state.portsToScan = ports;
            state.totalPorts = ports.length;
            elements.portsQueuedBadge.textContent = `${ports.length.toLocaleString()} Ports Queued`;
            elements.statTotal.textContent = ports.length.toLocaleString();
            buildMatrixGrid(ports);
        }
    }

    function updateCustomPortsCount() {
        const raw = elements.customPortsInput.value;
        const parsed = parseCustomPorts(raw);
        state.portsToScan = parsed;
        state.totalPorts = parsed.length || 0;
        elements.portsQueuedBadge.textContent = `${parsed.length.toLocaleString()} Ports Queued`;
        elements.statTotal.textContent = parsed.length.toLocaleString();
        buildMatrixGrid(parsed.slice(0, 500)); // cap preview to 500 for perf
    }

    function parseCustomPorts(str) {
        if (!str || !str.trim()) return [];
        const ports = new Set();
        const parts = str.replace(/\s+/g, '').split(',');
        for (const p of parts) {
            if (!p) continue;
            if (p.includes('-')) {
                const [start, end] = p.split('-').map(Number);
                if (!isNaN(start) && !isNaN(end)) {
                    const minP = Math.max(1, Math.min(start, end));
                    const maxP = Math.min(65535, Math.max(start, end));
                    for (let i = minP; i <= Math.min(maxP, minP + 5000); i++) {
                        ports.add(i);
                    }
                }
            } else {
                const num = Number(p);
                if (!isNaN(num) && num >= 1 && num <= 65535) {
                    ports.add(num);
                }
            }
        }
        return Array.from(ports).sort((a, b) => a - b);
    }

    // Build Port Matrix Spectrum Grid
    function buildMatrixGrid(ports) {
        elements.matrixGrid.innerHTML = '';
        state.matrixCells.clear();

        const displayPorts = ports.slice(0, 1024); // smooth visual cap
        const fragment = document.createDocumentFragment();

        displayPorts.forEach(port => {
            const cell = document.createElement('div');
            cell.className = 'matrix-cell';
            cell.title = `Port ${port}`;
            cell.dataset.port = port;

            cell.addEventListener('click', () => {
                const existing = state.results.find(r => r.port === port);
                if (existing) {
                    openPortInspector(existing);
                } else {
                    openPortInspector({ port: port, state: 'QUEUED', service: 'Unknown', risk: 'Info', description: 'Port in scan queue' });
                }
            });

            state.matrixCells.set(port, cell);
            fragment.appendChild(cell);
        });

        elements.matrixGrid.appendChild(fragment);
    }

    // Resolve Target Host Info
    async function resolveTargetInfo(target) {
        if (!target) return;
        try {
            elements.intelTarget.textContent = target;
            elements.intelIp.textContent = 'Resolving...';
            elements.intelHost.textContent = '...';
            elements.intelLatency.textContent = '...';

            const resp = await fetch('/api/target-info', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ target: target })
            });

            if (!resp.ok) throw new Error('Failed to resolve host');

            const res = await resp.json();
            state.targetInfo = res.data;
            elements.intelTarget.textContent = res.data.target;
            elements.intelIp.textContent = res.data.ip;
            elements.intelHost.textContent = res.data.hostname;
            elements.intelLatency.textContent = `${res.data.latency_ms} ms`;
        } catch (e) {
            elements.intelIp.textContent = 'Unreachable';
            elements.intelHost.textContent = 'N/A';
            elements.intelLatency.textContent = '--';
        }
    }

    // Start Scan Action
    function startScan() {
        const target = elements.targetInput.value.trim();
        if (!target) {
            showToast('Please enter a target IP or hostname.', 'warning');
            return;
        }

        if (!state.ws || state.ws.readyState !== WebSocket.OPEN) {
            showToast('Connecting to scan server...', 'warning');
            connectWebSocket();
            return;
        }

        // Prepare UI
        state.isScanning = true;
        state.results = [];
        state.openPorts = [];
        state.scannedCount = 0;
        elements.resultsTableBody.innerHTML = '';
        elements.radarBlipsContainer.innerHTML = '';
        elements.btnStartScan.disabled = true;
        elements.btnStopScan.disabled = false;
        elements.radarSweep.classList.remove('paused');
        elements.radarStatus.textContent = 'RADAR ACTIVE';
        elements.radarStatus.classList.add('text-green');

        // Reset matrix cells
        state.matrixCells.forEach(cell => {
            cell.className = 'matrix-cell';
        });

        // Send start command to WebSocket
        const payload = {
            action: 'start',
            target: target,
            preset: state.activePreset,
            custom_ports: state.activePreset === 'custom' ? elements.customPortsInput.value : null,
            threads: Number(elements.threadsSlider.value),
            timeout: Number(elements.timeoutSlider.value)
        };

        state.ws.send(JSON.stringify(payload));
        showToast(`Scan initiated against ${target}`, 'success');
    }

    // Stop Scan Action
    function stopScan() {
        if (!state.isScanning) return;
        if (state.ws && state.ws.readyState === WebSocket.OPEN) {
            state.ws.send(JSON.stringify({ action: 'stop' }));
        }
        onScanStopped();
    }

    // Scan Started Event Callback
    function onScanStarted(ev) {
        state.totalPorts = ev.total_ports;
        state.scanStartTime = Date.now();
        elements.statTotal.textContent = ev.total_ports.toLocaleString();
        elements.statScanned.textContent = '0';
        elements.statProgressFill.style.width = '0%';
        elements.statOpen.textContent = '0';
        elements.openRateBadge.textContent = '0 Active';

        if (state.scanTimerInterval) clearInterval(state.scanTimerInterval);
        state.scanTimerInterval = setInterval(updateElapsedTimer, 200);
    }

    // Port Scanned Event Callback
    function onPortScanned(ev) {
        const portData = ev.port_data;
        state.results.push(portData);
        state.scannedCount = ev.scanned_count;

        // Update Matrix visualizer
        const cell = state.matrixCells.get(portData.port);
        if (cell) {
            if (portData.state === 'OPEN') {
                cell.className = 'matrix-cell open';
            } else {
                cell.className = 'matrix-cell closed';
            }
        }

        // If OPEN, handle discovery
        if (portData.state === 'OPEN') {
            state.openPorts.push(portData);
            addRadarBlip();
            addTableRow(portData);
        }

        // Update Stats Counters
        elements.statScanned.textContent = ev.scanned_count.toLocaleString();
        elements.statProgressFill.style.width = `${ev.percent}%`;
        elements.statOpen.textContent = state.openPorts.length;
        elements.openRateBadge.textContent = `${state.openPorts.length} Active`;
        elements.statSpeed.innerHTML = `${ev.speed} <span class="stat-unit">p/s</span>`;

        updateRiskAssessment();
        updateFilterCounts();
    }

    // Scan Completed Event Callback
    function onScanCompleted(summary) {
        resetScanUI();
        elements.statProgressFill.style.width = '100%';
        elements.statScanned.textContent = summary.scanned_ports.toLocaleString();
        elements.statOpen.textContent = summary.open_count;
        elements.statElapsed.textContent = `${summary.duration_seconds}s elapsed`;
        elements.statSpeed.innerHTML = `${summary.speed_ports_sec} <span class="stat-unit">p/s</span>`;

        // Save to History
        saveScanToHistory(summary);

        showToast(`Scan finished! Found ${summary.open_count} open port(s) in ${summary.duration_seconds}s.`, 'success');
    }

    function onScanStopped() {
        resetScanUI();
        showToast('Scan stopped by user.', 'warning');
    }

    function resetScanUI() {
        state.isScanning = false;
        elements.btnStartScan.disabled = false;
        elements.btnStopScan.disabled = true;
        elements.radarSweep.classList.add('paused');
        elements.radarStatus.textContent = 'RADAR STANDBY';
        elements.radarStatus.classList.remove('text-green');
        if (state.scanTimerInterval) {
            clearInterval(state.scanTimerInterval);
            state.scanTimerInterval = null;
        }
    }

    function updateElapsedTimer() {
        if (!state.scanStartTime) return;
        const elapsed = ((Date.now() - state.scanStartTime) / 1000).toFixed(1);
        elements.statElapsed.textContent = `${elapsed}s elapsed`;
    }

    // Radar Blip Animation
    function addRadarBlip() {
        const blip = document.createElement('div');
        blip.className = 'radar-blip';

        // Generate random polar position within radar circle
        const angle = Math.random() * Math.PI * 2;
        const radius = Math.random() * 55 + 10; // max 65px radius
        const x = 70 + radius * Math.cos(angle);
        const y = 70 + radius * Math.sin(angle);

        blip.style.left = `${x}px`;
        blip.style.top = `${y}px`;

        elements.radarBlipsContainer.appendChild(blip);

        // Remove blip after 15s to keep DOM lightweight
        setTimeout(() => blip.remove(), 15000);
    }

    // Risk Exposure Analyzer
    function updateRiskAssessment() {
        let critical = 0, high = 0, medium = 0, low = 0;
        state.openPorts.forEach(p => {
            if (p.risk === 'Critical') critical++;
            else if (p.risk === 'High') high++;
            else if (p.risk === 'Medium') medium++;
            else if (p.risk === 'Low') low++;
        });

        if (critical > 0) {
            elements.statRisk.textContent = 'CRITICAL';
            elements.statRisk.className = 'stat-value text-red';
        } else if (high > 0) {
            elements.statRisk.textContent = 'HIGH RISK';
            elements.statRisk.className = 'stat-value text-red';
        } else if (medium > 0) {
            elements.statRisk.textContent = 'MODERATE';
            elements.statRisk.className = 'stat-value text-yellow';
        } else if (state.openPorts.length > 0) {
            elements.statRisk.textContent = 'LOW RISK';
            elements.statRisk.className = 'stat-value text-green';
        } else {
            elements.statRisk.textContent = 'CLEAR';
            elements.statRisk.className = 'stat-value text-cyan';
        }

        elements.statRiskBreakdown.textContent = `${critical + high} High | ${medium} Med | ${low} Low`;
    }

    // Table Rendering
    function addTableRow(portData) {
        // Clear empty state if first item
        const emptyRow = elements.resultsTableBody.querySelector('.empty-row');
        if (emptyRow) emptyRow.remove();

        const tr = document.createElement('tr');
        tr.dataset.port = portData.port;
        tr.dataset.risk = portData.risk;
        tr.dataset.state = portData.state;

        const riskClass = (portData.risk || 'info').toLowerCase();

        tr.innerHTML = `
            <td><span class="port-num">${portData.port}</span></td>
            <td><span class="port-state ${portData.state.toLowerCase()}"><i class="fa-solid fa-circle-check"></i> ${portData.state}</span></td>
            <td><strong class="service-name">${escapeHtml(portData.service)}</strong><span class="service-proto">${portData.protocol}</span></td>
            <td><span class="risk-badge ${riskClass}">${portData.risk}</span></td>
            <td><span class="resp-time">${portData.response_time_ms} ms</span></td>
            <td><span class="banner-text" title="${escapeHtml(portData.banner || portData.description || 'No banner')}">${escapeHtml(portData.banner || portData.description || 'N/A')}</span></td>
            <td class="text-right">
                <button class="btn-inspect" data-port="${portData.port}">
                    <i class="fa-solid fa-shield-halved"></i> Inspect
                </button>
            </td>
        `;

        tr.querySelector('.btn-inspect').addEventListener('click', () => {
            openPortInspector(portData);
        });

        elements.resultsTableBody.prepend(tr);
        elements.resultsCountBadge.textContent = `${state.openPorts.length} Open Found`;
    }

    function renderTableRows() {
        const rows = elements.resultsTableBody.querySelectorAll('tr:not(.empty-row)');
        let visibleCount = 0;

        rows.forEach(tr => {
            const port = tr.dataset.port;
            const risk = tr.dataset.risk;
            const service = tr.querySelector('.service-name')?.textContent || '';
            const banner = tr.querySelector('.banner-text')?.textContent || '';
            const searchTarget = `${port} ${service} ${risk} ${banner}`.toLowerCase();

            let matchesFilter = true;
            if (state.activeFilter === 'open' && tr.dataset.state !== 'OPEN') matchesFilter = false;
            if (state.activeFilter === 'risk' && !['Critical', 'High', 'Medium'].includes(risk)) matchesFilter = false;

            let matchesSearch = true;
            if (state.searchQuery && !searchTarget.includes(state.searchQuery)) matchesSearch = false;

            if (matchesFilter && matchesSearch) {
                tr.style.display = '';
                visibleCount++;
            } else {
                tr.style.display = 'none';
            }
        });
    }

    function updateFilterCounts() {
        elements.countFilterAll.textContent = state.results.length;
        elements.countFilterOpen.textContent = state.openPorts.length;
        const risky = state.openPorts.filter(p => ['Critical', 'High', 'Medium'].includes(p.risk)).length;
        elements.countFilterRisk.textContent = risky;
    }

    // Port Inspector Modal
    function openPortInspector(portData) {
        const adv = SECURITY_ADVISORIES[portData.port] || {
            risk: portData.risk || 'Info',
            advice: 'Standard service. Ensure strict firewall access controls and maintain software patch updates.'
        };

        const targetIp = state.targetInfo ? state.targetInfo.ip : '127.0.0.1';
        const isWeb = [80, 443, 8000, 8080, 8443, 3000, 5000].includes(portData.port);
        const webUrl = portData.port === 443 || portData.port === 8443 ? `https://${targetIp}:${portData.port}` : `http://${targetIp}:${portData.port}`;

        elements.modalBody.innerHTML = `
            <div class="modal-intel-header">
                <div class="modal-port-badge">PORT ${portData.port}</div>
                <div class="modal-port-title">
                    <h3>${escapeHtml(portData.service)} (${portData.protocol || 'TCP'})</h3>
                    <p class="text-muted">${escapeHtml(portData.description || '')}</p>
                </div>
                <span class="risk-badge ${(portData.risk || 'low').toLowerCase()}">${portData.risk || 'Low'} Risk</span>
            </div>

            <div class="modal-section">
                <h4><i class="fa-solid fa-code text-cyan"></i> Service Fingerprint / Banner</h4>
                <pre class="banner-box">${escapeHtml(portData.banner || 'No banner response received on connection probe.')}</pre>
            </div>

            <div class="modal-section advisory-box">
                <h4><i class="fa-solid fa-triangle-exclamation text-yellow"></i> Security Analysis & Recommendations</h4>
                <p>${escapeHtml(adv.advice)}</p>
            </div>

            <div class="modal-actions-bar">
                ${isWeb ? `<a href="${webUrl}" target="_blank" class="btn-primary"><i class="fa-solid fa-arrow-up-right-from-square"></i> Open in Browser</a>` : ''}
                <button class="btn-ghost" id="btnCopyPortInfo"><i class="fa-solid fa-copy"></i> Copy Target:Port</button>
            </div>
        `;

        document.getElementById('btnCopyPortInfo')?.addEventListener('click', () => {
            navigator.clipboard.writeText(`${targetIp}:${portData.port}`);
            showToast(`Copied ${targetIp}:${portData.port} to clipboard!`, 'success');
        });

        elements.portModal.classList.add('open');
    }

    // Save Scan to Session History
    function saveScanToHistory(summary) {
        state.history.unshift(summary);
        if (state.history.length > 20) state.history.pop();

        elements.historyList.innerHTML = '';
        state.history.forEach((h, idx) => {
            const card = document.createElement('div');
            card.className = 'history-card';
            card.innerHTML = `
                <div class="history-meta">
                    <span>${new Date(h.timestamp).toLocaleTimeString()}</span>
                    <span class="text-green">${h.open_count} Open</span>
                </div>
                <div class="history-target">${escapeHtml(h.target_info.target)} (${h.target_info.ip})</div>
                <div class="history-stats">Scanned ${h.scanned_ports} ports in ${h.duration_seconds}s (${h.speed_ports_sec} p/s)</div>
            `;

            card.addEventListener('click', () => {
                elements.targetInput.value = h.target_info.target;
                elements.historyDrawer.classList.remove('open');
                showToast(`Loaded target ${h.target_info.target}`, 'success');
            });

            elements.historyList.appendChild(card);
        });
    }

    // Export Handlers
    function exportJSON() {
        if (!state.results.length) {
            showToast('No scan data to export.', 'warning');
            return;
        }
        const dataStr = 'data:text/json;charset=utf-8,' + encodeURIComponent(JSON.stringify({
            target: state.targetInfo || elements.targetInput.value,
            scan_time: new Date().toISOString(),
            total_scanned: state.results.length,
            open_count: state.openPorts.length,
            open_ports: state.openPorts,
            all_results: state.results
        }, null, 2));

        downloadFile(dataStr, `scan_${elements.targetInput.value}_${Date.now()}.json`);
        elements.exportModal.classList.remove('open');
    }

    function exportCSV() {
        if (!state.results.length) {
            showToast('No scan data to export.', 'warning');
            return;
        }
        let csv = 'Port,Protocol,State,Service,Risk,Response_Time_ms,Banner\n';
        state.results.forEach(r => {
            const cleanBanner = (r.banner || r.description || '').replace(/"/g, '""');
            csv += `"${r.port}","${r.protocol}","${r.state}","${r.service}","${r.risk}","${r.response_time_ms}","${cleanBanner}"\n`;
        });

        const dataStr = 'data:text/csv;charset=utf-8,' + encodeURIComponent(csv);
        downloadFile(dataStr, `scan_${elements.targetInput.value}_${Date.now()}.csv`);
        elements.exportModal.classList.remove('open');
    }

    function printReport() {
        elements.exportModal.classList.remove('open');
        window.print();
    }

    function downloadFile(dataUri, filename) {
        const link = document.createElement('a');
        link.setAttribute('href', dataUri);
        link.setAttribute('download', filename);
        document.body.appendChild(link);
        link.click();
        link.remove();
        showToast(`Exported ${filename}`, 'success');
    }

    // Toast System
    function showToast(message, type = 'info') {
        const toast = document.createElement('div');
        toast.className = `toast ${type}`;
        const icon = type === 'success' ? 'fa-circle-check' : (type === 'error' ? 'fa-triangle-exclamation' : 'fa-info-circle');
        toast.innerHTML = `<i class="fa-solid ${icon}"></i> <span>${escapeHtml(message)}</span>`;

        elements.toastContainer.appendChild(toast);

        setTimeout(() => {
            toast.style.opacity = '0';
            toast.style.transform = 'translateX(100%)';
            setTimeout(() => toast.remove(), 300);
        }, 4000);
    }

    function escapeHtml(str) {
        if (!str) return '';
        return String(str)
            .replace(/&/g, '&amp;')
            .replace(/</g, '&lt;')
            .replace(/>/g, '&gt;')
            .replace(/"/g, '&quot;')
            .replace(/'/g, '&#039;');
    }

    // Run on Load
    document.addEventListener('DOMContentLoaded', init);
})();
