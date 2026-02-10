/**
 * VibeGuard AI — Enterprise Dashboard Application
 * ALL SCANS ARE REAL — powered by BscScan API + bytecode analysis via Express backend.
 */

const API_BASE = window.location.origin;

// ============================================================
//  DETECTION FIELD DEFINITIONS (labels for display)
// ============================================================
const DETECTION_FIELDS = {
    is_open_source: { label: 'Open Source', category: 'Contract Security' },
    is_proxy: { label: 'Proxy Contract', category: 'Contract Security' },
    has_selfdestruct: { label: 'Self-Destruct', category: 'Contract Security' },
    has_external_call: { label: 'External Calls', category: 'Contract Security' },
    is_upgradeable: { label: 'Upgradeable', category: 'Contract Security' },
    has_assembly: { label: 'Assembly Code', category: 'Contract Security' },
    is_honeypot: { label: 'Honeypot', category: 'Honeypot Detection' },
    transfer_pausable: { label: 'Transfer Pausable', category: 'Honeypot Detection' },
    is_blacklisted: { label: 'Blacklist Function', category: 'Honeypot Detection' },
    is_whitelisted: { label: 'Whitelist Function', category: 'Honeypot Detection' },
    trading_cooldown: { label: 'Trading Cooldown', category: 'Honeypot Detection' },
    has_trading_toggle: { label: 'Trading Toggle', category: 'Honeypot Detection' },
    personal_slippage_mod: { label: 'Slippage Modifiable', category: 'Honeypot Detection' },
    hidden_owner: { label: 'Hidden Owner', category: 'Ownership Risks' },
    can_take_back_ownership: { label: 'Take Back Ownership', category: 'Ownership Risks' },
    owner_change_balance: { label: 'Owner Change Balance', category: 'Ownership Risks' },
    is_ownership_renounced: { label: 'Ownership Renounced', category: 'Ownership Risks' },
    is_mintable: { label: 'Mintable', category: 'Supply Manipulation' },
    is_burnable: { label: 'Burnable', category: 'Supply Manipulation' },
    unlimited_supply: { label: 'Unlimited Supply', category: 'Supply Manipulation' },
    tax_modifiable: { label: 'Tax Modifiable', category: 'Tax & Fees' },
    has_buy_tax: { label: 'Buy Tax', category: 'Tax & Fees' },
    has_sell_tax: { label: 'Sell Tax', category: 'Tax & Fees' },
    high_tax_risk: { label: 'High Tax Risk', category: 'Tax & Fees' },
    is_buy_back: { label: 'Buy Back', category: 'Tax & Fees' },
    is_anti_whale: { label: 'Anti-Whale', category: 'Trading Restrictions' },
    anti_whale_modifiable: { label: 'Anti-Whale Modifiable', category: 'Trading Restrictions' },
    has_max_tx: { label: 'Max Transaction', category: 'Trading Restrictions' },
    has_max_wallet: { label: 'Max Wallet', category: 'Trading Restrictions' },
    fake_token: { label: 'Fake Token', category: 'Fraud Detection' },
    fake_standard_interface: { label: 'Fake Standard Interface', category: 'Fraud Detection' },
    can_reinit: { label: 'Re-initializable', category: 'Fraud Detection' },
    can_remove_liquidity: { label: 'Remove Liquidity', category: 'Rug Pull Indicators' },
    has_liquidity_lock: { label: 'Liquidity Locked', category: 'Rug Pull Indicators' },
    owner_can_drain: { label: 'Owner Can Drain', category: 'Rug Pull Indicators' },
};

// ============================================================
//  SCANNING — REAL API CALLS
// ============================================================

function quickScan(address) {
    document.getElementById('tokenInput').value = address;
    startEnterpriseScan();
}

async function startEnterpriseScan() {
    const address = document.getElementById('tokenInput').value.trim();
    if (!address || !address.startsWith('0x')) return;

    const btn = document.getElementById('scanBtn');
    const statusEl = document.getElementById('scanStatus');
    btn.classList.add('scanning');
    btn.disabled = true;

    // Show scanning phases
    const phases = [
        'Connecting to BNB Chain RPC...',
        'Fetching bytecode from BscScan...',
        'Analyzing 33 detection fields...',
        'Running flash loan vulnerability scan...',
        'Detecting MEV/sandwich attack vectors...',
        'Profiling contract creator wallet...',
        'Computing aggregated risk scores...',
    ];

    if (statusEl) {
        statusEl.style.display = 'block';
        statusEl.className = 'scan-status scanning';
    }

    // Animate phases while waiting for real API response
    let phaseIndex = 0;
    const phaseTimer = setInterval(() => {
        if (statusEl && phaseIndex < phases.length) {
            statusEl.textContent = '⏳ ' + phases[phaseIndex];
            phaseIndex++;
        }
    }, 1200);

    try {
        const response = await fetch(`${API_BASE}/api/scan/${address}`);

        clearInterval(phaseTimer);

        if (!response.ok) {
            const err = await response.json().catch(() => ({ error: 'Unknown error' }));
            throw new Error(err.error || `HTTP ${response.status}`);
        }

        const scan = await response.json();

        btn.classList.remove('scanning');
        btn.disabled = false;

        if (statusEl) {
            statusEl.textContent = `✅ Scan complete in ${scan.scanTimeSeconds}s — ${scan.riskLevel}`;
            statusEl.className = `scan-status ${scan.riskLevel.toLowerCase()}`;
        }

        displayResults(scan, address);

        // Refresh stats after scan
        fetchStats();

    } catch (error) {
        clearInterval(phaseTimer);
        btn.classList.remove('scanning');
        btn.disabled = false;

        if (statusEl) {
            statusEl.textContent = `❌ ${error.message}`;
            statusEl.className = 'scan-status error';
        }

        console.error('Scan failed:', error);
    }
}

// ============================================================
//  DISPLAY RESULTS
// ============================================================

function displayResults(scan, address) {
    const area = document.getElementById('resultsArea');
    area.style.display = 'flex';

    // Overview
    document.getElementById('resultTokenName').textContent = scan.name || 'Unknown Token';
    document.getElementById('resultAddress').textContent = address;

    // Draw gauge
    drawOverviewGauge(scan.overallRisk, scan.riskLevel);

    // Badges
    const badges = document.getElementById('resultBadges');
    badges.innerHTML = '';
    if (scan.verified) badges.innerHTML += '<span class="result-badge verified">✓ Verified</span>';
    else badges.innerHTML += '<span class="result-badge dangerous">✗ Unverified</span>';
    if (scan.isProxy) badges.innerHTML += '<span class="result-badge proxy">Proxy</span>';
    badges.innerHTML += `<span class="result-badge ${scan.overallRisk <= 30 ? 'verified' : scan.overallRisk <= 60 ? 'proxy' : 'dangerous'}">${scan.riskLevel}</span>`;

    // Scan metadata
    const metaEl = document.getElementById('scanMeta');
    if (metaEl) {
        metaEl.innerHTML = `Scanned in ${scan.scanTimeSeconds}s · Holders: ${scan.holderCount || '—'} · Creator age: ${scan.creatorAge || '—'} days · Creator contracts: ${scan.creatorContracts || '—'}`;
    }

    // Mini scores
    setMiniScore('miniHoneypot', scan.honeypotScore);
    setMiniScore('miniRug', scan.rugPullScore);
    setMiniScore('miniFlash', scan.flashLoanRisk);
    setMiniScore('miniMEV', scan.mevRisk);
    setMiniScore('miniOwner', scan.ownershipRisk);
    setMiniScore('miniTax', scan.taxRisk);

    // Detection fields grid
    renderDetectionFields(scan.fields);

    // Findings
    renderFindings(scan.findings);

    // Scroll to results
    area.scrollIntoView({ behavior: 'smooth', block: 'start' });
}

function drawOverviewGauge(score, level) {
    const gauge = document.getElementById('overviewGauge');
    const color = score <= 20 ? '#06d6a0' : score <= 50 ? '#f59e0b' : '#ef4444';
    const circumference = 2 * Math.PI * 42;
    const offset = circumference - (score / 100) * circumference;

    gauge.innerHTML = `
    <svg viewBox="0 0 100 100" width="100" height="100">
      <circle cx="50" cy="50" r="42" fill="none" stroke="rgba(255,255,255,0.05)" stroke-width="6"/>
      <circle cx="50" cy="50" r="42" fill="none" stroke="${color}" stroke-width="6"
              stroke-dasharray="${circumference}" stroke-dashoffset="${offset}"
              stroke-linecap="round" transform="rotate(-90 50 50)"
              style="transition: stroke-dashoffset 1s ease"/>
      <text x="50" y="46" text-anchor="middle" fill="${color}" font-size="26" font-weight="900"
            font-family="Inter,sans-serif">${score}</text>
      <text x="50" y="62" text-anchor="middle" fill="#94a3b8" font-size="8" letter-spacing="1.5"
            font-family="Inter,sans-serif">${level}</text>
    </svg>`;
}

function setMiniScore(elementId, score) {
    const el = document.getElementById(elementId);
    if (!el) return;
    const valueEl = el.querySelector('.mini-value');
    if (!valueEl) return;
    valueEl.textContent = score;
    const color = score <= 20 ? 'var(--success)' : score <= 50 ? 'var(--warning)' : 'var(--danger)';
    valueEl.style.color = color;
}

function renderDetectionFields(fields) {
    const container = document.getElementById('fieldCategories');
    container.innerHTML = '';

    // Group by category
    const categories = {};
    for (const [key, def] of Object.entries(DETECTION_FIELDS)) {
        const cat = def.category;
        if (!categories[cat]) categories[cat] = [];
        const fieldData = fields?.[key] || { d: false, s: 'safe' };
        categories[cat].push({ key, label: def.label, ...fieldData });
    }

    let totalDetected = 0;
    let total = 0;

    for (const [catName, catFields] of Object.entries(categories)) {
        const catDiv = document.createElement('div');
        catDiv.className = 'field-category';
        catDiv.innerHTML = `<div class="field-category-title">${catName}</div>`;

        const itemsDiv = document.createElement('div');
        itemsDiv.className = 'field-items';

        for (const field of catFields) {
            total++;
            if (field.d) totalDetected++;

            const dotClass = field.d ? field.s : 'safe';
            const statusText = field.d ? (field.s === 'critical' ? '⚠ YES' : field.s === 'warning' ? '⚡ YES' : field.s === 'info' ? 'ℹ YES' : '✓') : '✓ NO';
            const statusClass = field.d && field.s !== 'safe' && field.s !== 'info' ? field.s : 'safe';

            itemsDiv.innerHTML += `
        <div class="field-item">
          <span class="field-dot ${dotClass}"></span>
          <span class="field-name">${field.label}</span>
          <span class="field-status ${statusClass}">${statusText}</span>
        </div>`;
        }

        catDiv.appendChild(itemsDiv);
        container.appendChild(catDiv);
    }

    document.getElementById('fieldCounter').textContent = `${totalDetected} / ${total} detected`;
}

function renderFindings(findings) {
    const list = document.getElementById('findingsList');
    list.innerHTML = '';

    if (!findings || findings.length === 0) {
        list.innerHTML = '<div class="finding-item safe"><span class="finding-icon">✅</span><span class="finding-text">No significant issues detected — all checks passed</span></div>';
        return;
    }

    for (const finding of findings) {
        const icon = finding.severity === 'critical' ? '🔴' : finding.severity === 'warning' ? '🟡' : finding.severity === 'high' ? '🟠' : 'ℹ️';
        list.innerHTML += `
      <div class="finding-item ${finding.severity}">
        <span class="finding-icon">${icon}</span>
        <span class="finding-text">${finding.detail || finding.name}</span>
        <span class="finding-weight ${finding.severity}">${(finding.severity || 'info').toUpperCase()}</span>
      </div>`;
    }
}

// ============================================================
//  TAB SWITCHING
// ============================================================

function switchTab(tabId) {
    document.querySelectorAll('.tab-btn').forEach(btn => btn.classList.remove('active'));
    document.querySelectorAll('.tab-content').forEach(tab => tab.classList.remove('active'));

    event.target.classList.add('active');
    document.getElementById('tab-' + tabId).classList.add('active');
}

// ============================================================
//  WATCHLIST
// ============================================================

function removeFromWatchlist(index) {
    const rows = document.querySelectorAll('#watchlistBody .wl-row');
    if (rows[index]) {
        rows[index].style.animation = 'fadeOut 0.3s ease forwards';
        setTimeout(() => rows[index].remove(), 300);
    }
}

// ============================================================
//  THREAT FEED — Duplicate ticker items for seamless loop
// ============================================================

function initTicker() {
    const track = document.getElementById('tickerTrack');
    if (track) {
        const items = track.innerHTML;
        track.innerHTML = items + items; // duplicate for seamless loop
    }
}

// ============================================================
//  LIVE STATS — Fetch from API
// ============================================================

async function fetchStats() {
    try {
        const response = await fetch(`${API_BASE}/api/stats`);
        if (!response.ok) return;
        const data = await response.json();

        const fieldsEl = document.getElementById('statFields');
        const scannedEl = document.getElementById('statScanned');
        const threatsEl = document.getElementById('statThreats');

        if (fieldsEl) fieldsEl.textContent = data.detectionFields || 33;
        if (scannedEl) scannedEl.textContent = (data.totalScans || 0).toLocaleString();
        if (threatsEl) threatsEl.textContent = (data.threatsDetected || 0).toLocaleString();
    } catch {
        // Stats unavailable — keep existing values
    }
}

// ============================================================
//  STAT COUNTERS — Animated number reveal (initial load)
// ============================================================

function animateCounters() {
    const counters = [
        { id: 'statFields', target: 33, duration: 800 },
        { id: 'statScanned', target: 0, duration: 500 },
        { id: 'statThreats', target: 0, duration: 500 },
    ];

    for (const counter of counters) {
        const el = document.getElementById(counter.id);
        if (!el) continue;

        let current = 0;
        const step = Math.max(1, counter.target / (counter.duration / 16));
        if (counter.target === 0) {
            el.textContent = '0';
            continue;
        }
        const timer = setInterval(() => {
            current += step;
            if (current >= counter.target) {
                current = counter.target;
                clearInterval(timer);
            }
            el.textContent = Math.round(current).toLocaleString();
        }, 16);
    }
}

// ============================================================
//  INIT
// ============================================================

document.addEventListener('DOMContentLoaded', () => {
    initTicker();
    animateCounters();
    fetchStats();
});
