/**
 * VibeGuard AI — Enterprise Dashboard Application
 * Handles: 30+ field scanning, threat feed, watchlist, agent identity, tab switching
 */

// ============================================================
//  DETECTION FIELD DEFINITIONS (Mirror of contractAnalyzer.js)
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
//  SIMULATED SCAN DATA (for demo — in production, calls Agent API)
// ============================================================
const SCAN_PRESETS = {
    '0xbb4CdB9CBd36B01bD1cBaEBF2De08d9173bc095c': {
        name: 'Wrapped BNB', overallRisk: 8, riskLevel: 'SAFE',
        honeypotScore: 2, rugPullScore: 0, flashLoanRisk: 5, mevRisk: 18,
        ownershipRisk: 3, taxRisk: 0,
        fields: { is_open_source: { d: true, s: 'safe' }, is_proxy: { d: false, s: 'safe' }, has_selfdestruct: { d: false, s: 'safe' }, has_external_call: { d: false, s: 'safe' }, is_upgradeable: { d: false, s: 'safe' }, has_assembly: { d: false, s: 'safe' }, is_honeypot: { d: false, s: 'safe' }, transfer_pausable: { d: false, s: 'safe' }, is_blacklisted: { d: false, s: 'safe' }, is_whitelisted: { d: false, s: 'safe' }, trading_cooldown: { d: false, s: 'safe' }, has_trading_toggle: { d: false, s: 'safe' }, personal_slippage_mod: { d: false, s: 'safe' }, hidden_owner: { d: false, s: 'safe' }, can_take_back_ownership: { d: false, s: 'safe' }, owner_change_balance: { d: false, s: 'safe' }, is_ownership_renounced: { d: true, s: 'safe' }, is_mintable: { d: true, s: 'warning' }, is_burnable: { d: false, s: 'safe' }, unlimited_supply: { d: false, s: 'safe' }, tax_modifiable: { d: false, s: 'safe' }, has_buy_tax: { d: false, s: 'safe' }, has_sell_tax: { d: false, s: 'safe' }, high_tax_risk: { d: false, s: 'safe' }, is_buy_back: { d: false, s: 'safe' }, is_anti_whale: { d: false, s: 'safe' }, anti_whale_modifiable: { d: false, s: 'safe' }, has_max_tx: { d: false, s: 'safe' }, has_max_wallet: { d: false, s: 'safe' }, fake_token: { d: false, s: 'safe' }, fake_standard_interface: { d: false, s: 'safe' }, can_reinit: { d: false, s: 'safe' }, can_remove_liquidity: { d: false, s: 'safe' }, has_liquidity_lock: { d: true, s: 'safe' }, owner_can_drain: { d: false, s: 'safe' } },
        verified: true, isProxy: false,
        findings: [
            { name: 'is_mintable', severity: 'warning', detail: 'WBNB supports deposit/mint — expected for wrapped token' },
        ],
    },
    '0xe9e7CEA3DedcA5984780Bafc599bD69ADd087D56': {
        name: 'BUSD', overallRisk: 5, riskLevel: 'SAFE',
        honeypotScore: 0, rugPullScore: 0, flashLoanRisk: 3, mevRisk: 8,
        ownershipRisk: 5, taxRisk: 0,
        fields: { is_open_source: { d: true, s: 'safe' }, is_proxy: { d: true, s: 'warning' }, has_selfdestruct: { d: false, s: 'safe' }, has_external_call: { d: false, s: 'safe' }, is_upgradeable: { d: true, s: 'warning' }, has_assembly: { d: false, s: 'safe' }, is_honeypot: { d: false, s: 'safe' }, transfer_pausable: { d: true, s: 'info' }, is_blacklisted: { d: true, s: 'info' }, is_whitelisted: { d: false, s: 'safe' }, trading_cooldown: { d: false, s: 'safe' }, has_trading_toggle: { d: false, s: 'safe' }, personal_slippage_mod: { d: false, s: 'safe' }, hidden_owner: { d: false, s: 'safe' }, can_take_back_ownership: { d: false, s: 'safe' }, owner_change_balance: { d: false, s: 'safe' }, is_ownership_renounced: { d: false, s: 'safe' }, is_mintable: { d: true, s: 'info' }, is_burnable: { d: true, s: 'safe' }, unlimited_supply: { d: false, s: 'safe' }, tax_modifiable: { d: false, s: 'safe' }, has_buy_tax: { d: false, s: 'safe' }, has_sell_tax: { d: false, s: 'safe' }, high_tax_risk: { d: false, s: 'safe' }, is_buy_back: { d: false, s: 'safe' }, is_anti_whale: { d: false, s: 'safe' }, anti_whale_modifiable: { d: false, s: 'safe' }, has_max_tx: { d: false, s: 'safe' }, has_max_wallet: { d: false, s: 'safe' }, fake_token: { d: false, s: 'safe' }, fake_standard_interface: { d: false, s: 'safe' }, can_reinit: { d: false, s: 'safe' }, can_remove_liquidity: { d: false, s: 'safe' }, has_liquidity_lock: { d: true, s: 'safe' }, owner_can_drain: { d: false, s: 'safe' } },
        verified: true, isProxy: true,
        findings: [
            { name: 'is_proxy', severity: 'info', detail: 'BUSD is a proxy contract — Binance-managed, upgradeability expected' },
            { name: 'transfer_pausable', severity: 'info', detail: 'Pause mechanism present — standard for regulated stablecoin' },
        ],
    },
    '0x55d398326f99059fF775485246999027B3197955': {
        name: 'BSC-USD (USDT)', overallRisk: 6, riskLevel: 'SAFE',
        honeypotScore: 0, rugPullScore: 0, flashLoanRisk: 4, mevRisk: 10,
        ownershipRisk: 8, taxRisk: 0,
        fields: { is_open_source: { d: true, s: 'safe' }, is_proxy: { d: false, s: 'safe' }, has_selfdestruct: { d: false, s: 'safe' }, has_external_call: { d: false, s: 'safe' }, is_upgradeable: { d: false, s: 'safe' }, has_assembly: { d: false, s: 'safe' }, is_honeypot: { d: false, s: 'safe' }, transfer_pausable: { d: true, s: 'info' }, is_blacklisted: { d: true, s: 'info' }, is_whitelisted: { d: false, s: 'safe' }, trading_cooldown: { d: false, s: 'safe' }, has_trading_toggle: { d: false, s: 'safe' }, personal_slippage_mod: { d: false, s: 'safe' }, hidden_owner: { d: false, s: 'safe' }, can_take_back_ownership: { d: false, s: 'safe' }, owner_change_balance: { d: false, s: 'safe' }, is_ownership_renounced: { d: false, s: 'safe' }, is_mintable: { d: true, s: 'info' }, is_burnable: { d: true, s: 'safe' }, unlimited_supply: { d: false, s: 'safe' }, tax_modifiable: { d: false, s: 'safe' }, has_buy_tax: { d: false, s: 'safe' }, has_sell_tax: { d: false, s: 'safe' }, high_tax_risk: { d: false, s: 'safe' }, is_buy_back: { d: false, s: 'safe' }, is_anti_whale: { d: false, s: 'safe' }, anti_whale_modifiable: { d: false, s: 'safe' }, has_max_tx: { d: false, s: 'safe' }, has_max_wallet: { d: false, s: 'safe' }, fake_token: { d: false, s: 'safe' }, fake_standard_interface: { d: false, s: 'safe' }, can_reinit: { d: false, s: 'safe' }, can_remove_liquidity: { d: false, s: 'safe' }, has_liquidity_lock: { d: true, s: 'safe' }, owner_can_drain: { d: false, s: 'safe' } },
        verified: true, isProxy: false,
        findings: [],
    },
};

// Default scam token scan
const SCAM_SCAN = {
    name: 'Unknown Token', overallRisk: 87, riskLevel: 'CRITICAL',
    honeypotScore: 89, rugPullScore: 82, flashLoanRisk: 45, mevRisk: 62,
    ownershipRisk: 75, taxRisk: 90,
    fields: { is_open_source: { d: false, s: 'critical' }, is_proxy: { d: true, s: 'warning' }, has_selfdestruct: { d: true, s: 'critical' }, has_external_call: { d: true, s: 'warning' }, is_upgradeable: { d: true, s: 'warning' }, has_assembly: { d: true, s: 'warning' }, is_honeypot: { d: true, s: 'critical' }, transfer_pausable: { d: true, s: 'critical' }, is_blacklisted: { d: true, s: 'critical' }, is_whitelisted: { d: true, s: 'warning' }, trading_cooldown: { d: true, s: 'warning' }, has_trading_toggle: { d: true, s: 'critical' }, personal_slippage_mod: { d: true, s: 'critical' }, hidden_owner: { d: true, s: 'critical' }, can_take_back_ownership: { d: true, s: 'critical' }, owner_change_balance: { d: true, s: 'critical' }, is_ownership_renounced: { d: false, s: 'critical' }, is_mintable: { d: true, s: 'critical' }, is_burnable: { d: false, s: 'safe' }, unlimited_supply: { d: true, s: 'critical' }, tax_modifiable: { d: true, s: 'critical' }, has_buy_tax: { d: true, s: 'warning' }, has_sell_tax: { d: true, s: 'critical' }, high_tax_risk: { d: true, s: 'critical' }, is_buy_back: { d: false, s: 'safe' }, is_anti_whale: { d: true, s: 'warning' }, anti_whale_modifiable: { d: true, s: 'warning' }, has_max_tx: { d: true, s: 'warning' }, has_max_wallet: { d: true, s: 'warning' }, fake_token: { d: true, s: 'critical' }, fake_standard_interface: { d: true, s: 'critical' }, can_reinit: { d: true, s: 'critical' }, can_remove_liquidity: { d: true, s: 'critical' }, has_liquidity_lock: { d: false, s: 'critical' }, owner_can_drain: { d: true, s: 'critical' } },
    verified: false, isProxy: true,
    findings: [
        { name: 'is_honeypot', severity: 'critical', detail: 'Token cannot be sold — honeypot confirmed' },
        { name: 'has_selfdestruct', severity: 'critical', detail: 'Contract can self-destruct — funds at risk' },
        { name: 'hidden_owner', severity: 'critical', detail: 'Owner address hidden in private variable' },
        { name: 'owner_change_balance', severity: 'critical', detail: 'Owner can arbitrarily modify balances' },
        { name: 'high_tax_risk', severity: 'critical', detail: 'Sell tax can be set up to 99%' },
        { name: 'fake_token', severity: 'critical', detail: 'Contract name mimics mainstream token (BabyBNB)' },
        { name: 'can_remove_liquidity', severity: 'critical', detail: 'Owner can remove all liquidity (rug pull vector)' },
        { name: 'owner_can_drain', severity: 'critical', detail: 'emergencyWithdraw() accessible by owner' },
        { name: 'unlimited_supply', severity: 'critical', detail: 'No max supply cap — infinite mint risk' },
        { name: 'transfer_pausable', severity: 'warning', detail: 'Trading can be frozen by owner at any time' },
        { name: 'is_blacklisted', severity: 'warning', detail: 'Seller addresses can be blacklisted' },
        { name: 'tax_modifiable', severity: 'warning', detail: 'Fees can be changed post-deployment' },
    ],
};

// ============================================================
//  SCANNING LOGIC
// ============================================================

function quickScan(address) {
    document.getElementById('tokenInput').value = address;
    startEnterpriseScan();
}

async function startEnterpriseScan() {
    const address = document.getElementById('tokenInput').value.trim();
    if (!address || !address.startsWith('0x')) return;

    const btn = document.getElementById('scanBtn');
    btn.classList.add('scanning');

    // Simulate multi-phase scan with progressive reveal
    await simulatePhase('Fetching bytecode...', 600);
    await simulatePhase('Analyzing 33 detection fields...', 800);
    await simulatePhase('Running flash loan analysis...', 500);
    await simulatePhase('Scanning for MEV vulnerabilities...', 500);
    await simulatePhase('Computing risk scores...', 300);

    btn.classList.remove('scanning');

    // Get scan data
    const scan = SCAN_PRESETS[address] || { ...SCAM_SCAN };
    scan.address = address;

    // Display results
    displayResults(scan, address);
}

function simulatePhase(phase, duration) {
    return new Promise(resolve => setTimeout(resolve, duration));
}

function displayResults(scan, address) {
    const area = document.getElementById('resultsArea');
    area.style.display = 'flex';

    // Overview
    document.getElementById('resultTokenName').textContent = scan.name;
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
    const valueEl = el.querySelector('.mini-value');
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
        const fieldData = fields[key] || { d: false, s: 'safe' };
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
        const icon = finding.severity === 'critical' ? '🔴' : finding.severity === 'warning' ? '🟡' : 'ℹ️';
        list.innerHTML += `
      <div class="finding-item ${finding.severity}">
        <span class="finding-icon">${icon}</span>
        <span class="finding-text">${finding.detail || finding.name}</span>
        <span class="finding-weight ${finding.severity}">${finding.severity.toUpperCase()}</span>
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
    const items = track.innerHTML;
    track.innerHTML = items + items; // duplicate for seamless loop
}

// ============================================================
//  STAT COUNTERS — Animated number reveal
// ============================================================

function animateCounters() {
    const counters = [
        { id: 'statFields', target: 33, duration: 800 },
        { id: 'statScanned', target: 12847, duration: 1500, format: true },
        { id: 'statThreats', target: 2391, duration: 1200, format: true },
        { id: 'statAgents', target: 156, duration: 1000 },
    ];

    for (const counter of counters) {
        const el = document.getElementById(counter.id);
        if (!el) continue;

        let current = 0;
        const step = counter.target / (counter.duration / 16);
        const timer = setInterval(() => {
            current += step;
            if (current >= counter.target) {
                current = counter.target;
                clearInterval(timer);
            }
            el.textContent = counter.format
                ? Math.round(current).toLocaleString()
                : Math.round(current);
        }, 16);
    }
}

// ============================================================
//  INIT
// ============================================================

document.addEventListener('DOMContentLoaded', () => {
    initTicker();
    animateCounters();
});
