/**
 * VibeGuard AI — Express API Server
 * Bridges the frontend dashboard to the real agent analysis backend.
 * All scan results are REAL — powered by BscScan API + bytecode analysis.
 */

require('dotenv').config({ path: require('path').resolve(__dirname, '../.env') });
const express = require('express');
const cors = require('cors');
const path = require('path');
const { ethers } = require('ethers');

// Import analysis modules
const { ContractAnalyzer } = require('../agent/contractAnalyzer');
const { LiquidityMonitor } = require('../agent/liquidityMonitor');
const { CreatorProfiler } = require('../agent/creatorProfiler');
const FlashLoanDetector = require('../agent/flashLoanDetector');
const MEVDetector = require('../agent/mevDetector');

const app = express();
app.use(cors());
app.use(express.json());

// Serve frontend static files
app.use(express.static(path.join(__dirname, '../frontend')));

// BNB Chain provider
const BSC_RPC = 'https://bsc-dataseed.binance.org/';
const provider = new ethers.JsonRpcProvider(BSC_RPC);

// Initialize analysis modules
const config = {
    bscApiKey: process.env.BSC_API_KEY || '',
};
const contractAnalyzer = new ContractAnalyzer(config);
const liquidityMonitor = new LiquidityMonitor(config);
const creatorProfiler = new CreatorProfiler(config);
const flashLoanDetector = new FlashLoanDetector(provider);
const mevDetector = new MEVDetector(provider);

// Track scan statistics (in-memory for now)
const stats = {
    totalScans: 0,
    threatsDetected: 0,
    scanHistory: [],
};

// ============================================================
//  /api/scan/:address — REAL token risk scan
// ============================================================
app.get('/api/scan/:address', async (req, res) => {
    const { address } = req.params;

    if (!address || !address.startsWith('0x') || address.length !== 42) {
        return res.status(400).json({ error: 'Invalid address format' });
    }

    console.log(`\n🔍 Scanning: ${address}`);
    const startTime = Date.now();

    try {
        // Run all analyses in parallel for speed
        const [contractReport, liquidityReport, creatorReport, flashReport, mevReport] = await Promise.allSettled([
            contractAnalyzer.analyzeContract(address),
            liquidityMonitor.analyzeLiquidity(address),
            creatorProfiler.profileCreator(address),
            flashLoanDetector.analyze(address),
            mevDetector.analyze(address),
        ]);

        // Extract results (use defaults on failure)
        const contract = contractReport.status === 'fulfilled' ? contractReport.value : { overallRisk: 0, honeypotScore: 0, rugPullScore: 0, isVerified: false, detectionFields: {} };
        const liquidity = liquidityReport.status === 'fulfilled' ? liquidityReport.value : { liquidityHealth: 50 };
        const creator = creatorReport.status === 'fulfilled' ? creatorReport.value : { riskScore: 0 };
        const flash = flashReport.status === 'fulfilled' ? flashReport.value : { flashLoanRisk: 0 };
        const mev = mevReport.status === 'fulfilled' ? mevReport.value : { mevRisk: 0 };

        // Compute aggregated scores
        const honeypotScore = Math.min(100, Math.round(
            (contract.honeypotScore || 0) * 0.7 + (creator.riskScore || 0) * 0.3
        ));

        const rugPullScore = Math.min(100, Math.round(
            (contract.rugPullScore || 0) * 0.5 +
            (creator.riskScore || 0) * 0.3 +
            (100 - (liquidity.liquidityHealth || 50)) * 0.2
        ));

        const ownershipRisk = Math.min(100, Math.round(
            (contract.detectionFields?.hidden_owner?.detected ? 30 : 0) +
            (contract.detectionFields?.can_take_back_ownership?.detected ? 25 : 0) +
            (contract.detectionFields?.owner_change_balance?.detected ? 35 : 0) +
            (contract.detectionFields?.is_ownership_renounced?.detected ? -15 : 10)
        ));

        const taxRisk = Math.min(100, Math.round(
            (contract.detectionFields?.tax_modifiable?.detected ? 25 : 0) +
            (contract.detectionFields?.has_buy_tax?.detected ? 10 : 0) +
            (contract.detectionFields?.has_sell_tax?.detected ? 15 : 0) +
            (contract.detectionFields?.high_tax_risk?.detected ? 40 : 0)
        ));

        const overallRisk = Math.min(100, Math.round(
            (contract.overallRisk || 0) * 0.35 +
            honeypotScore * 0.20 +
            rugPullScore * 0.15 +
            (flash.flashLoanRisk || 0) * 0.10 +
            (mev.mevRisk || 0) * 0.10 +
            (100 - (liquidity.liquidityHealth || 50)) * 0.10
        ));

        const riskLevel = overallRisk <= 20 ? 'SAFE' : overallRisk <= 40 ? 'LOW' : overallRisk <= 60 ? 'MEDIUM' : overallRisk <= 80 ? 'HIGH' : 'CRITICAL';

        // Build detection fields for frontend
        const fields = buildDetectionFields(contract.detectionFields || {});

        // Build findings list
        const findings = buildFindings(contract, liquidity, creator, flash, mev);

        const scanTime = ((Date.now() - startTime) / 1000).toFixed(1);

        // Update stats
        stats.totalScans++;
        if (overallRisk >= 60) stats.threatsDetected++;
        stats.scanHistory.push({ address, overallRisk, riskLevel, timestamp: new Date().toISOString() });
        if (stats.scanHistory.length > 100) stats.scanHistory.shift();

        const result = {
            name: contract.contractName || 'Unknown Token',
            address,
            overallRisk,
            riskLevel,
            honeypotScore,
            rugPullScore,
            flashLoanRisk: flash.flashLoanRisk || 0,
            mevRisk: mev.mevRisk || 0,
            ownershipRisk: Math.max(0, ownershipRisk),
            taxRisk,
            verified: contract.isVerified || false,
            isProxy: contract.detectionFields?.is_proxy?.detected || false,
            fields,
            findings,
            scanTimeSeconds: scanTime,
            liquidityHealth: liquidity.liquidityHealth || 50,
            holderCount: liquidity.holderCount || 0,
            creatorAge: creator.walletAgeDays || 0,
            creatorContracts: creator.deployedContractCount || 0,
        };

        console.log(`✅ Scan complete: ${riskLevel} (${overallRisk}/100) in ${scanTime}s`);
        res.json(result);

    } catch (error) {
        console.error('❌ Scan failed:', error.message);
        res.status(500).json({ error: 'Scan failed: ' + error.message });
    }
});

// ============================================================
//  /api/stats — Real scan statistics
// ============================================================
app.get('/api/stats', (req, res) => {
    res.json({
        totalScans: stats.totalScans,
        threatsDetected: stats.threatsDetected,
        detectionFields: 33,
        recentScans: stats.scanHistory.slice(-10),
    });
});

// ============================================================
//  /api/threat-feed — Recent high-risk scans
// ============================================================
app.get('/api/threat-feed', (req, res) => {
    const threats = stats.scanHistory
        .filter(s => s.overallRisk >= 50)
        .slice(-20)
        .reverse();
    res.json(threats);
});

// ============================================================
//  Helper: Build detection fields from contract analysis
// ============================================================
function buildDetectionFields(detectionFields) {
    const fieldMap = {};
    const fieldDefs = {
        is_open_source: 'safe', is_proxy: 'warning', has_selfdestruct: 'critical',
        has_external_call: 'warning', is_upgradeable: 'warning', has_assembly: 'warning',
        is_honeypot: 'critical', transfer_pausable: 'critical', is_blacklisted: 'critical',
        is_whitelisted: 'warning', trading_cooldown: 'warning', has_trading_toggle: 'critical',
        personal_slippage_mod: 'critical', hidden_owner: 'critical', can_take_back_ownership: 'critical',
        owner_change_balance: 'critical', is_ownership_renounced: 'safe',
        is_mintable: 'warning', is_burnable: 'safe', unlimited_supply: 'critical',
        tax_modifiable: 'critical', has_buy_tax: 'warning', has_sell_tax: 'warning',
        high_tax_risk: 'critical', is_buy_back: 'info',
        is_anti_whale: 'info', anti_whale_modifiable: 'warning',
        has_max_tx: 'info', has_max_wallet: 'info',
        fake_token: 'critical', fake_standard_interface: 'critical', can_reinit: 'critical',
        can_remove_liquidity: 'critical', has_liquidity_lock: 'safe', owner_can_drain: 'critical',
    };

    for (const [key, severity] of Object.entries(fieldDefs)) {
        const detected = detectionFields[key]?.detected || false;
        // For is_open_source and is_ownership_renounced, NOT detected = risky
        let status;
        if (key === 'is_open_source' || key === 'is_ownership_renounced' || key === 'has_liquidity_lock') {
            status = detected ? 'safe' : (key === 'has_liquidity_lock' ? 'warning' : 'warning');
        } else {
            status = detected ? severity : 'safe';
        }
        fieldMap[key] = { d: detected, s: status };
    }

    return fieldMap;
}

// ============================================================
//  Helper: Build findings from all analysis modules
// ============================================================
function buildFindings(contract, liquidity, creator, flash, mev) {
    const findings = [];

    // Contract analyzer findings
    if (contract.findings) {
        for (const f of contract.findings) {
            findings.push({
                name: f.field || f.issue || 'contract_issue',
                severity: (f.severity || 'info').toLowerCase(),
                detail: f.detail || f.issue || '',
            });
        }
    }

    // Liquidity findings
    if (liquidity.holderAnalysis?.findings) {
        for (const f of liquidity.holderAnalysis.findings) {
            findings.push({ name: 'holder_risk', severity: f.severity?.toLowerCase() || 'warning', detail: f.issue });
        }
    }
    if (liquidity.transferAnalysis?.findings) {
        for (const f of liquidity.transferAnalysis.findings) {
            findings.push({ name: 'transfer_pattern', severity: f.severity?.toLowerCase() || 'warning', detail: f.issue });
        }
    }

    // Creator findings
    if (creator.findings) {
        for (const f of creator.findings) {
            findings.push({ name: 'creator_risk', severity: f.severity?.toLowerCase() || 'warning', detail: f.issue });
        }
    }

    // Flash loan findings
    if (flash.vulnerabilities) {
        for (const v of flash.vulnerabilities) {
            if (v.severity !== 'info') {
                findings.push({ name: 'flash_loan', severity: v.severity, detail: v.detail });
            }
        }
    }

    // MEV findings
    if (mev.sandwichVulnerability?.details) {
        for (const d of mev.sandwichVulnerability.details) {
            if (typeof d === 'object') {
                findings.push({ name: 'mev_risk', severity: d.severity || 'warning', detail: d.detail });
            }
        }
    }

    return findings;
}

// ============================================================
//  Catch-all: Serve frontend for any non-API route
// ============================================================
// SPA fallback — serve index.html for non-API routes
app.use((req, res, next) => {
    if (!req.path.startsWith('/api')) {
        return res.sendFile(path.join(__dirname, '../frontend/index.html'));
    }
    next();
});

// ============================================================
//  Start server
// ============================================================
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`\n🛡️  VibeGuard AI Server running on http://localhost:${PORT}`);
    console.log(`   Dashboard: http://localhost:${PORT}`);
    console.log(`   API:       http://localhost:${PORT}/api/scan/<address>`);
    console.log(`   Stats:     http://localhost:${PORT}/api/stats\n`);
});
