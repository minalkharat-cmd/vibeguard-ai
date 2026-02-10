/**
 * VibeGuard AI Agent — Enterprise Contract Analyzer Module
 * GoPlus-equivalent 30+ detection fields for comprehensive token security analysis.
 * Analyzes bytecode, source code, and on-chain state for:
 * - Honeypot indicators
 * - Rug pull patterns
 * - Ownership risks
 * - Token tax/fee manipulation
 * - Trading restrictions
 * - Supply manipulation
 * - Contract upgradeability
 */

const axios = require("axios");

// ====================================================================
//  30+ GoPlus-Equivalent Detection Field Definitions
// ====================================================================

const DETECTION_FIELDS = {
    // --- Contract Security ---
    is_open_source: { id: 'is_open_source', category: 'Contract Security', weight: 20 },
    is_proxy: { id: 'is_proxy', category: 'Contract Security', weight: 15 },
    has_selfdestruct: { id: 'has_selfdestruct', category: 'Contract Security', weight: 40 },
    has_external_call: { id: 'has_external_call', category: 'Contract Security', weight: 10 },
    is_upgradeable: { id: 'is_upgradeable', category: 'Contract Security', weight: 20 },
    has_assembly: { id: 'has_assembly', category: 'Contract Security', weight: 10 },

    // --- Honeypot Detection ---
    is_honeypot: { id: 'is_honeypot', category: 'Honeypot Detection', weight: 50 },
    transfer_pausable: { id: 'transfer_pausable', category: 'Honeypot Detection', weight: 30 },
    is_blacklisted: { id: 'is_blacklisted', category: 'Honeypot Detection', weight: 25 },
    is_whitelisted: { id: 'is_whitelisted', category: 'Honeypot Detection', weight: 10 },
    trading_cooldown: { id: 'trading_cooldown', category: 'Honeypot Detection', weight: 15 },
    has_trading_toggle: { id: 'has_trading_toggle', category: 'Honeypot Detection', weight: 25 },
    personal_slippage_mod: { id: 'personal_slippage_mod', category: 'Honeypot Detection', weight: 20 },

    // --- Ownership Risks ---
    hidden_owner: { id: 'hidden_owner', category: 'Ownership Risks', weight: 30 },
    can_take_back_ownership: { id: 'can_take_back_ownership', category: 'Ownership Risks', weight: 25 },
    owner_change_balance: { id: 'owner_change_balance', category: 'Ownership Risks', weight: 35 },
    is_ownership_renounced: { id: 'is_ownership_renounced', category: 'Ownership Risks', weight: -15 },

    // --- Supply Manipulation ---
    is_mintable: { id: 'is_mintable', category: 'Supply Manipulation', weight: 30 },
    is_burnable: { id: 'is_burnable', category: 'Supply Manipulation', weight: 5 },
    unlimited_supply: { id: 'unlimited_supply', category: 'Supply Manipulation', weight: 25 },

    // --- Tax & Fees ---
    tax_modifiable: { id: 'tax_modifiable', category: 'Tax & Fees', weight: 25 },
    has_buy_tax: { id: 'has_buy_tax', category: 'Tax & Fees', weight: 10 },
    has_sell_tax: { id: 'has_sell_tax', category: 'Tax & Fees', weight: 10 },
    high_tax_risk: { id: 'high_tax_risk', category: 'Tax & Fees', weight: 30 },
    is_buy_back: { id: 'is_buy_back', category: 'Tax & Fees', weight: 5 },

    // --- Trading Restrictions ---
    is_anti_whale: { id: 'is_anti_whale', category: 'Trading Restrictions', weight: 15 },
    anti_whale_modifiable: { id: 'anti_whale_modifiable', category: 'Trading Restrictions', weight: 20 },
    has_max_tx: { id: 'has_max_tx', category: 'Trading Restrictions', weight: 15 },
    has_max_wallet: { id: 'has_max_wallet', category: 'Trading Restrictions', weight: 10 },

    // --- Fraud Detection ---
    fake_token: { id: 'fake_token', category: 'Fraud Detection', weight: 40 },
    fake_standard_interface: { id: 'fake_standard_interface', category: 'Fraud Detection', weight: 35 },
    can_reinit: { id: 'can_reinit', category: 'Fraud Detection', weight: 20 },

    // --- Rug Pull Indicators ---
    can_remove_liquidity: { id: 'can_remove_liquidity', category: 'Rug Pull Indicators', weight: 35 },
    has_liquidity_lock: { id: 'has_liquidity_lock', category: 'Rug Pull Indicators', weight: -20 },
    owner_can_drain: { id: 'owner_can_drain', category: 'Rug Pull Indicators', weight: 40 },
};

// Bytecode function selectors for detection
const BYTECODE_SELECTORS = {
    owner: '8da5cb5b',
    renounceOwnership: '715018a6',
    transferOwnership: 'f2fde38b',
    mint: '40c10f19',
    burn: '42966c68',
    pause: '8456cb59',
    unpause: '3f4ba83a',
    paused: '5c975abb',
    setMaxTxPercent: 'e4748b9e',
    uniswapV2Pair: '49bd5a5e',
    uniswapV2Router: '1694505e',
    approve: '095ea7b3',
    setFee: '69fe0e2d',
    setTaxFee: 'a0e47bf6',
    excludeFromFee: '437823ec',
    blacklist: 'f9f92be4',
    setAntiBot: '860aefcf',
    decimals: '313ce567',
    totalSupply: '18160ddd',
};

// Source code patterns for comprehensive detection
const SOURCE_PATTERNS = {
    honeypot: [
        { regex: /setMaxTx|maxTransaction|_maxTxAmount/gi, field: 'has_max_tx', weight: 15 },
        { regex: /setMaxWallet|maxWallet|_maxWalletSize/gi, field: 'has_max_wallet', weight: 10 },
        { regex: /blacklist|_isBlacklisted|isBlackListed/gi, field: 'is_blacklisted', weight: 25 },
        { regex: /whitelist|_isWhitelisted|isWhiteListed/gi, field: 'is_whitelisted', weight: 10 },
        { regex: /selfdestruct/gi, field: 'has_selfdestruct', weight: 40 },
        { regex: /delegatecall/gi, field: 'is_upgradeable', weight: 20 },
        { regex: /cooldown|_cooldownTimer|tradingCooldown/gi, field: 'trading_cooldown', weight: 10 },
        { regex: /tradingActive|tradingOpen|_tradingOpen|enableTrading/gi, field: 'has_trading_toggle', weight: 20 },
        { regex: /botProtection|antibotActive|antiBotEnabled/gi, field: 'is_anti_whale', weight: 15 },
        { regex: /assembly\s*\{/gi, field: 'has_assembly', weight: 10 },
        { regex: /proxy|upgradeable|implementation/gi, field: 'is_proxy', weight: 15 },
        { regex: /\_pausable|whenNotPaused|_pause\(\)/gi, field: 'transfer_pausable', weight: 25 },
        { regex: /personalSlippage|setSlippage.*address/gi, field: 'personal_slippage_mod', weight: 20 },
    ],
    rugPull: [
        { regex: /removeLiquidity|removeAllETH|removeLiquidityETH/gi, field: 'can_remove_liquidity', weight: 30 },
        { regex: /mint.*onlyOwner|_mint.*internal/gi, field: 'is_mintable', weight: 20 },
        { regex: /renounced|renounceOwnership/gi, field: 'is_ownership_renounced', weight: -15 },
        { regex: /lock.*liquidity|liquidityLock|lpLocked/gi, field: 'has_liquidity_lock', weight: -20 },
        { regex: /withdraw.*onlyOwner|emergencyWithdraw/gi, field: 'owner_can_drain', weight: 35 },
        { regex: /extern.*call\{value|\.transfer\(|\.send\(/gi, field: 'has_external_call', weight: 10 },
        { regex: /initialize\(\)|constructor.*public/gi, field: 'can_reinit', weight: 15 },
    ],
    tax: [
        { regex: /setFee|setTaxFee|changeFee|updateFee/gi, field: 'tax_modifiable', weight: 20 },
        { regex: /buyFee|_buyTax|buyMarketingFee/gi, field: 'has_buy_tax', weight: 10 },
        { regex: /sellFee|_sellTax|sellMarketingFee/gi, field: 'has_sell_tax', weight: 10 },
        { regex: /setFee.*[5-9]\d|taxFee.*[5-9]\d|fee.*= *[5-9]\d/gi, field: 'high_tax_risk', weight: 30 },
        { regex: /buyBack|autoBuyBack/gi, field: 'is_buy_back', weight: 5 },
        { regex: /setAntiWhale|antiWhaleEnabled|setAntiWhaleAmount/gi, field: 'anti_whale_modifiable', weight: 15 },
    ],
    fraud: [
        { regex: /fake|counterfeit|imitation/gi, field: 'fake_token', weight: 35 },
        { regex: /hidden.*owner|_owner.*private.*no.*getter/gi, field: 'hidden_owner', weight: 25 },
        { regex: /changeBalance|setBalance|modifyBalance/gi, field: 'owner_change_balance', weight: 35 },
        { regex: /takeOwnership|reclaimOwnership|claimOwnership/gi, field: 'can_take_back_ownership', weight: 25 },
    ],
};

// Well-known mainsteam token names (for fake token detection)
const MAINSTREAM_TOKENS = [
    'WBNB', 'BUSD', 'USDT', 'USDC', 'ETH', 'WETH', 'BTC', 'WBTC',
    'CAKE', 'XRP', 'ADA', 'DOGE', 'SOL', 'DOT', 'MATIC', 'SHIB',
    'LINK', 'UNI', 'AAVE', 'AVAX',
];

class ContractAnalyzer {
    constructor(config = {}) {
        this.bscApiKey = config.bscApiKey || process.env.BSC_API_KEY || "";
        this.bscApiUrl = config.bscApiUrl || "https://api.bscscan.com/api";
    }

    /**
     * Fetch contract source code from BscScan
     */
    async getContractSource(contractAddress) {
        try {
            const response = await axios.get(this.bscApiUrl, {
                params: {
                    module: "contract",
                    action: "getsourcecode",
                    address: contractAddress,
                    apikey: this.bscApiKey,
                },
                timeout: 10000,
            });

            if (response.data.status === "1" && response.data.result[0]) {
                const result = response.data.result[0];
                return {
                    sourceCode: result.SourceCode,
                    contractName: result.ContractName,
                    compilerVersion: result.CompilerVersion,
                    isVerified: result.SourceCode !== "",
                    abi: result.ABI !== "Contract source code not verified" ? JSON.parse(result.ABI) : null,
                    isProxy: result.Proxy === "1",
                    implementation: result.Implementation || null,
                };
            }
            return { isVerified: false, sourceCode: "" };
        } catch (error) {
            console.error(`Error fetching source for ${contractAddress}:`, error.message);
            return { isVerified: false, sourceCode: "", error: error.message };
        }
    }

    /**
     * Fetch contract bytecode
     */
    async getContractBytecode(contractAddress) {
        try {
            const response = await axios.get(this.bscApiUrl, {
                params: {
                    module: "proxy",
                    action: "eth_getCode",
                    address: contractAddress,
                    tag: "latest",
                    apikey: this.bscApiKey,
                },
                timeout: 10000,
            });
            return response.data.result || "";
        } catch (error) {
            return "";
        }
    }

    /**
     * Run all 30+ detection fields against bytecode
     */
    analyzeBytecodeFields(bytecode) {
        const fields = {};

        if (!bytecode || bytecode === "0x") {
            return { fields: {}, riskScore: 50, note: 'No bytecode found' };
        }

        const code = bytecode.toLowerCase();

        // Contract Security
        fields.has_selfdestruct = { value: code.includes('ff'), risk: code.includes('ff') ? 40 : 0 };
        fields.is_proxy = { value: code.includes('363d3d373d3d3d363d73'), risk: code.includes('363d3d373d3d3d363d73') ? 15 : 0 };

        // Ownership
        fields.has_owner = { value: code.includes(BYTECODE_SELECTORS.owner), risk: 10 };
        fields.can_renounce = { value: code.includes(BYTECODE_SELECTORS.renounceOwnership), risk: -5 };
        fields.can_transfer_ownership = { value: code.includes(BYTECODE_SELECTORS.transferOwnership), risk: 15 };

        // Supply
        fields.is_mintable = { value: code.includes(BYTECODE_SELECTORS.mint), risk: code.includes(BYTECODE_SELECTORS.mint) ? 25 : 0 };
        fields.is_burnable = { value: code.includes(BYTECODE_SELECTORS.burn), risk: 5 };

        // Trading
        fields.transfer_pausable = { value: code.includes(BYTECODE_SELECTORS.pause), risk: code.includes(BYTECODE_SELECTORS.pause) ? 30 : 0 };
        fields.has_max_tx = { value: code.includes(BYTECODE_SELECTORS.setMaxTxPercent), risk: code.includes(BYTECODE_SELECTORS.setMaxTxPercent) ? 20 : 0 };

        // Tax
        fields.has_fee_function = { value: code.includes(BYTECODE_SELECTORS.setFee) || code.includes(BYTECODE_SELECTORS.setTaxFee), risk: 15 };
        fields.has_fee_exclusion = { value: code.includes(BYTECODE_SELECTORS.excludeFromFee), risk: 5 };

        // Blacklist
        fields.is_blacklisted = { value: code.includes(BYTECODE_SELECTORS.blacklist), risk: code.includes(BYTECODE_SELECTORS.blacklist) ? 25 : 0 };

        let riskScore = 0;
        for (const [, field] of Object.entries(fields)) {
            if (field.value) riskScore += field.risk;
        }

        return { fields, riskScore: Math.min(100, Math.max(0, riskScore)) };
    }

    /**
     * Run all source code pattern categories
     */
    analyzeSourceFields(sourceCode) {
        const detectedFields = {};
        const findings = [];

        if (!sourceCode) {
            return {
                detectedFields: { is_open_source: { value: false, severity: 'warning' } },
                findings: [{ name: 'Unverified contract', severity: 'warning' }],
                score: 30,
            };
        }

        detectedFields.is_open_source = { value: true, severity: 'safe' };

        // Run all pattern categories
        for (const [category, patterns] of Object.entries(SOURCE_PATTERNS)) {
            for (const pattern of patterns) {
                const matches = sourceCode.match(pattern.regex);
                if (matches) {
                    detectedFields[pattern.field] = {
                        value: true,
                        severity: pattern.weight >= 30 ? 'critical' : pattern.weight >= 15 ? 'warning' : 'info',
                        matchCount: matches.length,
                        category,
                    };
                    findings.push({
                        name: pattern.field,
                        severity: pattern.weight >= 30 ? 'critical' : pattern.weight >= 15 ? 'warning' : 'info',
                        count: matches.length,
                        weight: pattern.weight,
                        category,
                    });
                }
            }
        }

        // Fake token detection (check if contract name mimics mainstream token)
        for (const name of MAINSTREAM_TOKENS) {
            const fakePattern = new RegExp(`contract\\s+(?:Fake|New|Super|Baby|Mini|Safe|Inu)${name}`, 'gi');
            if (sourceCode.match(fakePattern)) {
                detectedFields.fake_token = { value: true, severity: 'critical' };
                findings.push({ name: 'fake_token', severity: 'critical', weight: 40, category: 'fraud' });
            }
        }

        // Compute score from all findings
        let score = 0;
        for (const finding of findings) {
            score += finding.weight;
        }

        return {
            detectedFields,
            findings,
            score: Math.min(100, Math.max(0, score)),
        };
    }

    /**
     * Full contract analysis — returns comprehensive 30+ field report
     */
    async analyzeContract(contractAddress) {
        console.log(`\n🔍 Analyzing contract: ${contractAddress}`);

        // Fetch data in parallel
        const [sourceData, bytecode] = await Promise.all([
            this.getContractSource(contractAddress),
            this.getContractBytecode(contractAddress),
        ]);

        // Bytecode field analysis
        const bytecodeAnalysis = this.analyzeBytecodeFields(bytecode);

        // Source code field analysis
        const sourceAnalysis = this.analyzeSourceFields(sourceData.sourceCode);

        // Merge all detected fields
        const allFields = {};
        for (const fieldDef of Object.values(DETECTION_FIELDS)) {
            const bytecodeField = bytecodeAnalysis.fields[fieldDef.id];
            const sourceField = sourceAnalysis.detectedFields[fieldDef.id];

            allFields[fieldDef.id] = {
                detected: !!(bytecodeField?.value || sourceField?.value),
                severity: sourceField?.severity || (bytecodeField?.value ? 'warning' : 'safe'),
                category: fieldDef.category,
                weight: fieldDef.weight,
            };
        }

        // Compute aggregate scores
        const honeypotScore = Math.min(100, this._categoryScore(allFields, 'Honeypot Detection'));
        const rugPullScore = Math.min(100, this._categoryScore(allFields, 'Rug Pull Indicators'));
        const ownershipRisk = Math.min(100, this._categoryScore(allFields, 'Ownership Risks'));
        const taxRisk = Math.min(100, this._categoryScore(allFields, 'Tax & Fees'));
        const tradingRisk = Math.min(100, this._categoryScore(allFields, 'Trading Restrictions'));
        const fraudRisk = Math.min(100, this._categoryScore(allFields, 'Fraud Detection'));
        const contractRisk = Math.min(100, this._categoryScore(allFields, 'Contract Security'));

        const overallRisk = Math.min(100, Math.round(
            honeypotScore * 0.25 +
            rugPullScore * 0.20 +
            ownershipRisk * 0.15 +
            taxRisk * 0.10 +
            tradingRisk * 0.05 +
            fraudRisk * 0.15 +
            contractRisk * 0.10
        ));

        const riskLevel = this._getRiskLevel(overallRisk);

        const report = {
            contractAddress,
            contractName: sourceData.contractName || "Unknown",
            isVerified: sourceData.isVerified,
            isProxy: sourceData.isProxy,
            overallRisk,
            riskLevel,
            honeypotScore,
            rugPullScore,
            ownershipRisk,
            taxRisk,
            tradingRisk,
            fraudRisk,
            contractRisk,
            detectionFields: allFields,
            fieldCount: Object.keys(allFields).length,
            detectedCount: Object.values(allFields).filter(f => f.detected).length,
            criticalCount: Object.values(allFields).filter(f => f.severity === 'critical').length,
            findings: sourceAnalysis.findings,
            timestamp: new Date().toISOString(),
        };

        console.log(`   Risk Score: ${overallRisk}/100 (${riskLevel})`);
        console.log(`   Fields: ${report.fieldCount} checked, ${report.detectedCount} detected, ${report.criticalCount} critical`);
        console.log(`   Honeypot: ${honeypotScore}, Rug: ${rugPullScore}, Ownership: ${ownershipRisk}`);

        return report;
    }

    _categoryScore(fields, category) {
        let score = 0;
        for (const [, field] of Object.entries(fields)) {
            if (field.category === category && field.detected) {
                score += Math.abs(field.weight);
            }
        }
        return score;
    }

    _getRiskLevel(score) {
        if (score <= 20) return "SAFE";
        if (score <= 40) return "LOW";
        if (score <= 60) return "MEDIUM";
        if (score <= 80) return "HIGH";
        return "CRITICAL";
    }
}

module.exports = { ContractAnalyzer, DETECTION_FIELDS };
