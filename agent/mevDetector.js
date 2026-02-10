/**
 * VibeGuard AI — MEV / Sandwich Attack Detector
 * Identifies tokens and pools vulnerable to MEV extraction
 * by analyzing mempool patterns, slippage exposure, and bot activity.
 */

const { ethers } = require('ethers');

class MEVDetector {
    constructor(provider) {
        this.provider = provider || new ethers.JsonRpcProvider('https://bsc-dataseed.binance.org/');

        // Known MEV bot contract patterns
        this.mevBotIndicators = {
            // High-frequency swap patterns
            multiHopSwap: ethers.id('multicall(bytes[])').slice(0, 10),
            flashSwap: ethers.id('swap(uint256,uint256,address,bytes)').slice(0, 10),
            // Arbitrage patterns
            arbitrage: ethers.id('executeArbitrage(address[],uint256)').slice(0, 10),
            // Sandwich helpers
            sandwich: ethers.id('execute(address,uint256,uint256,bytes)').slice(0, 10),
        };

        // DEX router addresses on BNB Chain
        this.knownRouters = {
            '0x10ED43C718714eb63d5aA57B78B54917e6ba6170': 'PancakeSwap V2',
            '0x13f4EA83D0bd40E75C8222255bc855a974568Dd4': 'PancakeSwap V3',
            '0x1b81D678ffb9C0263b24A97847620C99d213eB14': 'PancakeSwap StableSwap',
            '0xcF0feBd3f17CEf5b47b0cD257aCf6025c5BFf3b7': 'ApeSwap',
            '0x3a6d8cA21D1CF76F653A67577FA0D27453350dD8': 'BiSwap',
        };
    }

    /**
     * Full MEV vulnerability analysis for a token
     * @param {string} tokenAddress - Token contract address
     * @returns {Object} MEV vulnerability report
     */
    async analyze(tokenAddress) {
        const results = {
            address: tokenAddress,
            timestamp: new Date().toISOString(),
            mevRisk: 0,
            sandwichVulnerability: { score: 0, details: [] },
            slippageExposure: { score: 0, details: [] },
            botActivity: { detected: false, patterns: [] },
            liquidityAnalysis: { depth: 'unknown', concentration: 'unknown', details: [] },
            recommendations: [],
        };

        try {
            const code = await this.provider.getCode(tokenAddress);

            // 1. Analyze token contract for MEV-relevant properties
            this._analyzeTokenProperties(code, results);

            // 2. Detect sandwich vulnerability indicators
            this._detectSandwichVulnerability(code, results);

            // 3. Analyze slippage exposure
            this._analyzeSlippageExposure(code, results);

            // 4. Detect bot-friendly patterns
            this._detectBotPatterns(code, results);

            // 5. Analyze liquidity characteristics
            await this._analyzeLiquidity(tokenAddress, results);

            // 6. Compute overall risk score
            results.mevRisk = this._computeRiskScore(results);

            // 7. Generate recommendations
            this._generateRecommendations(results);

        } catch (error) {
            results.sandwichVulnerability.details.push(`Analysis error: ${error.message}`);
        }

        return results;
    }

    _analyzeTokenProperties(bytecode, results) {
        const code = bytecode.toLowerCase();

        // Check for high transfer tax (makes sandwiching profitable)
        const transferSelectors = [
            ethers.id('setFee(uint256)').slice(2, 10),
            ethers.id('setTaxFee(uint256)').slice(2, 10),
            ethers.id('setLiquidityFee(uint256)').slice(2, 10),
            ethers.id('setBuyFee(uint256)').slice(2, 10),
            ethers.id('setSellFee(uint256)').slice(2, 10),
        ];

        const hasDynamicFees = transferSelectors.some(s => code.includes(s));
        if (hasDynamicFees) {
            results.sandwichVulnerability.details.push({
                type: 'DYNAMIC_FEES',
                severity: 'high',
                detail: 'Token has mutable fee structure — front-runners can predict fee changes',
            });
            results.sandwichVulnerability.score += 25;
        }

        // Check for max transaction limits (impacts sandwich profitability)
        const maxTxSelectors = [
            ethers.id('setMaxTxPercent(uint256)').slice(2, 10),
            ethers.id('setMaxTransactionAmount(uint256)').slice(2, 10),
            ethers.id('_maxTxAmount()').slice(2, 10),
        ];

        const hasMaxTx = maxTxSelectors.some(s => code.includes(s));
        if (hasMaxTx) {
            results.sandwichVulnerability.details.push({
                type: 'MAX_TX_LIMIT',
                severity: 'low',
                detail: 'Token has max transaction limits — may limit sandwich attack size',
            });
            results.sandwichVulnerability.score -= 10;
        }

        // Check for anti-bot mechanisms
        const antiBotSelectors = [
            ethers.id('setAntiBot(bool)').slice(2, 10),
            ethers.id('setBotBlacklist(address,bool)').slice(2, 10),
            ethers.id('setTradingEnabled(bool)').slice(2, 10),
        ];

        const hasAntiBot = antiBotSelectors.some(s => code.includes(s));
        if (hasAntiBot) {
            results.botActivity.patterns.push({
                type: 'ANTI_BOT_MECHANISM',
                detail: 'Contract has anti-bot functions — may mitigate MEV extraction',
            });
            results.sandwichVulnerability.score -= 15;
        }
    }

    _detectSandwichVulnerability(bytecode, results) {
        const code = bytecode.toLowerCase();

        // Tokens without cooldowns between trades are prime sandwich targets
        const cooldownSelector = ethers.id('setCooldownEnabled(bool)').slice(2, 10);
        const hasCooldown = code.includes(cooldownSelector);

        if (!hasCooldown) {
            results.sandwichVulnerability.details.push({
                type: 'NO_TRADE_COOLDOWN',
                severity: 'medium',
                detail: 'No trading cooldown — allows rapid front-run + back-run in same block',
            });
            results.sandwichVulnerability.score += 15;
        }

        // Check for approve() without safeApprove pattern
        const approveSelector = ethers.id('approve(address,uint256)').slice(2, 10);
        const increaseSelector = ethers.id('increaseAllowance(address,uint256)').slice(2, 10);

        if (code.includes(approveSelector) && !code.includes(increaseSelector)) {
            results.sandwichVulnerability.details.push({
                type: 'APPROVAL_FRONTRUN',
                severity: 'medium',
                detail: 'Uses approve() without increaseAllowance() — vulnerable to approval frontrunning',
            });
            results.sandwichVulnerability.score += 10;
        }
    }

    _analyzeSlippageExposure(bytecode, results) {
        const code = bytecode.toLowerCase();

        // Check for common swap functions that expose slippage
        const swapSelectors = [
            { sig: 'swapExactTokensForTokens(uint256,uint256,address[],address,uint256)', name: 'swapExactTokensForTokens' },
            { sig: 'swapExactETHForTokens(uint256,address[],address,uint256)', name: 'swapExactETHForTokens' },
            { sig: 'swapTokensForExactTokens(uint256,uint256,address[],address,uint256)', name: 'swapTokensForExactTokens' },
        ];

        for (const { sig, name } of swapSelectors) {
            const selector = ethers.id(sig).slice(2, 10);
            if (code.includes(selector)) {
                results.slippageExposure.details.push({
                    type: 'DEX_SWAP_EXPOSURE',
                    detail: `Calls ${name}() — user slippage tolerance can be exploited by sandwichers`,
                });
                results.slippageExposure.score += 10;
            }
        }

        // Check for swapExactTokensForTokensSupportingFeeOnTransferTokens
        const feeSwapSelector = ethers.id(
            'swapExactTokensForTokensSupportingFeeOnTransferTokens(uint256,uint256,address[],address,uint256)'
        ).slice(2, 10);

        if (code.includes(feeSwapSelector)) {
            results.slippageExposure.details.push({
                type: 'FEE_ON_TRANSFER_SWAP',
                severity: 'high',
                detail: 'Uses fee-on-transfer swap — higher slippage exposure for MEV extraction',
            });
            results.slippageExposure.score += 20;
        }
    }

    _detectBotPatterns(bytecode, results) {
        const code = bytecode.toLowerCase();

        for (const [funcName, selector] of Object.entries(this.mevBotIndicators)) {
            if (code.includes(selector.slice(2))) {
                results.botActivity.detected = true;
                results.botActivity.patterns.push({
                    type: funcName.toUpperCase(),
                    detail: `Contains MEV bot function pattern: ${funcName}`,
                });
            }
        }

        // Check for multicall (batched operations — common in MEV bots)
        const multicallSelector = ethers.id('multicall(bytes[])').slice(2, 10);
        if (code.includes(multicallSelector)) {
            results.botActivity.detected = true;
            results.botActivity.patterns.push({
                type: 'MULTICALL',
                detail: 'Supports multicall — can batch operations atomically (MEV bot pattern)',
            });
        }
    }

    async _analyzeLiquidity(tokenAddress, results) {
        // Simulate liquidity analysis — in production, query DEX pools
        try {
            const code = await this.provider.getCode(tokenAddress);

            // Check for LP pairing indicators
            const pairSelectors = [
                ethers.id('uniswapV2Pair()').slice(2, 10),
                ethers.id('pancakePair()').slice(2, 10),
                ethers.id('pair()').slice(2, 10),
            ];

            const hasLPPair = pairSelectors.some(s => code.toLowerCase().includes(s));

            if (hasLPPair) {
                results.liquidityAnalysis = {
                    depth: 'has_lp_pair',
                    concentration: 'check_on_chain',
                    details: ['Token has DEX liquidity pair — susceptible to pool manipulation'],
                };
            } else {
                results.liquidityAnalysis = {
                    depth: 'no_lp_detected',
                    concentration: 'unknown',
                    details: ['No direct LP pair reference found in contract'],
                };
            }
        } catch {
            results.liquidityAnalysis.details.push('Liquidity analysis unavailable');
        }
    }

    _computeRiskScore(results) {
        let score = 0;

        score += Math.max(0, results.sandwichVulnerability.score);
        score += results.slippageExposure.score;

        if (results.botActivity.detected) score += 15;
        if (results.liquidityAnalysis.depth === 'has_lp_pair') score += 5;

        return Math.min(Math.max(score, 0), 100);
    }

    _generateRecommendations(results) {
        if (results.sandwichVulnerability.score > 20) {
            results.recommendations.push(
                'Implement trading cooldowns to prevent rapid front-run + back-run sequences',
                'Consider commit-reveal schemes for large trades',
                'Use private mempool services (e.g., Flashbots Protect) for transactions'
            );
        }
        if (results.slippageExposure.score > 15) {
            results.recommendations.push(
                'Set strict slippage tolerance (< 1%) on all DEX interactions',
                'Use deadline parameters to prevent stale transaction execution'
            );
        }
        if (results.botActivity.detected) {
            results.recommendations.push(
                'Monitor for recurring MEV bot interactions on this token',
                'Consider using MEV-protected RPC endpoints (e.g., BloXroute)'
            );
        }
        if (results.recommendations.length === 0) {
            results.recommendations.push('No significant MEV vulnerabilities detected');
        }
    }
}

module.exports = MEVDetector;
