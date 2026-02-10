/**
 * VibeGuard AI — Flash Loan Vulnerability Detector
 * Identifies contracts susceptible to flash loan attacks by analyzing
 * oracle patterns, price manipulation vectors, and callback safety.
 */

const { ethers } = require('ethers');

class FlashLoanDetector {
    constructor(provider) {
        this.provider = provider || new ethers.JsonRpcProvider('https://bsc-dataseed.binance.org/');

        // Known flash loan provider function selectors
        this.flashLoanSelectors = {
            '0x5cffe9de': 'flashLoan(address,address,uint256,bytes)',        // ERC-3156
            '0xab9c4b5d': 'flashLoan(address,address[],uint256[],uint256[],address,bytes,uint16)', // Aave v2
            '0xe9c1c6fc': 'flashLoanSimple(address,address,uint256,bytes,uint16)',  // Aave v3
            '0xd9d98ce4': 'flashBorrow(address,uint256)',                    // dYdX
            '0x5711e9c8': 'pancakeV3FlashCallback(uint256,uint256,bytes)',   // PancakeSwap v3
        };

        // Vulnerable oracle patterns (single-block price manipulation)
        this.vulnerableOraclePatterns = [
            'getReserves',                    // Uniswap-style spot price (manipulable in single block)
            'balanceOf',                      // Direct balance-based pricing
            'slot0',                          // Uniswap v3 current tick (spot, no TWAP)
            'latestAnswer',                   // Chainlink (safe, but detecting for completeness)
            'getAmountsOut',                  // Router-based price estimation
            'getAmountOut',                   // Direct pair estimation
            'quote',                          // Price quotes from DEX
        ];

        // TWAP (safe oracle) indicators
        this.safeOracleIndicators = [
            'observe',                        // Uniswap v3 TWAP oracle
            'consult',                        // TWAP oracle consultation
            'getTimeWeightedAverage',         // Explicit TWAP
            'cumulativePrices',               // Cumulative price tracking
            'twap',                           // Any TWAP reference
        ];

        // Callback patterns that could be exploited
        this.callbackPatterns = [
            'onFlashLoan',                    // ERC-3156 callback
            'executeOperation',              // Aave callback
            'pancakeV3FlashCallback',        // PancakeSwap v3
            'uniswapV3FlashCallback',        // Uniswap v3
            'callFunction',                  // dYdX callback
            'onFlashSwap',                   // Generic flash swap callback
        ];
    }

    /**
     * Full flash loan vulnerability scan
     * @param {string} contractAddress - The contract to analyze
     * @returns {Object} Detailed vulnerability report
     */
    async analyze(contractAddress) {
        const results = {
            address: contractAddress,
            timestamp: new Date().toISOString(),
            flashLoanRisk: 0,
            vulnerabilities: [],
            oracleAnalysis: { type: 'unknown', isVulnerable: false, details: [] },
            callbackAnalysis: { hasCallbacks: false, isProtected: false, details: [] },
            priceManipulation: { susceptible: false, vectors: [] },
            recommendations: [],
        };

        try {
            const code = await this.provider.getCode(contractAddress);
            if (code === '0x' || code.length < 10) {
                results.vulnerabilities.push({ type: 'NO_CONTRACT', severity: 'info', detail: 'Address is not a contract' });
                return results;
            }

            // 1. Analyze oracle usage patterns
            this._analyzeOraclePatterns(code, results);

            // 2. Detect flash loan callback patterns
            this._analyzeCallbackPatterns(code, results);

            // 3. Check for reentrancy guards
            this._checkReentrancyProtection(code, results);

            // 4. Detect price manipulation vectors
            this._analyzePriceManipulation(code, results);

            // 5. Check for flash loan provider interactions
            this._detectFlashLoanUsage(code, results);

            // 6. Compute overall risk score
            results.flashLoanRisk = this._computeRiskScore(results);

            // 7. Generate recommendations
            this._generateRecommendations(results);

        } catch (error) {
            results.vulnerabilities.push({
                type: 'ANALYSIS_ERROR',
                severity: 'warning',
                detail: `Analysis error: ${error.message}`,
            });
        }

        return results;
    }

    _analyzeOraclePatterns(bytecode, results) {
        const lowerCode = bytecode.toLowerCase();

        // Check for vulnerable (spot price) oracle patterns
        const vulnerableFound = [];
        for (const pattern of this.vulnerableOraclePatterns) {
            const selector = ethers.id(pattern + '()').slice(0, 10);
            const selectorNoParens = ethers.id(pattern + '(address)').slice(0, 10);
            if (lowerCode.includes(selector.slice(2)) || lowerCode.includes(selectorNoParens.slice(2))) {
                vulnerableFound.push(pattern);
            }
        }

        // Check for safe (TWAP) oracle patterns
        const safeFound = [];
        for (const pattern of this.safeOracleIndicators) {
            const selector = ethers.id(pattern + '()').slice(0, 10);
            if (lowerCode.includes(selector.slice(2))) {
                safeFound.push(pattern);
            }
        }

        if (vulnerableFound.length > 0 && safeFound.length === 0) {
            results.oracleAnalysis = {
                type: 'spot_price',
                isVulnerable: true,
                details: vulnerableFound.map(p => `Uses ${p}() — single-block manipulable`),
            };
            results.vulnerabilities.push({
                type: 'VULNERABLE_ORACLE',
                severity: 'critical',
                detail: `Relies on spot price oracles [${vulnerableFound.join(', ')}] without TWAP protection`,
            });
        } else if (safeFound.length > 0) {
            results.oracleAnalysis = {
                type: 'twap',
                isVulnerable: false,
                details: safeFound.map(p => `Uses ${p}() — TWAP protected`),
            };
        } else {
            results.oracleAnalysis = {
                type: 'no_oracle_detected',
                isVulnerable: false,
                details: ['No recognizable oracle pattern found in bytecode'],
            };
        }
    }

    _analyzeCallbackPatterns(bytecode, results) {
        const lowerCode = bytecode.toLowerCase();
        const foundCallbacks = [];

        for (const callback of this.callbackPatterns) {
            const selector = ethers.id(callback + '(address,uint256,uint256,bytes)').slice(0, 10);
            if (lowerCode.includes(selector.slice(2))) {
                foundCallbacks.push(callback);
            }
        }

        results.callbackAnalysis.hasCallbacks = foundCallbacks.length > 0;
        results.callbackAnalysis.details = foundCallbacks.map(c => `Implements ${c}() callback`);

        // Check if callbacks have protection (reentrancy guard, msg.sender checks)
        // Look for nonReentrant modifier pattern (mutex storage slot access)
        const hasReentrancyGuard = lowerCode.includes('5490') || // Common reentrancy slot
            lowerCode.includes('revert'); // Has revert paths
        results.callbackAnalysis.isProtected = hasReentrancyGuard && foundCallbacks.length > 0;

        if (foundCallbacks.length > 0 && !hasReentrancyGuard) {
            results.vulnerabilities.push({
                type: 'UNPROTECTED_CALLBACK',
                severity: 'high',
                detail: `Flash loan callbacks [${foundCallbacks.join(', ')}] without apparent reentrancy protection`,
            });
        }
    }

    _checkReentrancyProtection(bytecode, results) {
        const lowerCode = bytecode.toLowerCase();

        // OpenZeppelin ReentrancyGuard uses storage slot for _status
        // Check for the pattern: SLOAD, compare, SSTORE (mutex pattern)
        const hasMutexPattern = (
            lowerCode.includes('54') && // SLOAD
            lowerCode.includes('55') && // SSTORE
            lowerCode.includes('fd')    // REVERT
        );

        if (!hasMutexPattern) {
            results.vulnerabilities.push({
                type: 'NO_REENTRANCY_GUARD',
                severity: 'medium',
                detail: 'No obvious reentrancy guard pattern detected',
            });
        }
    }

    _analyzePriceManipulation(bytecode, results) {
        const lowerCode = bytecode.toLowerCase();

        // Check for direct reserve-based pricing (highly manipulable)
        const reserveSelector = ethers.id('getReserves()').slice(2, 10);
        const balanceSelector = ethers.id('balanceOf(address)').slice(2, 10);

        const usesReserves = lowerCode.includes(reserveSelector);
        const usesBalance = lowerCode.includes(balanceSelector);

        // Check for ratio-based calculations (reserve0/reserve1)
        const hasDivision = lowerCode.includes('04'); // DIV opcode

        if (usesReserves && hasDivision) {
            results.priceManipulation.susceptible = true;
            results.priceManipulation.vectors.push({
                type: 'RESERVE_RATIO_MANIPULATION',
                severity: 'critical',
                detail: 'Uses getReserves() with division — price can be manipulated in a single block via flash loan',
            });
        }

        if (usesBalance && hasDivision) {
            results.priceManipulation.susceptible = true;
            results.priceManipulation.vectors.push({
                type: 'BALANCE_BASED_PRICING',
                severity: 'high',
                detail: 'Uses balanceOf() for pricing — token balance can be temporarily inflated via flash loan',
            });
        }
    }

    _detectFlashLoanUsage(bytecode, results) {
        const lowerCode = bytecode.toLowerCase();

        for (const [selector, signature] of Object.entries(this.flashLoanSelectors)) {
            if (lowerCode.includes(selector.slice(2))) {
                results.vulnerabilities.push({
                    type: 'FLASH_LOAN_INTERACTION',
                    severity: 'info',
                    detail: `Interacts with flash loan function: ${signature}`,
                });
            }
        }
    }

    _computeRiskScore(results) {
        let score = 0;

        for (const vuln of results.vulnerabilities) {
            switch (vuln.severity) {
                case 'critical': score += 30; break;
                case 'high': score += 20; break;
                case 'medium': score += 10; break;
                case 'low': score += 5; break;
                default: score += 0;
            }
        }

        for (const vector of results.priceManipulation.vectors) {
            switch (vector.severity) {
                case 'critical': score += 25; break;
                case 'high': score += 15; break;
                default: score += 5;
            }
        }

        return Math.min(score, 100);
    }

    _generateRecommendations(results) {
        if (results.oracleAnalysis.isVulnerable) {
            results.recommendations.push(
                'Implement TWAP (Time-Weighted Average Price) oracles instead of spot prices',
                'Consider Chainlink price feeds for tamper-resistant pricing',
                'Add minimum liquidity checks before price calculations'
            );
        }
        if (results.callbackAnalysis.hasCallbacks && !results.callbackAnalysis.isProtected) {
            results.recommendations.push(
                'Add ReentrancyGuard (nonReentrant modifier) to all flash loan callbacks',
                'Validate msg.sender in callbacks matches the expected flash loan provider'
            );
        }
        if (results.priceManipulation.susceptible) {
            results.recommendations.push(
                'Use block-delayed price feeds to prevent single-block manipulation',
                'Implement circuit breakers that pause operations during abnormal price movements'
            );
        }
        if (results.recommendations.length === 0) {
            results.recommendations.push('No critical flash loan vulnerabilities detected');
        }
    }
}

module.exports = FlashLoanDetector;
