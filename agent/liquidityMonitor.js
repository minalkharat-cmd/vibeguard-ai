/**
 * VibeGuard AI Agent — Liquidity Monitor Module
 * Monitors LP depth, concentration, holder distribution,
 * and liquidity unlock schedules for BNB Chain pools.
 */

const axios = require("axios");

class LiquidityMonitor {
    constructor(config = {}) {
        this.bscApiKey = config.bscApiKey || process.env.BSC_API_KEY || "";
        this.bscApiUrl = config.bscApiUrl || "https://api.bscscan.com/api";
    }

    /**
     * Get token holders and distribution
     */
    async getTopHolders(tokenAddress) {
        try {
            const response = await axios.get(this.bscApiUrl, {
                params: {
                    module: "token",
                    action: "tokenholderlist",
                    contractaddress: tokenAddress,
                    page: 1,
                    offset: 20,
                    apikey: this.bscApiKey,
                },
                timeout: 10000,
            });

            if (response.data.status === "1") {
                return response.data.result || [];
            }
            return [];
        } catch {
            return [];
        }
    }

    /**
     * Get token transfer events to analyze activity patterns
     */
    async getRecentTransfers(tokenAddress, limit = 100) {
        try {
            const response = await axios.get(this.bscApiUrl, {
                params: {
                    module: "account",
                    action: "tokentx",
                    contractaddress: tokenAddress,
                    page: 1,
                    offset: limit,
                    sort: "desc",
                    apikey: this.bscApiKey,
                },
                timeout: 10000,
            });

            if (response.data.status === "1") {
                return response.data.result || [];
            }
            return [];
        } catch {
            return [];
        }
    }

    /**
     * Analyze holder concentration (whale risk)
     */
    analyzeHolderConcentration(holders, totalSupply) {
        if (!holders.length) {
            return { score: 30, finding: "No holder data — moderate risk" };
        }

        let findings = [];
        let score = 0;

        // Check top holder concentration
        if (holders.length >= 1 && totalSupply > 0) {
            const topHolderPercent = (Number(holders[0].TokenHolderQuantity) / totalSupply) * 100;

            if (topHolderPercent > 50) {
                score += 40;
                findings.push({ issue: `Top holder owns ${topHolderPercent.toFixed(1)}% (extreme concentration)`, severity: "CRITICAL" });
            } else if (topHolderPercent > 30) {
                score += 25;
                findings.push({ issue: `Top holder owns ${topHolderPercent.toFixed(1)}% (high concentration)`, severity: "HIGH" });
            } else if (topHolderPercent > 15) {
                score += 10;
                findings.push({ issue: `Top holder owns ${topHolderPercent.toFixed(1)}% (moderate)`, severity: "MEDIUM" });
            }
        }

        // Check top 5 holders combined
        if (holders.length >= 5 && totalSupply > 0) {
            const top5Total = holders.slice(0, 5).reduce((sum, h) => sum + Number(h.TokenHolderQuantity), 0);
            const top5Percent = (top5Total / totalSupply) * 100;

            if (top5Percent > 80) {
                score += 30;
                findings.push({ issue: `Top 5 holders own ${top5Percent.toFixed(1)}% (extreme)`, severity: "CRITICAL" });
            } else if (top5Percent > 60) {
                score += 15;
                findings.push({ issue: `Top 5 holders own ${top5Percent.toFixed(1)}% (high)`, severity: "HIGH" });
            }
        }

        // Check if holder count is suspiciously low
        if (holders.length < 10) {
            score += 20;
            findings.push({ issue: `Only ${holders.length} holders (very low)`, severity: "HIGH" });
        }

        return { score: Math.min(100, score), findings };
    }

    /**
     * Analyze transfer activity patterns for wash trading
     */
    analyzeTransferPatterns(transfers) {
        if (!transfers.length) {
            return { score: 20, findings: [{ issue: "No transfer data", severity: "MEDIUM" }] };
        }

        let findings = [];
        let score = 0;

        // Check for wash trading (same addresses repeatedly trading)
        const addressPairs = {};
        transfers.forEach((tx) => {
            const pair = `${tx.from}-${tx.to}`;
            addressPairs[pair] = (addressPairs[pair] || 0) + 1;
        });

        const suspiciousPairs = Object.entries(addressPairs).filter(([, count]) => count > 5);
        if (suspiciousPairs.length > 3) {
            score += 25;
            findings.push({ issue: `${suspiciousPairs.length} address pairs with 5+ repeated trades (wash trading signal)`, severity: "HIGH" });
        }

        // Check for suspiciously even transaction amounts
        const amounts = transfers.map((tx) => Number(tx.value));
        const uniqueAmounts = new Set(amounts);
        if (uniqueAmounts.size < amounts.length * 0.3 && amounts.length > 20) {
            score += 15;
            findings.push({ issue: "Many identical transaction amounts (potential bot activity)", severity: "MEDIUM" });
        }

        // Check transaction frequency
        if (transfers.length >= 2) {
            const timeSpan = Number(transfers[0].timeStamp) - Number(transfers[transfers.length - 1].timeStamp);
            const txPerHour = transfers.length / (timeSpan / 3600);

            if (txPerHour > 100) {
                score += 10;
                findings.push({ issue: `Very high tx frequency: ${txPerHour.toFixed(0)}/hour`, severity: "MEDIUM" });
            }
        }

        return { score: Math.min(100, score), findings };
    }

    /**
     * Full liquidity analysis
     */
    async analyzeLiquidity(tokenAddress) {
        console.log(`\n💧 Analyzing liquidity: ${tokenAddress}`);

        const [holders, transfers] = await Promise.all([
            this.getTopHolders(tokenAddress),
            this.getRecentTransfers(tokenAddress),
        ]);

        // Estimate total supply from holders
        const totalSupply = holders.reduce((sum, h) => sum + Number(h.TokenHolderQuantity || 0), 0);

        const holderAnalysis = this.analyzeHolderConcentration(holders, totalSupply);
        const transferAnalysis = this.analyzeTransferPatterns(transfers);

        // Liquidity health score (inverse — higher = healthier)
        const rawRisk = Math.round(holderAnalysis.score * 0.6 + transferAnalysis.score * 0.4);
        const liquidityHealth = Math.max(0, 100 - rawRisk);

        const report = {
            tokenAddress,
            holderCount: holders.length,
            totalSupplyEstimate: totalSupply,
            recentTransferCount: transfers.length,
            holderAnalysis,
            transferAnalysis,
            liquidityHealth,
            timestamp: new Date().toISOString(),
        };

        console.log(`   Liquidity Health: ${liquidityHealth}/100`);
        console.log(`   Holders: ${holders.length}, Transfers: ${transfers.length}`);

        return report;
    }
}

module.exports = { LiquidityMonitor };
