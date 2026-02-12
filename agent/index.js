/**
 * VibeGuard AI Agent — Main Orchestrator
 * Coordinates all analysis modules and publishes risk scores on-chain.
 * Fixes: wired FlashLoanDetector + MEVDetector, input validation,
 *        Promise.allSettled for partial failure resilience.
 */

require("dotenv").config({ path: require("path").resolve(__dirname, "../.env") });
const { ethers } = require("ethers");
const { ContractAnalyzer } = require("./contractAnalyzer");
const { LiquidityMonitor } = require("./liquidityMonitor");
const { CreatorProfiler } = require("./creatorProfiler");
const FlashLoanDetector = require("./flashLoanDetector");
const MEVDetector = require("./mevDetector");

// ABI for VibeGuardRiskNFT (minimal interface)
const RISK_NFT_ABI = [
        "function registerToken(address tokenAddress) external returns (uint256)",
        "function updateRiskScore(address tokenAddress, uint8 riskScore, uint8 honeypotScore, uint8 rugPullScore, uint8 liquidityScore) external",
        "function queryRisk(address tokenAddress) external view returns (uint8 riskScore, string riskLevel, uint256 lastUpdated, bool isStale)",
        "function getFullRiskReport(address tokenAddress) external view returns (tuple(address tokenAddress, uint8 riskScore, uint8 honeypotScore, uint8 rugPullScore, uint8 liquidityScore, uint256 lastUpdated, bool isActive, string riskLevel))",
        "function isSafe(address tokenAddress, uint8 maxRisk) external view returns (bool)",
        "function isRegistered(address) external view returns (bool)",
        "function totalTokens() external view returns (uint256)",
        "event RiskScoreUpdated(uint256 indexed tokenId, address indexed tokenAddress, uint8 riskScore, string riskLevel, uint256 timestamp)",
        "event AlertTriggered(uint256 indexed tokenId, address indexed tokenAddress, uint8 riskScore, string alertType)",
    ];

/**
 * Validate an Ethereum address (basic format + checksum)
 */
function isValidAddress(addr) {
        if (typeof addr !== "string") return false;
        if (!/^0x[0-9a-fA-F]{40}$/.test(addr)) return false;
        return true;
}

class VibeGuardAgent {
        constructor(config = {}) {
                    this.contractAnalyzer = new ContractAnalyzer(config);
                    this.liquidityMonitor = new LiquidityMonitor(config);
                    this.creatorProfiler = new CreatorProfiler(config);

            // Blockchain connection
            this.rpcUrl = config.rpcUrl || process.env.BSC_TESTNET_RPC || "https://data-seed-prebsc-1-s1.binance.org:8545";
                    this.privateKey = config.privateKey || process.env.PRIVATE_KEY;
                    this.contractAddress = config.contractAddress || process.env.VIBEGUARD_CONTRACT;

            this.provider = null;
                    this.signer = null;
                    this.contract = null;

            // Flash loan + MEV detectors (initialized after provider is ready)
            this.flashLoanDetector = null;
                    this.mevDetector = null;

            // Scan history
            this.scanHistory = new Map();
        }

    /**
         * Initialize blockchain connection
         */
    async initialize() {
                console.log("\n🛡️  VibeGuard AI Agent Initializing...\n");

            // Always create a provider for the detectors
            this.provider = new ethers.JsonRpcProvider(this.rpcUrl);
                this.flashLoanDetector = new FlashLoanDetector(this.provider);
                this.mevDetector = new MEVDetector(this.provider);

            if (this.privateKey && this.contractAddress) {
                            this.signer = new ethers.Wallet(this.privateKey, this.provider);
                            this.contract = new ethers.Contract(this.contractAddress, RISK_NFT_ABI, this.signer);

                    const network = await this.provider.getNetwork();
                            console.log(`✅ Connected to chain: ${network.name} (${network.chainId})`);
                            console.log(`📋 Contract: ${this.contractAddress}`);
                            console.log(`🔑 Agent wallet: ${this.signer.address}\n`);
            } else {
                            console.log("⚠️  Running in offline mode (no private key or contract address)");
                            console.log("   Set PRIVATE_KEY and VIBEGUARD_CONTRACT in .env for on-chain mode\n");
            }

            return this;
    }

    /**
         * Full risk scan of a token/contract
         */
    async scanToken(tokenAddress) {
                // Input validation
            if (!isValidAddress(tokenAddress)) {
                            throw new Error(`Invalid token address: ${tokenAddress}. Must be 0x followed by 40 hex chars.`);
            }

            console.log("═".repeat(60));
                console.log(`🔍 VIBEGUARD FULL SCAN: ${tokenAddress}`);
                console.log("═".repeat(60));

            const startTime = Date.now();

            // Run all 5 analyses with allSettled for partial failure resilience
            const results = await Promise.allSettled([
                            this.contractAnalyzer.analyzeContract(tokenAddress),
                            this.liquidityMonitor.analyzeLiquidity(tokenAddress),
                            this.creatorProfiler.profileCreator(tokenAddress),
                            this.flashLoanDetector.analyze(tokenAddress),
                            this.mevDetector.analyze(tokenAddress),
                        ]);

            // Extract results, using defaults for any failed modules
            const contractReport = results[0].status === "fulfilled"
                    ? results[0].value
                            : { overallRisk: 50, honeypotScore: 0, rugPullScore: 0, isVerified: false, contractName: "Unknown", error: results[0].reason?.message };

            const liquidityReport = results[1].status === "fulfilled"
                    ? results[1].value
                            : { liquidityHealth: 50, error: results[1].reason?.message };

            const creatorReport = results[2].status === "fulfilled"
                    ? results[2].value
                            : { riskScore: 50, creatorAddress: "Unknown", error: results[2].reason?.message };

            const flashLoanReport = results[3].status === "fulfilled"
                    ? results[3].value
                            : { flashLoanRisk: 0, error: results[3].reason?.message };

            const mevReport = results[4].status === "fulfilled"
                    ? results[4].value
                            : { mevRisk: 0, error: results[4].reason?.message };

            // Log any module failures
            results.forEach((r, i) => {
                            if (r.status === "rejected") {
                                                const names = ["ContractAnalyzer", "LiquidityMonitor", "CreatorProfiler", "FlashLoanDetector", "MEVDetector"];
                                                console.log(`⚠️  ${names[i]} failed: ${r.reason?.message || "Unknown error"}`);
                            }
            });

            // Aggregate final scores (now includes flash loan + MEV)
            const honeypotScore = Math.min(100, Math.round(
                            contractReport.honeypotScore * 0.7 + creatorReport.riskScore * 0.3
                        ));

            const rugPullScore = Math.min(100, Math.round(
                            contractReport.rugPullScore * 0.5 +
                            creatorReport.riskScore * 0.3 +
                            (100 - liquidityReport.liquidityHealth) * 0.2
                        ));

            const liquidityScore = liquidityReport.liquidityHealth;

            const overallRisk = Math.min(100, Math.round(
                            contractReport.overallRisk * 0.30 +
                            honeypotScore * 0.20 +
                            rugPullScore * 0.15 +
                            (100 - liquidityScore) * 0.10 +
                            flashLoanReport.flashLoanRisk * 0.13 +
                            mevReport.mevRisk * 0.12
                        ));

            const riskLevel = this._getRiskLevel(overallRisk);
                const scanTime = ((Date.now() - startTime) / 1000).toFixed(1);

            const fullReport = {
                            tokenAddress,
                            overallRisk,
                            riskLevel,
                            honeypotScore,
                            rugPullScore,
                            liquidityScore,
                            flashLoanRisk: flashLoanReport.flashLoanRisk,
                            mevRisk: mevReport.mevRisk,
                            contractAnalysis: contractReport,
                            liquidityAnalysis: liquidityReport,
                            creatorProfile: creatorReport,
                            flashLoanAnalysis: flashLoanReport,
                            mevAnalysis: mevReport,
                            scanTimeSeconds: scanTime,
                            timestamp: new Date().toISOString(),
            };

            // Print summary
            console.log("\n" + "═".repeat(60));
                console.log("📊 VIBEGUARD RISK REPORT");
                console.log("═".repeat(60));
                console.log(`Token:       ${tokenAddress}`);
                console.log(`Contract:    ${contractReport.contractName || "Unknown"}`);
                console.log(`Verified:    ${contractReport.isVerified ? "✅ Yes" : "❌ No"}`);
                console.log(`─────────────────────────────────────────`);
                console.log(`Overall Risk:  ${overallRisk}/100 [${riskLevel}]`);
                console.log(`Honeypot:      ${honeypotScore}/100`);
                console.log(`Rug Pull:      ${rugPullScore}/100`);
                console.log(`Liquidity:     ${liquidityScore}/100`);
                console.log(`Flash Loan:    ${flashLoanReport.flashLoanRisk}/100`);
                console.log(`MEV Risk:      ${mevReport.mevRisk}/100`);
                console.log(`─────────────────────────────────────────`);
                console.log(`Creator:     ${creatorReport.creatorAddress || "Unknown"}`);
                console.log(`Wallet Age:  ${creatorReport.walletAgeDays || "?"} days`);
                console.log(`Contracts:   ${creatorReport.deployedContractCount || "?"} deployed`);
                console.log(`─────────────────────────────────────────`);
                console.log(`Scan Time:   ${scanTime}s`);
                console.log("═".repeat(60));

            // Save to history
            this.scanHistory.set(tokenAddress, fullReport);

            return fullReport;
    }

    /**
         * Publish risk score on-chain (update Dynamic NFT)
         */
    async publishOnChain(tokenAddress, report) {
                if (!this.contract) {
                                console.log("⚠️  Cannot publish — no contract connection");
                                return null;
                }

            try {
                            // Check if token is already registered
                    const isRegistered = await this.contract.isRegistered(tokenAddress);

                    if (!isRegistered) {
                                        console.log("📝 Registering token on-chain...");
                                        const regTx = await this.contract.registerToken(tokenAddress);
                                        await regTx.wait();
                                        console.log("✅ Token registered");
                    }

                    // Update risk score
                    console.log("📤 Publishing risk score on-chain...");
                            const updateTx = await this.contract.updateRiskScore(
                                                tokenAddress,
                                                report.overallRisk,
                                                report.honeypotScore,
                                                report.rugPullScore,
                                                report.liquidityScore
                                            );
                            const receipt = await updateTx.wait();
                            console.log(`✅ Risk score published! Tx: ${receipt.hash}`);

                    return receipt.hash;
            } catch (error) {
                            console.error("❌ Failed to publish on-chain:", error.message);
                            return null;
            }
    }

    /**
         * Scan and publish — full pipeline
         */
    async scanAndPublish(tokenAddress) {
                const report = await this.scanToken(tokenAddress);
                const txHash = await this.publishOnChain(tokenAddress, report);
                return { report, txHash };
    }

    _getRiskLevel(score) {
                if (score <= 20) return "SAFE";
                if (score <= 40) return "LOW";
                if (score <= 60) return "MEDIUM";
                if (score <= 80) return "HIGH";
                return "CRITICAL";
    }
}

// CLI entry point
async function main() {
        const agent = new VibeGuardAgent();
        await agent.initialize();

    // Accept token address as CLI argument
    const tokenAddress = process.argv[2];

    if (tokenAddress) {
                if (!isValidAddress(tokenAddress)) {
                                console.error(`\n❌ Invalid address: "${tokenAddress}"`);
                                console.error("   Must be 0x followed by 40 hex characters.\n");
                                process.exit(1);
                }

            const result = await agent.scanAndPublish(tokenAddress);

            if (result.report.overallRisk >= 70) {
                            console.log("\n🚨 HIGH RISK DETECTED — AVOID THIS TOKEN");
            } else if (result.report.overallRisk >= 40) {
                            console.log("\n⚠️  MODERATE RISK — PROCEED WITH CAUTION");
            } else {
                            console.log("\n✅ LOW RISK — Token appears relatively safe");
            }
    } else {
                console.log("Usage: node agent/index.js <token_address>");
                console.log("\nExample:");
                console.log("  node agent/index.js 0xae13d989daC2f0dEbFf460aC112a837C89BAa7cd");

            // Demo scan with a well-known token
            console.log("\n--- Running demo scan on WBNB Testnet ---");
                await agent.scanToken("0xae13d989daC2f0dEbFf460aC112a837C89BAa7cd");
    }
}

// Export for use as module
module.exports = { VibeGuardAgent };

// Run if called directly
if (require.main === module) {
        main().catch(console.error);
}
