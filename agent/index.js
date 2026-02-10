/**
 * VibeGuard AI Agent — Main Orchestrator
 * Coordinates all analysis modules and publishes risk scores on-chain.
 */

require("dotenv").config({ path: require("path").resolve(__dirname, "../.env") });
const { ethers } = require("ethers");
const { ContractAnalyzer } = require("./contractAnalyzer");
const { LiquidityMonitor } = require("./liquidityMonitor");
const { CreatorProfiler } = require("./creatorProfiler");

// ABI for VibeGuardRiskNFT (minimal interface)
const RISK_NFT_ABI = [
    "function registerToken(address tokenAddress) external returns (uint256)",
    "function updateRiskScore(address tokenAddress, uint8 riskScore, uint8 honeypotScore, uint8 rugPullScore, uint8 liquidityScore) external",
    "function queryRisk(address tokenAddress) external view returns (uint8 riskScore, string riskLevel, uint256 lastUpdated)",
    "function getFullRiskReport(address tokenAddress) external view returns (tuple(address tokenAddress, uint8 riskScore, uint8 honeypotScore, uint8 rugPullScore, uint8 liquidityScore, uint256 lastUpdated, bool isActive, string riskLevel))",
    "function isSafe(address tokenAddress, uint8 maxRisk) external view returns (bool)",
    "function isRegistered(address) external view returns (bool)",
    "function totalTokens() external view returns (uint256)",
    "event RiskScoreUpdated(uint256 indexed tokenId, address indexed tokenAddress, uint8 riskScore, string riskLevel, uint256 timestamp)",
    "event AlertTriggered(uint256 indexed tokenId, address indexed tokenAddress, uint8 riskScore, string alertType)",
];

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

        // Scan history
        this.scanHistory = new Map();
    }

    /**
     * Initialize blockchain connection
     */
    async initialize() {
        console.log("\n🛡️  VibeGuard AI Agent Initializing...\n");

        if (this.privateKey && this.contractAddress) {
            this.provider = new ethers.JsonRpcProvider(this.rpcUrl);
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
        console.log("═".repeat(60));
        console.log(`🔍 VIBEGUARD FULL SCAN: ${tokenAddress}`);
        console.log("═".repeat(60));

        const startTime = Date.now();

        // Run all analyses in parallel
        const [contractReport, liquidityReport, creatorReport] = await Promise.all([
            this.contractAnalyzer.analyzeContract(tokenAddress),
            this.liquidityMonitor.analyzeLiquidity(tokenAddress),
            this.creatorProfiler.profileCreator(tokenAddress),
        ]);

        // Aggregate final scores
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
            contractReport.overallRisk * 0.4 +
            honeypotScore * 0.25 +
            rugPullScore * 0.2 +
            (100 - liquidityScore) * 0.15
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
            contractAnalysis: contractReport,
            liquidityAnalysis: liquidityReport,
            creatorProfile: creatorReport,
            scanTimeSeconds: scanTime,
            timestamp: new Date().toISOString(),
        };

        // Print summary
        console.log("\n" + "═".repeat(60));
        console.log("📊 VIBEGUARD RISK REPORT");
        console.log("═".repeat(60));
        console.log(`Token:        ${tokenAddress}`);
        console.log(`Contract:     ${contractReport.contractName || "Unknown"}`);
        console.log(`Verified:     ${contractReport.isVerified ? "✅ Yes" : "❌ No"}`);
        console.log(`─────────────────────────────────────────`);
        console.log(`Overall Risk: ${overallRisk}/100 [${riskLevel}]`);
        console.log(`Honeypot:     ${honeypotScore}/100`);
        console.log(`Rug Pull:     ${rugPullScore}/100`);
        console.log(`Liquidity:    ${liquidityScore}/100`);
        console.log(`─────────────────────────────────────────`);
        console.log(`Creator:      ${creatorReport.creatorAddress || "Unknown"}`);
        console.log(`Wallet Age:   ${creatorReport.walletAgeDays || "?"} days`);
        console.log(`Contracts:    ${creatorReport.deployedContractCount || "?"} deployed`);
        console.log(`─────────────────────────────────────────`);
        console.log(`Scan Time:    ${scanTime}s`);
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
