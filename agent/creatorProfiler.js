/**
 * VibeGuard AI Agent — Creator Profiler Module
 * Cross-references deployer wallet addresses against transaction history
 * to identify serial scammers and suspicious deployment patterns.
 */

const axios = require("axios");

class CreatorProfiler {
    constructor(config = {}) {
        this.bscApiKey = config.bscApiKey || process.env.BSC_API_KEY || "";
        this.bscApiUrl = config.bscApiUrl || "https://api.bscscan.com/api";
    }

    /**
     * Get the deployer (creator) of a contract
     */
    async getContractCreator(contractAddress) {
        try {
            const response = await axios.get(this.bscApiUrl, {
                params: {
                    module: "contract",
                    action: "getcontractcreation",
                    contractaddresses: contractAddress,
                    apikey: this.bscApiKey,
                },
                timeout: 10000,
            });

            if (response.data.status === "1" && response.data.result.length > 0) {
                return {
                    creator: response.data.result[0].contractCreator,
                    txHash: response.data.result[0].txHash,
                };
            }
            return null;
        } catch {
            return null;
        }
    }

    /**
     * Get all contracts deployed by a specific address
     */
    async getDeployedContracts(deployerAddress) {
        try {
            // Get internal transactions (contract creations show as internal txs)
            const response = await axios.get(this.bscApiUrl, {
                params: {
                    module: "account",
                    action: "txlistinternal",
                    address: deployerAddress,
                    startblock: 0,
                    endblock: 99999999,
                    page: 1,
                    offset: 100,
                    sort: "desc",
                    apikey: this.bscApiKey,
                },
                timeout: 10000,
            });

            if (response.data.status === "1") {
                // Filter for contract creation transactions
                const creations = response.data.result.filter(
                    (tx) => tx.type === "create" || tx.type === "create2"
                );
                return creations;
            }
            return [];
        } catch {
            return [];
        }
    }

    /**
     * Get wallet balance and age
     */
    async getWalletInfo(address) {
        try {
            const [balanceRes, txListRes] = await Promise.all([
                axios.get(this.bscApiUrl, {
                    params: {
                        module: "account",
                        action: "balance",
                        address: address,
                        tag: "latest",
                        apikey: this.bscApiKey,
                    },
                    timeout: 10000,
                }),
                axios.get(this.bscApiUrl, {
                    params: {
                        module: "account",
                        action: "txlist",
                        address: address,
                        startblock: 0,
                        endblock: 99999999,
                        page: 1,
                        offset: 5,
                        sort: "asc",
                        apikey: this.bscApiKey,
                    },
                    timeout: 10000,
                }),
            ]);

            const balance = balanceRes.data.result
                ? Number(balanceRes.data.result) / 1e18
                : 0;

            const firstTx = txListRes.data.result?.[0];
            const walletAge = firstTx
                ? Math.floor((Date.now() / 1000 - Number(firstTx.timeStamp)) / 86400)
                : 0;

            return { balance, walletAgeDays: walletAge, firstTxTimestamp: firstTx?.timeStamp };
        } catch {
            return { balance: 0, walletAgeDays: 0 };
        }
    }

    /**
     * Profile the creator of a contract
     */
    async profileCreator(contractAddress) {
        console.log(`\n👤 Profiling creator of: ${contractAddress}`);

        const creatorInfo = await this.getContractCreator(contractAddress);
        if (!creatorInfo) {
            return {
                contractAddress,
                riskScore: 30,
                findings: [{ issue: "Could not identify contract creator", severity: "MEDIUM" }],
            };
        }

        const [deployedContracts, walletInfo] = await Promise.all([
            this.getDeployedContracts(creatorInfo.creator),
            this.getWalletInfo(creatorInfo.creator),
        ]);

        let score = 0;
        let findings = [];

        // New wallet risk
        if (walletInfo.walletAgeDays < 7) {
            score += 30;
            findings.push({ issue: `Wallet is only ${walletInfo.walletAgeDays} days old (very new)`, severity: "HIGH" });
        } else if (walletInfo.walletAgeDays < 30) {
            score += 15;
            findings.push({ issue: `Wallet is ${walletInfo.walletAgeDays} days old (relatively new)`, severity: "MEDIUM" });
        } else if (walletInfo.walletAgeDays > 365) {
            score -= 10;
            findings.push({ issue: `Wallet is ${walletInfo.walletAgeDays} days old (established)`, severity: "LOW" });
        }

        // Serial deployer risk
        if (deployedContracts.length > 20) {
            score += 30;
            findings.push({ issue: `Deployed ${deployedContracts.length} contracts (serial deployer — high scam signal)`, severity: "CRITICAL" });
        } else if (deployedContracts.length > 10) {
            score += 15;
            findings.push({ issue: `Deployed ${deployedContracts.length} contracts (prolific deployer)`, severity: "HIGH" });
        } else if (deployedContracts.length > 5) {
            score += 5;
            findings.push({ issue: `Deployed ${deployedContracts.length} contracts`, severity: "MEDIUM" });
        }

        // Low balance risk (drained wallet)
        if (walletInfo.balance < 0.01) {
            score += 15;
            findings.push({ issue: `Very low balance: ${walletInfo.balance.toFixed(4)} BNB (potentially drained)`, severity: "HIGH" });
        }

        const report = {
            contractAddress,
            creatorAddress: creatorInfo.creator,
            creationTxHash: creatorInfo.txHash,
            walletAgeDays: walletInfo.walletAgeDays,
            walletBalance: walletInfo.balance,
            deployedContractCount: deployedContracts.length,
            riskScore: Math.min(100, Math.max(0, score)),
            findings,
            timestamp: new Date().toISOString(),
        };

        console.log(`   Creator: ${creatorInfo.creator}`);
        console.log(`   Wallet Age: ${walletInfo.walletAgeDays} days`);
        console.log(`   Contracts Deployed: ${deployedContracts.length}`);
        console.log(`   Creator Risk Score: ${report.riskScore}/100`);

        return report;
    }
}

module.exports = { CreatorProfiler };
