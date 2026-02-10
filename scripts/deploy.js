const { ethers } = require("hardhat");

async function main() {
    console.log("🛡️  Deploying VibeGuard AI Enterprise contracts...\n");

    const [deployer] = await ethers.getSigners();
    console.log("Deployer address:", deployer.address);
    console.log("Balance:", ethers.formatEther(await ethers.provider.getBalance(deployer.address)), "BNB\n");

    // ─── 1. Deploy VibeGuardRiskNFT ───
    console.log("📦 Deploying VibeGuardRiskNFT...");
    const VibeGuardRiskNFT = await ethers.getContractFactory("VibeGuardRiskNFT");
    const riskNFT = await VibeGuardRiskNFT.deploy();
    await riskNFT.waitForDeployment();
    const riskNFTAddress = await riskNFT.getAddress();
    console.log("✅ VibeGuardRiskNFT deployed to:", riskNFTAddress);

    // ─── 2. Deploy VibeGuardAgentRegistry (ERC-8004) ───
    console.log("\n📦 Deploying VibeGuardAgentRegistry (ERC-8004)...");
    const VibeGuardAgentRegistry = await ethers.getContractFactory("VibeGuardAgentRegistry");
    const agentRegistry = await VibeGuardAgentRegistry.deploy();
    await agentRegistry.waitForDeployment();
    const agentRegistryAddress = await agentRegistry.getAddress();
    console.log("✅ VibeGuardAgentRegistry deployed to:", agentRegistryAddress);

    // ─── 3. Demo: Register a sample token risk score ───
    console.log("\n🧪 Running demo operations...");

    const sampleToken = "0xae13d989daC2f0dEbFf460aC112a837C89BAa7cd"; // WBNB Testnet
    const tx1 = await riskNFT.registerToken(sampleToken);
    await tx1.wait();
    console.log("✅ Registered sample token (WBNB Testnet)");

    const tx2 = await riskNFT.updateRiskScore(sampleToken, 25, 5, 10, 85);
    await tx2.wait();
    console.log("✅ Updated risk score: 25 (LOW)");

    const [riskScore, riskLevel, lastUpdated] = await riskNFT.queryRisk(sampleToken);
    console.log(`\n📊 Risk Query Result:`);
    console.log(`   Score: ${riskScore}`);
    console.log(`   Level: ${riskLevel}`);
    console.log(`   Updated: ${new Date(Number(lastUpdated) * 1000).toISOString()}`);

    const safe = await riskNFT.isSafe(sampleToken, 40);
    console.log(`   Safe (threshold 40): ${safe}`);

    // ─── 4. Demo: Register agent in ERC-8004 registry ───
    console.log("\n🆔 Registering VibeGuard agent identity (ERC-8004)...");
    const tx3 = await agentRegistry.registerAgent(
        deployer.address,
        "risk-scanner",
        "ipfs://QmVibeGuardAgentRegistration/metadata.json"
    );
    await tx3.wait();
    console.log("✅ Agent registered as ERC-8004 identity (ID: 0)");

    // Query agent info
    const metadata = await agentRegistry.agentMetadata(0);
    const isActive = await agentRegistry.isAgentActive(0);
    console.log(`   Type: ${metadata.agentType}`);
    console.log(`   Active: ${isActive}`);

    // ─── Summary ───
    const network = await ethers.provider.getNetwork();
    console.log("\n==========================================");
    console.log("🛡️  VibeGuard AI Enterprise Deployment");
    console.log("==========================================");
    console.log(`VibeGuardRiskNFT:      ${riskNFTAddress}`);
    console.log(`VibeGuardAgentRegistry: ${agentRegistryAddress}`);
    console.log(`Network: ${network.name}`);
    console.log(`Chain ID: ${network.chainId}`);
    console.log("==========================================\n");

    // Save deployment info
    const fs = require("fs");
    const deploymentInfo = {
        network: network.name,
        chainId: Number(network.chainId),
        contracts: {
            VibeGuardRiskNFT: riskNFTAddress,
            VibeGuardAgentRegistry: agentRegistryAddress,
        },
        deployer: deployer.address,
        timestamp: new Date().toISOString(),
    };
    fs.writeFileSync("deployment.json", JSON.stringify(deploymentInfo, null, 2));
    console.log("📄 Deployment info saved to deployment.json");
}

main()
    .then(() => process.exit(0))
    .catch((error) => {
        console.error(error);
        process.exit(1);
    });
