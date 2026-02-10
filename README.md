# 🛡️ VibeGuard AI — Enterprise On-Chain Risk Intelligence for BNB Chain

<div align="center">
  <h3>30+ GoPlus-Equivalent Detection Fields | ERC-8004 Agent Identity | Flash Loan & MEV Analysis</h3>
  <p><strong>Good Vibes Only: OpenClaw Edition | BNBChain Hackathon 2026</strong></p>
  <br/>
  <img src="https://img.shields.io/badge/BNB%20Chain-BSC-F0B90B?style=for-the-badge" alt="BNB Chain"/>
  <img src="https://img.shields.io/badge/Solidity-0.8.24-363636?style=for-the-badge" alt="Solidity"/>
  <img src="https://img.shields.io/badge/ERC--8004-Agent%20Identity-blue?style=for-the-badge" alt="ERC-8004"/>
  <img src="https://img.shields.io/badge/Detection-33%20Fields-06d6a0?style=for-the-badge" alt="33 Fields"/>
  <img src="https://img.shields.io/badge/AI%20Agent-Enterprise-8b5cf6?style=for-the-badge" alt="Enterprise"/>
</div>

---

## 🎯 What is VibeGuard AI?

**VibeGuard AI** is an enterprise-grade autonomous AI agent that performs **33-field security analysis** on BNB Chain tokens — covering honeypots, rug pulls, flash loan vulnerabilities, MEV/sandwich attacks, and ownership risks — then publishes verifiable risk scores as **Dynamic NFTs** that other AI agents and DeFi protocols can **query directly on-chain**.

The agent is registered as a **first-class ERC-8004 identity** with on-chain reputation and pluggable validation, enabling trustless agent-to-agent composability.

```
🔍 33-Field Scan → 💰 Flash Loan Check → 🥪 MEV Analysis → ⛓️ On-Chain NFT → 🤖 Agent Query → ⭐ Reputation
```

### Why This Matters

| Problem | VibeGuard Solution |
|:---|:---|
| AI trading agents can't assess token safety | On-chain `queryRisk()` / `isSafe()` — no API keys needed |
| Token scanners check only ~10 fields | **33 GoPlus-equivalent detection fields** across 7 categories |
| Flash loan attacks drain $100M+/year | Dedicated oracle, callback, and manipulation analysis |
| MEV bots sandwich unsuspecting traders | Slippage exposure scoring and bot pattern detection |
| No agent identity or reputation system | **ERC-8004** NFT identity with on-chain reputation registry |
| Risk data is off-chain and centralized | Dynamic NFTs with risk scores stored on-chain |

---

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│                     VibeGuard AI Agent (Enterprise)                  │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────────────────┐  │
│  │  Contract     │  │  Flash Loan  │  │  MEV/Sandwich            │  │
│  │  Analyzer     │  │  Detector    │  │  Detector                │  │
│  │  ─ 33 fields  │  │  ─ Oracles   │  │  ─ Sandwich risk        │  │
│  │  ─ Honeypots  │  │  ─ Callbacks │  │  ─ Slippage exposure    │  │
│  │  ─ Rug pulls  │  │  ─ Price     │  │  ─ Bot detection        │  │
│  │  ─ Proxy/Fake │  │  manipulation│  │  ─ Dynamic fees         │  │
│  └──────┬───────┘  └──────┬───────┘  └──────────┬───────────────┘  │
│  ┌──────┴───────┐  ┌──────┴───────┐              │                  │
│  │  Liquidity   │  │  Creator     │              │                  │
│  │  Monitor     │  │  Profiler    │              │                  │
│  └──────┬───────┘  └──────┬───────┘              │                  │
│         └──────────────────┼─────────────────────┘                  │
│                            ▼                                        │
│                   Risk Scoring Engine                               │
│                   (7-Category Weighted)                             │
└────────────────────────────┬────────────────────────────────────────┘
                             │
              ┌──────────────┼──────────────┐
              ▼                              ▼
 ┌─────────────────────────┐  ┌────────────────────────────────┐
 │  VibeGuardRiskNFT.sol   │  │  VibeGuardAgentRegistry.sol    │
 │  (BSC / opBNB)          │  │  (ERC-8004 Standard)           │
 │  ─ registerToken()      │  │  ─ Identity Registry (NFT)     │
 │  ─ updateRiskScore()    │  │  ─ Reputation Registry         │
 │  ─ queryRisk() ← 🤖    │  │  ─ Validation Registry         │
 │  ─ isSafe() ← 🤖       │  │  ─ Circuit Breaker (Pausable)  │
 │  ─ Dynamic SVG NFTs     │  │  ─ giveFeedback()              │
 └─────────────────────────┘  └────────────────────────────────┘
```

---

## 🚀 Quick Start

### Prerequisites
- Node.js v18+
- npm or yarn

### Install & Build
```bash
git clone https://github.com/YOUR_USERNAME/vibeguard-ai.git
cd vibeguard-ai
npm install
npx hardhat compile
```

### Run the AI Agent
```bash
node agent/index.js 0xae13d989daC2f0dEbFf460aC112a837C89BAa7cd
```

### Deploy to BSC Testnet
```bash
cp .env.example .env
# Add your PRIVATE_KEY and BSC_API_KEY
npx hardhat run scripts/deploy.js --network bscTestnet
```

### Open the Enterprise Dashboard
```bash
open frontend/index.html
```

---

## 📂 Project Structure

```
vibeguard-ai/
├── contracts/
│   ├── VibeGuardRiskNFT.sol          # Dynamic Risk NFT (ERC-721)
│   └── VibeGuardAgentRegistry.sol    # ERC-8004 Agent Identity Registry
├── agent/
│   ├── index.js                      # Main agent orchestrator
│   ├── contractAnalyzer.js           # 33-field GoPlus-equivalent analysis
│   ├── flashLoanDetector.js          # Flash loan vulnerability detection
│   ├── mevDetector.js                # MEV/sandwich attack detection
│   ├── liquidityMonitor.js           # Holder & liquidity analysis
│   └── creatorProfiler.js            # Deployer wallet profiling
├── frontend/
│   ├── index.html                    # Enterprise dashboard
│   ├── styles.css                    # Premium dark-mode design system
│   └── app.js                        # Scanner, field grid, watchlist
├── scripts/
│   └── deploy.js                     # Hardhat deployment script
├── hardhat.config.js                 # Solidity config (BSC/opBNB)
└── package.json
```

---

## 🔍 33 GoPlus-Equivalent Detection Fields

### Contract Security (6 fields)
`is_open_source` · `is_proxy` · `has_selfdestruct` · `has_external_call` · `is_upgradeable` · `has_assembly`

### Honeypot Detection (7 fields)
`is_honeypot` · `transfer_pausable` · `is_blacklisted` · `is_whitelisted` · `trading_cooldown` · `has_trading_toggle` · `personal_slippage_mod`

### Ownership Risks (4 fields)
`hidden_owner` · `can_take_back_ownership` · `owner_change_balance` · `is_ownership_renounced`

### Supply Manipulation (3 fields)
`is_mintable` · `is_burnable` · `unlimited_supply`

### Tax & Fees (5 fields)
`tax_modifiable` · `has_buy_tax` · `has_sell_tax` · `high_tax_risk` · `is_buy_back`

### Trading Restrictions (4 fields)
`is_anti_whale` · `anti_whale_modifiable` · `has_max_tx` · `has_max_wallet`

### Fraud & Rug Pull (6 fields)
`fake_token` · `fake_standard_interface` · `can_reinit` · `can_remove_liquidity` · `has_liquidity_lock` · `owner_can_drain`

---

## 🆔 ERC-8004 Agent Identity

VibeGuard implements the full **ERC-8004 "Trustless Agents"** standard:

| Registry | Functions | Purpose |
|:---|:---|:---|
| **Identity** | `registerAgent()`, `setAgentURI()` | ERC-721 NFT per agent with JSON metadata |
| **Reputation** | `giveFeedback()`, `getAverageReputation()` | On-chain client feedback with tags |
| **Validation** | `validationRequest()`, `validationResponse()` | Pluggable trust models (zkML, TEE, etc.) |

```solidity
// Register VibeGuard as an ERC-8004 agent
uint256 agentId = registry.registerAgent(wallet, "risk-scanner", "ipfs://...");

// Give reputation feedback
registry.giveFeedback(agentId, 92, 0, "accuracy", "", "", "", bytes32(0));

// Query average reputation
(int256 avg, uint256 count) = registry.getAverageReputation(agentId);
```

---

## 🔗 Smart Contract API

### For AI Agents & DeFi Protocols

```solidity
// Quick safety check before trading
bool safe = vibeGuard.isSafe(tokenAddress, 50);
require(safe, "Token risk too high");

// Get detailed risk breakdown
(uint8 score, string memory level, uint256 updated) =
    vibeGuard.queryRisk(tokenAddress);

// Full risk report with flash loan + MEV scores
VibeGuardRiskNFT.RiskData memory report =
    vibeGuard.getFullRiskReport(tokenAddress);
```

### Risk Score Scale

| Score | Level | Meaning |
|:---:|:---|:---|
| 0-20 | 🟢 SAFE | Low risk, standard token patterns |
| 21-40 | 🟡 LOW | Minor concerns, proceed with caution |
| 41-60 | 🟠 MEDIUM | Multiple risk signals detected |
| 61-80 | 🔴 HIGH | Significant risks — not recommended |
| 81-100 | ⛔ CRITICAL | Extreme risk — likely scam |

---

## 🧠 AI Analysis Modules

### 1. Contract Analyzer (33 fields)
- GoPlus-equivalent analysis across 7 risk categories
- Bytecode selector scanning + source code pattern matching
- Fake token detection against mainstream token names

### 2. Flash Loan Detector
- Oracle vulnerability analysis (spot price vs TWAP)
- Unprotected callback detection (ERC-3156, Aave, PancakeSwap v3)
- Price manipulation vectors and reentrancy guard verification

### 3. MEV/Sandwich Detector
- Sandwich attack susceptibility scoring
- Slippage exposure in DEX swap functions
- Bot pattern detection (multicall, flash swap, arbitrage selectors)

### 4. Liquidity Monitor
- Top holder concentration and whale risk
- Wash trading detection through address-pair analysis
- LP depth and holder count analysis

### 5. Creator Profiler
- Deployer wallet age and history
- Serial deployer detection (20+ contracts = scam signal)
- Wallet balance drainage patterns

---

## 🖥️ Enterprise Dashboard

The web dashboard includes:
- **🔴 Live Threat Feed** — Real-time scrolling ticker of detected threats
- **🔍 Enterprise Scanner** — Multi-phase scan with 33 detection fields
- **🆔 ERC-8004 Agent Panel** — Identity / Reputation / Validation cards
- **📊 Token Watchlist** — Persistent risk tracking table
- **💻 3-Tab API Docs** — Solidity, JavaScript, and ERC-8004 code examples

---

## 🏆 Hackathon Track

**Good Vibes Only: OpenClaw Edition | BNBChain 2026**

- **Track:** AI Agent × On-chain Actions + Platform Technology
- **On-chain Proof:** Dynamic Risk NFTs + ERC-8004 Agent Registry on BSC
- **Innovation:** First agent-to-agent queryable risk intelligence protocol with reputation on BNB Chain
- **Enterprise:** 33-field GoPlus-equivalent scanner + Flash Loan + MEV detection

---

## 📜 License

MIT License — built for the open-source agent economy.
