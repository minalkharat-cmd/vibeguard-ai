const { expect } = require("chai");
const { ethers } = require("hardhat");

describe("VibeGuardRiskNFT", function () {
      let vibeGuard;
      let owner, agent, user;
      const DUMMY_TOKEN = "0x1111111111111111111111111111111111111111";
      const DUMMY_TOKEN_2 = "0x2222222222222222222222222222222222222222";

             beforeEach(async function () {
                       [owner, agent, user] = await ethers.getSigners();
                       const Factory = await ethers.getContractFactory("VibeGuardRiskNFT");
                       vibeGuard = await Factory.deploy();
             });

             // ── Deployment ──────────────────────────────────────────
             describe("Deployment", function () {
                       it("should set deployer as owner", async function () {
                                     expect(await vibeGuard.owner()).to.equal(owner.address);
                       });

                              it("should authorize deployer as agent", async function () {
                                            expect(await vibeGuard.authorizedAgents(owner.address)).to.be.true;
                              });

                              it("should start with 0 tokens", async function () {
                                            expect(await vibeGuard.totalTokens()).to.equal(0);
                              });

                              it("should have 24h default staleness threshold", async function () {
                                            expect(await vibeGuard.stalenessThreshold()).to.equal(24 * 60 * 60);
                              });
             });

             // ── Agent Management ───────────────────────────────────
             describe("Agent Management", function () {
                       it("should authorize a new agent", async function () {
                                     await vibeGuard.authorizeAgent(agent.address);
                                     expect(await vibeGuard.authorizedAgents(agent.address)).to.be.true;
                       });

                              it("should revoke an agent", async function () {
                                            await vibeGuard.authorizeAgent(agent.address);
                                            await vibeGuard.revokeAgent(agent.address);
                                            expect(await vibeGuard.authorizedAgents(agent.address)).to.be.false;
                              });

                              it("should reject zero-address agent authorization", async function () {
                                            await expect(
                                                              vibeGuard.authorizeAgent(ethers.ZeroAddress)
                                                          ).to.be.revertedWith("VibeGuard: Zero address");
                              });

                              it("should reject non-owner from authorizing", async function () {
                                            await expect(
                                                              vibeGuard.connect(user).authorizeAgent(agent.address)
                                                          ).to.be.reverted;
                              });
             });

             // ── Token Registration ─────────────────────────────────
             describe("Token Registration", function () {
                       it("should register a token and mint NFT", async function () {
                                     await vibeGuard.registerToken(DUMMY_TOKEN);
                                     expect(await vibeGuard.isRegistered(DUMMY_TOKEN)).to.be.true;
                                     expect(await vibeGuard.totalTokens()).to.equal(1);
                       });

                              it("should reject duplicate registration", async function () {
                                            await vibeGuard.registerToken(DUMMY_TOKEN);
                                            await expect(
                                                              vibeGuard.registerToken(DUMMY_TOKEN)
                                                          ).to.be.revertedWith("VibeGuard: Already registered");
                              });

                              it("should reject zero-address registration", async function () {
                                            await expect(
                                                              vibeGuard.registerToken(ethers.ZeroAddress)
                                                          ).to.be.revertedWith("VibeGuard: Zero address");
                              });

                              it("should reject unauthorized caller", async function () {
                                            await expect(
                                                              vibeGuard.connect(user).registerToken(DUMMY_TOKEN)
                                                          ).to.be.revertedWith("VibeGuard: Not authorized");
                              });
             });

             // ── Risk Score Updates ─────────────────────────────────
             describe("Risk Score Updates", function () {
                       beforeEach(async function () {
                                     await vibeGuard.registerToken(DUMMY_TOKEN);
                       });

                              it("should update risk scores", async function () {
                                            await vibeGuard.updateRiskScore(DUMMY_TOKEN, 75, 60, 80, 30);
                                            const report = await vibeGuard.getFullRiskReport(DUMMY_TOKEN);
                                            expect(report.riskScore).to.equal(75);
                                            expect(report.honeypotScore).to.equal(60);
                                            expect(report.rugPullScore).to.equal(80);
                                            expect(report.liquidityScore).to.equal(30);
                                            expect(report.riskLevel).to.equal("HIGH");
                              });

                              it("should reject scores > 100", async function () {
                                            await expect(
                                                              vibeGuard.updateRiskScore(DUMMY_TOKEN, 101, 0, 0, 0)
                                                          ).to.be.revertedWith("VibeGuard: Score out of range");
                              });

                              it("should reject unregistered token update", async function () {
                                            await expect(
                                                              vibeGuard.updateRiskScore(DUMMY_TOKEN_2, 50, 50, 50, 50)
                                                          ).to.be.revertedWith("VibeGuard: Token not registered");
                              });

                              it("should emit AlertTriggered for critical risk", async function () {
                                            await expect(vibeGuard.updateRiskScore(DUMMY_TOKEN, 85, 30, 30, 50))
                                                .to.emit(vibeGuard, "AlertTriggered")
                                                .withArgs(0, DUMMY_TOKEN, 85, "CRITICAL_RISK");
                              });
             });

             // ── Query Functions ────────────────────────────────────
             describe("Query Functions", function () {
                       beforeEach(async function () {
                                     await vibeGuard.registerToken(DUMMY_TOKEN);
                                     await vibeGuard.updateRiskScore(DUMMY_TOKEN, 25, 10, 15, 80);
                       });

                              it("queryRisk should return correct data and not stale", async function () {
                                            const [score, level, , isStale] = await vibeGuard.queryRisk(DUMMY_TOKEN);
                                            expect(score).to.equal(25);
                                            expect(level).to.equal("LOW");
                                            expect(isStale).to.be.false;
                              });

                              it("isSafe should return true for low-risk fresh data", async function () {
                                            expect(await vibeGuard.isSafe(DUMMY_TOKEN, 40)).to.be.true;
                              });

                              it("isSafe should return false for unregistered token", async function () {
                                            expect(await vibeGuard.isSafe(DUMMY_TOKEN_2, 40)).to.be.false;
                              });

                              it("isSafe should return false when score exceeds threshold", async function () {
                                            expect(await vibeGuard.isSafe(DUMMY_TOKEN, 10)).to.be.false;
                              });
             });

             // ── Pausable Circuit Breaker ───────────────────────────
             describe("Pausable", function () {
                       it("should pause and block registerToken", async function () {
                                     await vibeGuard.pause();
                                     await expect(
                                                       vibeGuard.registerToken(DUMMY_TOKEN)
                                                   ).to.be.reverted;
                       });

                              it("should pause and block updateRiskScore", async function () {
                                            await vibeGuard.registerToken(DUMMY_TOKEN);
                                            await vibeGuard.pause();
                                            await expect(
                                                              vibeGuard.updateRiskScore(DUMMY_TOKEN, 50, 50, 50, 50)
                                                          ).to.be.reverted;
                              });

                              it("should unpause and allow operations", async function () {
                                            await vibeGuard.pause();
                                            await vibeGuard.unpause();
                                            await vibeGuard.registerToken(DUMMY_TOKEN);
                                            expect(await vibeGuard.isRegistered(DUMMY_TOKEN)).to.be.true;
                              });

                              it("should reject non-owner from pausing", async function () {
                                            await expect(vibeGuard.connect(user).pause()).to.be.reverted;
                              });
             });

             // ── Risk Level Mapping ─────────────────────────────────
             describe("Risk Levels", function () {
                       beforeEach(async function () {
                                     await vibeGuard.registerToken(DUMMY_TOKEN);
                       });

                              it("0-20 = SAFE", async function () {
                                            await vibeGuard.updateRiskScore(DUMMY_TOKEN, 15, 0, 0, 100);
                                            const report = await vibeGuard.getFullRiskReport(DUMMY_TOKEN);
                                            expect(report.riskLevel).to.equal("SAFE");
                              });

                              it("21-40 = LOW", async function () {
                                            await vibeGuard.updateRiskScore(DUMMY_TOKEN, 35, 0, 0, 100);
                                            const report = await vibeGuard.getFullRiskReport(DUMMY_TOKEN);
                                            expect(report.riskLevel).to.equal("LOW");
                              });

                              it("41-60 = MEDIUM", async function () {
                                            await vibeGuard.updateRiskScore(DUMMY_TOKEN, 55, 0, 0, 100);
                                            const report = await vibeGuard.getFullRiskReport(DUMMY_TOKEN);
                                            expect(report.riskLevel).to.equal("MEDIUM");
                              });

                              it("61-80 = HIGH", async function () {
                                            await vibeGuard.updateRiskScore(DUMMY_TOKEN, 75, 0, 0, 100);
                                            const report = await vibeGuard.getFullRiskReport(DUMMY_TOKEN);
                                            expect(report.riskLevel).to.equal("HIGH");
                              });

                              it("81-100 = CRITICAL", async function () {
                                            await vibeGuard.updateRiskScore(DUMMY_TOKEN, 95, 0, 0, 100);
                                            const report = await vibeGuard.getFullRiskReport(DUMMY_TOKEN);
                                            expect(report.riskLevel).to.equal("CRITICAL");
                              });
             });

             // ── Dynamic NFT Metadata ───────────────────────────────
             describe("tokenURI", function () {
                       it("should return valid base64 JSON", async function () {
                                     await vibeGuard.registerToken(DUMMY_TOKEN);
                                     await vibeGuard.updateRiskScore(DUMMY_TOKEN, 42, 20, 30, 70);
                                     const uri = await vibeGuard.tokenURI(0);
                                     expect(uri).to.contain("data:application/json;base64,");
                       });
             });
});
