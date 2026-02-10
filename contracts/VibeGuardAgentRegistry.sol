// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "@openzeppelin/contracts/token/ERC721/extensions/ERC721URIStorage.sol";
import "@openzeppelin/contracts/access/Ownable.sol";
import "@openzeppelin/contracts/utils/Pausable.sol";
import "@openzeppelin/contracts/utils/Strings.sol";
import "@openzeppelin/contracts/utils/Base64.sol";

/**
 * @title VibeGuardAgentRegistry
 * @notice ERC-8004 compliant Agent Identity, Reputation, and Validation Registry
 * @dev Implements the three core registries from the ERC-8004 "Trustless Agents" standard:
 *      1. Identity Registry — ERC-721 NFT per agent with agentURI to registration JSON
 *      2. Reputation Registry — Signed feedback from clients with value/tags
 *      3. Validation Registry — Request/response flow for pluggable trust models
 *
 *      Designed for BNB Chain — gas-optimized with circuit breaker (Pausable).
 */
contract VibeGuardAgentRegistry is ERC721URIStorage, Ownable, Pausable {
    using Strings for uint256;

    // ============================================================
    //                    IDENTITY REGISTRY
    // ============================================================

    uint256 private _nextAgentId;

    struct AgentMetadata {
        address agentWallet;     // Wallet address the agent uses for on-chain actions
        string  agentType;       // e.g., "risk-scanner", "trading-bot", "validator"
        uint256 registeredAt;
        bool    isActive;
    }

    // agentId => metadata
    mapping(uint256 => AgentMetadata) public agentMetadata;
    // wallet => agentId (reverse lookup)
    mapping(address => uint256) public walletToAgentId;
    mapping(address => bool) public hasRegistered;

    event AgentRegistered(
        uint256 indexed agentId,
        address indexed agentWallet,
        string agentType,
        string agentURI,
        uint256 timestamp
    );
    event AgentDeactivated(uint256 indexed agentId);
    event AgentReactivated(uint256 indexed agentId);

    // ============================================================
    //                    REPUTATION REGISTRY
    // ============================================================

    struct Feedback {
        address clientAddress;
        int128  value;           // Signed fixed-point (e.g., 87 = 87/100 stars)
        uint8   valueDecimals;   // 0-18
        string  tag1;            // e.g., "accuracy", "speed", "reliability"
        string  tag2;            // Optional secondary tag
        uint64  feedbackIndex;   // 1-indexed counter per client-agent pair
        bool    isRevoked;
        uint256 timestamp;
    }

    // agentId => feedbacks array
    mapping(uint256 => Feedback[]) public agentFeedbacks;
    // agentId => clientAddress => feedback count
    mapping(uint256 => mapping(address => uint64)) public feedbackCount;
    // agentId => aggregate stats
    mapping(uint256 => int256) public reputationSum;
    mapping(uint256 => uint256) public reputationCount;

    event NewFeedback(
        uint256 indexed agentId,
        address indexed clientAddress,
        uint64  feedbackIndex,
        int128  value,
        uint8   valueDecimals,
        string  tag1,
        string  tag2,
        string  endpoint,
        string  feedbackURI,
        bytes32 feedbackHash
    );
    event FeedbackRevoked(uint256 indexed agentId, address indexed clientAddress, uint64 feedbackIndex);

    // ============================================================
    //                    VALIDATION REGISTRY
    // ============================================================

    struct ValidationRecord {
        address validatorAddress;
        uint256 agentId;
        uint8   response;        // 0-100 (0=failed, 100=passed)
        bytes32 responseHash;
        string  tag;
        uint256 lastUpdate;
    }

    // requestHash => ValidationRecord
    mapping(bytes32 => ValidationRecord) public validations;
    // agentId => requestHashes
    mapping(uint256 => bytes32[]) public agentValidations;
    // validatorAddress => requestHashes
    mapping(address => bytes32[]) public validatorRequests;

    event ValidationRequest(
        address indexed validatorAddress,
        uint256 indexed agentId,
        string  requestURI,
        bytes32 indexed requestHash
    );
    event ValidationResponse(
        address indexed validatorAddress,
        uint256 indexed agentId,
        bytes32 indexed requestHash,
        uint8   response,
        string  responseURI,
        bytes32 responseHash,
        string  tag
    );

    // ============================================================
    //                    CONSTRUCTOR
    // ============================================================

    constructor()
        ERC721("VibeGuard Agent Identity", "VGAGENT")
        Ownable(msg.sender)
    {}

    // ============================================================
    //                IDENTITY: REGISTRATION
    // ============================================================

    /**
     * @notice Register a new agent, minting an ERC-721 identity NFT
     * @param agentWallet The wallet address the agent uses on-chain
     * @param agentType The type/category of the agent
     * @param agentURI The URI pointing to the Agent Registration File (JSON/IPFS)
     */
    function registerAgent(
        address agentWallet,
        string calldata agentType,
        string calldata agentURI
    ) external whenNotPaused returns (uint256) {
        require(agentWallet != address(0), "VG: Zero address");
        require(!hasRegistered[agentWallet], "VG: Wallet already registered");

        uint256 agentId = _nextAgentId++;
        _mint(msg.sender, agentId);
        _setTokenURI(agentId, agentURI);

        agentMetadata[agentId] = AgentMetadata({
            agentWallet: agentWallet,
            agentType: agentType,
            registeredAt: block.timestamp,
            isActive: true
        });

        walletToAgentId[agentWallet] = agentId;
        hasRegistered[agentWallet] = true;

        emit AgentRegistered(agentId, agentWallet, agentType, agentURI, block.timestamp);
        return agentId;
    }

    /**
     * @notice Update Agent Registration File URI
     */
    function setAgentURI(uint256 agentId, string calldata newURI) external {
        require(_isAuthorized(ownerOf(agentId), msg.sender, agentId), "VG: Not authorized");
        _setTokenURI(agentId, newURI);
    }

    function deactivateAgent(uint256 agentId) external {
        require(_isAuthorized(ownerOf(agentId), msg.sender, agentId), "VG: Not authorized");
        agentMetadata[agentId].isActive = false;
        emit AgentDeactivated(agentId);
    }

    function reactivateAgent(uint256 agentId) external {
        require(_isAuthorized(ownerOf(agentId), msg.sender, agentId), "VG: Not authorized");
        agentMetadata[agentId].isActive = true;
        emit AgentReactivated(agentId);
    }

    // ============================================================
    //              REPUTATION: FEEDBACK
    // ============================================================

    /**
     * @notice Give feedback to an agent (ERC-8004 Reputation Registry)
     * @param agentId The target agent
     * @param value Signed fixed-point feedback value
     * @param valueDecimals Decimal places for value (0-18)
     * @param tag1 Primary categorization tag
     * @param tag2 Secondary tag (optional)
     * @param endpoint Agent endpoint URI (emitted, not stored)
     * @param feedbackURI Off-chain feedback file URI (emitted, not stored)
     * @param feedbackHash Keccak256 of feedback content (for non-IPFS URIs)
     */
    function giveFeedback(
        uint256 agentId,
        int128 value,
        uint8 valueDecimals,
        string calldata tag1,
        string calldata tag2,
        string calldata endpoint,
        string calldata feedbackURI,
        bytes32 feedbackHash
    ) external whenNotPaused {
        require(agentId < _nextAgentId, "VG: Agent not registered");
        require(valueDecimals <= 18, "VG: Max 18 decimals");
        require(
            msg.sender != ownerOf(agentId),
            "VG: Owner cannot self-rate"
        );

        uint64 newIndex = ++feedbackCount[agentId][msg.sender];

        agentFeedbacks[agentId].push(Feedback({
            clientAddress: msg.sender,
            value: value,
            valueDecimals: valueDecimals,
            tag1: tag1,
            tag2: tag2,
            feedbackIndex: newIndex,
            isRevoked: false,
            timestamp: block.timestamp
        }));

        reputationSum[agentId] += int256(value);
        reputationCount[agentId]++;

        emit NewFeedback(
            agentId, msg.sender, newIndex,
            value, valueDecimals,
            tag1, tag2, endpoint, feedbackURI, feedbackHash
        );
    }

    /**
     * @notice Query average reputation score for an agent
     */
    function getAverageReputation(uint256 agentId) external view returns (int256 average, uint256 count) {
        count = reputationCount[agentId];
        if (count == 0) return (0, 0);
        average = reputationSum[agentId] / int256(count);
    }

    function getFeedbackCount(uint256 agentId) external view returns (uint256) {
        return agentFeedbacks[agentId].length;
    }

    // ============================================================
    //             VALIDATION: REQUEST / RESPONSE
    // ============================================================

    /**
     * @notice Request validation from a validator contract (ERC-8004)
     * @param validatorAddress The validator smart contract
     * @param agentId The agent requesting validation
     * @param requestURI Off-chain data for the validator
     * @param requestHash Keccak256 commitment to the request payload
     */
    function validationRequest(
        address validatorAddress,
        uint256 agentId,
        string calldata requestURI,
        bytes32 requestHash
    ) external whenNotPaused {
        require(_isAuthorized(ownerOf(agentId), msg.sender, agentId), "VG: Not authorized");
        require(validatorAddress != address(0), "VG: Zero validator");

        agentValidations[agentId].push(requestHash);
        validatorRequests[validatorAddress].push(requestHash);

        // Store initial record
        validations[requestHash] = ValidationRecord({
            validatorAddress: validatorAddress,
            agentId: agentId,
            response: 0,
            responseHash: bytes32(0),
            tag: "",
            lastUpdate: block.timestamp
        });

        emit ValidationRequest(validatorAddress, agentId, requestURI, requestHash);
    }

    /**
     * @notice Respond to a validation request (called by the validator)
     */
    function validationResponse(
        bytes32 requestHash,
        uint8 response,
        string calldata responseURI,
        bytes32 responseHash,
        string calldata tag
    ) external whenNotPaused {
        ValidationRecord storage record = validations[requestHash];
        require(record.validatorAddress == msg.sender, "VG: Not the validator");
        require(response <= 100, "VG: Response 0-100");

        record.response = response;
        record.responseHash = responseHash;
        record.tag = tag;
        record.lastUpdate = block.timestamp;

        emit ValidationResponse(
            msg.sender, record.agentId, requestHash,
            response, responseURI, responseHash, tag
        );
    }

    /**
     * @notice Get validation status for a request
     */
    function getValidationStatus(bytes32 requestHash) external view returns (
        address validatorAddress,
        uint256 agentId,
        uint8 response,
        bytes32 responseHash,
        string memory tag,
        uint256 lastUpdate
    ) {
        ValidationRecord memory r = validations[requestHash];
        return (r.validatorAddress, r.agentId, r.response, r.responseHash, r.tag, r.lastUpdate);
    }

    function getAgentValidations(uint256 agentId) external view returns (bytes32[] memory) {
        return agentValidations[agentId];
    }

    // ============================================================
    //                    CIRCUIT BREAKER
    // ============================================================

    function pause() external onlyOwner { _pause(); }
    function unpause() external onlyOwner { _unpause(); }

    // ============================================================
    //                    VIEW HELPERS
    // ============================================================

    function totalAgents() external view returns (uint256) {
        return _nextAgentId;
    }

    function isAgentActive(uint256 agentId) external view returns (bool) {
        if (agentId >= _nextAgentId) return false;
        return agentMetadata[agentId].isActive;
    }
}
