// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "@openzeppelin/contracts/token/ERC721/ERC721.sol";
import "@openzeppelin/contracts/access/Ownable.sol";
import "@openzeppelin/contracts/utils/Strings.sol";
import "@openzeppelin/contracts/utils/Base64.sol";

/**
 * @title VibeGuardRiskNFT
 * @notice Dynamic NFT that stores real-time risk scores for BNB Chain pools/tokens.
 *         Other AI agents can query risk scores on-chain before executing trades.
 * @dev Each NFT represents a monitored pool/token with an updateable risk score.
 */
contract VibeGuardRiskNFT is ERC721, Ownable {
    using Strings for uint256;

    struct RiskData {
        address tokenAddress;       // The token/pool being assessed
        uint8 riskScore;            // 0-100 (0 = safe, 100 = extreme risk)
        uint8 honeypotScore;        // 0-100 honeypot probability
        uint8 rugPullScore;         // 0-100 rug pull probability
        uint8 liquidityScore;       // 0-100 liquidity health (100 = healthy)
        uint256 lastUpdated;        // Timestamp of last update
        bool isActive;              // Whether monitoring is active
        string riskLevel;           // "SAFE", "LOW", "MEDIUM", "HIGH", "CRITICAL"
    }

    // Token ID counter
    uint256 private _nextTokenId;

    // Mapping: tokenId => RiskData
    mapping(uint256 => RiskData) public riskRegistry;

    // Mapping: monitored token address => NFT tokenId
    mapping(address => uint256) public tokenToNftId;

    // Mapping: token address => whether it has been registered
    mapping(address => bool) public isRegistered;

    // Authorized agents that can update risk scores
    mapping(address => bool) public authorizedAgents;

    // Events
    event RiskScoreUpdated(
        uint256 indexed tokenId,
        address indexed tokenAddress,
        uint8 riskScore,
        string riskLevel,
        uint256 timestamp
    );
    event TokenRegistered(
        uint256 indexed tokenId,
        address indexed tokenAddress,
        uint256 timestamp
    );
    event AgentAuthorized(address indexed agent);
    event AgentRevoked(address indexed agent);
    event AlertTriggered(
        uint256 indexed tokenId,
        address indexed tokenAddress,
        uint8 riskScore,
        string alertType
    );

    modifier onlyAuthorizedAgent() {
        require(
            authorizedAgents[msg.sender] || msg.sender == owner(),
            "VibeGuard: Not authorized"
        );
        _;
    }

    constructor() ERC721("VibeGuard Risk Certificate", "VGRISK") Ownable(msg.sender) {
        authorizedAgents[msg.sender] = true;
    }

    // ============================================================
    //                    AGENT MANAGEMENT
    // ============================================================

    function authorizeAgent(address agent) external onlyOwner {
        authorizedAgents[agent] = true;
        emit AgentAuthorized(agent);
    }

    function revokeAgent(address agent) external onlyOwner {
        authorizedAgents[agent] = false;
        emit AgentRevoked(agent);
    }

    // ============================================================
    //                    CORE FUNCTIONS
    // ============================================================

    /**
     * @notice Register a new token/pool for risk monitoring
     * @param tokenAddress The address of the token or LP to monitor
     * @return tokenId The minted NFT ID representing this risk certificate
     */
    function registerToken(address tokenAddress) external onlyAuthorizedAgent returns (uint256) {
        require(!isRegistered[tokenAddress], "VibeGuard: Already registered");
        require(tokenAddress != address(0), "VibeGuard: Zero address");

        uint256 tokenId = _nextTokenId++;
        _mint(address(this), tokenId); // Mint to contract (non-transferable risk cert)

        riskRegistry[tokenId] = RiskData({
            tokenAddress: tokenAddress,
            riskScore: 50, // Start neutral
            honeypotScore: 0,
            rugPullScore: 0,
            liquidityScore: 50,
            lastUpdated: block.timestamp,
            isActive: true,
            riskLevel: "PENDING"
        });

        tokenToNftId[tokenAddress] = tokenId;
        isRegistered[tokenAddress] = true;

        emit TokenRegistered(tokenId, tokenAddress, block.timestamp);
        return tokenId;
    }

    /**
     * @notice Update risk scores for a monitored token (called by AI agent)
     * @param tokenAddress The token being assessed
     * @param riskScore Overall risk score 0-100
     * @param honeypotScore Honeypot probability 0-100
     * @param rugPullScore Rug pull probability 0-100
     * @param liquidityScore Liquidity health 0-100
     */
    function updateRiskScore(
        address tokenAddress,
        uint8 riskScore,
        uint8 honeypotScore,
        uint8 rugPullScore,
        uint8 liquidityScore
    ) external onlyAuthorizedAgent {
        require(isRegistered[tokenAddress], "VibeGuard: Token not registered");
        require(riskScore <= 100 && honeypotScore <= 100 && rugPullScore <= 100 && liquidityScore <= 100,
            "VibeGuard: Score out of range");

        uint256 tokenId = tokenToNftId[tokenAddress];
        string memory riskLevel = _getRiskLevel(riskScore);

        riskRegistry[tokenId] = RiskData({
            tokenAddress: tokenAddress,
            riskScore: riskScore,
            honeypotScore: honeypotScore,
            rugPullScore: rugPullScore,
            liquidityScore: liquidityScore,
            lastUpdated: block.timestamp,
            isActive: true,
            riskLevel: riskLevel
        });

        emit RiskScoreUpdated(tokenId, tokenAddress, riskScore, riskLevel, block.timestamp);

        // Auto-trigger alerts for high-risk tokens
        if (riskScore >= 80) {
            emit AlertTriggered(tokenId, tokenAddress, riskScore, "CRITICAL_RISK");
        } else if (honeypotScore >= 70) {
            emit AlertTriggered(tokenId, tokenAddress, honeypotScore, "HONEYPOT_WARNING");
        } else if (rugPullScore >= 70) {
            emit AlertTriggered(tokenId, tokenAddress, rugPullScore, "RUG_PULL_WARNING");
        }
    }

    // ============================================================
    //              QUERY FUNCTIONS (For Other Agents)
    // ============================================================

    /**
     * @notice Query the risk score of a token (used by trading agents)
     * @param tokenAddress The token to check
     * @return riskScore The overall risk score (0-100)
     * @return riskLevel The human-readable risk level
     * @return lastUpdated When the score was last updated
     */
    function queryRisk(address tokenAddress) external view returns (
        uint8 riskScore,
        string memory riskLevel,
        uint256 lastUpdated
    ) {
        require(isRegistered[tokenAddress], "VibeGuard: Token not monitored");
        uint256 tokenId = tokenToNftId[tokenAddress];
        RiskData memory data = riskRegistry[tokenId];
        return (data.riskScore, data.riskLevel, data.lastUpdated);
    }

    /**
     * @notice Get full risk breakdown for a token
     */
    function getFullRiskReport(address tokenAddress) external view returns (RiskData memory) {
        require(isRegistered[tokenAddress], "VibeGuard: Token not monitored");
        uint256 tokenId = tokenToNftId[tokenAddress];
        return riskRegistry[tokenId];
    }

    /**
     * @notice Quick safety check — returns true if risk is below threshold
     * @param tokenAddress The token to check
     * @param maxRisk Maximum acceptable risk score (e.g., 40)
     */
    function isSafe(address tokenAddress, uint8 maxRisk) external view returns (bool) {
        if (!isRegistered[tokenAddress]) return false;
        uint256 tokenId = tokenToNftId[tokenAddress];
        return riskRegistry[tokenId].riskScore <= maxRisk;
    }

    // ============================================================
    //                  DYNAMIC NFT METADATA
    // ============================================================

    function tokenURI(uint256 tokenId) public view override returns (string memory) {
        RiskData memory data = riskRegistry[tokenId];

        string memory color = _getRiskColor(data.riskScore);
        string memory svg = _generateSVG(data, color);

        string memory json = string(abi.encodePacked(
            '{"name":"VibeGuard Risk Certificate #', tokenId.toString(),
            '","description":"On-chain risk assessment for ', _toHexString(data.tokenAddress),
            '","image":"data:image/svg+xml;base64,', Base64.encode(bytes(svg)),
            '","attributes":[',
            '{"trait_type":"Risk Score","value":', uint256(data.riskScore).toString(), '},',
            '{"trait_type":"Risk Level","value":"', data.riskLevel, '"},',
            '{"trait_type":"Honeypot Score","value":', uint256(data.honeypotScore).toString(), '},',
            '{"trait_type":"Rug Pull Score","value":', uint256(data.rugPullScore).toString(), '},',
            '{"trait_type":"Liquidity Health","value":', uint256(data.liquidityScore).toString(), '},',
            '{"trait_type":"Last Updated","value":', data.lastUpdated.toString(), '}',
            ']}'
        ));

        return string(abi.encodePacked("data:application/json;base64,", Base64.encode(bytes(json))));
    }

    // ============================================================
    //                    INTERNAL HELPERS
    // ============================================================

    function _getRiskLevel(uint8 score) internal pure returns (string memory) {
        if (score <= 20) return "SAFE";
        if (score <= 40) return "LOW";
        if (score <= 60) return "MEDIUM";
        if (score <= 80) return "HIGH";
        return "CRITICAL";
    }

    function _getRiskColor(uint8 score) internal pure returns (string memory) {
        if (score <= 20) return "#22c55e"; // Green
        if (score <= 40) return "#84cc16"; // Lime
        if (score <= 60) return "#eab308"; // Yellow
        if (score <= 80) return "#f97316"; // Orange
        return "#ef4444"; // Red
    }

    function _generateSVG(RiskData memory data, string memory color) internal pure returns (string memory) {
        return string(abi.encodePacked(
            '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 400 500">',
            '<defs><linearGradient id="bg" x1="0" y1="0" x2="1" y2="1">',
            '<stop offset="0%" stop-color="#0f172a"/><stop offset="100%" stop-color="#1e293b"/></linearGradient></defs>',
            '<rect width="400" height="500" fill="url(#bg)" rx="20"/>',
            '<text x="200" y="40" text-anchor="middle" fill="#94a3b8" font-size="14" font-family="monospace">VIBEGUARD AI</text>',
            '<text x="200" y="70" text-anchor="middle" fill="white" font-size="18" font-weight="bold" font-family="sans-serif">Risk Certificate</text>',
            '<circle cx="200" cy="180" r="80" fill="none" stroke="', color, '" stroke-width="8" opacity="0.3"/>',
            '<circle cx="200" cy="180" r="80" fill="none" stroke="', color, '" stroke-width="8" ',
            'stroke-dasharray="502" stroke-dashoffset="', uint256(502 - (uint256(data.riskScore) * 502 / 100)).toString(), '" transform="rotate(-90 200 180)"/>',
            '<text x="200" y="175" text-anchor="middle" fill="', color, '" font-size="48" font-weight="bold" font-family="sans-serif">', uint256(data.riskScore).toString(), '</text>',
            '<text x="200" y="200" text-anchor="middle" fill="#94a3b8" font-size="14" font-family="sans-serif">', data.riskLevel, '</text>',
            '<text x="40" y="310" fill="#64748b" font-size="12" font-family="monospace">Honeypot</text>',
            '<text x="360" y="310" text-anchor="end" fill="white" font-size="14" font-family="sans-serif">', uint256(data.honeypotScore).toString(), '%</text>',
            '<text x="40" y="345" fill="#64748b" font-size="12" font-family="monospace">Rug Pull</text>',
            '<text x="360" y="345" text-anchor="end" fill="white" font-size="14" font-family="sans-serif">', uint256(data.rugPullScore).toString(), '%</text>',
            '<text x="40" y="380" fill="#64748b" font-size="12" font-family="monospace">Liquidity</text>',
            '<text x="360" y="380" text-anchor="end" fill="white" font-size="14" font-family="sans-serif">', uint256(data.liquidityScore).toString(), '%</text>',
            '<text x="200" y="460" text-anchor="middle" fill="#475569" font-size="10" font-family="monospace">', _toHexStringShort(data.tokenAddress), '</text>',
            '</svg>'
        ));
    }

    function _toHexString(address addr) internal pure returns (string memory) {
        bytes memory buffer = new bytes(42);
        buffer[0] = '0';
        buffer[1] = 'x';
        bytes20 addrBytes = bytes20(addr);
        bytes memory hexChars = "0123456789abcdef";
        for (uint256 i = 0; i < 20; i++) {
            buffer[2 + i * 2] = hexChars[uint8(addrBytes[i] >> 4)];
            buffer[3 + i * 2] = hexChars[uint8(addrBytes[i] & 0x0f)];
        }
        return string(buffer);
    }

    function _toHexStringShort(address addr) internal pure returns (string memory) {
        string memory full = _toHexString(addr);
        bytes memory fullBytes = bytes(full);
        bytes memory result = new bytes(13); // 0x1234...abcd
        for (uint256 i = 0; i < 6; i++) result[i] = fullBytes[i];
        result[6] = '.';
        result[7] = '.';
        result[8] = '.';
        for (uint256 i = 0; i < 4; i++) result[9 + i] = fullBytes[38 + i];
        return string(result);
    }

    function totalTokens() external view returns (uint256) {
        return _nextTokenId;
    }
}
