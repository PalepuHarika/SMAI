// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @title AuditRegistry
 * @author SMAI Trust Layer Phase 3
 * @notice Immutable on-chain registry for SMAI smart contract audit records.
 *         Stores a deterministic audit identity anchored by cryptographic hashes
 *         of the audited source and the audit report. Does NOT store source code
 *         or full vulnerability explanations on-chain.
 *
 * @dev Each audit entry is identified by a deterministic auditId derived from
 *      (contractHash, reportHash, auditor address). Duplicate registrations of
 *      identical audit identities are rejected.
 */
contract AuditRegistry {

    // -------------------------------------------------------------------------
    // Structs
    // -------------------------------------------------------------------------

    /**
     * @notice An immutable record of a single SMAI audit.
     * @param contractHash  SHA-256 / Keccak-256 hash of the audited Solidity source.
     * @param reportHash    Deterministic canonical hash of the full audit report.
     * @param securityScore Integer score in [0, 100].
     * @param findingsCount Total number of vulnerability findings recorded.
     * @param timestamp     Unix timestamp (seconds) of registration.
     * @param auditor       Address of the registering account.
     * @param exists        Internal sentinel to distinguish populated vs. empty entries.
     */
    struct AuditRecord {
        bytes32 contractHash;
        bytes32 reportHash;
        uint256 securityScore;
        uint256 findingsCount;
        uint256 timestamp;
        address auditor;
        bool    exists;
    }

    // -------------------------------------------------------------------------
    // State variables
    // -------------------------------------------------------------------------

    /// @notice Maps auditId to AuditRecord.
    mapping(bytes32 => AuditRecord) private _audits;

    /// @notice Owner of this registry (set once at deployment; cannot be changed).
    address public immutable owner;

    /// @notice Total number of audits registered.
    uint256 public totalAudits;

    // -------------------------------------------------------------------------
    // Events
    // -------------------------------------------------------------------------

    /**
     * @notice Emitted when a new audit is successfully registered.
     * @param auditId       Deterministic identifier for this audit entry.
     * @param contractHash  Hash of the audited source.
     * @param reportHash    Hash of the full audit report.
     * @param securityScore Integer score in [0, 100].
     * @param findingsCount Total number of findings.
     * @param timestamp     Block timestamp of registration.
     * @param auditor       Address of the registering account.
     */
    event AuditRegistered(
        bytes32 indexed auditId,
        bytes32 indexed contractHash,
        bytes32 indexed reportHash,
        uint256 securityScore,
        uint256 findingsCount,
        uint256 timestamp,
        address auditor
    );

    // -------------------------------------------------------------------------
    // Errors
    // -------------------------------------------------------------------------

    /// @notice Thrown when attempting to register an audit that already exists.
    error AuditAlreadyExists(bytes32 auditId);

    /// @notice Thrown when a hash argument is the zero value.
    error InvalidHash();

    /// @notice Thrown when securityScore exceeds 100.
    error InvalidSecurityScore(uint256 score);

    // -------------------------------------------------------------------------
    // Constructor
    // -------------------------------------------------------------------------

    constructor() {
        owner = msg.sender;
    }

    // -------------------------------------------------------------------------
    // External functions
    // -------------------------------------------------------------------------

    /**
     * @notice Register a new SMAI audit on-chain.
     * @dev The auditId is computed deterministically as:
     *      keccak256(abi.encodePacked(contractHash, reportHash, msg.sender))
     *
     * @param contractHash  SHA-256 hash (as bytes32) of the audited Solidity source.
     * @param reportHash    Deterministic canonical hash of the audit report.
     * @param securityScore Integer score in [0, 100].
     * @param findingsCount Total number of vulnerability findings.
     * @return auditId      The computed deterministic identifier.
     */
    function registerAudit(
        bytes32 contractHash,
        bytes32 reportHash,
        uint256 securityScore,
        uint256 findingsCount
    ) external returns (bytes32 auditId) {
        if (contractHash == bytes32(0)) revert InvalidHash();
        if (reportHash    == bytes32(0)) revert InvalidHash();
        if (securityScore > 100)         revert InvalidSecurityScore(securityScore);

        auditId = computeAuditId(contractHash, reportHash, msg.sender);

        if (_audits[auditId].exists) revert AuditAlreadyExists(auditId);

        uint256 ts = block.timestamp;

        _audits[auditId] = AuditRecord({
            contractHash:  contractHash,
            reportHash:    reportHash,
            securityScore: securityScore,
            findingsCount: findingsCount,
            timestamp:     ts,
            auditor:       msg.sender,
            exists:        true
        });

        totalAudits += 1;

        emit AuditRegistered(
            auditId,
            contractHash,
            reportHash,
            securityScore,
            findingsCount,
            ts,
            msg.sender
        );
    }

    /**
     * @notice Retrieve a stored audit record by its deterministic auditId.
     * @param auditId The deterministic audit identifier.
     * @return record The full AuditRecord struct.
     */
    function getAudit(bytes32 auditId)
        external
        view
        returns (AuditRecord memory record)
    {
        return _audits[auditId];
    }

    /**
     * @notice Check whether an audit with the given auditId has been registered.
     * @param auditId The deterministic audit identifier.
     * @return True if the audit exists, false otherwise.
     */
    function auditExists(bytes32 auditId) external view returns (bool) {
        return _audits[auditId].exists;
    }

    // -------------------------------------------------------------------------
    // Pure helpers
    // -------------------------------------------------------------------------

    /**
     * @notice Compute the deterministic auditId for a given triple.
     * @param contractHash  Hash of the audited source.
     * @param reportHash    Hash of the audit report.
     * @param auditor       Address of the registering account.
     * @return auditId      keccak256(abi.encodePacked(contractHash, reportHash, auditor))
     */
    function computeAuditId(
        bytes32 contractHash,
        bytes32 reportHash,
        address auditor
    ) public pure returns (bytes32 auditId) {
        return keccak256(abi.encodePacked(contractHash, reportHash, auditor));
    }
}
