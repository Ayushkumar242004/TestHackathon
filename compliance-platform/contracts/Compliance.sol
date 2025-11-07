// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "@openzeppelin/contracts/access/AccessControl.sol";
import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";

contract Compliance is AccessControl {
    using ECDSA for bytes32; // optional, but we'll call ECDSA.* explicitly below

    bytes32 public constant SUBMITTER_ROLE = keccak256("SUBMITTER_ROLE");
    bytes32 public constant INSPECTOR_ROLE = keccak256("INSPECTOR_ROLE");
    bytes32 public constant AGENT_ROLE = keccak256("AGENT_ROLE");
    bytes32 public constant ADMIN_ROLE = DEFAULT_ADMIN_ROLE;

    struct Certificate {
        bytes32 certHash;
        address issuer;
        address owner;
        uint256 issuedAt;
        uint256 expiry; // unix timestamp, 0 if none
        bool revoked;
    }

    event InspectionRecorded(
        bytes32 indexed contentHash,
        bytes32 indexed summaryHash,
        address indexed inspector,
        uint256 ts,
        bytes meta
    );

    event AgentAction(
        bytes32 indexed actionHash,
        address indexed agent,
        string actionType,
        uint256 ts,
        bytes meta
    );

    event CertificateIssued(bytes32 indexed certHash, address issuer, address owner, uint256 expiry);
    event CertificateRevoked(bytes32 indexed certHash, address revokedBy, uint256 ts);
    event PolicyChanged(bytes32 indexed policyKey, address changedBy, uint256 ts);

    mapping(bytes32 => Certificate) public certificates;
    mapping(bytes32 => bool) public seenInspections; // contentHash -> bool
    mapping(bytes32 => bool) public usedSignatures;   // replay protection by signature hash (optional)

    constructor(address admin) {
        _grantRole(ADMIN_ROLE, admin);
        _grantRole(ADMIN_ROLE, msg.sender);
    }

    // -------------------------
    // Helpers: build & verify signed message
    // -------------------------
    function _inspectionMessageHash(
        bytes32 contentHash,
        bytes32 summaryHash,
        address inspector,
        uint256 timestamp,
        bytes32 nonce
    ) internal view returns (bytes32) {
        return keccak256(abi.encodePacked(address(this), block.chainid, contentHash, summaryHash, inspector, timestamp, nonce));
    }

    function _certificateMessageHash(
        bytes32 certHash,
        address owner,
        uint256 expiry,
        address issuer,
        bytes32 nonce
    ) internal view returns (bytes32) {
        return keccak256(abi.encodePacked(address(this), block.chainid, certHash, owner, expiry, issuer, nonce));
    }

    // recover signer from an Ethereum Signed Message (prefix added)
   function _recoverSigner(bytes32 rawHash, bytes memory signature) internal pure returns (address) {
    // Manually build the prefixed hash: "\x19Ethereum Signed Message:\n32" + rawHash
    bytes32 ethHash = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", rawHash));
    return ECDSA.recover(ethHash, signature);
}

    // -------------------------
    // Record an inspection (submitter submits inspector-signed payload)
    // -------------------------
    function recordInspectionWithSignature(
        bytes32 contentHash,
        bytes32 summaryHash,
        address inspector,
        uint256 inspectorTimestamp,
        bytes32 nonce,
        bytes calldata signature,
        bytes calldata meta
    ) external onlyRole(SUBMITTER_ROLE) {
        require(contentHash != bytes32(0), "invalid content hash");

        bytes32 raw = _inspectionMessageHash(contentHash, summaryHash, inspector, inspectorTimestamp, nonce);
        address recovered = _recoverSigner(raw, signature);

        require(recovered == inspector, "signature not from claimed inspector");
        require(hasRole(INSPECTOR_ROLE, inspector), "inspector not authorized");

        bytes32 sigKey = keccak256(abi.encodePacked(raw, signature));
        require(!usedSignatures[sigKey], "signature already used");
        usedSignatures[sigKey] = true;

        seenInspections[contentHash] = true;
        emit InspectionRecorded(contentHash, summaryHash, inspector, inspectorTimestamp, meta);
    }

    // Agent action
    function recordAgentAction(bytes32 actionHash, string calldata actionType, bytes calldata meta) external onlyRole(AGENT_ROLE) {
        require(actionHash != bytes32(0), "invalid action hash");
        emit AgentAction(actionHash, msg.sender, actionType, block.timestamp, meta);
    }

    // Certificate issuance with signature
    function issueCertificateWithSignature(
        bytes32 certHash,
        address owner,
        uint256 expiry,
        address issuer,
        bytes32 nonce,
        bytes calldata signature
    ) external onlyRole(SUBMITTER_ROLE) {
        require(certHash != bytes32(0), "invalid cert hash");
        require(certificates[certHash].certHash == bytes32(0), "already exists");

        bytes32 raw = _certificateMessageHash(certHash, owner, expiry, issuer, nonce);
        address recovered = _recoverSigner(raw, signature);

        require(recovered == issuer, "signature not from claimed issuer");
        require(hasRole(SUBMITTER_ROLE, issuer) || hasRole(ADMIN_ROLE, issuer), "issuer not authorized");

        bytes32 sigKey = keccak256(abi.encodePacked(raw, signature));
        require(!usedSignatures[sigKey], "signature already used");
        usedSignatures[sigKey] = true;

        certificates[certHash] = Certificate({
            certHash: certHash,
            issuer: issuer,
            owner: owner,
            issuedAt: block.timestamp,
            expiry: expiry,
            revoked: false
        });

        emit CertificateIssued(certHash, issuer, owner, expiry);
    }

    // Legacy / alternative methods (no signature)
    function recordInspection(bytes32 contentHash, bytes32 summaryHash, address inspector, bytes calldata meta) external onlyRole(SUBMITTER_ROLE) {
        require(contentHash != bytes32(0), "invalid content hash");
        require(hasRole(INSPECTOR_ROLE, inspector), "inspector not authorized");
        seenInspections[contentHash] = true;
        emit InspectionRecorded(contentHash, summaryHash, inspector, block.timestamp, meta);
    }

    function issueCertificate(bytes32 certHash, address owner, uint256 expiry) external onlyRole(SUBMITTER_ROLE) {
        require(certHash != bytes32(0), "invalid cert hash");
        require(certificates[certHash].certHash == bytes32(0), "already exists");
        certificates[certHash] = Certificate({
            certHash: certHash,
            issuer: msg.sender,
            owner: owner,
            issuedAt: block.timestamp,
            expiry: expiry,
            revoked: false
        });
        emit CertificateIssued(certHash, msg.sender, owner, expiry);
    }

    function revokeCertificate(bytes32 certHash) external onlyRole(SUBMITTER_ROLE) {
        Certificate storage c = certificates[certHash];
        require(c.certHash != bytes32(0), "not found");
        require(!c.revoked, "already revoked");
        c.revoked = true;
        emit CertificateRevoked(certHash, msg.sender, block.timestamp);
    }

    function setPolicy(bytes32 policyKey) external onlyRole(ADMIN_ROLE) {
        emit PolicyChanged(policyKey, msg.sender, block.timestamp);
    }

    function isCertificateValid(bytes32 certHash) external view returns (bool) {
        Certificate memory c = certificates[certHash];
        if (c.certHash == bytes32(0) || c.revoked) return false;
        if (c.expiry != 0 && block.timestamp > c.expiry) return false;
        return true;
    }
}
