pragma solidity ^0.8.24;

import { FHE, euint32, externalEuint32 } from "@fhevm/solidity/lib/FHE.sol";
import { ZamaEthereumConfig } from "@fhevm/solidity/config/ZamaConfig.sol";

contract SecureAuditAdapter is ZamaEthereumConfig {
    
    struct AuditRecord {
        string identifier;                    
        euint32 encryptedPayload;        
        uint256 publicMetadata1;          
        uint256 publicMetadata2;          
        string auditDescription;            
        address submitter;               
        uint256 submissionTime;             
        uint32 decryptedResult; 
        bool isVerified; 
    }
    

    mapping(string => AuditRecord) public auditRecords;
    
    string[] public auditIdentifiers;
    
    event AuditRecordCreated(string indexed identifier, address indexed submitter);
    event DecryptionVerified(string indexed identifier, uint32 decryptedResult);
    
    constructor() ZamaEthereumConfig() {
    }
    
    function createAuditRecord(
        string calldata identifier,
        string calldata name,
        externalEuint32 encryptedPayload,
        bytes calldata inputProof,
        uint256 publicMetadata1,
        uint256 publicMetadata2,
        string calldata auditDescription
    ) external {
        require(bytes(auditRecords[identifier].identifier).length == 0, "Audit record already exists");
        
        require(FHE.isInitialized(FHE.fromExternal(encryptedPayload, inputProof)), "Invalid encrypted input");
        
        auditRecords[identifier] = AuditRecord({
            identifier: identifier,
            encryptedPayload: FHE.fromExternal(encryptedPayload, inputProof),
            publicMetadata1: publicMetadata1,
            publicMetadata2: publicMetadata2,
            auditDescription: auditDescription,
            submitter: msg.sender,
            submissionTime: block.timestamp,
            decryptedResult: 0,
            isVerified: false
        });
        
        FHE.allowThis(auditRecords[identifier].encryptedPayload);
        
        FHE.makePubliclyDecryptable(auditRecords[identifier].encryptedPayload);
        
        auditIdentifiers.push(identifier);
        
        emit AuditRecordCreated(identifier, msg.sender);
    }
    
    function verifyDecryption(
        string calldata identifier, 
        bytes memory abiEncodedClearValue,
        bytes memory decryptionProof
    ) external {
        require(bytes(auditRecords[identifier].identifier).length > 0, "Audit record does not exist");
        require(!auditRecords[identifier].isVerified, "Data already verified");
        
        bytes32[] memory cts = new bytes32[](1);
        cts[0] = FHE.toBytes32(auditRecords[identifier].encryptedPayload);
        
        FHE.checkSignatures(cts, abiEncodedClearValue, decryptionProof);
        
        uint32 decodedValue = abi.decode(abiEncodedClearValue, (uint32));
        
        auditRecords[identifier].decryptedResult = decodedValue;
        auditRecords[identifier].isVerified = true;
        
        emit DecryptionVerified(identifier, decodedValue);
    }
    
    function getEncryptedPayload(string calldata identifier) external view returns (euint32) {
        require(bytes(auditRecords[identifier].identifier).length > 0, "Audit record does not exist");
        return auditRecords[identifier].encryptedPayload;
    }
    
    function getAuditRecord(string calldata identifier) external view returns (
        string memory name,
        uint256 publicMetadata1,
        uint256 publicMetadata2,
        string memory auditDescription,
        address submitter,
        uint256 submissionTime,
        bool isVerified,
        uint32 decryptedResult
    ) {
        require(bytes(auditRecords[identifier].identifier).length > 0, "Audit record does not exist");
        AuditRecord storage data = auditRecords[identifier];
        
        return (
            data.identifier,
            data.publicMetadata1,
            data.publicMetadata2,
            data.auditDescription,
            data.submitter,
            data.submissionTime,
            data.isVerified,
            data.decryptedResult
        );
    }
    
    function getAllAuditIdentifiers() external view returns (string[] memory) {
        return auditIdentifiers;
    }
    
    function isAvailable() public pure returns (bool) {
        return true;
    }
}


