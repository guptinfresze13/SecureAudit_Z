import { ConnectButton } from '@rainbow-me/rainbowkit';
import '@rainbow-me/rainbowkit/styles.css';
import React, { useEffect, useState } from "react";
import { getContractReadOnly, getContractWithSigner } from "./components/useContract";
import "./App.css";
import { useAccount } from 'wagmi';
import { useFhevm, useEncrypt, useDecrypt } from '../fhevm-sdk/src';
import { ethers } from 'ethers';

interface AuditData {
  id: string;
  name: string;
  encryptedValue: string;
  vulnerabilityCount: number;
  riskLevel: number;
  description: string;
  timestamp: number;
  creator: string;
  isVerified?: boolean;
  decryptedValue?: number;
}

interface VulnerabilityStats {
  critical: number;
  high: number;
  medium: number;
  low: number;
}

const App: React.FC = () => {
  const { address, isConnected } = useAccount();
  const [loading, setLoading] = useState(true);
  const [audits, setAudits] = useState<AuditData[]>([]);
  const [isRefreshing, setIsRefreshing] = useState(false);
  const [showCreateModal, setShowCreateModal] = useState(false);
  const [creatingAudit, setCreatingAudit] = useState(false);
  const [transactionStatus, setTransactionStatus] = useState<{ visible: boolean; status: "pending" | "success" | "error"; message: string; }>({ 
    visible: false, 
    status: "pending", 
    message: "" 
  });
  const [newAuditData, setNewAuditData] = useState({ name: "", code: "", description: "" });
  const [selectedAudit, setSelectedAudit] = useState<AuditData | null>(null);
  const [decryptedCode, setDecryptedCode] = useState<number | null>(null);
  const [isDecrypting, setIsDecrypting] = useState(false);
  const [contractAddress, setContractAddress] = useState("");
  const [fhevmInitializing, setFhevmInitializing] = useState(false);
  const [vulnerabilityStats, setVulnerabilityStats] = useState<VulnerabilityStats>({ critical: 0, high: 0, medium: 0, low: 0 });
  const [showFAQ, setShowFAQ] = useState(false);

  const { status, initialize, isInitialized } = useFhevm();
  const { encrypt, isEncrypting } = useEncrypt();
  const { verifyDecryption, isDecrypting: fheIsDecrypting } = useDecrypt();

  useEffect(() => {
    const initFhevmAfterConnection = async () => {
      if (!isConnected) return;
      if (isInitialized || fhevmInitializing) return;
      
      try {
        setFhevmInitializing(true);
        await initialize();
      } catch (error) {
        setTransactionStatus({ 
          visible: true, 
          status: "error", 
          message: "FHEVM initialization failed" 
        });
        setTimeout(() => setTransactionStatus({ visible: false, status: "pending", message: "" }), 3000);
      } finally {
        setFhevmInitializing(false);
      }
    };

    initFhevmAfterConnection();
  }, [isConnected, isInitialized, initialize, fhevmInitializing]);

  useEffect(() => {
    const loadDataAndContract = async () => {
      if (!isConnected) {
        setLoading(false);
        return;
      }
      
      try {
        await loadData();
        const contract = await getContractReadOnly();
        if (contract) setContractAddress(await contract.getAddress());
      } catch (error) {
        console.error('Failed to load data:', error);
      } finally {
        setLoading(false);
      }
    };

    loadDataAndContract();
  }, [isConnected]);

  const loadData = async () => {
    if (!isConnected) return;
    
    setIsRefreshing(true);
    try {
      const contract = await getContractReadOnly();
      if (!contract) return;
      
      const businessIds = await contract.getAllBusinessIds();
      const auditsList: AuditData[] = [];
      const stats: VulnerabilityStats = { critical: 0, high: 0, medium: 0, low: 0 };
      
      for (const businessId of businessIds) {
        try {
          const businessData = await contract.getBusinessData(businessId);
          auditsList.push({
            id: businessId,
            name: businessData.name,
            encryptedValue: businessId,
            vulnerabilityCount: Number(businessData.publicValue1) || 0,
            riskLevel: Number(businessData.publicValue2) || 0,
            description: businessData.description,
            timestamp: Number(businessData.timestamp),
            creator: businessData.creator,
            isVerified: businessData.isVerified,
            decryptedValue: Number(businessData.decryptedValue) || 0
          });
          
          if (businessData.isVerified) {
            const decrypted = Number(businessData.decryptedValue) || 0;
            if (decrypted > 90) stats.critical++;
            else if (decrypted > 70) stats.high++;
            else if (decrypted > 50) stats.medium++;
            else stats.low++;
          }
        } catch (e) {
          console.error('Error loading business data:', e);
        }
      }
      
      setAudits(auditsList);
      setVulnerabilityStats(stats);
    } catch (e) {
      setTransactionStatus({ visible: true, status: "error", message: "Failed to load data" });
      setTimeout(() => setTransactionStatus({ visible: false, status: "pending", message: "" }), 3000);
    } finally { 
      setIsRefreshing(false); 
    }
  };

  const createAudit = async () => {
    if (!isConnected || !address) { 
      setTransactionStatus({ visible: true, status: "error", message: "Please connect wallet first" });
      setTimeout(() => setTransactionStatus({ visible: false, status: "pending", message: "" }), 3000);
      return; 
    }
    
    setCreatingAudit(true);
    setTransactionStatus({ visible: true, status: "pending", message: "Creating audit with FHE..." });
    
    try {
      const contract = await getContractWithSigner();
      if (!contract) throw new Error("Failed to get contract");
      
      const codeValue = parseInt(newAuditData.code) || 0;
      const businessId = `audit-${Date.now()}`;
      
      const encryptedResult = await encrypt(contractAddress, address, codeValue);
      
      const tx = await contract.createBusinessData(
        businessId,
        newAuditData.name,
        encryptedResult.encryptedData,
        encryptedResult.proof,
        0,
        0,
        newAuditData.description
      );
      
      setTransactionStatus({ visible: true, status: "pending", message: "Waiting for confirmation..." });
      await tx.wait();
      
      setTransactionStatus({ visible: true, status: "success", message: "Audit created successfully!" });
      setTimeout(() => {
        setTransactionStatus({ visible: false, status: "pending", message: "" });
      }, 2000);
      
      await loadData();
      setShowCreateModal(false);
      setNewAuditData({ name: "", code: "", description: "" });
    } catch (e: any) {
      const errorMessage = e.message?.includes("user rejected transaction") 
        ? "Transaction rejected" 
        : "Submission failed";
      setTransactionStatus({ visible: true, status: "error", message: errorMessage });
      setTimeout(() => setTransactionStatus({ visible: false, status: "pending", message: "" }), 3000);
    } finally { 
      setCreatingAudit(false); 
    }
  };

  const decryptData = async (businessId: string): Promise<number | null> => {
    if (!isConnected || !address) { 
      setTransactionStatus({ visible: true, status: "error", message: "Connect wallet first" });
      setTimeout(() => setTransactionStatus({ visible: false, status: "pending", message: "" }), 3000);
      return null; 
    }
    
    setIsDecrypting(true);
    try {
      const contractRead = await getContractReadOnly();
      if (!contractRead) return null;
      
      const businessData = await contractRead.getBusinessData(businessId);
      if (businessData.isVerified) {
        const storedValue = Number(businessData.decryptedValue) || 0;
        setTransactionStatus({ visible: true, status: "success", message: "Data already verified" });
        setTimeout(() => setTransactionStatus({ visible: false, status: "pending", message: "" }), 2000);
        return storedValue;
      }
      
      const contractWrite = await getContractWithSigner();
      if (!contractWrite) return null;
      
      const encryptedValueHandle = await contractRead.getEncryptedValue(businessId);
      
      const result = await verifyDecryption(
        [encryptedValueHandle],
        contractAddress,
        (abiEncodedClearValues: string, decryptionProof: string) => 
          contractWrite.verifyDecryption(businessId, abiEncodedClearValues, decryptionProof)
      );
      
      setTransactionStatus({ visible: true, status: "pending", message: "Verifying decryption..." });
      
      const clearValue = result.decryptionResult.clearValues[encryptedValueHandle];
      
      await loadData();
      
      setTransactionStatus({ visible: true, status: "success", message: "Data decrypted successfully!" });
      setTimeout(() => setTransactionStatus({ visible: false, status: "pending", message: "" }), 2000);
      
      return Number(clearValue);
      
    } catch (e: any) { 
      if (e.message?.includes("Data already verified")) {
        setTransactionStatus({ visible: true, status: "success", message: "Data is already verified" });
        setTimeout(() => setTransactionStatus({ visible: false, status: "pending", message: "" }), 2000);
        await loadData();
        return null;
      }
      
      setTransactionStatus({ visible: true, status: "error", message: "Decryption failed" });
      setTimeout(() => setTransactionStatus({ visible: false, status: "pending", message: "" }), 3000);
      return null; 
    } finally { 
      setIsDecrypting(false); 
    }
  };

  const checkAvailability = async () => {
    try {
      const contract = await getContractReadOnly();
      if (!contract) return;
      
      const isAvailable = await contract.isAvailable();
      if (isAvailable) {
        setTransactionStatus({ visible: true, status: "success", message: "System is available" });
        setTimeout(() => setTransactionStatus({ visible: false, status: "pending", message: "" }), 2000);
      }
    } catch (e) {
      setTransactionStatus({ visible: true, status: "error", message: "Check failed" });
      setTimeout(() => setTransactionStatus({ visible: false, status: "pending", message: "" }), 3000);
    }
  };

  const renderVulnerabilityChart = () => {
    const total = vulnerabilityStats.critical + vulnerabilityStats.high + vulnerabilityStats.medium + vulnerabilityStats.low;
    if (total === 0) return null;

    return (
      <div className="vulnerability-chart">
        <div className="chart-row">
          <div className="chart-label">Critical</div>
          <div className="chart-bar">
            <div 
              className="bar-fill critical" 
              style={{ width: `${(vulnerabilityStats.critical / total) * 100}%` }}
            >
              <span className="bar-value">{vulnerabilityStats.critical}</span>
            </div>
          </div>
        </div>
        <div className="chart-row">
          <div className="chart-label">High</div>
          <div className="chart-bar">
            <div 
              className="bar-fill high" 
              style={{ width: `${(vulnerabilityStats.high / total) * 100}%` }}
            >
              <span className="bar-value">{vulnerabilityStats.high}</span>
            </div>
          </div>
        </div>
        <div className="chart-row">
          <div className="chart-label">Medium</div>
          <div className="chart-bar">
            <div 
              className="bar-fill medium" 
              style={{ width: `${(vulnerabilityStats.medium / total) * 100}%` }}
            >
              <span className="bar-value">{vulnerabilityStats.medium}</span>
            </div>
          </div>
        </div>
        <div className="chart-row">
          <div className="chart-label">Low</div>
          <div className="chart-bar">
            <div 
              className="bar-fill low" 
              style={{ width: `${(vulnerabilityStats.low / total) * 100}%` }}
            >
              <span className="bar-value">{vulnerabilityStats.low}</span>
            </div>
          </div>
        </div>
      </div>
    );
  };

  const renderDashboard = () => {
    const totalAudits = audits.length;
    const verifiedAudits = audits.filter(a => a.isVerified).length;
    const avgRisk = audits.length > 0 
      ? audits.reduce((sum, a) => sum + a.riskLevel, 0) / audits.length 
      : 0;
    
    const recentAudits = audits.filter(a => 
      Date.now()/1000 - a.timestamp < 60 * 60 * 24 * 7
    ).length;

    return (
      <div className="dashboard-panels">
        <div className="panel metal-panel">
          <h3>Total Audits</h3>
          <div className="stat-value">{totalAudits}</div>
          <div className="stat-trend">+{recentAudits} this week</div>
        </div>
        
        <div className="panel metal-panel">
          <h3>Verified Data</h3>
          <div className="stat-value">{verifiedAudits}/{totalAudits}</div>
          <div className="stat-trend">FHE Verified</div>
        </div>
        
        <div className="panel metal-panel">
          <h3>Avg Risk Level</h3>
          <div className="stat-value">{avgRisk.toFixed(1)}/10</div>
          <div className="stat-trend">Secure Processing</div>
        </div>
      </div>
    );
  };

  const renderFHEFlow = () => {
    return (
      <div className="fhe-flow">
        <div className="flow-step">
          <div className="step-icon">1</div>
          <div className="step-content">
            <h4>Code Encryption</h4>
            <p>Source code encrypted with FHE 🔐</p>
          </div>
        </div>
        <div className="flow-arrow">→</div>
        <div className="flow-step">
          <div className="step-icon">2</div>
          <div className="step-content">
            <h4>Homomorphic Scan</h4>
            <p>Vulnerability scan on encrypted data</p>
          </div>
        </div>
        <div className="flow-arrow">→</div>
        <div className="flow-step">
          <div className="step-icon">3</div>
          <div className="step-content">
            <h4>Secure Decryption</h4>
            <p>Client-side decryption with proof</p>
          </div>
        </div>
        <div className="flow-arrow">→</div>
        <div className="flow-step">
          <div className="step-icon">4</div>
          <div className="step-content">
            <h4>On-chain Verification</h4>
            <p>Proof verification on blockchain</p>
          </div>
        </div>
      </div>
    );
  };

  if (!isConnected) {
    return (
      <div className="app-container">
        <header className="app-header">
          <div className="logo">
            <h1>SecureAudit_Z 🔒</h1>
          </div>
          <div className="header-actions">
            <div className="wallet-connect-wrapper">
              <ConnectButton accountStatus="address" chainStatus="icon" showBalance={false}/>
            </div>
          </div>
        </header>
        
        <div className="connection-prompt">
          <div className="connection-content">
            <div className="connection-icon">🔐</div>
            <h2>Connect Your Wallet to Continue</h2>
            <p>Secure your code with FHE-based auditing technology</p>
            <div className="connection-steps">
              <div className="step">
                <span>1</span>
                <p>Connect wallet to initialize FHE system</p>
              </div>
              <div className="step">
                <span>2</span>
                <p>Upload encrypted code for vulnerability scanning</p>
              </div>
              <div className="step">
                <span>3</span>
                <p>Protect your intellectual property with homomorphic encryption</p>
              </div>
            </div>
          </div>
        </div>
      </div>
    );
  }

  if (!isInitialized || fhevmInitializing) {
    return (
      <div className="loading-screen">
        <div className="fhe-spinner"></div>
        <p>Initializing FHE Encryption System...</p>
        <p>Status: {fhevmInitializing ? "Initializing FHEVM" : status}</p>
      </div>
    );
  }

  if (loading) return (
    <div className="loading-screen">
      <div className="fhe-spinner"></div>
      <p>Loading secure auditing system...</p>
    </div>
  );

  return (
    <div className="app-container">
      <header className="app-header">
        <div className="logo">
          <h1>SecureAudit_Z 🔒</h1>
        </div>
        
        <div className="header-actions">
          <button 
            onClick={() => setShowCreateModal(true)} 
            className="create-btn"
          >
            + New Audit
          </button>
          <button 
            onClick={checkAvailability}
            className="check-btn"
          >
            Check System
          </button>
          <div className="wallet-connect-wrapper">
            <ConnectButton accountStatus="address" chainStatus="icon" showBalance={false}/>
          </div>
        </div>
      </header>
      
      <div className="main-content-container">
        <div className="dashboard-section">
          <h2>FHE-Based Secure Auditing</h2>
          {renderDashboard()}
          
          <div className="panel metal-panel full-width">
            <h3>FHE Vulnerability Scanning Process</h3>
            {renderFHEFlow()}
          </div>
          
          <div className="panel metal-panel">
            <h3>Vulnerability Distribution</h3>
            {renderVulnerabilityChart()}
          </div>
        </div>
        
        <div className="audits-section">
          <div className="section-header">
            <h2>Security Audits</h2>
            <div className="header-actions">
              <button 
                onClick={loadData} 
                className="refresh-btn" 
                disabled={isRefreshing}
              >
                {isRefreshing ? "Refreshing..." : "Refresh"}
              </button>
              <button 
                onClick={() => setShowFAQ(!showFAQ)}
                className="faq-btn"
              >
                {showFAQ ? "Hide FAQ" : "Show FAQ"}
              </button>
            </div>
          </div>
          
          {showFAQ && (
            <div className="faq-section">
              <h3>Frequently Asked Questions</h3>
              <div className="faq-item">
                <h4>How does FHE protect my code?</h4>
                <p>Your code is encrypted before processing, scanned while encrypted, and only decrypted locally after verification.</p>
              </div>
              <div className="faq-item">
                <h4>What types of vulnerabilities can be detected?</h4>
                <p>Our system detects common security issues like integer overflows, access control flaws, and logic errors.</p>
              </div>
              <div className="faq-item">
                <h4>Is my intellectual property safe?</h4>
                <p>Yes, your source code never exists in plaintext on any server or blockchain.</p>
              </div>
            </div>
          )}
          
          <div className="audits-list">
            {audits.length === 0 ? (
              <div className="no-audits">
                <p>No security audits found</p>
                <button 
                  className="create-btn" 
                  onClick={() => setShowCreateModal(true)}
                >
                  Create First Audit
                </button>
              </div>
            ) : audits.map((audit, index) => (
              <div 
                className={`audit-item ${selectedAudit?.id === audit.id ? "selected" : ""} ${audit.isVerified ? "verified" : ""}`} 
                key={index}
                onClick={() => setSelectedAudit(audit)}
              >
                <div className="audit-title">{audit.name}</div>
                <div className="audit-meta">
                  <span>Vulnerabilities: {audit.vulnerabilityCount}</span>
                  <span>Risk: {audit.riskLevel}/10</span>
                </div>
                <div className="audit-status">
                  Status: {audit.isVerified ? "✅ Verified" : "🔓 Pending Verification"}
                </div>
                <div className="audit-creator">Creator: {audit.creator.substring(0, 6)}...{audit.creator.substring(38)}</div>
              </div>
            ))}
          </div>
        </div>
      </div>
      
      {showCreateModal && (
        <ModalCreateAudit 
          onSubmit={createAudit} 
          onClose={() => setShowCreateModal(false)} 
          creating={creatingAudit} 
          auditData={newAuditData} 
          setAuditData={setNewAuditData}
          isEncrypting={isEncrypting}
        />
      )}
      
      {selectedAudit && (
        <AuditDetailModal 
          audit={selectedAudit} 
          onClose={() => { 
            setSelectedAudit(null); 
            setDecryptedCode(null); 
          }} 
          decryptedCode={decryptedCode} 
          setDecryptedCode={setDecryptedCode} 
          isDecrypting={isDecrypting || fheIsDecrypting} 
          decryptData={() => decryptData(selectedAudit.id)}
        />
      )}
      
      {transactionStatus.visible && (
        <div className="transaction-modal">
          <div className="transaction-content">
            <div className={`transaction-icon ${transactionStatus.status}`}>
              {transactionStatus.status === "pending" && <div className="fhe-spinner"></div>}
              {transactionStatus.status === "success" && <div className="success-icon">✓</div>}
              {transactionStatus.status === "error" && <div className="error-icon">✗</div>}
            </div>
            <div className="transaction-message">{transactionStatus.message}</div>
          </div>
        </div>
      )}
    </div>
  );
};

const ModalCreateAudit: React.FC<{
  onSubmit: () => void; 
  onClose: () => void; 
  creating: boolean;
  auditData: any;
  setAuditData: (data: any) => void;
  isEncrypting: boolean;
}> = ({ onSubmit, onClose, creating, auditData, setAuditData, isEncrypting }) => {
  const handleChange = (e: React.ChangeEvent<HTMLInputElement | HTMLTextAreaElement>) => {
    const { name, value } = e.target;
    if (name === 'code') {
      const intValue = value.replace(/[^\d]/g, '');
      setAuditData({ ...auditData, [name]: intValue });
    } else {
      setAuditData({ ...auditData, [name]: value });
    }
  };

  return (
    <div className="modal-overlay">
      <div className="create-audit-modal">
        <div className="modal-header">
          <h2>New Security Audit</h2>
          <button onClick={onClose} className="close-modal">&times;</button>
        </div>
        
        <div className="modal-body">
          <div className="fhe-notice">
            <strong>FHE 🔐 Encryption</strong>
            <p>Source code will be encrypted with FHE (Integer only)</p>
          </div>
          
          <div className="form-group">
            <label>Project Name *</label>
            <input 
              type="text" 
              name="name" 
              value={auditData.name} 
              onChange={handleChange} 
              placeholder="Enter project name..." 
            />
          </div>
          
          <div className="form-group">
            <label>Source Code (Integer representation) *</label>
            <input 
              type="number" 
              name="code" 
              value={auditData.code} 
              onChange={handleChange} 
              placeholder="Enter code integer..." 
              step="1"
              min="0"
            />
            <div className="data-type-label">FHE Encrypted Integer</div>
          </div>
          
          <div className="form-group">
            <label>Description *</label>
            <textarea 
              name="description" 
              value={auditData.description} 
              onChange={handleChange} 
              placeholder="Enter audit description..." 
            />
          </div>
        </div>
        
        <div className="modal-footer">
          <button onClick={onClose} className="cancel-btn">Cancel</button>
          <button 
            onClick={onSubmit} 
            disabled={creating || isEncrypting || !auditData.name || !auditData.code || !auditData.description} 
            className="submit-btn"
          >
            {creating || isEncrypting ? "Encrypting and Creating..." : "Create Audit"}
          </button>
        </div>
      </div>
    </div>
  );
};

const AuditDetailModal: React.FC<{
  audit: AuditData;
  onClose: () => void;
  decryptedCode: number | null;
  setDecryptedCode: (value: number | null) => void;
  isDecrypting: boolean;
  decryptData: () => Promise<number | null>;
}> = ({ audit, onClose, decryptedCode, setDecryptedCode, isDecrypting, decryptData }) => {
  const handleDecrypt = async () => {
    if (decryptedCode !== null) { 
      setDecryptedCode(null); 
      return; 
    }
    
    const decrypted = await decryptData();
    if (decrypted !== null) {
      setDecryptedCode(decrypted);
    }
  };

  return (
    <div className="modal-overlay">
      <div className="audit-detail-modal">
        <div className="modal-header">
          <h2>Security Audit Details</h2>
          <button onClick={onClose} className="close-modal">&times;</button>
        </div>
        
        <div className="modal-body">
          <div className="audit-info">
            <div className="info-item">
              <span>Project:</span>
              <strong>{audit.name}</strong>
            </div>
            <div className="info-item">
              <span>Creator:</span>
              <strong>{audit.creator.substring(0, 6)}...{audit.creator.substring(38)}</strong>
            </div>
            <div className="info-item">
              <span>Date:</span>
              <strong>{new Date(audit.timestamp * 1000).toLocaleDateString()}</strong>
            </div>
            <div className="info-item">
              <span>Vulnerabilities:</span>
              <strong>{audit.vulnerabilityCount}</strong>
            </div>
            <div className="info-item">
              <span>Risk Level:</span>
              <strong>{audit.riskLevel}/10</strong>
            </div>
          </div>
          
          <div className="description-section">
            <h3>Description</h3>
            <p>{audit.description}</p>
          </div>
          
          <div className="data-section">
            <h3>Encrypted Source Code</h3>
            
            <div className="data-row">
              <div className="data-label">Code Value:</div>
              <div className="data-value">
                {audit.isVerified && audit.decryptedValue ? 
                  `${audit.decryptedValue} (Verified)` : 
                  decryptedCode !== null ? 
                  `${decryptedCode} (Decrypted)` : 
                  "🔒 FHE Encrypted"
                }
              </div>
              <button 
                className={`decrypt-btn ${(audit.isVerified || decryptedCode !== null) ? 'decrypted' : ''}`}
                onClick={handleDecrypt} 
                disabled={isDecrypting}
              >
                {isDecrypting ? (
                  "🔓 Decrypting..."
                ) : audit.isVerified ? (
                  "✅ Verified"
                ) : decryptedCode !== null ? (
                  "🔄 Re-decrypt"
                ) : (
                  "🔓 Decrypt Code"
                )}
              </button>
            </div>
            
            <div className="fhe-info">
              <div className="fhe-icon">🔐</div>
              <div>
                <strong>FHE 🔐 Secure Processing</strong>
                <p>Your source code remains encrypted throughout the scanning process</p>
              </div>
            </div>
          </div>
        </div>
        
        <div className="modal-footer">
          <button onClick={onClose} className="close-btn">Close</button>
          {!audit.isVerified && (
            <button 
              onClick={handleDecrypt} 
              disabled={isDecrypting}
              className="verify-btn"
            >
              {isDecrypting ? "Verifying..." : "Verify on-chain"}
            </button>
          )}
        </div>
      </div>
    </div>
  );
};

export default App;


