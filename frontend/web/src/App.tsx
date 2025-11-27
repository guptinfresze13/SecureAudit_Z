import { ConnectButton } from '@rainbow-me/rainbowkit';
import '@rainbow-me/rainbowkit/styles.css';
import React, { useState, useEffect } from "react";
import { getContractReadOnly, getContractWithSigner } from "./components/useContract";
import "./App.css";
import { useAccount } from 'wagmi';
import { useFhevm, useEncrypt, useDecrypt } from '../fhevm-sdk/src';

interface AuditData {
  id: string;
  name: string;
  encryptedValue: string;
  publicValue1: number;
  publicValue2: number;
  description: string;
  creator: string;
  timestamp: number;
  isVerified: boolean;
  decryptedValue: number;
}

const App: React.FC = () => {
  const { address, isConnected } = useAccount();
  const [loading, setLoading] = useState(true);
  const [audits, setAudits] = useState<AuditData[]>([]);
  const [showCreateModal, setShowCreateModal] = useState(false);
  const [creatingAudit, setCreatingAudit] = useState(false);
  const [transactionStatus, setTransactionStatus] = useState<{ visible: boolean; status: "pending" | "success" | "error"; message: string; }>({ 
    visible: false, 
    status: "pending", 
    message: "" 
  });
  const [newAuditData, setNewAuditData] = useState({ name: "", value: "", description: "" });
  const [selectedAudit, setSelectedAudit] = useState<AuditData | null>(null);
  const [decryptedData, setDecryptedData] = useState<number | null>(null);
  const [isDecrypting, setIsDecrypting] = useState(false);
  const [contractAddress, setContractAddress] = useState("");
  const [searchTerm, setSearchTerm] = useState("");
  const [stats, setStats] = useState({ total: 0, verified: 0, avgScore: 0 });

  const { status, initialize, isInitialized } = useFhevm();
  const { encrypt, isEncrypting } = useEncrypt();
  const { verifyDecryption } = useDecrypt();

  useEffect(() => {
    const initFhevm = async () => {
      if (isConnected && !isInitialized) {
        try {
          await initialize();
        } catch (error) {
          console.error('FHEVM init failed:', error);
        }
      }
    };
    initFhevm();
  }, [isConnected, isInitialized, initialize]);

  useEffect(() => {
    const loadData = async () => {
      if (!isConnected) {
        setLoading(false);
        return;
      }
      try {
        const contract = await getContractReadOnly();
        if (!contract) return;
        setContractAddress(await contract.getAddress());
        const ids = await contract.getAllBusinessIds();
        const auditsList: AuditData[] = [];
        for (const id of ids) {
          const data = await contract.getBusinessData(id);
          auditsList.push({
            id,
            name: data.name,
            encryptedValue: id,
            publicValue1: Number(data.publicValue1),
            publicValue2: Number(data.publicValue2),
            description: data.description,
            creator: data.creator,
            timestamp: Number(data.timestamp),
            isVerified: data.isVerified,
            decryptedValue: Number(data.decryptedValue)
          });
        }
        setAudits(auditsList);
        updateStats(auditsList);
      } catch (error) {
        console.error('Load data error:', error);
      } finally {
        setLoading(false);
      }
    };
    loadData();
  }, [isConnected]);

  const updateStats = (data: AuditData[]) => {
    const total = data.length;
    const verified = data.filter(a => a.isVerified).length;
    const avgScore = total > 0 ? data.reduce((sum, a) => sum + a.publicValue1, 0) / total : 0;
    setStats({ total, verified, avgScore });
  };

  const createAudit = async () => {
    if (!isConnected || !address) return;
    setCreatingAudit(true);
    setTransactionStatus({ visible: true, status: "pending", message: "Creating audit..." });
    try {
      const contract = await getContractWithSigner();
      if (!contract) throw new Error("No contract");
      const value = parseInt(newAuditData.value) || 0;
      const encryptedResult = await encrypt(contractAddress, address, value);
      const tx = await contract.createBusinessData(
        `audit-${Date.now()}`,
        newAuditData.name,
        encryptedResult.encryptedData,
        encryptedResult.proof,
        Math.floor(Math.random() * 10) + 1,
        0,
        newAuditData.description
      );
      await tx.wait();
      setTransactionStatus({ visible: true, status: "success", message: "Audit created!" });
      setTimeout(() => setTransactionStatus({ visible: false, status: "pending", message: "" }), 2000);
      setShowCreateModal(false);
      setNewAuditData({ name: "", value: "", description: "" });
    } catch (error: any) {
      setTransactionStatus({ visible: true, status: "error", message: error.message || "Error" });
      setTimeout(() => setTransactionStatus({ visible: false, status: "pending", message: "" }), 3000);
    } finally {
      setCreatingAudit(false);
    }
  };

  const decryptData = async (id: string) => {
    if (!isConnected) return;
    setIsDecrypting(true);
    try {
      const contractRead = await getContractReadOnly();
      const contractWrite = await getContractWithSigner();
      if (!contractRead || !contractWrite) return;
      const encryptedValue = await contractRead.getEncryptedValue(id);
      const result = await verifyDecryption(
        [encryptedValue],
        contractAddress,
        (abiEncodedClearValues: string, decryptionProof: string) => 
          contractWrite.verifyDecryption(id, abiEncodedClearValues, decryptionProof)
      );
      const clearValue = result.decryptionResult.clearValues[encryptedValue];
      setDecryptedData(Number(clearValue));
    } catch (error) {
      console.error('Decrypt error:', error);
    } finally {
      setIsDecrypting(false);
    }
  };

  const checkAvailability = async () => {
    try {
      const contract = await getContractReadOnly();
      if (!contract) return;
      const available = await contract.isAvailable();
      if (available) {
        setTransactionStatus({ visible: true, status: "success", message: "Service is available!" });
        setTimeout(() => setTransactionStatus({ visible: false, status: "pending", message: "" }), 2000);
      }
    } catch (error) {
      console.error('Availability check failed:', error);
    }
  };

  const filteredAudits = audits.filter(audit => 
    audit.name.toLowerCase().includes(searchTerm.toLowerCase()) ||
    audit.description.toLowerCase().includes(searchTerm.toLowerCase())
  );

  if (!isConnected) {
    return (
      <div className="app-container">
        <header className="app-header">
          <h1>FHE Secure Audit</h1>
          <ConnectButton />
        </header>
        <div className="connection-prompt">
          <h2>Connect Wallet to Access Secure Auditing</h2>
          <p>Your code security starts here with FHE encryption</p>
        </div>
      </div>
    );
  }

  if (!isInitialized) {
    return (
      <div className="loading-screen">
        <div className="fhe-spinner"></div>
        <p>Initializing FHE System...</p>
      </div>
    );
  }

  if (loading) {
    return (
      <div className="loading-screen">
        <div className="fhe-spinner"></div>
        <p>Loading Audit Data...</p>
      </div>
    );
  }

  return (
    <div className="app-container">
      <header className="app-header">
        <div className="header-left">
          <h1>FHE Secure Audit</h1>
          <div className="wallet-connect">
            <ConnectButton />
          </div>
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
            Check Service
          </button>
        </div>
      </header>

      <div className="main-content">
        <div className="stats-panel">
          <div className="stat-card">
            <h3>Total Audits</h3>
            <p>{stats.total}</p>
          </div>
          <div className="stat-card">
            <h3>Verified</h3>
            <p>{stats.verified}</p>
          </div>
          <div className="stat-card">
            <h3>Avg Score</h3>
            <p>{stats.avgScore.toFixed(1)}</p>
          </div>
        </div>

        <div className="search-bar">
          <input
            type="text"
            placeholder="Search audits..."
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
          />
        </div>

        <div className="audits-list">
          {filteredAudits.length === 0 ? (
            <div className="empty-state">
              <p>No audits found</p>
              <button 
                onClick={() => setShowCreateModal(true)}
                className="create-btn"
              >
                Create First Audit
              </button>
            </div>
          ) : (
            filteredAudits.map((audit) => (
              <div 
                key={audit.id}
                className={`audit-item ${selectedAudit?.id === audit.id ? 'selected' : ''}`}
                onClick={() => setSelectedAudit(audit)}
              >
                <div className="audit-header">
                  <h3>{audit.name}</h3>
                  <span className={`status ${audit.isVerified ? 'verified' : 'pending'}`}>
                    {audit.isVerified ? 'Verified' : 'Pending'}
                  </span>
                </div>
                <p>{audit.description}</p>
                <div className="audit-footer">
                  <span>Score: {audit.publicValue1}/10</span>
                  <span>{new Date(audit.timestamp * 1000).toLocaleDateString()}</span>
                </div>
              </div>
            ))
          )}
        </div>
      </div>

      {showCreateModal && (
        <div className="modal-overlay">
          <div className="create-modal">
            <div className="modal-header">
              <h2>New Secure Audit</h2>
              <button onClick={() => setShowCreateModal(false)} className="close-btn">
                ×
              </button>
            </div>
            <div className="modal-body">
              <div className="form-group">
                <label>Audit Name</label>
                <input
                  type="text"
                  value={newAuditData.name}
                  onChange={(e) => setNewAuditData({...newAuditData, name: e.target.value})}
                  placeholder="Enter audit name"
                />
              </div>
              <div className="form-group">
                <label>Encrypted Value (Integer)</label>
                <input
                  type="number"
                  value={newAuditData.value}
                  onChange={(e) => setNewAuditData({...newAuditData, value: e.target.value})}
                  placeholder="Enter integer value"
                />
              </div>
              <div className="form-group">
                <label>Description</label>
                <textarea
                  value={newAuditData.description}
                  onChange={(e) => setNewAuditData({...newAuditData, description: e.target.value})}
                  placeholder="Enter description"
                />
              </div>
            </div>
            <div className="modal-footer">
              <button onClick={() => setShowCreateModal(false)} className="cancel-btn">
                Cancel
              </button>
              <button 
                onClick={createAudit} 
                disabled={creatingAudit || isEncrypting}
                className="submit-btn"
              >
                {creatingAudit || isEncrypting ? 'Creating...' : 'Create Audit'}
              </button>
            </div>
          </div>
        </div>
      )}

      {selectedAudit && (
        <div className="modal-overlay">
          <div className="detail-modal">
            <div className="modal-header">
              <h2>Audit Details</h2>
              <button onClick={() => {
                setSelectedAudit(null);
                setDecryptedData(null);
              }} className="close-btn">
                ×
              </button>
            </div>
            <div className="modal-body">
              <div className="detail-section">
                <h3>{selectedAudit.name}</h3>
                <p>{selectedAudit.description}</p>
              </div>
              <div className="detail-section">
                <h4>Security Score</h4>
                <div className="score-bar">
                  <div 
                    className="score-fill" 
                    style={{ width: `${selectedAudit.publicValue1 * 10}%` }}
                  >
                    {selectedAudit.publicValue1}/10
                  </div>
                </div>
              </div>
              <div className="detail-section">
                <h4>Encrypted Data</h4>
                <div className="data-row">
                  <span>Status:</span>
                  <span className={`data-status ${selectedAudit.isVerified ? 'verified' : 'encrypted'}`}>
                    {selectedAudit.isVerified ? 'Verified' : 'Encrypted'}
                  </span>
                </div>
                {selectedAudit.isVerified && (
                  <div className="data-row">
                    <span>Decrypted Value:</span>
                    <span>{selectedAudit.decryptedValue}</span>
                  </div>
                )}
                {decryptedData !== null && !selectedAudit.isVerified && (
                  <div className="data-row">
                    <span>Local Decryption:</span>
                    <span>{decryptedData}</span>
                  </div>
                )}
                <button
                  onClick={() => decryptData(selectedAudit.id)}
                  disabled={isDecrypting || selectedAudit.isVerified}
                  className={`decrypt-btn ${selectedAudit.isVerified ? 'verified' : ''}`}
                >
                  {isDecrypting ? 'Decrypting...' : selectedAudit.isVerified ? 'Verified' : 'Decrypt'}
                </button>
              </div>
              <div className="detail-section">
                <h4>Metadata</h4>
                <div className="meta-grid">
                  <div className="meta-item">
                    <span>Creator:</span>
                    <span>{selectedAudit.creator.substring(0, 6)}...{selectedAudit.creator.substring(38)}</span>
                  </div>
                  <div className="meta-item">
                    <span>Created:</span>
                    <span>{new Date(selectedAudit.timestamp * 1000).toLocaleString()}</span>
                  </div>
                </div>
              </div>
            </div>
          </div>
        </div>
      )}

      {transactionStatus.visible && (
        <div className={`notification ${transactionStatus.status}`}>
          <div className="notification-content">
            {transactionStatus.status === 'pending' && <div className="spinner"></div>}
            <p>{transactionStatus.message}</p>
          </div>
        </div>
      )}
    </div>
  );
};

export default App;