import { useState, useEffect } from 'react';
import { invoke } from '@tauri-apps/api/core';
import { listen } from '@tauri-apps/api/event';
import { open } from '@tauri-apps/plugin-dialog';
import { AlertTriangle, HardDrive, File, Folder, Shield, CheckCircle, XCircle } from 'lucide-react';
import { DriveInfo, WipeResult, WipeMethod, WipeStatus } from './types';
import './index.css';

const WIPE_METHODS: { value: WipeMethod; label: string; description: string }[] = [
  {
    value: "NIST SP 800-88",
    label: "NIST SP 800-88",
    description: "Single pass with random data (Fast, Government Standard)"
  },
  {
    value: "DoD 5220.22-M",
    label: "DoD 5220.22-M",
    description: "3 passes: 0x00, 0xFF, Random (Military Grade)"
  },
  {
    value: "Gutmann",
    label: "Gutmann",
    description: "35 passes with specific patterns (Maximum Security)"
  },
  {
    value: "Random",
    label: "Random",
    description: "3 passes with random data (Balanced Security)"
  },
  {
    value: "Zero",
    label: "Zero",
    description: "Single pass with zeros (Fastest, Basic Security)"
  }
];

function App() {
  const [activeTab, setActiveTab] = useState<'file' | 'folder' | 'drive'>('file');
  const [selectedMethod, setSelectedMethod] = useState<WipeMethod>('NIST SP 800-88');
  const [selectedFiles, setSelectedFiles] = useState<string[]>([]);
  const [selectedFolder, setSelectedFolder] = useState<string>('');
  const [drives, setDrives] = useState<DriveInfo[]>([]);
  const [selectedDrive, setSelectedDrive] = useState<string>('');
  const [driveConfirmText, setDriveConfirmText] = useState<string>('');
  const [wipeStatus, setWipeStatus] = useState<WipeStatus>({
    isWiping: false,
    progress: null,
    result: null,
    error: null,
    certificatePath: null
  });
  
  // SECURITY: Rate limiting to prevent system resource exhaustion
  const [lastWipeTime, setLastWipeTime] = useState<number>(0);
  const [cooldownRemaining, setCooldownRemaining] = useState<number>(0);
  const COOLDOWN_SECONDS = 5; // 5 second cooldown between operations
  const [multiResults, setMultiResults] = useState<{ results: WipeResult[]; certificates: string[] } | null>(null);
  const [batchProgress, setBatchProgress] = useState<{ current: number; total: number; currentTarget: string } | null>(null);
  const [isAdmin, setIsAdmin] = useState<boolean>(false);
  const [adminCheckComplete, setAdminCheckComplete] = useState<boolean>(false);
  const [currentOperationId, setCurrentOperationId] = useState<string | null>(null);

  useEffect(() => {
    // Check if we're running in Tauri context
    console.log('Tauri context check:', typeof window !== 'undefined' && '__TAURI__' in window);
    
    loadDrives();
    checkAdminStatus();
    
    // Set up event listener for wipe progress updates
    const setupProgressListener = async () => {
      const unlisten = await listen('wipe-progress', (event) => {
        const [operationId, progress] = event.payload as [string, any];
        // Only update progress if this matches the current operation
        if (operationId === currentOperationId) {
          setWipeStatus(prev => ({
            ...prev,
            progress: progress
          }));
        }
      });
      
      // Return cleanup function
      return unlisten;
    };
    
    let cleanup: (() => void) | undefined;
    setupProgressListener().then(unlisten => {
      cleanup = unlisten;
    });
    
    return () => {
      if (cleanup) cleanup();
    };
  }, [currentOperationId]);

  // SECURITY: Cooldown timer to update remaining time
  useEffect(() => {
    if (cooldownRemaining > 0) {
      const timer = setInterval(() => {
        const elapsed = Math.floor((Date.now() - lastWipeTime) / 1000);
        const remaining = Math.max(0, COOLDOWN_SECONDS - elapsed);
        setCooldownRemaining(remaining);
        
        if (remaining === 0) {
          clearInterval(timer);
        }
      }, 100); // Update every 100ms for smooth countdown
      
      return () => clearInterval(timer);
    }
  }, [cooldownRemaining, lastWipeTime, COOLDOWN_SECONDS]);

  // SECURITY: Check if operation is allowed (rate limiting)
  const checkRateLimit = (): boolean => {
    const now = Date.now();
    const timeSinceLastWipe = Math.floor((now - lastWipeTime) / 1000);
    
    if (timeSinceLastWipe < COOLDOWN_SECONDS) {
      const remaining = COOLDOWN_SECONDS - timeSinceLastWipe;
      setCooldownRemaining(remaining);
      return false;
    }
    
    return true;
  };

  // SECURITY: Update rate limit after successful operation
  const updateRateLimit = () => {
    const now = Date.now();
    setLastWipeTime(now);
    setCooldownRemaining(COOLDOWN_SECONDS);
  };

  const checkAdminStatus = async () => {
    try {
      const adminStatus = await invoke<boolean>('check_admin_status');
      setIsAdmin(adminStatus);
      setAdminCheckComplete(true);
    } catch (error) {
      console.error('Failed to check admin status:', error);
      setIsAdmin(false);
      setAdminCheckComplete(true);
    }
  };

  const loadDrives = async () => {
    try {
      const drivesData = await invoke<DriveInfo[]>('get_drives');
      setDrives(drivesData);
    } catch (error) {
      console.error('Failed to load drives:', error);
    }
  };

  const handleFileSelect = async () => {
    try {
      console.log('Opening file dialog...');
      const selected = await open({
        multiple: true,
        filters: [{
          name: 'All Files',
          extensions: ['*']
        }]
      });
      
      console.log('File dialog result:', selected);
      
      if (selected && Array.isArray(selected)) {
        setSelectedFiles(selected as string[]);
        console.log('Files selected:', selected);
      } else if (selected === null) {
        console.log('File selection cancelled by user');
      } else {
        console.log('Unexpected file selection result:', selected);
      }
    } catch (error) {
      console.error('Failed to select files:', error);
      // Don't show dialog errors in wipe status - they're not wipe errors
      alert(`Failed to open file dialog: ${error}`);
    }
  };

  const handleFolderSelect = async () => {
    try {
      console.log('Opening folder dialog...');
      const selected = await open({
        directory: true
      });
      
      console.log('Folder dialog result:', selected);
      
      if (selected && typeof selected === 'string') {
        setSelectedFolder(selected);
        console.log('Folder selected:', selected);
      } else if (selected === null) {
        console.log('Folder selection cancelled by user');
      } else {
        console.log('Unexpected folder selection result:', selected);
      }
    } catch (error) {
      console.error('Failed to select folder:', error);
      // Don't show dialog errors in wipe status - they're not wipe errors
      alert(`Failed to open folder dialog: ${error}`);
    }
  };

  const normalizeError = (error: unknown): string => {
    if (typeof error === 'string') return error;
    if (error && typeof error === 'object') {
      const anyErr = error as any;
      if (typeof anyErr.message === 'string') return anyErr.message;
      try { return JSON.stringify(anyErr); } catch (_) { /* ignore */ }
    }
    return 'An unknown error occurred';
  };

  const handleWipe = async () => {
    if (wipeStatus.isWiping) return;

    // SECURITY: Rate limiting check
    if (!checkRateLimit()) {
      setWipeStatus({
        isWiping: false,
        progress: null,
        result: null,
        error: `Rate limit: Please wait ${cooldownRemaining} seconds before starting another wipe operation.\n\nThis cooldown prevents system resource exhaustion from rapid operations.`,
        certificatePath: null
      });
      return;
    }

    // Generate operation ID for this wipe session
    const sessionOperationId = `session_${Date.now()}`;
    setCurrentOperationId(sessionOperationId);
    
    setWipeStatus({
      isWiping: true,
      progress: null,
      result: null,
      error: null,
      certificatePath: null
    });
    setMultiResults(null);
    setBatchProgress(null);

    // SECURITY: Update rate limit timestamp
    updateRateLimit();

    try {
      let result: WipeResult | null = null;

      if (activeTab === 'file' && selectedFiles.length > 0) {
        const results: WipeResult[] = [];
        const certificates: string[] = [];
        for (let i = 0; i < selectedFiles.length; i++) {
          const filePath = selectedFiles[i];
          setBatchProgress({ current: i + 1, total: selectedFiles.length, currentTarget: filePath.split('\\').pop() || filePath });
          const r = await invoke<WipeResult>('wipe_file', {
            filePath: filePath,
            method: selectedMethod,
            operationId: sessionOperationId
          });
          results.push(r);
          const certPath = await invoke<string>('generate_certificate', { result: r });
          certificates.push(certPath);
        }
        setBatchProgress(null);
        setMultiResults({ results, certificates });
        // synthesize a summary result for convenience display
        const totalBytes = results.reduce((acc, r) => acc + r.bytes_wiped, 0);
        result = {
          ...results[results.length - 1],
          target: `${results.length} files`,
          bytes_wiped: totalBytes,
        } as WipeResult;
      } else if (activeTab === 'folder' && selectedFolder) {
        result = await invoke<WipeResult>('wipe_folder', {
          folderPath: selectedFolder,
          method: selectedMethod,
          operationId: sessionOperationId
        });
      } else if (activeTab === 'drive' && selectedDrive) {
        result = await invoke<WipeResult>('wipe_drive', {
          driveLetter: selectedDrive,
          method: selectedMethod,
          operationId: sessionOperationId
        });
      } else {
        throw new Error('Please select files, folder, or drive to wipe');
      }

      // Generate certificate for non-multi-file paths
      const certificatePath = result && (!multiResults) ? await invoke<string>('generate_certificate', {
        result: result
      }) : null;

      setWipeStatus({
        isWiping: false,
        progress: null,
        result: result,
        error: null,
        certificatePath: certificatePath
      });
      
      // Clear operation ID when complete
      setCurrentOperationId(null);

    } catch (error) {
      setWipeStatus({
        isWiping: false,
        progress: null,
        result: null,
        error: normalizeError(error),
        certificatePath: null
      });
      
      // Clear operation ID on error
      setCurrentOperationId(null);
    }
  };

  const formatBytes = (bytes: number): string => {
    if (bytes === 0) return '0 Bytes';
    const k = 1024;
    const sizes = ['Bytes', 'KB', 'MB', 'GB', 'TB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
  };

  const formatDuration = (ms: number): string => {
    const seconds = Math.floor(ms / 1000);
    const minutes = Math.floor(seconds / 60);
    const hours = Math.floor(minutes / 60);
    
    if (hours > 0) {
      return `${hours}h ${minutes % 60}m ${seconds % 60}s`;
    } else if (minutes > 0) {
      return `${minutes}m ${seconds % 60}s`;
    } else {
      return `${seconds}s`;
    }
  };

  return (
    <div className="container">
      <div className="header">
        <h1>ZeroRecover</h1>
        <p>Secure Data Wiping Tool with Verifiable Proof</p>
      </div>

      {adminCheckComplete && !isAdmin && activeTab === 'drive' && (
        <div style={{
          background: '#fff3cd',
          border: '2px solid #ffc107',
          borderRadius: '8px',
          padding: '15px',
          marginBottom: '20px',
          color: '#856404'
        }}>
          <div style={{ display: 'flex', alignItems: 'center', marginBottom: '8px' }}>
            <AlertTriangle size={20} style={{ marginRight: '8px' }} />
            <strong>Administrator Privileges Required</strong>
          </div>
          <p style={{ margin: '5px 0', fontSize: '0.9rem' }}>
            Drive wiping requires administrator privileges. Please restart the application as Administrator.
          </p>
          <p style={{ margin: '5px 0', fontSize: '0.85rem', fontStyle: 'italic' }}>
            Right-click the application and select "Run as administrator"
          </p>
        </div>
      )}

      <div className="card">
        <div className="tab-container">
          <button
            className={`tab ${activeTab === 'file' ? 'active' : ''}`}
            onClick={() => setActiveTab('file')}
          >
            <File size={20} style={{ marginRight: '8px' }} />
            File Shredder
          </button>
          <button
            className={`tab ${activeTab === 'folder' ? 'active' : ''}`}
            onClick={() => setActiveTab('folder')}
          >
            <Folder size={20} style={{ marginRight: '8px' }} />
            Folder Wipe
          </button>
          <button
            className={`tab ${activeTab === 'drive' ? 'active' : ''}`}
            onClick={() => setActiveTab('drive')}
          >
            <HardDrive size={20} style={{ marginRight: '8px' }} />
            Full Drive Wipe
          </button>
        </div>

        <div className="method-selector">
          <label htmlFor="wipe-method">Wipe Method:</label>
          <select
            id="wipe-method"
            value={selectedMethod}
            onChange={(e) => setSelectedMethod(e.target.value as WipeMethod)}
          >
            {WIPE_METHODS.map((method) => (
              <option key={method.value} value={method.value}>
                {method.label} - {method.description}
              </option>
            ))}
          </select>
        </div>

        {activeTab === 'file' && (
          <div className="file-input">
            <label>Select Files to Wipe:</label>
            <button
              onClick={handleFileSelect}
              style={{
                marginTop: '10px',
                padding: '8px 16px',
                background: '#667eea',
                color: 'white',
                border: 'none',
                borderRadius: '4px',
                cursor: 'pointer'
              }}
            >
              Browse Files
            </button>
            <div style={{ fontSize: '0.8rem', color: '#666', marginTop: '5px' }}>
              Note: File dialog only works in the desktop app, not in browser preview
            </div>
            {selectedFiles.length > 0 && (
              <div style={{ marginTop: '10px' }}>
                <strong>Selected Files ({selectedFiles.length}):</strong>
                <ul style={{ marginTop: '5px', paddingLeft: '20px' }}>
                  {selectedFiles.map((file, index) => (
                    <li key={index} style={{ fontSize: '0.9rem', color: '#666' }}>
                      {file.split('\\').pop()}
                    </li>
                  ))}
                </ul>
              </div>
            )}
          </div>
        )}

        {activeTab === 'folder' && (
          <div className="file-input">
            <label>Select Folder to Wipe:</label>
            <button
              onClick={handleFolderSelect}
              style={{
                marginTop: '10px',
                padding: '8px 16px',
                background: '#667eea',
                color: 'white',
                border: 'none',
                borderRadius: '4px',
                cursor: 'pointer'
              }}
            >
              Browse Folder
            </button>
            <div style={{ fontSize: '0.8rem', color: '#666', marginTop: '5px' }}>
              Note: Folder dialog only works in the desktop app, not in browser preview
            </div>
            {selectedFolder && (
              <div style={{ marginTop: '10px', color: '#666' }}>
                <strong>Selected:</strong> {selectedFolder}
              </div>
            )}
          </div>
        )}

        {activeTab === 'drive' && (
          <div className="drive-list">
            <label>Select Drive to Wipe:</label>
            {drives.map((drive) => (
              <div
                key={drive.letter}
                className={`drive-item ${selectedDrive === drive.letter ? 'selected' : ''}`}
                onClick={() => setSelectedDrive(drive.letter)}
              >
                <div className="drive-info">
                  <div className="drive-letter">
                    {drive.letter}: 
                    <span style={{ 
                      marginLeft: '8px', 
                      fontSize: '0.8rem', 
                      padding: '2px 8px', 
                      borderRadius: '4px',
                      background: drive.drive_type === 'SSD' ? '#e3f2fd' : drive.drive_type === 'HDD' ? '#fff3e0' : '#f5f5f5',
                      color: drive.drive_type === 'SSD' ? '#1976d2' : drive.drive_type === 'HDD' ? '#f57c00' : '#666'
                    }}>
                      {drive.drive_type}
                    </span>
                  </div>
                  <div className="drive-details">
                    {drive.label} ({drive.file_system})
                  </div>
                  <div className="drive-size">
                    {formatBytes(drive.free_size)} free of {formatBytes(drive.total_size)}
                  </div>
                  {drive.drive_type === 'SSD' && (
                    <div style={{ fontSize: '0.75rem', color: '#1976d2', marginTop: '4px' }}>
                      ⚡ SSD-optimized wiping (reduced passes to minimize wear)
                    </div>
                  )}
                  {drive.drive_type === 'HDD' && (
                    <div style={{ fontSize: '0.75rem', color: '#f57c00', marginTop: '4px' }}>
                      💿 HDD detected (full passes for maximum security)
                    </div>
                  )}
                </div>
                <input
                  type="radio"
                  checked={selectedDrive === drive.letter}
                  onChange={() => setSelectedDrive(drive.letter)}
                />
              </div>
            ))}
          </div>
        )}

        {activeTab === 'drive' && (
          <>
            <div className="warning-box" style={{ background: '#ffebee', borderColor: '#ef5350' }}>
              <h3 style={{ color: '#c62828' }}>
                <AlertTriangle size={20} />
                🚨 CRITICAL WARNING: Full Drive Wipe
              </h3>
              <p style={{ color: '#c62828', fontWeight: 'bold' }}>
                This will permanently erase ALL data on the selected drive. This action CANNOT be undone.
              </p>
              <ul style={{ marginTop: '10px', marginLeft: '20px', color: '#c62828' }}>
                <li>All files, folders, and data will be destroyed</li>
                <li>The drive will be unrecoverable</li>
                <li>Make sure you have backed up important data</li>
                <li><strong>System drives are automatically blocked for safety</strong></li>
              </ul>
              <div style={{ marginTop: '15px', padding: '10px', background: '#fff', borderRadius: '4px', border: '1px solid #ef5350' }}>
                <div style={{ fontSize: '0.9rem', marginBottom: '6px', color: '#333' }}>
                  Type <strong style={{ color: '#c62828' }}>ERASE MY DRIVE</strong> to confirm:
                </div>
                <input
                  type="text"
                  value={driveConfirmText}
                  onChange={(e) => setDriveConfirmText(e.target.value)}
                  placeholder="ERASE MY DRIVE"
                  style={{ 
                    width: '100%', 
                    padding: '8px', 
                    borderRadius: '4px', 
                    border: '2px solid #ef5350',
                    fontSize: '1rem',
                    fontWeight: 'bold'
                  }}
                />
              </div>
            </div>
            <div style={{ 
              marginTop: '10px', 
              padding: '10px', 
              background: isAdmin ? '#e8f5e9' : '#fff3cd', 
              border: isAdmin ? '1px solid #4caf50' : '1px solid #ffc107',
              borderRadius: '4px',
              fontSize: '0.85rem'
            }}>
              <strong style={{ color: isAdmin ? '#2e7d32' : '#856404' }}>
                {isAdmin ? '✅ Administrator Mode Active' : '⚠️ Administrator Required'}
              </strong>
              <ul style={{ marginTop: '5px', marginLeft: '20px', color: isAdmin ? '#2e7d32' : '#856404' }}>
                {isAdmin ? (
                  <>
                    <li>Administrator privileges detected</li>
                    <li>Drive wiping operations are available</li>
                    <li>System drive (C:) is automatically blocked</li>
                    <li>Windows installation drives cannot be wiped</li>
                  </>
                ) : (
                  <>
                    <li>Drive wiping requires administrator privileges</li>
                    <li>Please restart as administrator to wipe drives</li>
                    <li>File and folder wiping still available</li>
                  </>
                )}
              </ul>
            </div>
          </>
        )}

        {/* SECURITY: Cooldown indicator */}
        {cooldownRemaining > 0 && !wipeStatus.isWiping && (
          <div style={{
            background: '#fff3cd',
            border: '1px solid #ffc107',
            borderRadius: '8px',
            padding: '12px',
            marginBottom: '15px',
            display: 'flex',
            alignItems: 'center',
            gap: '10px'
          }}>
            <AlertTriangle size={20} color="#856404" />
            <div style={{ flex: 1, color: '#856404' }}>
              <strong>Rate Limit Active</strong>
              <div style={{ fontSize: '0.9rem', marginTop: '4px' }}>
                Please wait {cooldownRemaining} second{cooldownRemaining !== 1 ? 's' : ''} before starting another operation.
                This prevents system resource exhaustion.
              </div>
            </div>
          </div>
        )}

        <button
          className="wipe-button"
          onClick={handleWipe}
          disabled={wipeStatus.isWiping || 
            cooldownRemaining > 0 ||
            (activeTab === 'file' && selectedFiles.length === 0) ||
            (activeTab === 'folder' && !selectedFolder) ||
            (activeTab === 'drive' && (!selectedDrive || driveConfirmText !== 'ERASE MY DRIVE' || !isAdmin))
          }
        >
          {wipeStatus.isWiping ? (
            <>
              <div className="pulse" style={{ display: 'inline-block', marginRight: '8px' }}>
                <Shield size={20} />
              </div>
              Wiping in Progress...
            </>
          ) : cooldownRemaining > 0 ? (
            <>
              <AlertTriangle size={20} style={{ marginRight: '8px' }} />
              Cooldown: {cooldownRemaining}s
            </>
          ) : (
            <>
              <Shield size={20} style={{ marginRight: '8px' }} />
              Start Secure Wipe
            </>
          )}
        </button>

        {wipeStatus.progress && (
          <div className="progress-container">
            <div className="progress-bar">
              <div
                className="progress-fill"
                style={{ width: `${wipeStatus.progress.percentage}%` }}
              />
            </div>
            <div className="progress-text">
              Pass {wipeStatus.progress.current_pass} of {wipeStatus.progress.total_passes} - 
              {wipeStatus.progress.percentage.toFixed(1)}% Complete
            </div>
            <div style={{ fontSize: '0.9rem', color: '#666', textAlign: 'center', marginTop: '5px' }}>
              {wipeStatus.progress.current_operation}
            </div>
          </div>
        )}

        {batchProgress && (
          <div className="progress-container" style={{ marginTop: '12px' }}>
            <div className="progress-text" style={{ textAlign: 'center' }}>
              Processing {batchProgress.current} of {batchProgress.total}
              {batchProgress.currentTarget ? ` - ${batchProgress.currentTarget}` : ''}
            </div>
            <div className="progress-bar">
              <div
                className="progress-fill"
                style={{ width: `${(batchProgress.current / batchProgress.total) * 100}%` }}
              />
            </div>
          </div>
        )}

        {wipeStatus.result && (
          <div className="status-message status-success fade-in">
            <h3 style={{ display: 'flex', alignItems: 'center', marginBottom: '10px' }}>
              <CheckCircle size={20} style={{ marginRight: '8px' }} />
              Wipe Completed Successfully
            </h3>
            <p><strong>Target:</strong> {wipeStatus.result.target}</p>
            <p><strong>Method:</strong> {wipeStatus.result.method}</p>
            <p><strong>Bytes Wiped:</strong> {formatBytes(wipeStatus.result.bytes_wiped)}</p>
            <p><strong>Passes Completed:</strong> {wipeStatus.result.passes_completed}</p>
            <p><strong>Duration:</strong> {formatDuration(wipeStatus.result.duration_ms)}</p>
            <p><strong>Device ID:</strong> {wipeStatus.result.device_id}</p>
            <p><strong>Hash:</strong> {wipeStatus.result.hash}</p>
          </div>
        )}

        {wipeStatus.certificatePath && (
          <div className="certificate-info fade-in">
            <h3>
              <CheckCircle size={20} style={{ marginRight: '8px' }} />
              Certificate Generated
            </h3>
            <p><strong>Certificate Path:</strong> {wipeStatus.certificatePath}</p>
            <p>The certificate contains tamper-proof proof of the wipe operation and can be used for compliance and verification purposes.</p>
          </div>
        )}

        {multiResults && multiResults.results.length > 0 && (
          <div className="status-message status-success fade-in" style={{ marginTop: '12px' }}>
            <h3 style={{ display: 'flex', alignItems: 'center', marginBottom: '10px' }}>
              <CheckCircle size={20} style={{ marginRight: '8px' }} />
              Per-file Results
            </h3>
            <ul style={{ marginTop: '5px', paddingLeft: '20px' }}>
              {multiResults.results.map((r, idx) => (
                <li key={idx} style={{ marginBottom: '6px' }}>
                  <div><strong>Target:</strong> {r.target}</div>
                  <div><strong>Bytes Wiped:</strong> {formatBytes(r.bytes_wiped)}</div>
                  <div><strong>Method:</strong> {r.method}</div>
                  <div style={{ fontSize: '0.85rem', color: '#555' }}>
                    <strong>Certificate:</strong> {multiResults.certificates[idx]}
                  </div>
                </li>
              ))}
            </ul>
          </div>
        )}

        {wipeStatus.error && (
          <div className="status-message status-error fade-in">
            <h3 style={{ display: 'flex', alignItems: 'center', marginBottom: '10px' }}>
              <XCircle size={20} style={{ marginRight: '8px' }} />
              Wipe Failed
            </h3>
            <p>{wipeStatus.error}</p>
          </div>
        )}
      </div>
    </div>
  );
}

export default App;
