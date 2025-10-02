import React, { useState, useEffect } from 'react';
import { invoke } from '@tauri-apps/api/core';
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
  const [multiResults, setMultiResults] = useState<{ results: WipeResult[]; certificates: string[] } | null>(null);
  const [batchProgress, setBatchProgress] = useState<{ current: number; total: number; currentTarget: string } | null>(null);

  useEffect(() => {
    loadDrives();
  }, []);

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
      const selected = await open({
        multiple: true,
        filters: [{
          name: 'All Files',
          extensions: ['*']
        }]
      });
      
      if (selected && Array.isArray(selected)) {
        setSelectedFiles(selected as string[]);
      }
    } catch (error) {
      console.error('Failed to select files:', error);
    }
  };

  const handleFolderSelect = async () => {
    try {
      const selected = await open({
        directory: true
      });
      
      if (selected && typeof selected === 'string') {
        setSelectedFolder(selected);
      }
    } catch (error) {
      console.error('Failed to select folder:', error);
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

    setWipeStatus({
      isWiping: true,
      progress: null,
      result: null,
      error: null,
      certificatePath: null
    });
    setMultiResults(null);
    setBatchProgress(null);

    try {
      let result: WipeResult | null = null;

      if (activeTab === 'file' && selectedFiles.length > 0) {
        const results: WipeResult[] = [];
        const certificates: string[] = [];
        for (let i = 0; i < selectedFiles.length; i++) {
          const filePath = selectedFiles[i];
          setBatchProgress({ current: i + 1, total: selectedFiles.length, currentTarget: filePath.split('\\').pop() || filePath });
          const r = await invoke<WipeResult>('wipe_file', {
            filePath,
            method: selectedMethod
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
          method: selectedMethod
        });
      } else if (activeTab === 'drive' && selectedDrive) {
        result = await invoke<WipeResult>('wipe_drive', {
          driveLetter: selectedDrive,
          method: selectedMethod
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

    } catch (error) {
      setWipeStatus({
        isWiping: false,
        progress: null,
        result: null,
        error: normalizeError(error),
        certificatePath: null
      });
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
          <div className="warning-box">
            <h3>
              <AlertTriangle size={20} />
              DANGER: Full Drive Wipe
            </h3>
            <p>
              This will permanently erase ALL data on the selected drive. This action cannot be undone.
              Make sure you have backed up any important data before proceeding.
            </p>
            <div style={{ marginTop: '10px' }}>
              <div style={{ fontSize: '0.9rem', marginBottom: '6px' }}>
                Type <strong>ERASE MY DRIVE</strong> to confirm:
              </div>
              <input
                type="text"
                value={driveConfirmText}
                onChange={(e) => setDriveConfirmText(e.target.value)}
                placeholder="ERASE MY DRIVE"
                style={{ width: '100%', padding: '8px', borderRadius: '4px', border: '1px solid #ddd' }}
              />
            </div>
          </div>
        )}

        <button
          className="wipe-button"
          onClick={handleWipe}
          disabled={wipeStatus.isWiping || 
            (activeTab === 'file' && selectedFiles.length === 0) ||
            (activeTab === 'folder' && !selectedFolder) ||
            (activeTab === 'drive' && (!selectedDrive || driveConfirmText !== 'ERASE MY DRIVE'))
          }
        >
          {wipeStatus.isWiping ? (
            <>
              <div className="pulse" style={{ display: 'inline-block', marginRight: '8px' }}>
                <Shield size={20} />
              </div>
              Wiping in Progress...
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
