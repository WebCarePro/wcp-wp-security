import { Fragment, useState, useEffect } from '@wordpress/element';
import apiFetch from '@wordpress/api-fetch';
import { 
  ShieldAlert, 
  ShieldCheck, 
  Shield,
  Play, 
  CheckCircle2, 
  AlertTriangle, 
  FileCode, 
  Database, 
  Layers, 
  Search, 
  ChevronDown, 
  ChevronRight,
  ExternalLink, 
  Info, 
  Activity, 
  Archive, 
  RotateCcw,
  Server,
  HardDrive,
  Download,
  Trash2,
  History,
  UserCheck,
  Key,
  RefreshCw,
  FileQuestion,
  FileText,
  Lock,
  Unlock,
  CheckCircle,
  XCircle,
  Zap,
  Filter,
  FileWarning
} from 'lucide-react';
import './index.css';

interface ScanData {
  id: number;
  status: string;
  scan_target?: string;
  scanned_files: number;
  total_files: number;
  issues_found: number;
  risk_score: number;
  duration?: number;
  created_at: string;
  completed_at?: string;
}

interface IssueData {
  id: number;
  scan_id: number;
  engine: string;
  type: string;
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
  confidence: number;
  file_path: string;
  line_number?: number;
  code_snippet?: string;
  evidence?: string;
  description: string;
  status: string;
}

interface ScannedFileInfo {
  id: number;
  scan_id: number;
  file_path: string;
  file_size: number;
  status: 'clean' | 'threat';
  scanned_at: string;
}

interface QuarantineRecord {
  id: number;
  scan_id?: number;
  issue_id?: number;
  original_path: string;
  quarantine_filename: string;
  sha256: string;
  file_size: number;
  status: 'quarantined' | 'restored';
  quarantined_at: string;
  restored_at?: string;
}

interface RiskSummary {
  score: number;
  level: string;
  counts: {
    critical: number;
    high: number;
    medium: number;
    low: number;
    info: number;
  };
  total: number;
}

interface BackupItem {
  filename: string;
  size_mb: number;
  size_bytes: number;
  created: string;
  timestamp: number;
}

interface ServerInfoData {
  php: {
    version: string;
    sapi: string;
    memory_limit: string;
    memory_usage_mb: number;
    max_execution_time: number;
    upload_max_filesize: string;
    post_max_size: string;
    display_errors: string;
    disabled_functions: string[];
    extensions: Record<string, boolean>;
  };
  database: {
    version: string;
    name: string;
    host: string;
    charset: string;
    collate: string;
    size_mb: number;
    table_prefix: string;
  };
  server: {
    software: string;
    os: string;
    arch: string;
    ip: string;
    webroot: string;
  };
  wordpress: {
    version: string;
    debug: boolean;
    debug_log: boolean;
    debug_display: boolean;
    ssl: boolean;
    multisite: boolean;
  };
  permissions: {
    'wp-config.php': string;
    '.htaccess': string;
    'wp-content': string;
    'uploads': string;
  };
}

const TAB_TO_PAGE: Record<string, string> = {
  dashboard: 'wcp-security-scanner',
  targeted: 'wcp-scanner-tools',
  logs: 'wcp-scanner-logs',
  backup: 'wcp-scanner-backup',
  server: 'wcp-scanner-server',
};

const PAGE_TO_TAB: Record<string, 'dashboard' | 'targeted' | 'logs' | 'backup' | 'server'> = {
  'wcp-security-scanner': 'dashboard',
  'wcp-scanner-tools': 'targeted',
  'wcp-scanner-logs': 'logs',
  'wcp-scanner-backup': 'backup',
  'wcp-scanner-server': 'server',
};

export const App = () => {
  const getInitialNavTab = (): 'dashboard' | 'targeted' | 'logs' | 'backup' | 'server' => {
    try {
      const urlParams = new URLSearchParams(window.location.search);
      const page = urlParams.get('page');
      if (page && PAGE_TO_TAB[page]) {
        return PAGE_TO_TAB[page];
      }
    } catch (e) {}

    const localized = (window as any).wcpScannerSettings?.initialTab;
    if (localized && (PAGE_TO_TAB[localized] || ['dashboard', 'targeted', 'logs', 'backup', 'server'].includes(localized))) {
      return PAGE_TO_TAB[localized] || localized;
    }
    return 'dashboard';
  };

  const [navTab, setNavTab] = useState<'dashboard' | 'targeted' | 'logs' | 'backup' | 'server'>(getInitialNavTab);

  // Synchronize browser URL bar and WordPress sidebar active menu on tab switch
  const handleNavTabChange = (newTab: 'dashboard' | 'targeted' | 'logs' | 'backup' | 'server') => {
    setNavTab(newTab);
    const targetPage = TAB_TO_PAGE[newTab];
    if (targetPage) {
      try {
        const url = new URL(window.location.href);
        url.searchParams.set('page', targetPage);
        window.history.pushState({ tab: newTab }, '', url.toString());

        // Update WordPress sidebar menu highlight
        const submenus = document.querySelectorAll('#adminmenu a[href*="page=wcp-"]');
        submenus.forEach((el) => {
          const href = el.getAttribute('href') || '';
          const li = el.closest('li');
          if (href.includes(`page=${targetPage}`)) {
            li?.classList.add('current');
            el.classList.add('current');
          } else {
            li?.classList.remove('current');
            el.classList.remove('current');
          }
        });
      } catch (err) {
        console.error('Failed to update URL history state', err);
      }
    }
  };

  // Listen to browser back/forward buttons
  useEffect(() => {
    const handlePopState = () => {
      const urlParams = new URLSearchParams(window.location.search);
      const page = urlParams.get('page') || 'wcp-security-scanner';
      const matched = PAGE_TO_TAB[page] || 'dashboard';
      setNavTab(matched);
    };

    window.addEventListener('popstate', handlePopState);
    return () => window.removeEventListener('popstate', handlePopState);
  }, []);

  // Dashboard states
  const [loading, setLoading] = useState<boolean>(true);
  const [scanning, setScanning] = useState<boolean>(false);
  const [scanStage, setScanStage] = useState<string>('');
  const [scanTarget, setScanTarget] = useState<'plugins_themes' | 'full'>('plugins_themes');
  const [currentScan, setCurrentScan] = useState<ScanData | null>(null);
  const [summary, setSummary] = useState<RiskSummary | null>(null);
  const [issues, setIssues] = useState<IssueData[]>([]);
  const [scannedFiles, setScannedFiles] = useState<ScannedFileInfo[]>([]);
  const [quarantinedFiles, setQuarantinedFiles] = useState<QuarantineRecord[]>([]);
  const [dashboardSubTab, setDashboardSubTab] = useState<'issues' | 'quarantine' | 'files'>('issues');
  const [severityFilter, setSeverityFilter] = useState<string>('all');
  const [issueSearch, setIssueSearch] = useState<string>('');
  const [fileFilter, setFileFilter] = useState<string>('');
  const [progress, setProgress] = useState<number>(0);
  const [currentFile, setCurrentFile] = useState<string>('');
  const [expandedIssue, setExpandedIssue] = useState<number | null>(null);

  // Targeted scans state
  const [adminOnlyUsers, setAdminOnlyUsers] = useState<boolean>(true);
  const [targetedScanning, setTargetedScanning] = useState<string | null>(null);
  const [targetedResult, setTargetedResult] = useState<{ target: string; summary: RiskSummary; issues: IssueData[] } | null>(null);

  // Scan Logs state
  const [scanHistory, setScanHistory] = useState<ScanData[]>([]);
  const [historyLoading, setHistoryLoading] = useState<boolean>(false);
  const [selectedScanDetail, setSelectedScanDetail] = useState<{ scan: ScanData; summary: RiskSummary; issues: IssueData[]; files_count: number } | null>(null);

  // Database Backup state
  const [backups, setBackups] = useState<BackupItem[]>([]);
  const [backupLoading, setBackupLoading] = useState<boolean>(false);
  const [creatingBackup, setCreatingBackup] = useState<boolean>(false);

  // Server Info state
  const [serverInfo, setServerInfo] = useState<ServerInfoData | null>(null);
  const [serverInfoLoading, setServerInfoLoading] = useState<boolean>(false);

  // 1. Load latest scan & quarantine
  const loadLatestScan = async () => {
    try {
      setLoading(true);
      const res: any = await apiFetch({ path: '/wcp-scanner/v1/scan/latest' });
      if (res?.has_scan) {
        setCurrentScan(res.scan);
        setSummary(res.summary || null);
        setIssues(res.issues || []);
        setScannedFiles(res.files || []);
      }

      const qRes: any = await apiFetch({ path: '/wcp-scanner/v1/quarantine' });
      if (qRes?.records) {
        setQuarantinedFiles(qRes.records);
      }
    } catch (e) {
      console.error('Failed to load scan info', e);
    } finally {
      setLoading(false);
    }
  };

  // 2. Load scan logs history
  const loadScanHistory = async () => {
    try {
      setHistoryLoading(true);
      const res: any = await apiFetch({ path: '/wcp-scanner/v1/scan/history' });
      if (res?.scans) {
        setScanHistory(res.scans);
      }
    } catch (e) {
      console.error('Failed to load scan history', e);
    } finally {
      setHistoryLoading(false);
    }
  };

  // Load single historical scan log
  const loadScanLogDetail = async (id: number) => {
    try {
      const res: any = await apiFetch({ path: `/wcp-scanner/v1/scan/history/${id}` });
      if (res?.success) {
        setSelectedScanDetail({
          scan: res.scan,
          summary: res.summary,
          issues: res.issues || [],
          files_count: res.files_count || 0
        });
      }
    } catch (e) {
      console.error('Failed to load scan log detail', e);
    }
  };

  // Clear all old scan history & logs
  const handleClearAllScanHistory = async () => {
    if (!confirm('Are you sure you want to permanently clear all old scan logs and history records? This cannot be undone.')) {
      return;
    }
    try {
      setHistoryLoading(true);
      const res: any = await apiFetch({
        path: '/wcp-scanner/v1/scan/history/clear',
        method: 'POST'
      });
      if (res?.success) {
        alert(res.message || 'All old scan logs cleared successfully.');
        setScanHistory([]);
        setSelectedScanDetail(null);
        await loadLatestScan();
      } else {
        alert('Could not clear scan logs.');
      }
    } catch (e) {
      console.error('Failed to clear scan history', e);
      alert('Error clearing scan logs.');
    } finally {
      setHistoryLoading(false);
    }
  };

  // 3. Load backups
  const loadBackups = async () => {
    try {
      setBackupLoading(true);
      const res: any = await apiFetch({ path: '/wcp-scanner/v1/backup/list' });
      if (res?.backups) {
        setBackups(res.backups);
      }
    } catch (e) {
      console.error('Failed to load backups', e);
    } finally {
      setBackupLoading(false);
    }
  };

  const handleCreateBackup = async () => {
    try {
      setCreatingBackup(true);
      const res: any = await apiFetch({
        path: '/wcp-scanner/v1/backup/create',
        method: 'POST'
      });
      if (res?.success) {
        alert(res.message || 'Database backup created successfully!');
        await loadBackups();
      } else {
        alert(res?.message || 'Failed to create backup.');
      }
    } catch (e) {
      console.error('Backup creation failed', e);
      alert('Error creating database backup.');
    } finally {
      setCreatingBackup(false);
    }
  };

  const handleDeleteBackup = async (filename: string) => {
    if (!confirm(`Are you sure you want to delete backup file:\n${filename}?`)) {
      return;
    }
    try {
      const res: any = await apiFetch({
        path: '/wcp-scanner/v1/backup/delete',
        method: 'POST',
        data: { filename }
      });
      if (res?.success) {
        setBackups((prev) => prev.filter((b) => b.filename !== filename));
      } else {
        alert('Could not delete backup file.');
      }
    } catch (e) {
      console.error('Failed to delete backup', e);
    }
  };

  const handleDownloadBackup = (filename: string) => {
    const root = (window as any).wcpScannerSettings?.root || '/wp-json/wcp-scanner/v1';
    const nonce = (window as any).wcpScannerSettings?.nonce || '';
    const url = `${root}/backup/download?filename=${encodeURIComponent(filename)}&_wpnonce=${nonce}`;
    window.open(url, '_blank');
  };

  // 4. Load Server Info
  const loadServerInfo = async () => {
    try {
      setServerInfoLoading(true);
      const res: any = await apiFetch({ path: '/wcp-scanner/v1/server-info' });
      if (res?.info) {
        setServerInfo(res.info);
      }
    } catch (e) {
      console.error('Failed to load server info', e);
    } finally {
      setServerInfoLoading(false);
    }
  };

  // Fetch data on tab change or mount
  useEffect(() => {
    loadLatestScan();
  }, []);

  useEffect(() => {
    if (navTab === 'logs') {
      loadScanHistory();
    } else if (navTab === 'backup') {
      loadBackups();
    } else if (navTab === 'server') {
      loadServerInfo();
    }
  }, [navTab]);

  // Standard Dashboard Scan Handler
  const handleStartScan = async () => {
    try {
      setScanning(true);
      setProgress(0);
      setScanStage('Initializing filesystem scanner...');
      setCurrentFile('Collecting file manifest...');

      const startRes: any = await apiFetch({
        path: '/wcp-scanner/v1/scan/start',
        method: 'POST',
        data: { target: scanTarget },
      });

      if (!startRes?.success) {
        alert('Could not start scan');
        setScanning(false);
        return;
      }

      const scanId = startRes.scan_id;
      const total = startRes.total_files || 1;

      // Phase 1: Filesystem batch loop
      setScanStage('Stage 1/2: Scanning Files & Malware Heuristics...');
      let finished = false;
      while (!finished) {
        const batchRes: any = await apiFetch({
          path: '/wcp-scanner/v1/scan/batch',
          method: 'POST',
          data: { scan_id: scanId, batch_size: 30 },
        });

        if (batchRes.last_file) {
          setCurrentFile(batchRes.last_file);
        }

        const remaining = batchRes.remaining || 0;
        const processed = total - remaining;
        const currentPercent = Math.min(85, Math.round((processed / total) * 85));
        setProgress(currentPercent);

        if (batchRes.is_finished) {
          finished = true;
        }
      }

      // Phase 2: Deep audits
      setScanStage('Stage 2/2: Deep Audit (Core Integrity, Database Injections, SEO Spam, Updates)...');
      setCurrentFile('Running cross-engine correlation & risk assessment...');
      setProgress(90);

      await apiFetch({
        path: '/wcp-scanner/v1/scan/deep-audit',
        method: 'POST',
        data: { scan_id: scanId, target: scanTarget },
      });

      setProgress(100);
      setScanStage('Scan completed successfully!');
      setCurrentFile('Audit finalized.');
      await loadLatestScan();
    } catch (err) {
      console.error('Error during scan batching', err);
      alert('Error occurred during scanning');
    } finally {
      setScanning(false);
    }
  };

  // Targeted Single-Option Scan Handler
  const handleStartTargetedScan = async (targetType: string, extraOptions: any = {}) => {
    try {
      setTargetedScanning(targetType);
      setTargetedResult(null);

      const startRes: any = await apiFetch({
        path: '/wcp-scanner/v1/scan/start',
        method: 'POST',
        data: { target: targetType },
      });

      if (!startRes?.success) {
        alert('Could not start targeted audit.');
        setTargetedScanning(null);
        return;
      }

      const scanId = startRes.scan_id;
      const totalFiles = startRes.total_files || 0;

      // If filesystem-only scan, run file batch loop
      if (targetType === 'filesystem_only' && totalFiles > 0) {
        let finished = false;
        while (!finished) {
          const batchRes: any = await apiFetch({
            path: '/wcp-scanner/v1/scan/batch',
            method: 'POST',
            data: { scan_id: scanId, batch_size: 40 },
          });
          if (batchRes.is_finished) {
            finished = true;
          }
        }
      }

      // Run deep audit for the target
      const auditRes: any = await apiFetch({
        path: '/wcp-scanner/v1/scan/deep-audit',
        method: 'POST',
        data: { 
          scan_id: scanId, 
          target: targetType,
          admins_only: extraOptions.admins_only ?? false
        },
      });

      // Fetch the findings of this scan
      const detailRes: any = await apiFetch({
        path: `/wcp-scanner/v1/scan/history/${scanId}`
      });

      if (detailRes?.success) {
        setTargetedResult({
          target: targetType,
          summary: detailRes.summary,
          issues: detailRes.issues || []
        });
      }

      // Also refresh dashboard & history in background
      loadLatestScan();
    } catch (err) {
      console.error('Targeted scan error', err);
      alert('An error occurred while executing targeted scan.');
    } finally {
      setTargetedScanning(null);
    }
  };

  const handleUpdateIssue = async (id: number, status: string) => {
    try {
      await apiFetch({
        path: `/wcp-scanner/v1/issues/${id}`,
        method: 'POST',
        data: { status },
      });
      setIssues((prev) => prev.map((item) => (item.id === id ? { ...item, status } : item)));
      if (targetedResult) {
        setTargetedResult({
          ...targetedResult,
          issues: targetedResult.issues.map((item) => (item.id === id ? { ...item, status } : item))
        });
      }
    } catch (e) {
      console.error(e);
    }
  };

  const handleQuarantine = async (issue: IssueData) => {
    if (!confirm(`Are you sure you want to safely isolate and quarantine:\n${issue.file_path}?`)) {
      return;
    }
    try {
      const res: any = await apiFetch({
        path: '/wcp-scanner/v1/quarantine',
        method: 'POST',
        data: {
          file_path: issue.file_path,
          scan_id: issue.scan_id,
          issue_id: issue.id,
        },
      });

      if (res?.success) {
        alert(res.message || 'File quarantined successfully!');
        handleUpdateIssue(issue.id, 'quarantined');
        loadLatestScan();
      } else {
        alert(res?.message || 'Quarantine failed.');
      }
    } catch (err) {
      console.error(err);
      alert('Failed to quarantine file');
    }
  };

  const handleRestoreQuarantine = async (id: number) => {
    if (!confirm('Are you sure you want to restore this file back to its original location?')) {
      return;
    }
    try {
      const res: any = await apiFetch({
        path: `/wcp-scanner/v1/quarantine/${id}/restore`,
        method: 'POST',
      });

      if (res?.success) {
        alert(res.message || 'File restored successfully!');
        loadLatestScan();
      } else {
        alert(res?.message || 'Restore failed.');
      }
    } catch (err) {
      console.error(err);
      alert('Failed to restore file');
    }
  };

  const filteredIssues = issues.filter((item) => {
    const matchesSeverity = severityFilter === 'all' || item.severity === severityFilter;
    const matchesSearch =
      issueSearch === '' ||
      item.file_path.toLowerCase().includes(issueSearch.toLowerCase()) ||
      item.description.toLowerCase().includes(issueSearch.toLowerCase()) ||
      item.type.toLowerCase().includes(issueSearch.toLowerCase());
    return matchesSeverity && matchesSearch;
  });

  const filteredFiles = scannedFiles.filter((item) => {
    if (!fileFilter) return true;
    return item.file_path.toLowerCase().includes(fileFilter.toLowerCase());
  });

  return (
    <div className="wcp-container">
      {/* App Top Header */}
      <div className="wcp-header">
        <div>
          <h1>
            <ShieldAlert size={28} color="#3b82f6" />
            WCP Security Scanner Pro
          </h1>
          <p>
            Multi-engine malware defense, database integrity, integrity checksums & automated vulnerability mitigation.
          </p>
        </div>
        <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
          <span className="wcp-badge" style={{ background: '#ecfdf5', color: '#047857', border: '1px solid #a7f3d0' }}>
            ● Engine v1.2.0 Active
          </span>
          <button 
            className="wcp-btn"
            style={{ background: '#f1f5f9', color: '#475569', padding: '8px 14px' }}
            onClick={() => {
              if (navTab === 'dashboard') loadLatestScan();
              else if (navTab === 'logs') loadScanHistory();
              else if (navTab === 'backup') loadBackups();
              else if (navTab === 'server') loadServerInfo();
            }}
          >
            <RefreshCw size={15} /> Refresh
          </button>
        </div>
      </div>

      {/* Main Navigation Sub-pages Tabs */}
      <div className="wcp-nav-tabs">
        <button
          className={`wcp-nav-tab ${navTab === 'dashboard' ? 'active' : ''}`}
          onClick={() => handleNavTabChange('dashboard')}
        >
          <Shield size={18} />
          Dashboard & Scanner
        </button>
        <button
          className={`wcp-nav-tab ${navTab === 'targeted' ? 'active' : ''}`}
          onClick={() => handleNavTabChange('targeted')}
        >
          <Zap size={18} />
          Targeted Scans
        </button>
        <button
          className={`wcp-nav-tab ${navTab === 'logs' ? 'active' : ''}`}
          onClick={() => handleNavTabChange('logs')}
        >
          <History size={18} />
          Scan Logs & History
        </button>
        <button
          className={`wcp-nav-tab ${navTab === 'backup' ? 'active' : ''}`}
          onClick={() => handleNavTabChange('backup')}
        >
          <Database size={18} />
          Database Backup Vault
        </button>
        <button
          className={`wcp-nav-tab ${navTab === 'server' ? 'active' : ''}`}
          onClick={() => handleNavTabChange('server')}
        >
          <Server size={18} />
          Server & Environment Info
        </button>
      </div>

      {/* VIEW 1: DASHBOARD */}
      {navTab === 'dashboard' && (
        <Fragment>
          {/* Metrics Overview Grid */}
          <div className="wcp-metrics-grid">
            <div className="wcp-metric-card">
              <div>
                <div className="wcp-metric-label">Risk Score</div>
                <div
                  className="wcp-metric-val"
                  style={{
                    color:
                      summary && summary.score > 60
                        ? '#ef4444'
                        : summary && summary.score > 25
                        ? '#f59e0b'
                        : '#10b981',
                  }}
                >
                  {summary ? `${summary.score}/100` : '0/100'}
                </div>
              </div>
              <ShieldCheck
                size={36}
                color={
                  summary && summary.score > 60
                    ? '#ef4444'
                    : summary && summary.score > 25
                    ? '#f59e0b'
                    : '#10b981'
                }
              />
            </div>

            <div className="wcp-metric-card">
              <div>
                <div className="wcp-metric-label">Critical Threats</div>
                <div className="wcp-metric-val" style={{ color: '#ef4444' }}>
                  {summary?.counts?.critical || 0}
                </div>
              </div>
              <AlertTriangle size={36} color="#ef4444" />
            </div>

            <div className="wcp-metric-card">
              <div>
                <div className="wcp-metric-label">High / Med Issues</div>
                <div className="wcp-metric-val" style={{ color: '#f59e0b' }}>
                  {(summary?.counts?.high || 0) + (summary?.counts?.medium || 0)}
                </div>
              </div>
              <Activity size={36} color="#f59e0b" />
            </div>

            <div className="wcp-metric-card">
              <div>
                <div className="wcp-metric-label">Files Scanned</div>
                <div className="wcp-metric-val">
                  {currentScan?.scanned_files || 0}
                </div>
              </div>
              <FileCode size={36} color="#3b82f6" />
            </div>
          </div>

          {/* Scanner Control Banner */}
          <div className="wcp-scanner-box">
            <div className="wcp-scanner-box-inner">
              <div>
                <h2>Comprehensive Security Audit</h2>
                <p>
                  Scans files for malicious PHP functions, reverse integrity anomalies, backdoor shells, database SQL injections & spam redirects.
                </p>
                <div style={{ marginTop: '12px', display: 'flex', gap: '16px', alignItems: 'center' }}>
                  <label style={{ display: 'flex', alignItems: 'center', gap: '6px', fontSize: '13px', cursor: 'pointer' }}>
                    <input
                      type="radio"
                      name="scan_target"
                      value="plugins_themes"
                      checked={scanTarget === 'plugins_themes'}
                      onChange={() => setScanTarget('plugins_themes')}
                      disabled={scanning}
                    />
                    Plugins & Themes (Fast, Recommended)
                  </label>
                  <label style={{ display: 'flex', alignItems: 'center', gap: '6px', fontSize: '13px', cursor: 'pointer' }}>
                    <input
                      type="radio"
                      name="scan_target"
                      value="full"
                      checked={scanTarget === 'full'}
                      onChange={() => setScanTarget('full')}
                      disabled={scanning}
                    />
                    Full WordPress Tree (Deep Audit)
                  </label>
                </div>
              </div>

              <button
                className="wcp-btn wcp-btn-primary"
                onClick={handleStartScan}
                disabled={scanning}
                style={{ padding: '14px 28px', fontSize: '16px' }}
              >
                <Play size={18} fill="#ffffff" />
                {scanning ? 'Audit Running...' : 'Start Full Audit'}
              </button>
            </div>

            {/* Live Progress Bar */}
            {scanning && (
              <div className="wcp-progress-container">
                <div className="wcp-progress-bar-bg">
                  <div
                    className="wcp-progress-fill"
                    style={{ width: `${progress}%` }}
                  />
                </div>
                <div className="wcp-progress-info">
                  <span>{scanStage}</span>
                  <span>{progress}%</span>
                </div>
                {currentFile && (
                  <div style={{ fontSize: '12px', color: '#94a3b8', marginTop: '6px', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                    Examining: <code>{currentFile}</code>
                  </div>
                )}
              </div>
            )}
          </div>

          {/* Findings & Vault Sub-tabs */}
          <div className="wcp-card">
            <div className="wcp-card-header">
              <div style={{ display: 'flex', gap: '12px' }}>
                <button
                  className={`wcp-btn ${dashboardSubTab === 'issues' ? 'wcp-btn-primary' : ''}`}
                  style={{ background: dashboardSubTab === 'issues' ? '#3b82f6' : '#f1f5f9', color: dashboardSubTab === 'issues' ? '#fff' : '#475569', padding: '8px 16px' }}
                  onClick={() => setDashboardSubTab('issues')}
                >
                  <AlertTriangle size={16} /> Findings ({issues.length})
                </button>
                <button
                  className={`wcp-btn ${dashboardSubTab === 'quarantine' ? 'wcp-btn-primary' : ''}`}
                  style={{ background: dashboardSubTab === 'quarantine' ? '#3b82f6' : '#f1f5f9', color: dashboardSubTab === 'quarantine' ? '#fff' : '#475569', padding: '8px 16px' }}
                  onClick={() => setDashboardSubTab('quarantine')}
                >
                  <Archive size={16} /> Quarantine Vault ({quarantinedFiles.filter(q => q.status === 'quarantined').length})
                </button>
                <button
                  className={`wcp-btn ${dashboardSubTab === 'files' ? 'wcp-btn-primary' : ''}`}
                  style={{ background: dashboardSubTab === 'files' ? '#3b82f6' : '#f1f5f9', color: dashboardSubTab === 'files' ? '#fff' : '#475569', padding: '8px 16px' }}
                  onClick={() => setDashboardSubTab('files')}
                >
                  <FileCode size={16} /> Scanned Files Log ({scannedFiles.length})
                </button>
              </div>

              {dashboardSubTab === 'issues' && (
                <div style={{ display: 'flex', gap: '10px' }}>
                  <select
                    value={severityFilter}
                    onChange={(e) => setSeverityFilter(e.target.value)}
                    style={{ padding: '6px 12px', borderRadius: '6px', border: '1px solid #cbd5e1' }}
                  >
                    <option value="all">All Severities</option>
                    <option value="critical">Critical</option>
                    <option value="high">High</option>
                    <option value="medium">Medium</option>
                    <option value="low">Low</option>
                  </select>
                  <input
                    type="text"
                    placeholder="Search findings..."
                    value={issueSearch}
                    onChange={(e) => setIssueSearch(e.target.value)}
                    style={{ padding: '6px 12px', borderRadius: '6px', border: '1px solid #cbd5e1', width: '220px' }}
                  />
                </div>
              )}
            </div>

            {/* Findings Table */}
            {dashboardSubTab === 'issues' && (
              <div>
                {filteredIssues.length === 0 ? (
                  <div style={{ padding: '48px', textAlign: 'center', color: '#64748b' }}>
                    <CheckCircle2 size={48} color="#10b981" style={{ margin: '0 auto 12px auto' }} />
                    <h4 style={{ margin: '0 0 6px 0', fontSize: '18px', color: '#1e293b' }}>No threats detected</h4>
                    <p style={{ margin: 0, fontSize: '14px' }}>
                      Your scanned WordPress installation is clean of known malware patterns and vulnerabilities.
                    </p>
                  </div>
                ) : (
                  <table className="wcp-table">
                    <thead>
                      <tr>
                        <th style={{ width: '40px' }}></th>
                        <th>Severity</th>
                        <th>Engine</th>
                        <th>Threat / Type</th>
                        <th>Location</th>
                        <th>Status</th>
                        <th style={{ textAlign: 'right' }}>Mitigation</th>
                      </tr>
                    </thead>
                    <tbody>
                      {filteredIssues.map((issue) => (
                        <Fragment key={issue.id}>
                          <tr>
                            <td style={{ textAlign: 'center' }}>
                              <button
                                style={{ background: 'none', border: 'none', cursor: 'pointer', padding: '4px' }}
                                onClick={() => setExpandedIssue(expandedIssue === issue.id ? null : issue.id)}
                              >
                                {expandedIssue === issue.id ? <ChevronDown size={18} /> : <ChevronRight size={18} />}
                              </button>
                            </td>
                            <td>
                              <span className={`wcp-badge wcp-badge-${issue.severity}`}>
                                {issue.severity}
                              </span>
                            </td>
                            <td><span style={{ fontSize: '12px', color: '#64748b' }}>{issue.engine}</span></td>
                            <td style={{ fontWeight: 600 }}>{issue.type}</td>
                            <td>
                              <span style={{ fontFamily: 'monospace', fontSize: '12px', color: '#334155' }}>
                                {issue.file_path} {issue.line_number ? `:${issue.line_number}` : ''}
                              </span>
                            </td>
                            <td>
                              <span className="wcp-badge" style={{ background: issue.status === 'open' ? '#fee2e2' : '#f1f5f9', color: issue.status === 'open' ? '#b91c1c' : '#475569' }}>
                                {issue.status}
                              </span>
                            </td>
                            <td style={{ textAlign: 'right' }}>
                              <div style={{ display: 'inline-flex', gap: '8px' }}>
                                {issue.status === 'open' && (
                                  <Fragment>
                                    <button
                                      className="wcp-btn"
                                      style={{ background: '#fecaca', color: '#991b1b', padding: '4px 10px', fontSize: '12px' }}
                                      onClick={() => handleQuarantine(issue)}
                                      title="Safely isolate this file in protected quarantine vault"
                                    >
                                      <Archive size={13} /> Quarantine
                                    </button>
                                    <button
                                      className="wcp-btn"
                                      style={{ background: '#f1f5f9', color: '#475569', padding: '4px 10px', fontSize: '12px' }}
                                      onClick={() => handleUpdateIssue(issue.id, 'ignored')}
                                    >
                                      Ignore
                                    </button>
                                  </Fragment>
                                )}
                                {issue.status === 'quarantined' && (
                                  <span style={{ fontSize: '12px', color: '#b91c1c', fontWeight: 600 }}>Quarantined</span>
                                )}
                                {issue.status === 'ignored' && (
                                  <button
                                    className="wcp-btn"
                                    style={{ background: '#f1f5f9', color: '#475569', padding: '4px 10px', fontSize: '12px' }}
                                    onClick={() => handleUpdateIssue(issue.id, 'open')}
                                  >
                                    Reopen
                                  </button>
                                )}
                              </div>
                            </td>
                          </tr>

                          {/* Expanded Issue Detail */}
                          {expandedIssue === issue.id && (
                            <tr style={{ background: '#f8fafc' }}>
                              <td></td>
                              <td colSpan={6} style={{ padding: '16px 20px' }}>
                                <div style={{ fontSize: '14px', marginBottom: '8px' }}>
                                  <strong>Description:</strong> {issue.description}
                                </div>
                                {issue.evidence && (
                                  <div style={{ fontSize: '13px', color: '#64748b', marginBottom: '8px' }}>
                                    <strong>Evidence:</strong> {issue.evidence}
                                  </div>
                                )}
                                {issue.code_snippet && (
                                  <div style={{ marginTop: '8px' }}>
                                    <div style={{ fontSize: '12px', color: '#475569', marginBottom: '4px', fontWeight: 600 }}>Detected Code Snippet:</div>
                                    <pre style={{ background: '#0f172a', color: '#38bdf8', padding: '12px', borderRadius: '6px', overflowX: 'auto', fontSize: '12px', margin: 0 }}>
                                      {issue.code_snippet}
                                    </pre>
                                  </div>
                                )}
                              </td>
                            </tr>
                          )}
                        </Fragment>
                      ))}
                    </tbody>
                  </table>
                )}
              </div>
            )}

            {/* Quarantine Vault Table */}
            {dashboardSubTab === 'quarantine' && (
              <div>
                {quarantinedFiles.length === 0 ? (
                  <div style={{ padding: '48px', textAlign: 'center', color: '#64748b' }}>
                    <Archive size={48} color="#94a3b8" style={{ margin: '0 auto 12px auto' }} />
                    <h4 style={{ margin: '0 0 6px 0', fontSize: '18px', color: '#1e293b' }}>Quarantine Vault is Empty</h4>
                    <p style={{ margin: 0, fontSize: '14px' }}>
                      Files quarantined from security findings will appear here with cryptographic SHA256 hashes and 1-click restore options.
                    </p>
                  </div>
                ) : (
                  <table className="wcp-table">
                    <thead>
                      <tr>
                        <th>Original Path</th>
                        <th>Vault File</th>
                        <th>SHA-256</th>
                        <th>Size</th>
                        <th>Quarantined At</th>
                        <th>Status</th>
                        <th style={{ textAlign: 'right' }}>Actions</th>
                      </tr>
                    </thead>
                    <tbody>
                      {quarantinedFiles.map((q) => (
                        <tr key={q.id}>
                          <td style={{ fontFamily: 'monospace', fontSize: '12px', fontWeight: 600 }}>{q.original_path}</td>
                          <td style={{ fontSize: '12px', color: '#64748b' }}>{q.quarantine_filename}</td>
                          <td><span className="wcp-code-preview" title={q.sha256}>{q.sha256.substring(0, 16)}...</span></td>
                          <td>{(q.file_size / 1024).toFixed(1)} KB</td>
                          <td style={{ fontSize: '13px', color: '#64748b' }}>{q.quarantined_at}</td>
                          <td>
                            <span className="wcp-badge" style={{ background: q.status === 'quarantined' ? '#fee2e2' : '#ecfdf5', color: q.status === 'quarantined' ? '#b91c1c' : '#047857' }}>
                              {q.status}
                            </span>
                          </td>
                          <td style={{ textAlign: 'right' }}>
                            {q.status === 'quarantined' && (
                              <button
                                className="wcp-btn"
                                style={{ background: '#ecfdf5', color: '#047857', border: '1px solid #a7f3d0', padding: '4px 10px', fontSize: '12px' }}
                                onClick={() => handleRestoreQuarantine(q.id)}
                              >
                                <RotateCcw size={13} /> Restore File
                              </button>
                            )}
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                )}
              </div>
            )}

            {/* Scanned Files List */}
            {dashboardSubTab === 'files' && (
              <div>
                <div style={{ padding: '12px 20px', borderBottom: '1px solid #e2e8f0', display: 'flex', justifyContent: 'flex-end' }}>
                  <input
                    type="text"
                    placeholder="Filter scanned paths..."
                    value={fileFilter}
                    onChange={(e) => setFileFilter(e.target.value)}
                    style={{ padding: '6px 12px', borderRadius: '6px', border: '1px solid #cbd5e1', width: '280px' }}
                  />
                </div>
                <div style={{ maxHeight: '420px', overflowY: 'auto' }}>
                  <table className="wcp-table">
                    <thead>
                      <tr>
                        <th>Path</th>
                        <th>Size</th>
                        <th>Status</th>
                        <th>Time</th>
                      </tr>
                    </thead>
                    <tbody>
                      {filteredFiles.slice(0, 150).map((file) => (
                        <tr key={file.id}>
                          <td style={{ fontFamily: 'monospace', fontSize: '12px' }}>{file.file_path}</td>
                          <td>{(file.file_size / 1024).toFixed(1)} KB</td>
                          <td>
                            <span className="wcp-badge" style={{ background: file.status === 'threat' ? '#fee2e2' : '#ecfdf5', color: file.status === 'threat' ? '#b91c1c' : '#047857' }}>
                              {file.status}
                            </span>
                          </td>
                          <td style={{ fontSize: '12px', color: '#64748b' }}>{file.scanned_at}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </div>
            )}
          </div>
        </Fragment>
      )}

      {/* VIEW 2: TARGETED SCANS */}
      {navTab === 'targeted' && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: '20px' }}>
          <div style={{ background: '#ffffff', padding: '24px', borderRadius: '12px', border: '1px solid #e2e8f0' }}>
            <h2 style={{ margin: '0 0 6px 0', fontSize: '20px', display: 'flex', alignItems: 'center', gap: '10px' }}>
              <Zap size={22} color="#3b82f6" /> Targeted Single-Purpose Audits
            </h2>
            <p style={{ margin: 0, color: '#64748b', fontSize: '14px' }}>
              Run focused, rapid scans for specific vectors without waiting for a full filesystem scan cycle.
            </p>
          </div>

          <div className="wcp-targeted-grid">
            {/* 1. Unknown Files Finder */}
            <div className="wcp-action-card">
              <div style={{ display: 'flex', alignItems: 'center', gap: '12px', marginBottom: '12px' }}>
                <div className="wcp-action-icon" style={{ background: '#eff6ff', color: '#3b82f6' }}>
                  <FileQuestion size={24} />
                </div>
                <div>
                  <h3 style={{ margin: 0, fontSize: '17px' }}>Unknown Files Audit</h3>
                  <span style={{ fontSize: '12px', color: '#64748b' }}>Core, Plugins & Themes Reverse Check</span>
                </div>
              </div>
              <p style={{ fontSize: '13px', color: '#475569', minHeight: '52px', margin: '0 0 16px 0' }}>
                Reconciles files inside <code>wp-admin</code>, <code>wp-includes</code>, and official plugins/themes against official WordPress.org checksums to isolate unrecognized or rogue backdoors.
              </p>
              <button
                className="wcp-btn wcp-btn-primary"
                style={{ width: '100%', justifyContent: 'center' }}
                onClick={() => handleStartTargetedScan('unknown_files')}
                disabled={!!targetedScanning}
              >
                {targetedScanning === 'unknown_files' ? 'Scanning Unknown Files...' : 'Find Only Unknown Files'}
              </button>
            </div>

            {/* 2. Spam Posts / Pages Only */}
            <div className="wcp-action-card">
              <div style={{ display: 'flex', alignItems: 'center', gap: '12px', marginBottom: '12px' }}>
                <div className="wcp-action-icon" style={{ background: '#fef2f2', color: '#ef4444' }}>
                  <Search size={24} />
                </div>
                <div>
                  <h3 style={{ margin: 0, fontSize: '17px' }}>Spam Content & DB Audit</h3>
                  <span style={{ fontSize: '12px', color: '#64748b' }}>Posts, Pages & Comments</span>
                </div>
              </div>
              <p style={{ fontSize: '13px', color: '#475569', minHeight: '52px', margin: '0 0 16px 0' }}>
                Inspects all published posts, pages, comments, and options for blackhat pharmaceutical spam, hidden iframes, base64 script tags, and malicious SEO keyword cloaking.
              </p>
              <button
                className="wcp-btn wcp-btn-primary"
                style={{ width: '100%', justifyContent: 'center', background: '#ef4444' }}
                onClick={() => handleStartTargetedScan('spam_content')}
                disabled={!!targetedScanning}
              >
                {targetedScanning === 'spam_content' ? 'Auditing Content Spam...' : 'Scan Spam Content Only'}
              </button>
            </div>

            {/* 3. Filesystem Only */}
            <div className="wcp-action-card">
              <div style={{ display: 'flex', alignItems: 'center', gap: '12px', marginBottom: '12px' }}>
                <div className="wcp-action-icon" style={{ background: '#f0fdf4', color: '#16a34a' }}>
                  <HardDrive size={24} />
                </div>
                <div>
                  <h3 style={{ margin: 0, fontSize: '17px' }}>Filesystem Security Only</h3>
                  <span style={{ fontSize: '12px', color: '#64748b' }}>Permissions, Uploads & Symlinks</span>
                </div>
              </div>
              <p style={{ fontSize: '13px', color: '#475569', minHeight: '52px', margin: '0 0 16px 0' }}>
                Audits filesystem permissions, dangerous symlinks leading outside docroot, and flags PHP or executable scripts disguised inside <code>wp-content/uploads/</code>.
              </p>
              <button
                className="wcp-btn wcp-btn-primary"
                style={{ width: '100%', justifyContent: 'center', background: '#16a34a' }}
                onClick={() => handleStartTargetedScan('filesystem_only')}
                disabled={!!targetedScanning}
              >
                {targetedScanning === 'filesystem_only' ? 'Auditing Filesystem...' : 'Audit Filesystem Only'}
              </button>
            </div>

            {/* 4. User Password Strength & Admin Audit */}
            <div className="wcp-action-card">
              <div style={{ display: 'flex', alignItems: 'center', gap: '12px', marginBottom: '12px' }}>
                <div className="wcp-action-icon" style={{ background: '#fffbeb', color: '#d97706' }}>
                  <UserCheck size={24} />
                </div>
                <div>
                  <h3 style={{ margin: 0, fontSize: '17px' }}>User & Password Audit</h3>
                  <span style={{ fontSize: '12px', color: '#64748b' }}>Credentials & Privilege Escalation</span>
                </div>
              </div>
              <p style={{ fontSize: '13px', color: '#475569', minHeight: '52px', margin: '0 0 8px 0' }}>
                Performs dictionary check against hashes to detect weak passwords, exposes username enumeration display leaks, and flags unauthorized users with admin rights.
              </p>
              <div style={{ marginBottom: '14px' }}>
                <label style={{ display: 'flex', alignItems: 'center', gap: '6px', fontSize: '13px', cursor: 'pointer', color: '#334155' }}>
                  <input
                    type="checkbox"
                    checked={adminOnlyUsers}
                    onChange={(e) => setAdminOnlyUsers(e.target.checked)}
                  />
                  <strong>Audit Administrator Users Only</strong>
                </label>
              </div>
              <button
                className="wcp-btn wcp-btn-primary"
                style={{ width: '100%', justifyContent: 'center', background: '#d97706' }}
                onClick={() => handleStartTargetedScan('user_security', { admins_only: adminOnlyUsers })}
                disabled={!!targetedScanning}
              >
                {targetedScanning === 'user_security' ? 'Checking Passwords...' : 'Audit Password Strength'}
              </button>
            </div>

            {/* 5. Outdated Software Audit */}
            <div className="wcp-action-card">
              <div style={{ display: 'flex', alignItems: 'center', gap: '12px', marginBottom: '12px' }}>
                <div className="wcp-action-icon" style={{ background: '#faf5ff', color: '#9333ea' }}>
                  <Activity size={24} />
                </div>
                <div>
                  <h3 style={{ margin: 0, fontSize: '17px' }}>Outdated Software Audit</h3>
                  <span style={{ fontSize: '12px', color: '#64748b' }}>WP Core, Plugins & Themes</span>
                </div>
              </div>
              <p style={{ fontSize: '13px', color: '#475569', minHeight: '52px', margin: '0 0 16px 0' }}>
                Audits all installed plugins, active/inactive themes, and WordPress core against the official repository to flag software requiring security updates.
              </p>
              <button
                className="wcp-btn wcp-btn-primary"
                style={{ width: '100%', justifyContent: 'center', background: '#9333ea' }}
                onClick={() => handleStartTargetedScan('outdated_software')}
                disabled={!!targetedScanning}
              >
                {targetedScanning === 'outdated_software' ? 'Checking Updates...' : 'Audit Outdated Software'}
              </button>
            </div>

            {/* 6. Uploads Executables & Suspicious Files */}
            <div className="wcp-action-card">
              <div style={{ display: 'flex', alignItems: 'center', gap: '12px', marginBottom: '12px' }}>
                <div className="wcp-action-icon" style={{ background: '#fef2f2', color: '#dc2626' }}>
                  <FileWarning size={24} />
                </div>
                <div>
                  <h3 style={{ margin: 0, fontSize: '17px' }}>Uploads Executables Audit</h3>
                  <span style={{ fontSize: '12px', color: '#64748b' }}>Detect .php, .sh & Rogue Files in Uploads</span>
                </div>
              </div>
              <p style={{ fontSize: '13px', color: '#475569', minHeight: '52px', margin: '0 0 16px 0' }}>
                Recursively audits <code>wp-content/uploads/</code> to detect forbidden <code>.php</code>, <code>.sh</code>, shell scripts, disguised double extensions, and rogue server configs.
              </p>
              <button
                className="wcp-btn wcp-btn-primary"
                style={{ width: '100%', justifyContent: 'center', background: '#dc2626' }}
                onClick={() => handleStartTargetedScan('suspicious_uploads')}
                disabled={!!targetedScanning}
              >
                {targetedScanning === 'suspicious_uploads' ? 'Scanning Uploads...' : 'Scan Uploads for Executables'}
              </button>
            </div>
          </div>

          {/* Targeted Scan Result Section */}
          {targetedResult && (
            <div className="wcp-card" style={{ marginTop: '12px' }}>
              <div className="wcp-card-header">
                <div>
                  <h3 style={{ margin: 0 }}>Targeted Audit Results: {targetedResult.target}</h3>
                  <p style={{ margin: '4px 0 0 0', fontSize: '13px', color: '#64748b' }}>
                    Risk Score: <strong>{targetedResult.summary.score}/100</strong> ({targetedResult.summary.level.toUpperCase()}) | Issues Found: <strong>{targetedResult.issues.length}</strong>
                  </p>
                </div>
                <button
                  className="wcp-btn"
                  style={{ background: '#f1f5f9', color: '#475569', padding: '6px 12px' }}
                  onClick={() => setTargetedResult(null)}
                >
                  Close Findings
                </button>
              </div>

              {targetedResult.issues.length === 0 ? (
                <div style={{ padding: '36px', textAlign: 'center', color: '#10b981' }}>
                  <CheckCircle size={40} style={{ margin: '0 auto 8px auto' }} />
                  <div style={{ fontWeight: 600, fontSize: '16px', color: '#1e293b' }}>Audit Passed Cleanly</div>
                  <div style={{ fontSize: '13px', color: '#64748b' }}>No threats or anomalies detected for this targeted profile.</div>
                </div>
              ) : (
                <table className="wcp-table">
                  <thead>
                    <tr>
                      <th>Severity</th>
                      <th>Type</th>
                      <th>Location / Subject</th>
                      <th>Description</th>
                      <th>Mitigation</th>
                    </tr>
                  </thead>
                  <tbody>
                    {targetedResult.issues.map((iss) => (
                      <tr key={iss.id}>
                        <td><span className={`wcp-badge wcp-badge-${iss.severity}`}>{iss.severity}</span></td>
                        <td style={{ fontWeight: 600 }}>{iss.type}</td>
                        <td style={{ fontFamily: 'monospace', fontSize: '12px' }}>{iss.file_path}</td>
                        <td style={{ fontSize: '13px' }}>{iss.description}</td>
                        <td>
                          {iss.status === 'open' && (
                            <button
                              className="wcp-btn"
                              style={{ background: '#fee2e2', color: '#991b1b', padding: '4px 8px', fontSize: '12px' }}
                              onClick={() => handleQuarantine(iss)}
                            >
                              <Archive size={12} /> Quarantine
                            </button>
                          )}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              )}
            </div>
          )}
        </div>
      )}

      {/* VIEW 3: SCAN LOGS & HISTORY */}
      {navTab === 'logs' && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: '20px' }}>
          <div style={{ background: '#ffffff', padding: '24px', borderRadius: '12px', border: '1px solid #e2e8f0', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
            <div>
              <h2 style={{ margin: '0 0 6px 0', fontSize: '20px', display: 'flex', alignItems: 'center', gap: '10px' }}>
                <History size={22} color="#3b82f6" /> Scan Logs & Audit History
              </h2>
              <p style={{ margin: 0, color: '#64748b', fontSize: '14px' }}>
                Each scan run maintains an independent audit log, duration tracking, risk score, and discovered issues archive.
              </p>
            </div>
            <div style={{ display: 'flex', gap: '10px' }}>
              <button
                className="wcp-btn"
                style={{ background: '#fee2e2', color: '#b91c1c', border: '1px solid #fecaca', padding: '8px 14px' }}
                onClick={handleClearAllScanHistory}
                disabled={historyLoading || scanHistory.length === 0}
                title="Permanently remove all previous scan runs and log entries"
              >
                <Trash2 size={15} /> Clear All Logs
              </button>
              <button
                className="wcp-btn"
                style={{ background: '#f1f5f9', color: '#475569', padding: '8px 14px' }}
                onClick={loadScanHistory}
                disabled={historyLoading}
              >
                <RefreshCw size={15} /> Refresh Logs
              </button>
            </div>
          </div>

          <div className="wcp-card">
            {scanHistory.length === 0 ? (
              <div style={{ padding: '48px', textAlign: 'center', color: '#64748b' }}>
                <History size={48} color="#94a3b8" style={{ margin: '0 auto 12px auto' }} />
                <h4 style={{ margin: '0 0 6px 0', fontSize: '18px', color: '#1e293b' }}>No Historical Logs Recorded</h4>
                <p style={{ margin: 0, fontSize: '14px' }}>Run your first scan to generate an audit log entry.</p>
              </div>
            ) : (
              <table className="wcp-table">
                <thead>
                  <tr>
                    <th>Scan #</th>
                    <th>Date & Time</th>
                    <th>Target Profile</th>
                    <th>Status</th>
                    <th>Files Scanned</th>
                    <th>Issues</th>
                    <th>Risk Score</th>
                    <th>Duration</th>
                    <th style={{ textAlign: 'right' }}>Actions</th>
                  </tr>
                </thead>
                <tbody>
                  {scanHistory.map((s) => (
                    <tr key={s.id}>
                      <td style={{ fontWeight: 700 }}>#{s.id}</td>
                      <td style={{ fontSize: '13px' }}>{s.created_at}</td>
                      <td>
                        <span className="wcp-badge" style={{ background: '#eff6ff', color: '#1d4ed8' }}>
                          {s.scan_target || 'plugins_themes'}
                        </span>
                      </td>
                      <td>
                        <span className="wcp-badge" style={{ background: s.status === 'completed' ? '#ecfdf5' : '#fffbeb', color: s.status === 'completed' ? '#047857' : '#b45309' }}>
                          {s.status}
                        </span>
                      </td>
                      <td>{s.scanned_files} / {s.total_files}</td>
                      <td>
                        <span style={{ fontWeight: 700, color: s.issues_found > 0 ? '#ef4444' : '#10b981' }}>
                          {s.issues_found}
                        </span>
                      </td>
                      <td>
                        <span className={`wcp-badge ${s.risk_score > 60 ? 'wcp-badge-critical' : s.risk_score > 25 ? 'wcp-badge-high' : 'wcp-badge-low'}`}>
                          {s.risk_score}/100
                        </span>
                      </td>
                      <td style={{ fontSize: '13px', color: '#64748b' }}>{s.duration || 1}s</td>
                      <td style={{ textAlign: 'right' }}>
                        <button
                          className="wcp-btn"
                          style={{ background: '#3b82f6', color: '#ffffff', padding: '6px 12px', fontSize: '12px' }}
                          onClick={() => loadScanLogDetail(s.id)}
                        >
                          <FileText size={13} /> View Findings
                        </button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
          </div>

          {/* Detailed Scan Log Inspector Modal / Panel */}
          {selectedScanDetail && (
            <div className="wcp-card" style={{ border: '2px solid #3b82f6' }}>
              <div className="wcp-card-header" style={{ background: '#eff6ff' }}>
                <div>
                  <h3 style={{ margin: 0, color: '#1e3a8a' }}>
                    Inspection: Scan #{selectedScanDetail.scan.id} Log Details
                  </h3>
                  <p style={{ margin: '4px 0 0 0', fontSize: '13px', color: '#3b82f6' }}>
                    Run at {selectedScanDetail.scan.created_at} | Profile: <strong>{selectedScanDetail.scan.scan_target || 'plugins_themes'}</strong> | Risk Score: <strong>{selectedScanDetail.summary.score}/100</strong>
                  </p>
                </div>
                <button
                  className="wcp-btn"
                  style={{ background: '#ffffff', color: '#475569', border: '1px solid #cbd5e1', padding: '6px 12px' }}
                  onClick={() => setSelectedScanDetail(null)}
                >
                  Close Inspection
                </button>
              </div>

              {selectedScanDetail.issues.length === 0 ? (
                <div style={{ padding: '36px', textAlign: 'center', color: '#10b981' }}>
                  <CheckCircle size={36} style={{ margin: '0 auto 8px auto' }} />
                  <div style={{ fontWeight: 600 }}>Zero findings recorded in this scan log.</div>
                </div>
              ) : (
                <table className="wcp-table">
                  <thead>
                    <tr>
                      <th>Severity</th>
                      <th>Engine</th>
                      <th>Type</th>
                      <th>Location</th>
                      <th>Description</th>
                    </tr>
                  </thead>
                  <tbody>
                    {selectedScanDetail.issues.map((issue) => (
                      <tr key={issue.id}>
                        <td><span className={`wcp-badge wcp-badge-${issue.severity}`}>{issue.severity}</span></td>
                        <td style={{ fontSize: '12px', color: '#64748b' }}>{issue.engine}</td>
                        <td style={{ fontWeight: 600 }}>{issue.type}</td>
                        <td style={{ fontFamily: 'monospace', fontSize: '12px' }}>{issue.file_path}</td>
                        <td style={{ fontSize: '13px' }}>{issue.description}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              )}
            </div>
          )}
        </div>
      )}

      {/* VIEW 4: DATABASE BACKUP */}
      {navTab === 'backup' && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: '20px' }}>
          <div style={{ background: '#ffffff', padding: '24px', borderRadius: '12px', border: '1px solid #e2e8f0', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
            <div>
              <h2 style={{ margin: '0 0 6px 0', fontSize: '20px', display: 'flex', alignItems: 'center', gap: '10px' }}>
                <Database size={22} color="#3b82f6" /> One-Click Database Backup Vault
              </h2>
              <p style={{ margin: 0, color: '#64748b', fontSize: '14px' }}>
                Instant, chunked MySQL SQL dump engine with Gzip compression. Stored in locked vault directory <code>wp-content/wcp-backups/</code> with public web access denied.
              </p>
            </div>
            <button
              className="wcp-btn wcp-btn-primary"
              onClick={handleCreateBackup}
              disabled={creatingBackup}
              style={{ padding: '12px 24px', fontSize: '15px' }}
            >
              <Download size={17} />
              {creatingBackup ? 'Creating SQL Backup...' : 'Create Instant Backup'}
            </button>
          </div>

          <div style={{ display: 'flex', gap: '16px' }}>
            <div className="wcp-metric-card" style={{ flex: 1 }}>
              <div>
                <div className="wcp-metric-label">Vault Security</div>
                <div className="wcp-metric-val" style={{ fontSize: '18px', color: '#10b981', display: 'flex', alignItems: 'center', gap: '6px' }}>
                  <Lock size={18} /> .htaccess & index.php Locked
                </div>
              </div>
            </div>
            <div className="wcp-metric-card" style={{ flex: 1 }}>
              <div>
                <div className="wcp-metric-label">Total Backups</div>
                <div className="wcp-metric-val" style={{ fontSize: '22px' }}>
                  {backups.length}
                </div>
              </div>
            </div>
            <div className="wcp-metric-card" style={{ flex: 1 }}>
              <div>
                <div className="wcp-metric-label">Total Vault Storage</div>
                <div className="wcp-metric-val" style={{ fontSize: '22px' }}>
                  {backups.reduce((acc, b) => acc + b.size_mb, 0).toFixed(2)} MB
                </div>
              </div>
            </div>
          </div>

          <div className="wcp-card">
            <div className="wcp-card-header">
              <h3 style={{ margin: 0 }}>Existing Database Backups</h3>
              <button
                className="wcp-btn"
                style={{ background: '#f1f5f9', color: '#475569', padding: '6px 12px' }}
                onClick={loadBackups}
                disabled={backupLoading}
              >
                <RefreshCw size={14} /> Refresh List
              </button>
            </div>

            {backups.length === 0 ? (
              <div style={{ padding: '48px', textAlign: 'center', color: '#64748b' }}>
                <Database size={48} color="#94a3b8" style={{ margin: '0 auto 12px auto' }} />
                <h4 style={{ margin: '0 0 6px 0', fontSize: '18px', color: '#1e293b' }}>No Backups Created Yet</h4>
                <p style={{ margin: 0, fontSize: '14px' }}>Click "Create Instant Backup" above to generate a full SQL snapshot before running remediations.</p>
              </div>
            ) : (
              <table className="wcp-table">
                <thead>
                  <tr>
                    <th>Backup Archive</th>
                    <th>File Size</th>
                    <th>Created At</th>
                    <th style={{ textAlign: 'right' }}>Actions</th>
                  </tr>
                </thead>
                <tbody>
                  {backups.map((b) => (
                    <tr key={b.filename}>
                      <td>
                        <span style={{ fontFamily: 'monospace', fontWeight: 600, color: '#1e293b' }}>
                          {b.filename}
                        </span>
                      </td>
                      <td>{b.size_mb} MB</td>
                      <td style={{ fontSize: '13px', color: '#64748b' }}>{b.created}</td>
                      <td style={{ textAlign: 'right' }}>
                        <div style={{ display: 'inline-flex', gap: '8px' }}>
                          <button
                            className="wcp-btn"
                            style={{ background: '#eff6ff', color: '#1d4ed8', border: '1px solid #bfdbfe', padding: '6px 12px', fontSize: '12px' }}
                            onClick={() => handleDownloadBackup(b.filename)}
                          >
                            <Download size={13} /> Download
                          </button>
                          <button
                            className="wcp-btn"
                            style={{ background: '#fee2e2', color: '#b91c1c', border: '1px solid #fecaca', padding: '6px 12px', fontSize: '12px' }}
                            onClick={() => handleDeleteBackup(b.filename)}
                          >
                            <Trash2 size={13} /> Delete
                          </button>
                        </div>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
          </div>
        </div>
      )}

      {/* VIEW 5: SERVER INFO */}
      {navTab === 'server' && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: '20px' }}>
          <div style={{ background: '#ffffff', padding: '24px', borderRadius: '12px', border: '1px solid #e2e8f0', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
            <div>
              <h2 style={{ margin: '0 0 6px 0', fontSize: '20px', display: 'flex', alignItems: 'center', gap: '10px' }}>
                <Server size={22} color="#3b82f6" /> Server & PHP Environment Info
              </h2>
              <p style={{ margin: 0, color: '#64748b', fontSize: '14px' }}>
                Technical audit of server runtime, PHP configuration limits, database engine, and file permission safety.
              </p>
            </div>
            <button
              className="wcp-btn"
              style={{ background: '#f1f5f9', color: '#475569', padding: '8px 14px' }}
              onClick={loadServerInfo}
              disabled={serverInfoLoading}
            >
              <RefreshCw size={15} /> Refresh Info
            </button>
          </div>

          {serverInfo ? (
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(360px, 1fr))', gap: '20px' }}>
              {/* PHP Configuration Card */}
              <div className="wcp-card">
                <div className="wcp-card-header">
                  <h3 style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                    <Server size={18} color="#3b82f6" /> PHP Environment
                  </h3>
                  <span className="wcp-badge" style={{ background: '#eff6ff', color: '#1d4ed8' }}>
                    v{serverInfo.php.version}
                  </span>
                </div>
                <div style={{ padding: '20px' }}>
                  <div className="wcp-info-row">
                    <span>PHP SAPI:</span>
                    <strong>{serverInfo.php.sapi}</strong>
                  </div>
                  <div className="wcp-info-row">
                    <span>Memory Limit:</span>
                    <strong>{serverInfo.php.memory_limit}</strong>
                  </div>
                  <div className="wcp-info-row">
                    <span>Current Memory Usage:</span>
                    <strong>{serverInfo.php.memory_usage_mb} MB</strong>
                  </div>
                  <div className="wcp-info-row">
                    <span>Max Execution Time:</span>
                    <strong>{serverInfo.php.max_execution_time}s</strong>
                  </div>
                  <div className="wcp-info-row">
                    <span>Upload Max Filesize:</span>
                    <strong>{serverInfo.php.upload_max_filesize}</strong>
                  </div>
                  <div className="wcp-info-row">
                    <span>Post Max Size:</span>
                    <strong>{serverInfo.php.post_max_size}</strong>
                  </div>
                  <div className="wcp-info-row">
                    <span>Display Errors:</span>
                    <strong style={{ color: serverInfo.php.display_errors === 'On' ? '#ef4444' : '#10b981' }}>
                      {serverInfo.php.display_errors}
                    </strong>
                  </div>
                </div>
              </div>

              {/* Database Server Card */}
              <div className="wcp-card">
                <div className="wcp-card-header">
                  <h3 style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                    <Database size={18} color="#3b82f6" /> Database Server
                  </h3>
                  <span className="wcp-badge" style={{ background: '#eff6ff', color: '#1d4ed8' }}>
                    MySQL v{serverInfo.database.version}
                  </span>
                </div>
                <div style={{ padding: '20px' }}>
                  <div className="wcp-info-row">
                    <span>Database Host:</span>
                    <strong>{serverInfo.database.host}</strong>
                  </div>
                  <div className="wcp-info-row">
                    <span>Database Name:</span>
                    <strong>{serverInfo.database.name}</strong>
                  </div>
                  <div className="wcp-info-row">
                    <span>Table Prefix:</span>
                    <code>{serverInfo.database.table_prefix}</code>
                  </div>
                  <div className="wcp-info-row">
                    <span>Charset & Collate:</span>
                    <strong>{serverInfo.database.charset} ({serverInfo.database.collate})</strong>
                  </div>
                  <div className="wcp-info-row">
                    <span>Total Database Size:</span>
                    <strong style={{ color: '#1e293b' }}>{serverInfo.database.size_mb} MB</strong>
                  </div>
                </div>
              </div>

              {/* Web Server & OS Card */}
              <div className="wcp-card">
                <div className="wcp-card-header">
                  <h3 style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                    <HardDrive size={18} color="#3b82f6" /> Web Server & OS
                  </h3>
                </div>
                <div style={{ padding: '20px' }}>
                  <div className="wcp-info-row">
                    <span>Server Software:</span>
                    <strong>{serverInfo.server.software}</strong>
                  </div>
                  <div className="wcp-info-row">
                    <span>Operating System:</span>
                    <strong>{serverInfo.server.os}</strong>
                  </div>
                  <div className="wcp-info-row">
                    <span>Server Architecture:</span>
                    <strong>{serverInfo.server.arch}</strong>
                  </div>
                  <div className="wcp-info-row">
                    <span>Server IP Address:</span>
                    <strong>{serverInfo.server.ip}</strong>
                  </div>
                  <div className="wcp-info-row">
                    <span>WordPress Version:</span>
                    <strong>v{serverInfo.wordpress.version}</strong>
                  </div>
                  <div className="wcp-info-row">
                    <span>SSL Active:</span>
                    <strong style={{ color: serverInfo.wordpress.ssl ? '#10b981' : '#ef4444' }}>
                      {serverInfo.wordpress.ssl ? 'Yes (HTTPS)' : 'No (Insecure HTTP)'}
                    </strong>
                  </div>
                </div>
              </div>

              {/* File Permissions Security Card */}
              <div className="wcp-card">
                <div className="wcp-card-header">
                  <h3 style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                    <Lock size={18} color="#3b82f6" /> Critical File Permissions
                  </h3>
                </div>
                <div style={{ padding: '20px' }}>
                  {Object.entries(serverInfo.permissions).map(([path, perm]) => (
                    <div key={path} className="wcp-info-row">
                      <span><code>{path}</code>:</span>
                      <div>
                        <strong style={{ fontFamily: 'monospace', marginRight: '8px' }}>{perm}</strong>
                        {perm === '0777' ? (
                          <span className="wcp-badge wcp-badge-critical">Insecure 0777</span>
                        ) : perm === '0644' || perm === '0755' ? (
                          <span className="wcp-badge" style={{ background: '#ecfdf5', color: '#047857' }}>Secure</span>
                        ) : (
                          <span className="wcp-badge wcp-badge-low">Permitted</span>
                        )}
                      </div>
                    </div>
                  ))}
                  <div style={{ marginTop: '16px', fontSize: '12px', color: '#64748b' }}>
                    Tip: Core files such as <code>wp-config.php</code> should ideally have permissions <code>0640</code> or <code>0644</code>. Directory permissions should not exceed <code>0755</code>.
                  </div>
                </div>
              </div>

              {/* Security PHP Extensions Card */}
              <div className="wcp-card" style={{ gridColumn: '1 / -1' }}>
                <div className="wcp-card-header">
                  <h3 style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                    <ShieldCheck size={18} color="#3b82f6" /> Critical PHP Extensions
                  </h3>
                </div>
                <div style={{ padding: '20px' }}>
                  <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(180px, 1fr))', gap: '12px' }}>
                    {Object.entries(serverInfo.php.extensions).map(([ext, enabled]) => (
                      <div
                        key={ext}
                        style={{
                          display: 'flex',
                          alignItems: 'center',
                          justifyContent: 'space-between',
                          padding: '10px 14px',
                          background: '#f8fafc',
                          borderRadius: '8px',
                          border: '1px solid #e2e8f0',
                        }}
                      >
                        <span style={{ fontWeight: 600, fontSize: '13px' }}>{ext}</span>
                        {enabled ? (
                          <span className="wcp-badge" style={{ background: '#ecfdf5', color: '#047857' }}>
                            Enabled
                          </span>
                        ) : (
                          <span className="wcp-badge wcp-badge-high">
                            Missing
                          </span>
                        )}
                      </div>
                    ))}
                  </div>
                </div>
              </div>
            </div>
          ) : (
            <div style={{ padding: '48px', textAlign: 'center', color: '#64748b' }}>
              <Server size={48} color="#3b82f6" style={{ margin: '0 auto 12px auto' }} />
              <div>Loading server environment metrics...</div>
            </div>
          )}
        </div>
      )}
    </div>
  );
};

export default App;
