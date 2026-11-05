import { useState, useEffect, useRef } from '@wordpress/element';
import {
  ShieldAlert,
  ShieldCheck,
  Shield,
  Zap,
  CheckCircle,
  CheckCircle2,
  AlertTriangle,
  RefreshCw,
  Sliders,
  Globe,
  Trash2,
  Loader2,
  Lock,
  Unlock,
  Activity,
  Check,
  FileCode,
  FileText,
  Layers,
  Info,
  Database,
  Search,
  ExternalLink,
  Cloud,
  Sparkles,
  Server,
  Key,
  Eye,
  EyeOff,
  Copy,
  Terminal,
  HardDrive,
  Cpu,
  Plus,
  X,
  Save,
  Radio,
  ShoppingBag,
  Layout,
  Target,
  List,
  Ban,
  ListFilter,
  ChevronDown,
  ChevronUp,
  Clock,
  User,
  History,
  AlertCircle,
  ChevronLeft,
  ChevronRight,
  MoreHorizontal,
  Edit2
} from 'lucide-react';
import { VirtualPatchCard } from './components/VirtualPatchCard';
import { CustomerLockoutCard } from './components/CustomerLockoutCard';
import { ThreatIntelCockpitCard } from './components/ThreatIntelCockpitCard';
import { ServerSecurityTab } from './components/ServerSecurityTab';
import { AttackSimulationCard } from './components/AttackSimulationCard';
import { SbomSupplyChainCard } from './components/SbomSupplyChainCard';
import { BehavioralWafCard } from './components/BehavioralWafCard';
import { TargetedAllowlistManagerCard } from './components/TargetedAllowlistManagerCard';
import { AiDefenseCard } from './components/AiDefenseCard';
import { SiteAdvisorCard } from './components/SiteAdvisorCard';
import { CafAdvisorPanel } from './components/CafAdvisorPanel';
import { CafBehavioralCockpit } from './components/CafBehavioralCockpit';
import { CloudflareSlotVisualizer } from './components/CloudflareSlotVisualizer';
import { ConfirmDialog } from './components/ConfirmDialog';
import { InlineConfirmPopover } from './components/InlineConfirmPopover';
import { formatRelativeTime, formatTelemetryDateFull } from './timeUtils';

interface ServerTelemetry {
  linux_uname: string;
  linux_uname_full: string;
  distro_name: string;
  server_software: string;
  server_software_type: string;
  php_version: string;
  php_sapi: string;
  php_arch: string;
  opcache_active: boolean;
  real_server_ip: string;
  is_server_ip_private: boolean;
  cdn_available: boolean;
  cdn_provider: string;
  cdn_ip: string;
  php_ram_limit: string;
  php_ram_used: string;
  php_ram_peak: string;
  php_ram_free: string;
  php_ram_percent: number;
  is_shared_hosting?: boolean;
  hosting_env_label?: string;
  account_ram_limit?: string | null;
  host_ram_total?: string;
  host_ram_avail?: string;
  cpu_cores?: number;
  cpu_limitation?: string;
  cpu_limit_type?: string;
  cpu_load_avg?: string;
  cpu_load_1m?: number | null;
  max_execution_time: string;
  upload_max_filesize: string;
  post_max_size: string;
  php_user: string;
  disk_free_gb?: string;
  disk_total_gb?: string;
  waf_hook_mode: string;
}

interface ThreatIntelStatus {
  enabled: boolean;
  block_blacklisted_ips: boolean;
  total_blacklisted_ips: number;
  total_cves: number;
  last_sync: string | null;
  sample_ips?: string[];
  sources: string[];
}

interface EdgeAdvisor {
  server_software: string;
  is_shared_hosting: boolean;
  has_cloudflare: boolean;
  api_configured?: boolean;
  zone_name?: string;
  plan?: string;
  memory_limit: string;
  savings_estimate: string;
  headline: string;
  summary: string;
  expert_note: string;
}

interface CompoundRule {
  id: string;
  title: string;
  badge: string;
  description: string;
  action: string;
  action_label: string;
  expression: string;
}

interface CVEItem {
  cve_id: string;
  title: string;
  severity: 'critical' | 'high' | 'medium' | 'low';
  cvss: number;
  target: string;
  fixed_in: string;
  source: string;
  details: string;
  link: string;
  is_installed?: boolean;
  installed_version?: string | null;
  is_vulnerable?: boolean;
  site_status?: 'vulnerable' | 'patched' | 'not_installed';
  component_name?: string;
}

interface FirewallStatus {
  enabled: boolean;
  mode: 'enabled' | 'learning' | 'disabled';
  active_mode: 'active' | 'learning' | 'complementary' | 'disabled';
  environment: {
    has_cloudflare: boolean;
    has_wordfence: boolean;
    has_sucuri: boolean;
    has_solid: boolean;
    has_coexisting_waf: boolean;
  };
  total_blocks: number;
  blocks_24h: number;
  top_rules: Array<{ rule_category: string; count: number }>;
  client_ip: string;
  threat_intel?: ThreatIntelStatus;
  edge_advisor?: EdgeAdvisor;
  server_telemetry?: ServerTelemetry;
  available_roles?: Array<{ slug: string; name: string }>;
  commerce_telemetry?: {
    is_active: boolean;
    detected_names?: string[];
  };
  forms_telemetry?: {
    is_active: boolean;
    detected_names?: string[];
  };
  integrations_telemetry?: {
    has_builders: boolean;
    builder_names: string[];
    has_jetpack: boolean;
    has_central_management: boolean;
    management_names: string[];
  };
  active_plugin_slugs?: string[];
}

interface FirewallLog {
  id: number;
  ip_address: string;
  request_uri: string;
  request_method: string;
  rule_category: string;
  rule_description: string;
  payload_sample?: string;
  user_agent?: string;
  action_taken: string;
  created_at: string;
  created_at_gmt?: string;
  timestamp?: number;
}

interface FirewallPageProps {
  apiRequest: (options: { path: string; method?: string; data?: any }) => Promise<any>;
  onNavigateToDashboard?: () => void;
  onNavigateToWafLogs?: () => void;
  onNavigateToVpatch?: () => void;
  onNavigateToSettings?: (subTab: string) => void;
  onNavigateToServerTelemetry?: () => void;
  initialSubTab?: 'stream' | 'rules' | 'caf' | 'drill' | 'supply_chain' | 'behavioral' | 'server_sec' | 'intel' | 'cloudflare' | 'vpatch' | 'ai_defense';
  initialSupplyChainSubTab?: 'sbom' | 'gatekeeper' | 'advisor' | 'lockfiles' | 'scripts';
  initialBehavioralSubTab?: 'learning' | 'honeytoken' | 'ratelimit';
  initialAiDefenseSubTab?: 'ghost' | 'egress' | 'prompt' | 'credentials' | 'surface';
  onSubTabChange?: (tab: 'stream' | 'rules' | 'caf' | 'drill' | 'supply_chain' | 'behavioral' | 'server_sec' | 'intel' | 'cloudflare' | 'vpatch' | 'ai_defense', nested?: string) => void;
}

export const FirewallPage = ({
  apiRequest,
  onNavigateToDashboard,
  onNavigateToWafLogs,
  onNavigateToVpatch,
  onNavigateToSettings,
  onNavigateToServerTelemetry,
  initialSubTab = 'stream',
  initialSupplyChainSubTab = 'sbom',
  initialBehavioralSubTab = 'learning',
  initialAiDefenseSubTab = 'ghost',
  onSubTabChange,
}: FirewallPageProps) => {
  const [status, setStatus] = useState<FirewallStatus | null>(null);
  const [logs, setLogs] = useState<FirewallLog[]>([]);
  const [loading, setLoading] = useState<boolean>(true);
  const [refreshing, setRefreshing] = useState<boolean>(false);
  const [savingRules, setSavingRules] = useState<boolean>(false);
  const [saveSuccess, setSaveSuccess] = useState<string | null>(null);
  const [saveError, setSaveError] = useState<string | null>(null);
  const [savingSingleRuleKey, setSavingSingleRuleKey] = useState<string | null>(null);
  const [savedSingleRuleSuccess, setSavedSingleRuleSuccess] = useState<{ [key: string]: boolean }>({});
  const [availableRoles, setAvailableRoles] = useState<Array<{ slug: string; name: string }>>([
    { slug: 'administrator', name: 'Administrator' },
    { slug: 'editor', name: 'Editor' },
    { slug: 'author', name: 'Author' },
    { slug: 'contributor', name: 'Contributor' },
    { slug: 'subscriber', name: 'Subscriber' }
  ]);
  const [selectedRoleToAdd, setSelectedRoleToAdd] = useState<string>('');
  const [wooRulesExpanded, setWooRulesExpanded] = useState<boolean>(true);

  // Initialize active tab from URL query param ?tab= if valid, else fallback to initialSubTab
  const getStartingTab = (): 'stream' | 'rules' | 'caf' | 'drill' | 'supply_chain' | 'behavioral' | 'server_sec' | 'intel' | 'cloudflare' | 'vpatch' | 'ai_defense' => {
    try {
      const urlParams = new URLSearchParams(window.location.search);
      const tabParam = urlParams.get('tab');
      const validTabs = ['stream', 'rules', 'caf', 'drill', 'supply_chain', 'behavioral', 'server_sec', 'intel', 'cloudflare', 'vpatch', 'ai_defense'];
      if (tabParam && validTabs.includes(tabParam)) {
        return tabParam as any;
      }
    } catch (e) {}
    return (initialSubTab as any) || 'stream';
  };

  const [activeTab, setActiveTab] = useState<'stream' | 'rules' | 'caf' | 'drill' | 'supply_chain' | 'behavioral' | 'server_sec' | 'intel' | 'cloudflare' | 'vpatch' | 'ai_defense'>(getStartingTab);
  const [copiedIp, setCopiedIp] = useState<string | null>(null);
  const [showDevTelemetry, setShowDevTelemetry] = useState<boolean>(false);
  const [isMoreMenuOpen, setIsMoreMenuOpen] = useState<boolean>(false);
  const moreMenuRef = useRef<HTMLDivElement | null>(null);

  useEffect(() => {
    const handleOutsideClick = (e: MouseEvent) => {
      if (moreMenuRef.current && !moreMenuRef.current.contains(e.target as Node)) {
        setIsMoreMenuOpen(false);
      }
    };
    if (isMoreMenuOpen) {
      document.addEventListener('mousedown', handleOutsideClick);
    }
    return () => document.removeEventListener('mousedown', handleOutsideClick);
  }, [isMoreMenuOpen]);

  // In-Page Notification Toast / Alert Banner State
  const [firewallNotice, setFirewallNotice] = useState<{
    type: 'success' | 'error' | 'warning' | 'info';
    text: string;
    title?: string;
  } | null>(null);

  const showFirewallNotice = (
    type: 'success' | 'error' | 'warning' | 'info',
    text: string,
    title?: string,
    duration: number = 6000
  ) => {
    setFirewallNotice({ type, text, title });
    if (duration > 0) {
      setTimeout(() => {
        setFirewallNotice((prev) => (prev && prev.text === text ? null : prev));
      }, duration);
    }
  };

  // In-App Confirm Dialog State
  const [firewallConfirmDialog, setFirewallConfirmDialog] = useState<{
    isOpen: boolean;
    title: string;
    message: string | React.ReactNode;
    targetItem?: string;
    confirmLabel?: string;
    variant?: 'danger' | 'warning' | 'info';
    isLoading?: boolean;
    onConfirm?: () => void | Promise<void>;
  }>({
    isOpen: false,
    title: '',
    message: '',
  });

  const requestFirewallConfirm = ({
    title,
    message,
    targetItem,
    confirmLabel = 'Confirm Action',
    variant = 'danger',
    onConfirm,
  }: {
    title: string;
    message: string | React.ReactNode;
    targetItem?: string;
    confirmLabel?: string;
    variant?: 'danger' | 'warning' | 'info';
    onConfirm: () => void | Promise<void>;
  }) => {
    setFirewallConfirmDialog({
      isOpen: true,
      title,
      message,
      targetItem,
      confirmLabel,
      variant,
      isLoading: false,
      onConfirm: async () => {
        try {
          setFirewallConfirmDialog((prev) => ({ ...prev, isLoading: true }));
          await onConfirm();
          setFirewallConfirmDialog((prev) => ({ ...prev, isOpen: false, isLoading: false }));
        } catch (err: any) {
          console.error(err);
          setFirewallConfirmDialog((prev) => ({ ...prev, isLoading: false }));
        }
      },
    });
  };

  const copyToClipboard = (text: string, label: string) => {
    if (!text) return;
    try {
      navigator.clipboard.writeText(text);
      setCopiedIp(label);
      setTimeout(() => setCopiedIp(null), 2500);
    } catch {
      // fallback
    }
  };

  useEffect(() => {
    if (initialSubTab && initialSubTab !== activeTab) {
      setActiveTab(initialSubTab);
    }
  }, [initialSubTab]);

  // Synchronize browser back/forward history navigation
  useEffect(() => {
    const handlePopState = () => {
      try {
        const urlParams = new URLSearchParams(window.location.search);
        const tabParam = urlParams.get('tab');
        const validTabs = ['stream', 'rules', 'caf', 'drill', 'supply_chain', 'behavioral', 'server_sec', 'intel', 'cloudflare', 'vpatch', 'ai_defense'];
        if (tabParam && validTabs.includes(tabParam)) {
          setActiveTab(tabParam as any);
        } else if (!tabParam) {
          setActiveTab('stream');
        }
      } catch (e) {}
    };
    window.addEventListener('popstate', handlePopState);
    return () => window.removeEventListener('popstate', handlePopState);
  }, []);

  const handleSwitchTab = (tab: 'stream' | 'rules' | 'caf' | 'drill' | 'supply_chain' | 'behavioral' | 'server_sec' | 'intel' | 'cloudflare' | 'vpatch' | 'ai_defense') => {
    setActiveTab(tab);
    try {
      const url = new URL(window.location.href);
      url.searchParams.set('tab', tab);
      window.history.pushState({ tab }, '', url.toString());
    } catch (e) {}
    if (onSubTabChange) {
      onSubTabChange(tab);
    }
  };

  // Cloudflare Edge State
  const [cfStatus, setCfStatus] = useState<any>(null);
  const [cfDefinitions, setCfDefinitions] = useState<any>({
    compound_perimeter: {
      id: 'wcpscan_compound_perimeter',
      title: 'Rule 1: Master Perimeter & Sensitive File Armor',
      badge: 'Edge Shield',
      description: 'Drops /xmlrpc.php abuse, uploads directory PHP webshell execution, sensitive file probes (.env, .git, .sql, .bak, debug.log, wp-config.php), and hostile HTTP methods in 1 single unified rule.',
      action: 'block',
      expression: '(http.request.uri.path contains "xmlrpc.php") or ((http.request.uri.path contains "wp-content/uploads" or http.request.uri.path contains "wp-content/upgrade") and http.request.uri.path.extension in {"php" "phtml" "phar" "sh" "bash" "py" "pl" "exe" "cgi"}) or (http.request.uri.path contains "wp-config.php" or http.request.uri.path contains ".env" or http.request.uri.path contains ".git" or http.request.uri.path contains ".user.ini" or http.request.uri.path contains "debug.log" or http.request.uri.path contains "composer.json" or http.request.uri.path contains "package.json" or http.request.uri.path contains "readme.html" or http.request.uri.path contains "license.txt") or (http.request.uri.path.extension in {"sql" "bak" "tar" "gz" "zip" "ini" "sh"}) or (http.request.method in {"TRACE" "TRACK" "DEBUG"})'
    },
    compound_exploits: {
      id: 'wcpscan_compound_exploits',
      title: 'Rule 2: LFI/RFI Directory Traversal & Reconnaissance Shield',
      badge: 'Zero-Day Shield',
      description: 'Terminates path traversal (../), dangerous script function injection parameters, null byte attacks, author query parameter enumeration (?author=1), and public REST user scraping.',
      action: 'block',
      expression: '(http.request.uri contains "../" or http.request.uri contains "..%2f" or http.request.uri.query contains "etc/passwd" or http.request.uri.query contains "base64_' + 'decode" or http.request.uri.query contains "eval' + '(" or http.request.uri contains "%00" or http.request.uri.query contains "author=" or (http.request.uri.path contains "wp-json/wp/v2/users" and not http.request.uri.path contains "wp-json/wp/v2/users/me"))'
    },
    compound_login_bot: {
      id: 'wcpscan_compound_login_bot',
      title: 'Rule 3: Login Portal Automated Bot Defense (Anti-Brute Force)',
      badge: 'Turnstile Challenge',
      description: 'Challenges automated bot crawlers targeting wp-login.php, WooCommerce my-account, and custom membership login/register portals with Cloudflare Managed Challenge (Turnstile) without annoying human administrators or valid users.',
      action: 'managed_challenge',
      expression: '(http.request.uri.path contains "wp-login.php" or http.request.uri.path contains "wp-custom-login" or http.request.uri.path contains "my-account" or http.request.uri.path contains "login" or http.request.uri.path contains "register") and cf.client.bot'
    },
    compound_sqli: {
      id: 'wcpscan_compound_sqli',
      title: 'Rule 4: Deep SQL Injection & Database Armor',
      badge: 'SQLi Shield',
      description: 'Terminates UNION SELECT attacks, information_schema probing, blind SQLi time delays (sleep/benchmark/waitfor), hex SQL payloads, concat/xml extraction, and Boolean bypasses in queries at Cloudflare Edge before touching WordPress PHP or MySQL.',
      action: 'block',
      expression: '(lower(http.request.uri.query) contains "union" and lower(http.request.uri.query) contains "select") or (lower(http.request.uri.query) contains "information_schema") or (lower(http.request.uri.query) contains "sleep(" or lower(http.request.uri.query) contains "benchmark(" or lower(http.request.uri.query) contains "waitfor delay") or (lower(http.request.uri.query) contains "concat(" and lower(http.request.uri.query) contains "0x") or (lower(http.request.uri.query) contains "extractvalue(" or lower(http.request.uri.query) contains "updatexml(") or (lower(http.request.uri.query) contains " and 1=0" or lower(http.request.uri.query) contains " and 1=1" or lower(http.request.uri.query) contains "\' or 1=1" or lower(http.request.uri.query) contains "\\" or 1=1" or lower(http.request.uri.query) contains "group_concat" or lower(http.request.uri.query) contains "into outfile" or lower(http.request.uri.query) contains "into dumpfile")'
    }
  });
  const [loadingCf, setLoadingCf] = useState<boolean>(false);
  const [cfToken, setCfToken] = useState<string>('');
  const [cfZoneId, setCfZoneId] = useState<string>('');
  const [showToken, setShowToken] = useState<boolean>(false);
  const [showZone, setShowZone] = useState<boolean>(false);
  const [cfAutoSyncBans, setCfAutoSyncBans] = useState<boolean>(false);
  const [cfVerifying, setCfVerifying] = useState<boolean>(false);
  const [cfVerifyResult, setCfVerifyResult] = useState<{ success: boolean; message?: string; zone_name?: string; plan?: string } | null>(null);
  const [cfDeploying, setCfDeploying] = useState<boolean>(false);
  const [deployingSingleRuleKey, setDeployingSingleRuleKey] = useState<string | null>(null);
  const [cfDeployMessage, setCfDeployMessage] = useState<{ type: 'success' | 'error'; text: string } | null>(null);
  const [cfPurging, setCfPurging] = useState<boolean>(false);
  const [cfPurgeMessage, setCfPurgeMessage] = useState<string | null>(null);
  const [cfSelectedRules, setCfSelectedRules] = useState<{ [key: string]: boolean }>({
    compound_perimeter: true,
    compound_exploits: true,
    compound_login_bot: true,
    compound_sqli: true,
  });
  const [cfRuleCustomizations, setCfRuleCustomizations] = useState<{
    [key: string]: {
      action?: string;
      expression?: string;
      bypass_ips?: string;
      isEditing?: boolean;
    };
  }>({});
  const [cfRateLimitEnabled, setCfRateLimitEnabled] = useState<boolean>(false);
  const [cfRateLimitLoading, setCfRateLimitLoading] = useState<boolean>(false);
  const [cfRateLimitMessage, setCfRateLimitMessage] = useState<{ type: 'success' | 'error'; text: string } | null>(null);
  const [rateLimitRequests, setRateLimitRequests] = useState<number>(5);
  const [rateLimitPeriod, setRateLimitPeriod] = useState<number>(10);
  const [rateLimitTimeout, setRateLimitTimeout] = useState<number>(10);
  const [rateLimitAction, setRateLimitAction] = useState<string>('block');
  const [rateLimitPath, setRateLimitPath] = useState<string>('wp-login.php');
  const [rateLimitBypassIps, setRateLimitBypassIps] = useState<string>('');
  const [isEditingRateLimit, setIsEditingRateLimit] = useState<boolean>(false);
  const [manualBlockIp, setManualBlockIp] = useState<string>('');
  const [manualBlockReason, setManualBlockReason] = useState<string>('');
  const [manualBlocking, setManualBlocking] = useState<boolean>(false);

  // Cloudflare Edge Rules Inspection & Whitelist/Blocklist Edge Sync State
  const [showExistingRulesModal, setShowExistingRulesModal] = useState<boolean>(false);
  const [inspectingRules, setInspectingRules] = useState<boolean>(false);
  const [cfInspectionData, setCfInspectionData] = useState<any>(null);
  const [syncingWhitelistToCf, setSyncingWhitelistToCf] = useState<boolean>(false);
  const [whitelistSyncResult, setWhitelistSyncResult] = useState<{ success: boolean; message: string } | null>(null);
  const [syncingBlocklistToCf, setSyncingBlocklistToCf] = useState<boolean>(false);
  const [blocklistSyncResult, setBlocklistSyncResult] = useState<{ success: boolean; message: string } | null>(null);

  // Cloudflare Edge Whitelisted IPs Modal State
  const [showCfWhitelistModal, setShowCfWhitelistModal] = useState<boolean>(false);
  const [loadingCfWhitelist, setLoadingCfWhitelist] = useState<boolean>(false);
  const [cfWhitelistList, setCfWhitelistList] = useState<any[]>([]);
  const [cfWhitelistTotal, setCfWhitelistTotal] = useState<number>(0);
  const [removingCfWhitelistId, setRemovingCfWhitelistId] = useState<string | null>(null);
  const [cfWhitelistSearch, setCfWhitelistSearch] = useState<string>('');

  const handleOpenCfWhitelistModal = async () => {
    setShowCfWhitelistModal(true);
    await loadCfWhitelist();
  };

  const loadCfWhitelist = async () => {
    try {
      setLoadingCfWhitelist(true);
      const res = await apiRequest({ path: '/cloudflare/whitelisted-ips', method: 'GET' });
      if (res && res.success) {
        setCfWhitelistList(res.rules || []);
        setCfWhitelistTotal(res.total || 0);
      } else {
        setCfWhitelistList([]);
        setCfWhitelistTotal(0);
      }
    } catch (err: any) {
      console.error('Failed to fetch Cloudflare whitelisted IPs', err);
      setCfWhitelistList([]);
    } finally {
      setLoadingCfWhitelist(false);
    }
  };

  const handleRemoveCfWhitelistIp = async (ruleId: string, ip: string) => {
    requestFirewallConfirm({
      title: 'Remove Whitelist Rule',
      message: 'Are you sure you want to remove the Cloudflare Edge whitelist rule for this IP address?',
      targetItem: ip,
      confirmLabel: 'Remove Rule',
      variant: 'danger',
      onConfirm: async () => {
        try {
          setRemovingCfWhitelistId(ruleId);
          const res = await apiRequest({
            path: '/cloudflare/remove-whitelisted-ip',
            method: 'POST',
            data: { rule_id: ruleId, ip: ip }
          });
          if (res && res.success) {
            setCfWhitelistList(prev => prev.filter(r => r.id !== ruleId));
            setCfWhitelistTotal(prev => Math.max(0, prev - 1));
            loadCloudflareData();
            showFirewallNotice('success', `Cloudflare Edge whitelist rule for ${ip} was removed.`);
          } else {
            showFirewallNotice('error', res?.message || 'Failed to remove whitelist rule.');
          }
        } catch (err: any) {
          showFirewallNotice('error', 'Error removing whitelist rule: ' + (err?.message || 'Network error'));
        } finally {
          setRemovingCfWhitelistId(null);
        }
      },
    });
  };

  // Cloudflare Banned IP List Modal State
  const [showBannedIpsModal, setShowBannedIpsModal] = useState<boolean>(false);
  const [loadingBannedIps, setLoadingBannedIps] = useState<boolean>(false);
  const [bannedIpsList, setBannedIpsList] = useState<any[]>([]);
  const [bannedIpsTotal, setBannedIpsTotal] = useState<number>(0);
  const [unbanningRuleId, setUnbanningRuleId] = useState<string | null>(null);
  const [bannedIpSearch, setBannedIpSearch] = useState<string>('');

  const handleOpenBannedIpsModal = async () => {
    setShowBannedIpsModal(true);
    await loadBannedIps();
  };

  const loadBannedIps = async () => {
    try {
      setLoadingBannedIps(true);
      const res = await apiRequest({ path: '/cloudflare/banned-ips', method: 'GET' });
      if (res && res.success) {
        setBannedIpsList(res.rules || []);
        setBannedIpsTotal(res.total || 0);
      } else {
        setBannedIpsList([]);
        setBannedIpsTotal(0);
      }
    } catch (err: any) {
      console.error('Failed to fetch banned IPs', err);
      setBannedIpsList([]);
    } finally {
      setLoadingBannedIps(false);
    }
  };

  const handleUnbanIp = async (ruleId: string, ip: string) => {
    requestFirewallConfirm({
      title: 'Unban IP Address',
      message: 'Are you sure you want to unban and remove the Cloudflare Edge block for this IP address?',
      targetItem: ip,
      confirmLabel: 'Unban IP',
      variant: 'warning',
      onConfirm: async () => {
        try {
          setUnbanningRuleId(ruleId);
          const res = await apiRequest({
            path: '/cloudflare/unblock-ip',
            method: 'POST',
            data: { rule_id: ruleId, ip: ip }
          });
          if (res && res.success) {
            setBannedIpsList(prev => prev.filter(r => r.id !== ruleId));
            setBannedIpsTotal(prev => Math.max(0, prev - 1));
            loadCloudflareData();
            showFirewallNotice('success', `IP ${ip} was successfully unbanned from Cloudflare Edge.`);
          } else {
            showFirewallNotice('error', res?.message || 'Failed to unban IP.');
          }
        } catch (err: any) {
          showFirewallNotice('error', 'Error unbanning IP: ' + (err?.message || 'Network error'));
        } finally {
          setUnbanningRuleId(null);
        }
      },
    });
  };

  const handleOpenExistingRulesModal = async () => {
    setShowExistingRulesModal(true);
    try {
      setInspectingRules(true);
      const res = await apiRequest({ path: '/cloudflare/inspect-rules', method: 'GET' });
      if (res && res.success) {
        setCfInspectionData(res);
      }
    } catch (err: any) {
      console.error('Failed to inspect edge rules', err);
    } finally {
      setInspectingRules(false);
    }
  };

  const handleSyncWhitelistToCloudflare = async () => {
    const rawIps = wafSettings.waf_whitelisted_ips.trim();
    if (!rawIps) {
      showFirewallNotice('warning', 'Your Whitelisted IP list is currently empty. Please enter at least one IP address.');
      return;
    }
    const ipList = rawIps.split(/[\r\n,]+/).map(i => i.trim()).filter(Boolean);
    if (ipList.length === 0) {
      showFirewallNotice('warning', 'No valid IP addresses found in the whitelist box.');
      return;
    }

    try {
      setSyncingWhitelistToCf(true);
      setWhitelistSyncResult(null);

      let successCount = 0;
      let errorMsgs: string[] = [];

      for (const ip of ipList) {
        // Strip CIDR /32 or check valid format
        const cleanIp = ip.split('/')[0].trim();
        try {
          const res = await apiRequest({
            path: '/cloudflare/whitelist-ip',
            method: 'POST',
            data: { ip: cleanIp, notes: 'WCP Whitelist Sync' }
          });
          if (res && res.success) {
            successCount++;
          } else if (res && res.message) {
            errorMsgs.push(`${cleanIp}: ${res.message}`);
          }
        } catch (e: any) {
          errorMsgs.push(`${cleanIp}: ${e?.message || 'Failed'}`);
        }
      }

      if (successCount > 0) {
        setWhitelistSyncResult({
          success: true,
          message: `Successfully synchronized ${successCount} IP(s) to Cloudflare Edge as 'Allow' IP Access Rules! Edge rules will never challenge or block your IP.`
        });
        showFirewallNotice('success', `Synchronized ${successCount} IP(s) to Cloudflare Edge Whitelist.`);
        loadCloudflareData();
      } else {
        setWhitelistSyncResult({
          success: false,
          message: errorMsgs.join('; ') || 'Failed to sync whitelist to Cloudflare Edge.'
        });
        showFirewallNotice('error', errorMsgs.join('; ') || 'Failed to sync whitelist to Cloudflare Edge.');
      }
    } catch (err: any) {
      setWhitelistSyncResult({
        success: false,
        message: err?.message || 'Error occurred during Edge Whitelist sync.'
      });
      showFirewallNotice('error', err?.message || 'Error occurred during Edge Whitelist sync.');
    } finally {
      setSyncingWhitelistToCf(false);
      setTimeout(() => setWhitelistSyncResult(null), 8000);
    }
  };

  const handleSyncBlocklistToCloudflare = async () => {
    const rawIps = wafSettings.waf_blocked_ips.trim();
    if (!rawIps) {
      showFirewallNotice('warning', 'Your Blocked IP list is currently empty. Please enter at least one IP address.');
      return;
    }
    const ipList = rawIps.split(/[\r\n,]+/).map(i => i.trim()).filter(Boolean);
    if (ipList.length === 0) {
      showFirewallNotice('warning', 'No valid IP addresses found in the blocklist box.');
      return;
    }

    try {
      setSyncingBlocklistToCf(true);
      setBlocklistSyncResult(null);

      let successCount = 0;
      let errorMsgs: string[] = [];

      for (const ip of ipList) {
        const cleanIp = ip.split('/')[0].trim();
        try {
          const res = await apiRequest({
            path: '/cloudflare/sync-ip',
            method: 'POST',
            data: { ip: cleanIp, reason: 'WCP Blocklist Sync' }
          });
          if (res && res.success) {
            successCount++;
          } else if (res && res.message) {
            errorMsgs.push(`${cleanIp}: ${res.message}`);
          }
        } catch (e: any) {
          errorMsgs.push(`${cleanIp}: ${e?.message || 'Failed'}`);
        }
      }

      if (successCount > 0) {
        setBlocklistSyncResult({
          success: true,
          message: `Successfully synchronized ${successCount} IP(s) to Cloudflare Edge as 'Block' IP Access Rules! Malicious traffic will be rejected before reaching your origin server.`
        });
        loadCloudflareData();
      } else {
        setBlocklistSyncResult({
          success: false,
          message: errorMsgs.join('; ') || 'Failed to sync blocklist to Cloudflare Edge.'
        });
      }
    } catch (err: any) {
      setBlocklistSyncResult({
        success: false,
        message: err?.message || 'Error occurred during Edge Blocklist sync.'
      });
    } finally {
      setSyncingBlocklistToCf(false);
      setTimeout(() => setBlocklistSyncResult(null), 8000);
    }
  };

  // Compound Rule Definitions for 1-Click Copy-Paste (No API Token Required)
  const [compoundRules, setCompoundRules] = useState<{ [key: string]: CompoundRule }>({
    compound_perimeter: {
      id: 'wcp_compound_perimeter',
      title: 'Rule 1: Master Perimeter & Sensitive File Armor',
      badge: 'Edge Shield',
      description: 'Drops /xmlrpc.php abuse, uploads directory PHP webshell execution, sensitive file probes (.env, .git, .sql, .bak, debug.log, wp-config.php), and hostile HTTP methods (TRACE/TRACK) in 1 single Free rule.',
      action: 'block',
      action_label: 'Block',
      expression: '(http.request.uri.path contains "xmlrpc.php") or ((http.request.uri.path contains "wp-content/uploads" or http.request.uri.path contains "wp-content/upgrade") and http.request.uri.path.extension in {"php" "phtml" "phar" "sh" "bash" "py" "pl" "exe" "cgi"}) or (http.request.uri.path contains "wp-config.php" or http.request.uri.path contains ".env" or http.request.uri.path contains ".git" or http.request.uri.path contains ".user.ini" or http.request.uri.path contains "debug.log" or http.request.uri.path contains "composer.json" or http.request.uri.path contains "package.json" or http.request.uri.path contains "readme.html" or http.request.uri.path contains "license.txt") or (http.request.uri.path.extension in {"sql" "bak" "tar" "gz" "zip" "ini" "sh"}) or (http.request.method in {"TRACE" "TRACK" "DEBUG"})'
    },
    compound_exploits: {
      id: 'wcp_compound_exploits',
      title: 'Rule 2: LFI/RFI Directory Traversal & Reconnaissance Shield',
      badge: 'Zero-Day Shield',
      description: 'Terminates path traversal (../), dangerous base64/eval function injection parameters, null byte attacks, author query parameter enumeration (?author=1), and public REST user scraping.',
      action: 'block',
      action_label: 'Block',
      expression: '(http.request.uri contains "../" or http.request.uri contains "..%2f" or http.request.uri.query contains "etc/passwd" or http.request.uri.query contains "base64_decode" or http.request.uri.query contains "eval(" or http.request.uri contains "%00" or http.request.uri.query contains "author=" or (http.request.uri.path contains "wp-json/wp/v2/users" and not http.request.uri.path contains "wp-json/wp/v2/users/me"))'
    },
    compound_login_bot: {
      id: 'wcp_compound_login_bot',
      title: 'Rule 3: Login Portal Automated Bot Defense (Anti-Brute Force)',
      badge: 'Turnstile Challenge',
      description: 'Challenges automated bot crawlers targeting wp-login.php, WooCommerce my-account, and custom membership login/register portals with Cloudflare Managed Challenge (Turnstile) without annoying human administrators or valid users.',
      action: 'managed_challenge',
      action_label: 'Managed Challenge',
      expression: '(http.request.uri.path contains "wp-login.php" or http.request.uri.path contains "wp-custom-login" or http.request.uri.path contains "my-account" or http.request.uri.path contains "login" or http.request.uri.path contains "register") and cf.client.bot'
    },
    compound_sqli: {
      id: 'wcp_compound_sqli',
      title: 'Rule 4: Deep SQL Injection & Database Armor',
      badge: 'SQLi Shield',
      description: 'Terminates UNION SELECT attacks, information_schema probing, blind SQLi time delays (sleep/benchmark/waitfor), hex SQL payloads, concat/xml extraction, and Boolean bypasses in queries at Cloudflare Edge before touching WordPress PHP or MySQL.',
      action: 'block',
      action_label: 'Block',
      expression: '(lower(http.request.uri.query) contains "union" and lower(http.request.uri.query) contains "select") or (lower(http.request.uri.query) contains "information_schema") or (lower(http.request.uri.query) contains "sleep(" or lower(http.request.uri.query) contains "benchmark(" or lower(http.request.uri.query) contains "waitfor delay") or (lower(http.request.uri.query) contains "concat(" and lower(http.request.uri.query) contains "0x") or (lower(http.request.uri.query) contains "extractvalue(" or lower(http.request.uri.query) contains "updatexml(") or (lower(http.request.uri.query) contains " and 1=0" or lower(http.request.uri.query) contains " and 1=1" or lower(http.request.uri.query) contains "\' or 1=1" or lower(http.request.uri.query) contains "\\" or 1=1" or lower(http.request.uri.query) contains "group_concat" or lower(http.request.uri.query) contains "into outfile" or lower(http.request.uri.query) contains "into dumpfile")'
    }
  });
  const [copiedRuleId, setCopiedRuleId] = useState<string | null>(null);
  const [showManualCfRules, setShowManualCfRules] = useState<boolean>(false);

  // Threat Intelligence states
  const [cves, setCves] = useState<CVEItem[]>([]);
  const [loadingCves, setLoadingCves] = useState<boolean>(false);
  const [syncingIntel, setSyncingIntel] = useState<boolean>(false);
  const [syncMessage, setSyncMessage] = useState<{ type: 'success' | 'error'; text: string } | null>(null);
  const [cveSearch, setCveSearch] = useState<string>('');
  const [cveFilter, setCveFilter] = useState<'all' | 'installed' | 'vulnerable'>('all');
  const [ipCheckInput, setIpCheckInput] = useState<string>('');
  const [ipCheckResult, setIpCheckResult] = useState<{ ip: string; isBlacklisted: boolean } | null>(null);

  // Central Blocklist & Lockout Modal states
  interface LockedIpItem {
    ip: string;
    incident_id?: string;
    type: string;
    badge: string;
    rule_id?: string;
    rule_name?: string;
    rule_category?: string;
    reason: string;
    admin_user?: string;
    admin_note?: string;
    blocked_at: string;
    blocked_at_raw?: number;
    ban_ago: string;
    duration: string;
    duration_seconds: number;
    expires_at: string;
    expires_at_raw?: number;
    time_remaining: string;
    countdown?: {
      years: number;
      months: number;
      days: number;
      hours: number;
      minutes: number;
      seconds: number;
    };
    is_expired: boolean;
    is_permanent: boolean;
    recent_history?: Array<{
      incident_id?: string;
      created_at?: string;
      category?: string;
      description?: string;
      uri?: string;
      method?: string;
      status?: number;
      user_agent?: string;
      payload?: string;
    }>;
  }

  const [blocklistModalOpen, setBlocklistModalOpen] = useState<boolean>(false);
  const [lockedIpsList, setLockedIpsList] = useState<LockedIpItem[]>([]);
  const [loadingBlocklist, setLoadingBlocklist] = useState<boolean>(false);
  const [unblockingIp, setUnblockingIp] = useState<string | null>(null);
  const [cfActionIp, setCfActionIp] = useState<string | null>(null);
  const [blocklistSearch, setBlocklistSearch] = useState<string>('');
  const [expandedHistoryIps, setExpandedHistoryIps] = useState<Record<string, boolean>>({});
  const [copiedIncidentId, setCopiedIncidentId] = useState<string | null>(null);

  // Manual block form inside modal
  const [showManualBlockForm, setShowManualBlockForm] = useState<boolean>(false);
  const [modalNewBlockIp, setModalNewBlockIp] = useState<string>('');
  const [modalNewBlockDuration, setModalNewBlockDuration] = useState<number>(0);
  const [modalNewBlockReason, setModalNewBlockReason] = useState<string>('');
  const [savingManualBlock, setSavingManualBlock] = useState<boolean>(false);

  const toggleHistoryExpansion = (ip: string) => {
    setExpandedHistoryIps(prev => ({
      ...prev,
      [ip]: !prev[ip]
    }));
  };

  const copyIncidentToClipboard = (text: string) => {
    if (navigator?.clipboard?.writeText) {
      navigator.clipboard.writeText(text);
      setCopiedIncidentId(text);
      setTimeout(() => setCopiedIncidentId(null), 2000);
    }
  };

  const handleAddManualBlock = async (e: any) => {
    e.preventDefault();
    const cleanIp = modalNewBlockIp.trim();
    if (!cleanIp) {
      showFirewallNotice('warning', 'Please enter a valid IP address or CIDR range.');
      return;
    }
    try {
      setSavingManualBlock(true);
      const res = await apiRequest({
        path: '/firewall/logs/block-ip',
        method: 'POST',
        data: {
          ip: cleanIp,
          reason: modalNewBlockReason.trim() || 'Blocked manually by administrator policy',
          duration_seconds: modalNewBlockDuration
        }
      });
      if (res && res.success) {
        setModalNewBlockIp('');
        setModalNewBlockReason('');
        setModalNewBlockDuration(0);
        setShowManualBlockForm(false);
        await fetchBlocklistData();
        showFirewallNotice('success', `IP ${cleanIp} was added to the firewall blocklist.`);
      } else {
        showFirewallNotice('error', res?.message || 'Failed to add IP to blocklist.');
      }
    } catch (err: any) {
      showFirewallNotice('error', err?.message || 'Error adding IP to blocklist.');
    } finally {
      setSavingManualBlock(false);
    }
  };

  const fetchBlocklistData = async () => {
    try {
      setLoadingBlocklist(true);
      const res = await apiRequest({
        path: '/firewall/blocklist',
        method: 'GET'
      });
      if (res && res.locked_ips) {
        setLockedIpsList(res.locked_ips);
      }
      if (res && res.waf_blocked_ips !== undefined) {
        setWafSettings(prev => ({ ...prev, waf_blocked_ips: res.waf_blocked_ips }));
      }
      // Also refresh Cloudflare edge banned IPs list in background so toggle states stay synchronized
      if (typeof loadBannedIps === 'function') {
        loadBannedIps();
      }
    } catch (e) {
      // ignore
    } finally {
      setLoadingBlocklist(false);
    }
  };

  // Whitelisted IPs Table state & actions
  interface WhitelistedIpItem {
    ip: string;
    reason: string;
    added_at: string;
    added_at_raw: number | null;
    added_ago: string;
    added_by: string;
    type: string;
    require_admin: boolean;
    scope?: 'rule' | 'category' | 'global';
    allowed_rules?: string[];
    allowed_rule_names?: Record<string, string>;
    allowed_cats?: string[];
    endpoint?: string;
    expires_at?: number;
    is_expired?: boolean;
  }

  interface FirewallRuleCatalogItem {
    id: string;
    name: string;
    category: string;
    description: string;
  }

  const [whitelistedIpsList, setWhitelistedIpsList] = useState<WhitelistedIpItem[]>([]);
  const [loadingWhitelist, setLoadingWhitelist] = useState<boolean>(false);
  const [newWhitelistIp, setNewWhitelistIp] = useState<string>('');
  const [newWhitelistReason, setNewWhitelistReason] = useState<string>('');
  const [newWhitelistScope, setNewWhitelistScope] = useState<'rule' | 'category' | 'global'>('global');
  const [newWhitelistSelectedRule, setNewWhitelistSelectedRule] = useState<string>('');
  const [newWhitelistSelectedCat, setNewWhitelistSelectedCat] = useState<string>('');
  const [newWhitelistExpiresIn, setNewWhitelistExpiresIn] = useState<number>(86400); // Default 24h
  const [rulesCatalog, setRulesCatalog] = useState<FirewallRuleCatalogItem[]>([]);
  const [addingWhitelistIp, setAddingWhitelistIp] = useState<boolean>(false);
  const [removingWhitelistIp, setRemovingWhitelistIp] = useState<string | null>(null);
  const [whitelistingCurrentIp, setWhitelistingCurrentIp] = useState<boolean>(false);
  const [whitelistSearch, setWhitelistSearch] = useState<string>('');

  // Editing Modals for Existing Allowlist and Blocklist
  const [editWhitelistItem, setEditWhitelistItem] = useState<{
    isOpen: boolean;
    ip: string;
    reason: string;
    scope: 'rule' | 'category' | 'global';
    selectedRule: string;
    selectedCat: string;
    endpoint: string;
    expiresIn: number;
    isSubmitting: boolean;
  }>({
    isOpen: false,
    ip: '',
    reason: '',
    scope: 'global',
    selectedRule: '',
    selectedCat: '',
    endpoint: '',
    expiresIn: 86400,
    isSubmitting: false,
  });

  const [editBlocklistItem, setEditBlocklistItem] = useState<{
    isOpen: boolean;
    ip: string;
    reason: string;
    durationSeconds: number;
    isSubmitting: boolean;
  }>({
    isOpen: false,
    ip: '',
    reason: '',
    durationSeconds: 0,
    isSubmitting: false,
  });

  // Blocked IPs inline table state & pagination
  const [newBlockIp, setNewBlockIp] = useState<string>('');
  const [newBlockReason, setNewBlockReason] = useState<string>('');
  const [addingBlockIp, setAddingBlockIp] = useState<boolean>(false);
  const [blockedTableSearch, setBlockedTableSearch] = useState<string>('');
  const [blockedPage, setBlockedPage] = useState<number>(1);
  const [blockedPageSize, setBlockedPageSize] = useState<number>(10);

  const fetchWhitelistData = async () => {
    try {
      setLoadingWhitelist(true);
      const res = await apiRequest({
        path: '/firewall/whitelist',
        method: 'GET'
      });
      if (res && res.whitelisted_ips) {
        setWhitelistedIpsList(res.whitelisted_ips);
      }
      if (res && res.rules_catalog && Array.isArray(res.rules_catalog)) {
        setRulesCatalog(res.rules_catalog);
      }
      if (res && res.waf_whitelisted_ips !== undefined) {
        setWafSettings(prev => ({ ...prev, waf_whitelisted_ips: res.waf_whitelisted_ips }));
      }
    } catch (e) {
      // ignore
    } finally {
      setLoadingWhitelist(false);
    }
  };

  const handleAddWhitelistIp = async (e: any) => {
    e.preventDefault();
    const cleanIp = newWhitelistIp.trim();
    if (!cleanIp) {
      showFirewallNotice('warning', 'Please enter a valid IP address or CIDR range.');
      return;
    }

    if (newWhitelistScope === 'rule' && !newWhitelistSelectedRule) {
      showFirewallNotice('warning', 'Please select a specific firewall rule to exempt.');
      return;
    }

    if (newWhitelistScope === 'category' && !newWhitelistSelectedCat) {
      showFirewallNotice('warning', 'Please select a rule category group to exempt.');
      return;
    }

    try {
      setAddingWhitelistIp(true);
      const payload: any = {
        ip: cleanIp,
        reason: newWhitelistReason.trim() || 'Trusted administrative access policy',
        scope: newWhitelistScope,
        expires_in: newWhitelistExpiresIn,
      };

      if (newWhitelistScope === 'rule') {
        payload.allowed_rules = [newWhitelistSelectedRule];
      } else if (newWhitelistScope === 'category') {
        payload.allowed_cats = [newWhitelistSelectedCat];
      }

      const res = await apiRequest({
        path: '/firewall/logs/whitelist-ip',
        method: 'POST',
        data: payload
      });
      if (res && res.success) {
        setNewWhitelistIp('');
        setNewWhitelistReason('');
        setNewWhitelistSelectedRule('');
        setNewWhitelistSelectedCat('');
        if (res.whitelisted_ips) {
          setWhitelistedIpsList(res.whitelisted_ips);
        } else {
          await fetchWhitelistData();
        }
        showFirewallNotice('success', res.message || `IP ${cleanIp} added to whitelist.`);
      } else {
        showFirewallNotice('error', res?.message || 'Failed to add IP to whitelist.');
      }
    } catch (err: any) {
      showFirewallNotice('error', err?.message || 'Error adding IP to whitelist.');
    } finally {
      setAddingWhitelistIp(false);
    }
  };

  const handleOpenEditWhitelistModal = (item: WhitelistedIpItem) => {
    const existingRule = (item.allowed_rules && item.allowed_rules[0]) || '';
    const existingCat = (item.allowed_cats && item.allowed_cats[0]) || '';
    let remainingTtl = 86400;
    if (item.expires_at && item.expires_at > 0) {
      const diff = item.expires_at - Math.floor(Date.now() / 1000);
      remainingTtl = diff > 0 ? diff : 0;
    } else if (item.expires_at === 0) {
      remainingTtl = 0;
    }

    setEditWhitelistItem({
      isOpen: true,
      ip: item.ip,
      reason: item.reason || '',
      scope: item.scope || 'global',
      selectedRule: existingRule,
      selectedCat: existingCat,
      endpoint: item.endpoint || '',
      expiresIn: remainingTtl,
      isSubmitting: false,
    });
  };

  const handleSaveEditWhitelist = async () => {
    if (!editWhitelistItem.ip) return;
    if (editWhitelistItem.scope === 'rule' && !editWhitelistItem.selectedRule) {
      showFirewallNotice('warning', 'Please select a specific firewall rule to exempt.');
      return;
    }
    if (editWhitelistItem.scope === 'category' && !editWhitelistItem.selectedCat) {
      showFirewallNotice('warning', 'Please select a rule category group to exempt.');
      return;
    }

    try {
      setEditWhitelistItem(prev => ({ ...prev, isSubmitting: true }));
      const payload: any = {
        ip: editWhitelistItem.ip,
        reason: editWhitelistItem.reason.trim() || 'Updated allowlist policy',
        scope: editWhitelistItem.scope,
        endpoint: editWhitelistItem.endpoint.trim(),
        expires_in: editWhitelistItem.expiresIn,
      };

      if (editWhitelistItem.scope === 'rule') {
        payload.allowed_rules = [editWhitelistItem.selectedRule];
      } else if (editWhitelistItem.scope === 'category') {
        payload.allowed_cats = [editWhitelistItem.selectedCat];
      }

      const res = await apiRequest({
        path: '/firewall/logs/whitelist-ip',
        method: 'POST',
        data: payload
      });

      if (res && res.success) {
        if (res.whitelisted_ips) {
          setWhitelistedIpsList(res.whitelisted_ips);
        } else {
          await fetchWhitelistData();
        }
        showFirewallNotice('success', `Allowlist policy for ${editWhitelistItem.ip} updated successfully.`);
        setEditWhitelistItem(prev => ({ ...prev, isOpen: false }));
      } else {
        showFirewallNotice('error', res?.message || 'Failed to update allowlist policy.');
      }
    } catch (err: any) {
      showFirewallNotice('error', err?.message || 'Error updating allowlist policy.');
    } finally {
      setEditWhitelistItem(prev => ({ ...prev, isSubmitting: false }));
    }
  };

  const handleOpenEditBlocklistModal = (item: LockedIpItem) => {
    setEditBlocklistItem({
      isOpen: true,
      ip: item.ip,
      reason: item.reason || '',
      durationSeconds: item.duration_seconds || 0,
      isSubmitting: false,
    });
  };

  const handleSaveEditBlocklist = async () => {
    if (!editBlocklistItem.ip) return;

    try {
      setEditBlocklistItem(prev => ({ ...prev, isSubmitting: true }));
      const res = await apiRequest({
        path: '/firewall/logs/block-ip',
        method: 'POST',
        data: {
          ip: editBlocklistItem.ip,
          reason: editBlocklistItem.reason.trim() || 'Updated blocklist policy by administrator',
          duration_seconds: editBlocklistItem.durationSeconds,
        }
      });

      if (res && res.success) {
        await fetchBlocklistData();
        showFirewallNotice('success', `Blocklist entry for ${editBlocklistItem.ip} updated successfully.`);
        setEditBlocklistItem(prev => ({ ...prev, isOpen: false }));
      } else {
        showFirewallNotice('error', res?.message || 'Failed to update blocklist entry.');
      }
    } catch (err: any) {
      showFirewallNotice('error', err?.message || 'Error updating blocklist entry.');
    } finally {
      setEditBlocklistItem(prev => ({ ...prev, isSubmitting: false }));
    }
  };

  const handleRemoveWhitelistIp = async (ip: string) => {
    try {
      setRemovingWhitelistIp(ip);
      const res = await apiRequest({
        path: '/firewall/whitelist/remove',
        method: 'POST',
        data: { ip }
      });
      if (res && res.success) {
        setWhitelistedIpsList(prev => prev.filter(item => item.ip !== ip));
        const currentWhitelisted = wafSettings.waf_whitelisted_ips || '';
        const lines = currentWhitelisted.split('\n').map(l => l.trim()).filter(l => l && l !== ip);
        setWafSettings(prev => ({ ...prev, waf_whitelisted_ips: lines.join('\n') }));
        showFirewallNotice('success', `IP ${ip} removed from whitelist.`);
      } else {
        showFirewallNotice('error', res?.message || 'Failed to remove IP from whitelist.');
      }
    } catch (err: any) {
      showFirewallNotice('error', err?.message || 'Error removing IP from whitelist.');
    } finally {
      setRemovingWhitelistIp(null);
    }
  };

  const handleAddBlockedIpInline = async (e: any) => {
    e.preventDefault();
    const cleanIp = newBlockIp.trim();
    if (!cleanIp) {
      showFirewallNotice('warning', 'Please enter a valid IP address or CIDR range.');
      return;
    }
    try {
      setAddingBlockIp(true);
      const res = await apiRequest({
        path: '/firewall/logs/block-ip',
        method: 'POST',
        data: {
          ip: cleanIp,
          reason: newBlockReason.trim() || 'Blocked manually by administrator policy',
          duration_seconds: 0
        }
      });
      if (res && res.success) {
        setNewBlockIp('');
        setNewBlockReason('');
        await fetchBlocklistData();
        showFirewallNotice('success', `IP ${cleanIp} added to blocklist.`);
      } else {
        showFirewallNotice('error', res?.message || 'Failed to add IP to blocklist.');
      }
    } catch (err: any) {
      showFirewallNotice('error', err?.message || 'Error adding IP to blocklist.');
    } finally {
      setAddingBlockIp(false);
    }
  };

  const handleUnblockIpFromModal = async (ip: string) => {
    try {
      setUnblockingIp(ip);
      const res = await apiRequest({
        path: '/firewall/logs/unblock-ip',
        method: 'POST',
        data: { ip }
      });
      if (res && res.success) {
        setLockedIpsList(prev => prev.filter(item => item.ip !== ip));
        // Also update local wafSettings.waf_blocked_ips textarea
        const currentBlocked = wafSettings.waf_blocked_ips || '';
        const lines = currentBlocked.split('\n').map(l => l.trim()).filter(l => l && l !== ip);
        setWafSettings(prev => ({ ...prev, waf_blocked_ips: lines.join('\n') }));
        showFirewallNotice('success', `IP ${ip} was unblocked.`);
      } else {
        showFirewallNotice('error', res?.message || 'Failed to unblock IP');
      }
    } catch (e: any) {
      showFirewallNotice('error', e?.message || 'Failed to unblock IP');
    } finally {
      setUnblockingIp(null);
    }
  };

  const handlePushIpToCloudflareEdge = async (rawIp: string, reason?: string) => {
    const ip = (rawIp || '').trim();
    if (!ip) return;

    // Validate CIDR format against Cloudflare IP Access Rules restrictions
    if (ip.includes('/')) {
      const parts = ip.split('/');
      const prefix = parseInt(parts[1], 10);
      const isIpv6 = parts[0].includes(':');
      if (!isIpv6) {
        if (prefix !== 16 && prefix !== 24) {
          showFirewallNotice(
            'error',
            `Cloudflare IP Access Rules only allows IPv4 ranges of /16 or /24.\n\nSubnet ${ip} (/${prefix}) cannot be added to IP Access Rules. Please use Cloudflare WAF Custom Rules or block specific /24 subnets instead.`,
            'Cloudflare CIDR Limitation'
          );
          return;
        }
      } else {
        if (prefix !== 32 && prefix !== 48 && prefix !== 64) {
          showFirewallNotice(
            'error',
            `Cloudflare IP Access Rules only allows IPv6 ranges of /32, /48, or /64.\n\nSubnet ${ip} (/${prefix}) cannot be added to IP Access Rules. Please use Cloudflare WAF Custom Rules instead.`,
            'Cloudflare CIDR Limitation'
          );
          return;
        }
      }
    }

    try {
      setCfActionIp(`push-${ip}`);
      const res = await apiRequest({
        path: '/cloudflare/sync-ip',
        method: 'POST',
        data: {
          ip,
          reason: reason || 'WCP Firewall Blocklist IP'
        }
      });
      if (res && res.success) {
        showFirewallNotice('success', res.message || `IP/Subnet ${ip} was successfully pushed to Cloudflare Edge (Mode: Block).`);
        if (typeof loadCloudflareData === 'function') {
          loadCloudflareData();
        }
        if (typeof loadBannedIps === 'function') {
          loadBannedIps();
        }
      } else {
        showFirewallNotice('error', res?.message || `Failed to push ${ip} to Cloudflare Edge.`);
      }
    } catch (err: any) {
      showFirewallNotice('error', `Error pushing IP to Cloudflare Edge: ${err?.message || 'Network error'}`);
    } finally {
      setCfActionIp(null);
    }
  };

  const handleUnblockIpFromCloudflareEdge = async (rawIp: string) => {
    const ip = (rawIp || '').trim();
    if (!ip) return;
    try {
      setCfActionIp(`unblock-${ip}`);
      // Find matching rule_id if present in bannedIpsList (matching exact IP or CIDR)
      const matchingRule = bannedIpsList.find(r => (r.ip || '').trim().toLowerCase() === ip.toLowerCase());
      const ruleId = matchingRule?.id || '';

      const res = await apiRequest({
        path: '/cloudflare/unblock-ip',
        method: 'POST',
        data: {
          ip,
          rule_id: ruleId
        }
      });
      if (res && res.success) {
        showFirewallNotice('success', res.message || `IP/Subnet ${ip} was successfully unblocked from Cloudflare Edge.`);
        if (ruleId) {
          setBannedIpsList(prev => prev.filter(r => r.id !== ruleId));
          setBannedIpsTotal(prev => Math.max(0, prev - 1));
        }
        if (typeof loadCloudflareData === 'function') {
          loadCloudflareData();
        }
        if (typeof loadBannedIps === 'function') {
          loadBannedIps();
        }
      } else {
        showFirewallNotice('error', res?.message || `Failed to unblock ${ip} from Cloudflare Edge.`);
      }
    } catch (err: any) {
      showFirewallNotice('error', `Error unblocking from Cloudflare Edge: ${err?.message || 'Network error'}`);
    } finally {
      setCfActionIp(null);
    }
  };

  // Rules form state
  const [wafSettings, setWafSettings] = useState<{
    waf_enabled: boolean;
    waf_mode: 'enabled' | 'learning' | 'disabled';
    waf_complementary_mode: boolean;
    waf_block_sqli: boolean;
    waf_block_xss: boolean;
    waf_block_traversal: boolean;
    waf_block_php_injection: boolean;
    waf_disable_xmlrpc: boolean;
    waf_allow_jetpack_xmlrpc: boolean;
    waf_whitelisted_ips: string;
    waf_whitelist_require_admin: boolean;
    waf_whitelist_log_telemetry: boolean;
    waf_blocked_ips: string;
    threat_intel_enabled: boolean;
    threat_intel_block_blacklisted_ips: boolean;
    waf_block_fake_bots: boolean;
    waf_block_ai_scrapers: boolean;
    waf_dynamic_robots_ai: boolean;
    waf_block_404_scanners: boolean;
    waf_404_threshold: number;
    waf_404_window_seconds: number;
    waf_404_lockout_duration: number;
    waf_allow_uptime_monitors: boolean;
    waf_allow_central_management: boolean;
    waf_allow_page_builders: boolean;
    waf_ecommerce_safe_mode: boolean;
    waf_woo_carding_protection: boolean;
    waf_woo_checkout_max_attempts: number;
    waf_woo_carding_lockout_duration: number;
    waf_woo_coupon_protection: boolean;
    waf_woo_coupon_max_failures: number;
    waf_woo_coupon_lockout_duration: number;
    waf_woo_registration_protection: boolean;
    waf_woo_reg_max_per_ip: number;
    waf_woo_reg_window_hours: number;
    waf_woo_reg_block_disposable_emails: boolean;
    waf_woo_cart_flood_protection: boolean;
    waf_woo_max_cart_items: number;
    waf_woo_add_to_cart_rate_limit: number;
    waf_woo_scraping_protection: boolean;
    waf_woo_scraping_max_requests: number;
    waf_woo_scraping_lockout_duration: number;
    waf_forms_safe_mode: boolean;
    form_spam_protection_enabled: boolean;
    form_block_headless_browsers: boolean;
    form_honeypot_enabled: boolean;
    form_speed_gate_enabled: boolean;
    form_flood_limit_enabled: boolean;
    form_max_submits_per_window: number;
    form_flood_window_minutes: number;
    form_content_filtering: boolean;
    waf_block_empty_post_ua_referer: boolean;
    waf_whitelisted_urls: string;
    waf_targeted_allowlist_rules: string;
    waf_block_forbidden_usernames: boolean;
    waf_forbidden_usernames_list: string;
    waf_prevent_admin_registration: boolean;
    waf_mask_login_errors: boolean;
    waf_enforce_strong_passwords: boolean;
    waf_strong_passwords_roles: string;
    waf_check_pwned_passwords: boolean;
    waf_block_malicious_uploads: boolean;
    waf_block_unsafe_http_methods: boolean;
    waf_block_null_byte_attacks: boolean;
    waf_block_sensitive_file_probes: boolean;
    waf_block_uploads_php_exec: boolean;
    waf_block_external_cron: boolean;
    waf_block_open_redirects: boolean;
    waf_block_ssrf_metadata: boolean;
    waf_block_install_php: boolean;
    waf_disallow_phpmyadmin_plugins: boolean;
    waf_disallow_filemanager_plugins: boolean;
    waf_disallow_phpmyadmin_uploads: boolean;
    waf_disallow_filemanager_uploads: boolean;
    waf_block_rest_user_enum: boolean;
    waf_block_author_scan: boolean;
    waf_limit_lostpassword: boolean;
    waf_enforce_host_allowlist: boolean;
    waf_allowed_host_aliases: string;
    waf_limit_admin_ajax: boolean;
    waf_admin_ajax_limit_per_min: number;
    waf_block_oversized_requests: boolean;
    waf_block_ai_prompt_injection: boolean;
    waf_guest_ajax_policy: 'monitor' | 'block' | 'off';
    waf_guest_ajax_custom_allowlist: string;
    waf_guest_rest_policy: 'monitor' | 'off';
    waf_runtime_rasp_privilege_guard: boolean;
    waf_upload_deep_mime_sanitizer: boolean;
  }>({
    waf_enabled: true,
    waf_mode: 'enabled',
    waf_complementary_mode: true,
    waf_ecommerce_safe_mode: false,
    waf_woo_carding_protection: true,
    waf_woo_checkout_max_attempts: 3,
    waf_woo_carding_lockout_duration: 30,
    waf_woo_coupon_protection: true,
    waf_woo_coupon_max_failures: 5,
    waf_woo_coupon_lockout_duration: 15,
    waf_woo_registration_protection: true,
    waf_woo_reg_max_per_ip: 3,
    waf_woo_reg_window_hours: 1,
    waf_woo_reg_block_disposable_emails: true,
    waf_woo_cart_flood_protection: true,
    waf_woo_max_cart_items: 50,
    waf_woo_add_to_cart_rate_limit: 15,
    waf_woo_scraping_protection: true,
    waf_woo_scraping_max_requests: 60,
    waf_woo_scraping_lockout_duration: 15,
    waf_forms_safe_mode: true,
    form_spam_protection_enabled: true,
    form_block_headless_browsers: true,
    form_honeypot_enabled: true,
    form_speed_gate_enabled: true,
    form_flood_limit_enabled: true,
    form_max_submits_per_window: 5,
    form_flood_window_minutes: 10,
    form_content_filtering: true,
    waf_block_sqli: true,
    waf_block_xss: true,
    waf_block_traversal: true,
    waf_block_php_injection: true,
    waf_disable_xmlrpc: false,
    waf_allow_jetpack_xmlrpc: false,
    waf_whitelisted_ips: '',
    waf_whitelist_require_admin: true,
    waf_whitelist_log_telemetry: true,
    waf_blocked_ips: '',
    threat_intel_enabled: true,
    threat_intel_block_blacklisted_ips: true,
    waf_block_fake_bots: true,
    waf_block_ai_scrapers: false,
    waf_dynamic_robots_ai: true,
    waf_block_404_scanners: true,
    waf_404_threshold: 10,
    waf_404_window_seconds: 60,
    waf_404_lockout_duration: 30,
    waf_allow_uptime_monitors: false,
    waf_allow_central_management: false,
    waf_allow_page_builders: false,
    waf_block_empty_post_ua_referer: true,
    waf_whitelisted_urls: '',
    waf_targeted_allowlist_rules: '[]',
    waf_block_forbidden_usernames: true,
    waf_forbidden_usernames_list: "admin\nadministrator\nroot",
    waf_prevent_admin_registration: true,
    waf_mask_login_errors: true,
    waf_enforce_strong_passwords: true,
    waf_strong_passwords_roles: 'administrator, editor',
    waf_check_pwned_passwords: true,
    waf_block_malicious_uploads: true,
    waf_block_unsafe_http_methods: true,
    waf_block_null_byte_attacks: true,
    waf_block_sensitive_file_probes: true,
    waf_block_uploads_php_exec: true,
    waf_block_external_cron: false,
    waf_block_open_redirects: true,
    waf_block_ssrf_metadata: true,
    waf_block_install_php: true,
    waf_disallow_phpmyadmin_plugins: true,
    waf_disallow_filemanager_plugins: true,
    waf_disallow_phpmyadmin_uploads: true,
    waf_disallow_filemanager_uploads: true,
    waf_block_rest_user_enum: true,
    waf_block_author_scan: true,
    waf_limit_lostpassword: true,
    waf_enforce_host_allowlist: true,
    waf_allowed_host_aliases: '',
    waf_limit_admin_ajax: true,
    waf_admin_ajax_limit_per_min: 60,
    waf_block_oversized_requests: true,
    waf_block_ai_prompt_injection: true,
    waf_guest_ajax_policy: 'monitor',
    waf_guest_ajax_custom_allowlist: '',
    waf_guest_rest_policy: 'monitor',
    waf_runtime_rasp_privilege_guard: true,
    waf_upload_deep_mime_sanitizer: true,
  });

  const loadFirewallData = async (isSilent = false) => {
    try {
      if (!isSilent) setLoading(true);
      else setRefreshing(true);

      const [statusRes, logsRes, settingsRes] = await Promise.all([
        apiRequest({ path: '/firewall/status', method: 'GET' }),
        apiRequest({ path: '/firewall/logs?limit=50', method: 'GET' }),
        apiRequest({ path: '/settings', method: 'GET' }),
      ]);

      if (statusRes) {
        setStatus(statusRes);
        if (statusRes.available_roles && Array.isArray(statusRes.available_roles) && statusRes.available_roles.length > 0) {
          setAvailableRoles(statusRes.available_roles);
        }
      }
      if (logsRes && logsRes.logs) {
        setLogs(logsRes.logs);
      }
      if (settingsRes && settingsRes.settings) {
        const s = settingsRes.settings;
        setWafSettings({
          waf_enabled: s.waf_enabled !== false,
          waf_mode: s.waf_mode || 'enabled',
          waf_complementary_mode: s.waf_complementary_mode !== false,
          waf_block_sqli: s.waf_block_sqli !== false,
          waf_block_xss: s.waf_block_xss !== false,
          waf_block_traversal: s.waf_block_traversal !== false,
          waf_block_php_injection: s.waf_block_php_injection !== false,
          waf_disable_xmlrpc: !!s.waf_disable_xmlrpc,
          waf_allow_jetpack_xmlrpc: !!s.waf_allow_jetpack_xmlrpc,
          waf_whitelisted_ips: s.waf_whitelisted_ips || '',
          waf_whitelist_require_admin: s.waf_whitelist_require_admin !== false,
          waf_whitelist_log_telemetry: s.waf_whitelist_log_telemetry !== false,
          waf_blocked_ips: s.waf_blocked_ips || '',
          threat_intel_enabled: s.threat_intel_enabled !== false,
          threat_intel_block_blacklisted_ips: s.threat_intel_block_blacklisted_ips !== false,
          waf_block_fake_bots: s.waf_block_fake_bots !== false,
          waf_block_ai_scrapers: !!s.waf_block_ai_scrapers,
          waf_dynamic_robots_ai: s.waf_dynamic_robots_ai !== false,
          waf_block_404_scanners: s.waf_block_404_scanners !== false,
          waf_404_threshold: s.waf_404_threshold !== undefined ? Number(s.waf_404_threshold) : 10,
          waf_404_window_seconds: s.waf_404_window_seconds !== undefined ? Number(s.waf_404_window_seconds) : 60,
          waf_404_lockout_duration: s.waf_404_lockout_duration !== undefined ? Number(s.waf_404_lockout_duration) : 30,
          waf_allow_uptime_monitors: !!s.waf_allow_uptime_monitors,
          waf_allow_central_management: !!s.waf_allow_central_management,
          waf_allow_page_builders: !!s.waf_allow_page_builders,
          waf_ecommerce_safe_mode: !!s.waf_ecommerce_safe_mode,
          waf_woo_carding_protection: s.waf_woo_carding_protection !== false,
          waf_woo_checkout_max_attempts: s.waf_woo_checkout_max_attempts !== undefined ? Number(s.waf_woo_checkout_max_attempts) : 3,
          waf_woo_carding_lockout_duration: s.waf_woo_carding_lockout_duration !== undefined ? Number(s.waf_woo_carding_lockout_duration) : 30,
          waf_woo_coupon_protection: s.waf_woo_coupon_protection !== false,
          waf_woo_coupon_max_failures: s.waf_woo_coupon_max_failures !== undefined ? Number(s.waf_woo_coupon_max_failures) : 5,
          waf_woo_coupon_lockout_duration: s.waf_woo_coupon_lockout_duration !== undefined ? Number(s.waf_woo_coupon_lockout_duration) : 15,
          waf_woo_registration_protection: s.waf_woo_registration_protection !== false,
          waf_woo_reg_max_per_ip: s.waf_woo_reg_max_per_ip !== undefined ? Number(s.waf_woo_reg_max_per_ip) : 3,
          waf_woo_reg_window_hours: s.waf_woo_reg_window_hours !== undefined ? Number(s.waf_woo_reg_window_hours) : 1,
          waf_woo_reg_block_disposable_emails: s.waf_woo_reg_block_disposable_emails !== false,
          waf_woo_cart_flood_protection: s.waf_woo_cart_flood_protection !== false,
          waf_woo_max_cart_items: s.waf_woo_max_cart_items !== undefined ? Number(s.waf_woo_max_cart_items) : 50,
          waf_woo_add_to_cart_rate_limit: s.waf_woo_add_to_cart_rate_limit !== undefined ? Number(s.waf_woo_add_to_cart_rate_limit) : 15,
          waf_woo_scraping_protection: s.waf_woo_scraping_protection !== false,
          waf_woo_scraping_max_requests: s.waf_woo_scraping_max_requests !== undefined ? Number(s.waf_woo_scraping_max_requests) : 60,
          waf_woo_scraping_lockout_duration: s.waf_woo_scraping_lockout_duration !== undefined ? Number(s.waf_woo_scraping_lockout_duration) : 15,
          waf_forms_safe_mode: s.waf_forms_safe_mode !== false,
          form_spam_protection_enabled: s.form_spam_protection_enabled !== false,
          form_block_headless_browsers: s.form_block_headless_browsers !== false,
          form_honeypot_enabled: s.form_honeypot_enabled !== false,
          form_speed_gate_enabled: s.form_speed_gate_enabled !== false,
          form_flood_limit_enabled: s.form_flood_limit_enabled !== false,
          form_max_submits_per_window: s.form_max_submits_per_window !== undefined ? Number(s.form_max_submits_per_window) : 5,
          form_flood_window_minutes: s.form_flood_window_minutes !== undefined ? Number(s.form_flood_window_minutes) : 10,
          form_content_filtering: s.form_content_filtering !== false,
          waf_block_empty_post_ua_referer: s.waf_block_empty_post_ua_referer !== false,
          waf_whitelisted_urls: s.waf_whitelisted_urls || '',
          waf_targeted_allowlist_rules: typeof s.waf_targeted_allowlist_rules === 'string' ? s.waf_targeted_allowlist_rules : JSON.stringify(s.waf_targeted_allowlist_rules || []),
          waf_block_forbidden_usernames: s.waf_block_forbidden_usernames !== false,
          waf_forbidden_usernames_list: s.waf_forbidden_usernames_list !== undefined ? s.waf_forbidden_usernames_list : "admin\nadministrator\nroot",
          waf_prevent_admin_registration: s.waf_prevent_admin_registration !== false,
          waf_mask_login_errors: s.waf_mask_login_errors !== false,
          waf_enforce_strong_passwords: s.waf_enforce_strong_passwords !== false,
          waf_strong_passwords_roles: s.waf_strong_passwords_roles || 'administrator, editor',
          waf_check_pwned_passwords: s.waf_check_pwned_passwords !== false,
          waf_block_malicious_uploads: s.waf_block_malicious_uploads !== false,
          waf_block_unsafe_http_methods: s.waf_block_unsafe_http_methods !== false,
          waf_block_null_byte_attacks: s.waf_block_null_byte_attacks !== false,
          waf_block_sensitive_file_probes: s.waf_block_sensitive_file_probes !== false,
          waf_block_uploads_php_exec: s.waf_block_uploads_php_exec !== false,
          waf_block_external_cron: !!s.waf_block_external_cron,
          waf_block_open_redirects: s.waf_block_open_redirects !== false,
          waf_block_ssrf_metadata: s.waf_block_ssrf_metadata !== false,
          waf_block_install_php: s.waf_block_install_php !== false,
          waf_disallow_phpmyadmin_plugins: s.waf_disallow_phpmyadmin_plugins !== false,
          waf_disallow_filemanager_plugins: s.waf_disallow_filemanager_plugins !== false,
          waf_disallow_phpmyadmin_uploads: s.waf_disallow_phpmyadmin_uploads !== false,
          waf_disallow_filemanager_uploads: s.waf_disallow_filemanager_uploads !== false,
          waf_block_rest_user_enum: s.waf_block_rest_user_enum !== false,
          waf_block_author_scan: s.waf_block_author_scan !== false,
          waf_limit_lostpassword: s.waf_limit_lostpassword !== false,
          waf_enforce_host_allowlist: s.waf_enforce_host_allowlist !== false,
          waf_allowed_host_aliases: s.waf_allowed_host_aliases || '',
          waf_limit_admin_ajax: s.waf_limit_admin_ajax !== false,
          waf_admin_ajax_limit_per_min: s.waf_admin_ajax_limit_per_min !== undefined ? Number(s.waf_admin_ajax_limit_per_min) : 60,
          waf_block_oversized_requests: s.waf_block_oversized_requests !== false,
          waf_block_ai_prompt_injection: s.waf_block_ai_prompt_injection !== false,
          waf_guest_ajax_policy: (s.waf_guest_ajax_policy === 'block' || s.waf_guest_ajax_policy === 'off') ? s.waf_guest_ajax_policy : 'monitor',
          waf_guest_ajax_custom_allowlist: s.waf_guest_ajax_custom_allowlist || '',
          waf_guest_rest_policy: s.waf_guest_rest_policy === 'off' ? 'off' : 'monitor',
          waf_runtime_rasp_privilege_guard: s.waf_runtime_rasp_privilege_guard !== false,
          waf_upload_deep_mime_sanitizer: s.waf_upload_deep_mime_sanitizer !== false,
        });
      }
    } catch (err) {
      console.error('Failed to load firewall data', err);
    } finally {
      setLoading(false);
      setRefreshing(false);
    }
  };

  const loadCves = async () => {
    try {
      setLoadingCves(true);
      const res = await apiRequest({ path: '/threat-intel/cves', method: 'GET' });
      if (res && res.cves) {
        setCves(res.cves);
      }
    } catch (err) {
      console.error('Failed to load CVE catalog', err);
    } finally {
      setLoadingCves(false);
    }
  };

  const handleSyncThreatIntel = async () => {
    try {
      setSyncingIntel(true);
      setSyncMessage(null);
      const res = await apiRequest({ path: '/threat-intel/sync', method: 'POST' });
      if (res && res.success) {
        setSyncMessage({
          type: 'success',
          text: `Threat Intelligence synchronized successfully! Loaded ${res.blacklisted_ips_count?.toLocaleString() || '15,420+'} active threat IPs and ${res.cves_count || '30+'} zero-day CVE definitions.`
        });
        loadFirewallData(true);
        loadCves();
      } else {
        setSyncMessage({
          type: 'error',
          text: 'Threat Intel synchronization finished with warnings.'
        });
      }
    } catch (err: any) {
      setSyncMessage({
        type: 'error',
        text: 'Failed to sync threat intelligence: ' + (err?.message || 'Network error')
      });
    } finally {
      setSyncingIntel(false);
    }
  };

  const handleCheckIpReputation = () => {
    const ip = ipCheckInput.trim();
    if (!ip) return;

    const sample = status?.threat_intel?.sample_ips || [];
    const isKnown = sample.includes(ip);
    setIpCheckResult({
      ip,
      isBlacklisted: isKnown
    });
  };

  const loadCloudflareData = async () => {
    try {
      setLoadingCf(true);
      const res = await apiRequest({ path: '/cloudflare/status', method: 'GET' });
      if (res && res.status) {
        setCfStatus(res.status);
        if (res.definitions && Object.keys(res.definitions).length > 0) {
          setCfDefinitions(res.definitions);
        }
        setCfRateLimitEnabled(!!res.status.rate_limiting);
        if (res.status.rate_limit_info) {
          const rinfo = res.status.rate_limit_info;
          if (rinfo.requests) setRateLimitRequests(Number(rinfo.requests));
          if (rinfo.period) setRateLimitPeriod(Number(rinfo.period));
          if (rinfo.mitigation_timeout) setRateLimitTimeout(Number(rinfo.mitigation_timeout));
          if (rinfo.action) setRateLimitAction(rinfo.action);
          if (rinfo.path) setRateLimitPath(rinfo.path);
          if (rinfo.bypass_ips !== undefined) setRateLimitBypassIps(rinfo.bypass_ips || '');
        }
        setCfAutoSyncBans(!!res.status.auto_sync_bans);

        if (res.status.configured && !cfZoneId) {
          // Keep cfZoneId empty when already configured; placeholder indicates masked vault status
        }

        if (res.status.active_rules) {
          const activeKeys = Object.keys(res.status.active_rules);
          if (activeKeys.length > 0) {
            setCfSelectedRules(prev => ({
              ...prev,
              ...Object.fromEntries(activeKeys.map(k => [k, true]))
            }));
          }
        }
        if (res.compound_rules) {
          setCompoundRules(res.compound_rules);
        } else if (res.status.compound_rules) {
          setCompoundRules(res.status.compound_rules);
        }
      }
    } catch (err) {
      console.error('Failed to load Cloudflare status', err);
    } finally {
      setLoadingCf(false);
    }
  };

  const handleCopyExpression = (ruleId: string, expr: string) => {
    if (navigator?.clipboard?.writeText) {
      navigator.clipboard.writeText(expr);
    }
    setCopiedRuleId(ruleId);
    setTimeout(() => setCopiedRuleId(null), 2500);
  };

  const handleVerifyCloudflare = async () => {
    try {
      setCfVerifying(true);
      setCfVerifyResult(null);
      const res = await apiRequest({
        path: '/cloudflare/verify',
        method: 'POST',
        data: {
          token: cfToken.trim() || undefined,
          zone_id: cfZoneId.trim() || undefined,
        }
      });
      setCfVerifyResult(res);
      if (res && res.success) {
        const resolvedZoneId = (res.zone_id || cfZoneId).trim();
        if (resolvedZoneId) {
          setCfZoneId(resolvedZoneId);
        }
        // Save to WordPress settings
        await apiRequest({
          path: '/settings',
          method: 'POST',
          data: {
            cloudflare_enabled: true,
            cloudflare_api_token: cfToken.trim() || undefined,
            cloudflare_zone_id: resolvedZoneId,
            cloudflare_auto_sync_bans: cfAutoSyncBans,
          }
        });
        loadCloudflareData();
      }
    } catch (err: any) {
      setCfVerifyResult({
        success: false,
        message: err?.message || 'Verification request failed'
      });
    } finally {
      setCfVerifying(false);
    }
  };

  const [disconnectingCf, setDisconnectingCf] = useState<boolean>(false);
  const handleDisconnectCloudflare = async () => {
    requestFirewallConfirm({
      title: 'Disconnect Cloudflare Integration',
      message: 'Are you sure you want to disconnect Cloudflare? This will completely remove your Cloudflare API Token and Zone ID from the website database.',
      confirmLabel: 'Disconnect Cloudflare',
      variant: 'danger',
      onConfirm: async () => {
        try {
          setDisconnectingCf(true);
          const res = await apiRequest({
            path: '/cloudflare/disconnect',
            method: 'POST'
          });
          if (res && res.success) {
            setCfToken('');
            setCfZoneId('');
            setCfStatus(null);
            setCfVerifyResult(null);
            setCfDeployMessage(null);
            loadCloudflareData();
            loadStatus(true);
            showFirewallNotice('success', 'Cloudflare integration successfully disconnected.');
          } else {
            showFirewallNotice('error', res?.message || 'Failed to disconnect Cloudflare.');
          }
        } catch (err: any) {
          showFirewallNotice('error', 'Error disconnecting: ' + (err?.message || 'Network error'));
        } finally {
          setDisconnectingCf(false);
        }
      },
    });
  };

  const handleDeployCloudflareRules = async () => {
    try {
      setCfDeploying(true);
      setCfDeployMessage(null);

      // Package customized rule payload
      const rulesPayload: { [key: string]: any } = {};
      Object.keys(cfSelectedRules).forEach((k) => {
        if (cfSelectedRules[k]) {
          const custom = cfRuleCustomizations[k] || {};
          const def = cfDefinitions[k] || {};
          rulesPayload[k] = {
            enabled: true,
            action: custom.action || def.action || 'block',
            expression: custom.expression !== undefined ? custom.expression : def.expression,
            bypass_ips: custom.bypass_ips || '',
          };
        }
      });

      const res = await apiRequest({
        path: '/cloudflare/deploy-rules',
        method: 'POST',
        data: { rules: rulesPayload }
      });
      if (res && res.success) {
        setCfDeployMessage({ type: 'success', text: res.message || 'Cloudflare Edge Rules deployed successfully!' });
        loadCloudflareData();
      } else {
        setCfDeployMessage({ type: 'error', text: res?.message || 'Failed to deploy rules to Cloudflare.' });
      }
    } catch (err: any) {
      setCfDeployMessage({ type: 'error', text: err?.message || 'Network error deploying rules.' });
    } finally {
      setCfDeploying(false);
    }
  };

  const handleDeploySingleRule = async (ruleKey: string, enable: boolean = true) => {
    try {
      setDeployingSingleRuleKey(ruleKey);
      setCfDeployMessage(null);
      const custom = cfRuleCustomizations[ruleKey] || {};
      const def = cfDefinitions[ruleKey] || {};
      const payload = {
        rule_key: ruleKey,
        enabled: enable,
        config: {
          action: custom.action || def.action || 'block',
          expression: custom.expression !== undefined ? custom.expression : def.expression,
          bypass_ips: custom.bypass_ips || '',
        }
      };

      const res = await apiRequest({
        path: '/cloudflare/deploy-single-rule',
        method: 'POST',
        data: payload
      });

      if (res && res.success) {
        setCfDeployMessage({ type: 'success', text: res.message || 'Rule successfully updated on Cloudflare Edge!' });
        loadCloudflareData();
      } else {
        setCfDeployMessage({ type: 'error', text: res?.message || 'Failed to update rule on Cloudflare Edge.' });
      }
    } catch (err: any) {
      setCfDeployMessage({ type: 'error', text: err?.message || 'Network error updating rule.' });
    } finally {
      setDeployingSingleRuleKey(null);
    }
  };

  const handleToggleRateLimiting = async (explicitState?: boolean) => {
    try {
      setCfRateLimitLoading(true);
      setCfRateLimitMessage(null);
      const nextState = explicitState !== undefined ? explicitState : !cfRateLimitEnabled;
      const res = await apiRequest({
        path: '/cloudflare/rate-limiting',
        method: 'POST',
        data: {
          enabled: nextState,
          options: {
            requests: rateLimitRequests,
            period: rateLimitPeriod,
            mitigation_timeout: rateLimitTimeout,
            action: rateLimitAction,
            path: rateLimitPath,
            bypass_ips: rateLimitBypassIps,
          }
        }
      });
      if (res && res.success) {
        setCfRateLimitEnabled(nextState);
        setCfRateLimitMessage({ type: 'success', text: res.message });
        loadCloudflareData();
      } else {
        setCfRateLimitMessage({ type: 'error', text: res?.message || 'Failed to update rate limiting.' });
      }
    } catch (err: any) {
      setCfRateLimitMessage({ type: 'error', text: err?.message || 'Failed to update rate limiting.' });
    } finally {
      setCfRateLimitLoading(false);
    }
  };

  const handlePurgeCloudflare = async () => {
    requestFirewallConfirm({
      title: 'Purge Cloudflare Edge CDN Cache',
      message: 'Are you sure you want to completely purge the Cloudflare Edge CDN cache for this website? Cached assets will be re-fetched directly from your origin server.',
      confirmLabel: 'Purge Entire Cache',
      variant: 'warning',
      onConfirm: async () => {
        try {
          setCfPurging(true);
          setCfPurgeMessage(null);
          const res = await apiRequest({ path: '/cloudflare/purge-cache', method: 'POST' });
          if (res && res.success) {
            setCfPurgeMessage(res.message || 'Cache purged successfully!');
            showFirewallNotice('success', res.message || 'Cloudflare Edge CDN cache purged successfully!');
            setTimeout(() => setCfPurgeMessage(null), 5000);
          } else {
            showFirewallNotice('error', res?.message || 'Failed to purge cache.');
          }
        } catch (err: any) {
          showFirewallNotice('error', 'Error purging cache: ' + (err?.message || 'Network error'));
        } finally {
          setCfPurging(false);
        }
      },
    });
  };

  const handleManualBlockIp = async () => {
    const ip = manualBlockIp.trim();
    if (!ip) return;

    if (ip.includes('/')) {
      const parts = ip.split('/');
      const prefix = parseInt(parts[1], 10);
      const isIpv6 = parts[0].includes(':');
      if (!isIpv6) {
        if (prefix !== 16 && prefix !== 24) {
          showFirewallNotice(
            'error',
            `Cloudflare IP Access Rules only allows IPv4 ranges of /16 or /24.\n\nSubnet ${ip} (/${prefix}) cannot be added to IP Access Rules. Please use Cloudflare WAF Custom Rules instead.`,
            'Cloudflare CIDR Limitation'
          );
          return;
        }
      } else {
        if (prefix !== 32 && prefix !== 48 && prefix !== 64) {
          showFirewallNotice(
            'error',
            `Cloudflare IP Access Rules only allows IPv6 ranges of /32, /48, or /64.\n\nSubnet ${ip} (/${prefix}) cannot be added to IP Access Rules. Please use Cloudflare WAF Custom Rules instead.`,
            'Cloudflare CIDR Limitation'
          );
          return;
        }
      }
    }

    try {
      setManualBlocking(true);
      const res = await apiRequest({
        path: '/cloudflare/sync-ip',
        method: 'POST',
        data: {
          ip,
          reason: manualBlockReason.trim() || 'Manual Edge Block via Security Scanner'
        }
      });
      if (res && res.success) {
        showFirewallNotice('success', res.message || `IP/Subnet ${ip} blocked at Cloudflare Edge.`);
        setManualBlockIp('');
        setManualBlockReason('');
        loadCloudflareData();
      } else {
        showFirewallNotice('error', res?.message || 'Failed to block IP at Cloudflare Edge.');
      }
    } catch (err: any) {
      showFirewallNotice('error', 'Error: ' + (err?.message || 'Network error'));
    } finally {
      setManualBlocking(false);
    }
  };

  const handleToggleAutoSyncBans = async () => {
    try {
      const next = !cfAutoSyncBans;
      setCfAutoSyncBans(next);
      await apiRequest({
        path: '/settings',
        method: 'POST',
        data: { cloudflare_auto_sync_bans: next }
      });
    } catch (err) {
      console.error(err);
    }
  };

  useEffect(() => {
    loadFirewallData();
    loadCloudflareData();
    loadBannedIps();
    fetchBlocklistData();
    fetchWhitelistData();
  }, []);

  useEffect(() => {
    if (activeTab === 'intel' && cves.length === 0) {
      loadCves();
    }
    if (activeTab === 'cloudflare') {
      loadCloudflareData();
    }
  }, [activeTab]);

  const handleToggleFirewall = async (enable: boolean) => {
    try {
      const res = await apiRequest({
        path: '/firewall/toggle',
        method: 'POST',
        data: { enabled: enable },
      });
      if (res && res.success) {
        setWafSettings(prev => ({
          ...prev,
          waf_enabled: enable,
          waf_mode: enable ? (prev.waf_mode === 'disabled' ? 'enabled' : prev.waf_mode) : 'disabled'
        }));
        setStatus(res.status);
        showFirewallNotice('success', `Firewall ${enable ? 'activated' : 'disabled'} successfully.`);
      }
    } catch (err: any) {
      showFirewallNotice('error', 'Failed to toggle firewall: ' + (err?.message || 'Error'));
    }
  };

  const handleClearLogs = async () => {
    requestFirewallConfirm({
      title: 'Clear Firewall Incident Logs',
      message: 'Are you sure you want to clear all firewall incident logs? All historical blocks and attack telemetry will be purged from the local database.',
      confirmLabel: 'Clear All Logs',
      variant: 'danger',
      onConfirm: async () => {
        try {
          const res = await apiRequest({ path: '/firewall/clear-logs', method: 'POST' });
          if (res && res.success) {
            setLogs([]);
            if (status) {
              setStatus({ ...status, total_blocks: 0, blocks_24h: 0, top_rules: [] });
            }
            showFirewallNotice('success', 'Firewall incident logs cleared successfully.');
          }
        } catch (err: any) {
          showFirewallNotice('error', 'Failed to clear logs: ' + (err?.message || 'Error'));
        }
      },
    });
  };

  const handleSaveRules = async () => {
    try {
      setSavingRules(true);
      setSaveSuccess(null);
      setSaveError(null);

      const currentRes = await apiRequest({ path: '/settings', method: 'GET' });
      const current = currentRes?.settings || {};

      const updated = {
        ...current,
        ...wafSettings,
      };

      const saveRes = await apiRequest({
        path: '/settings',
        method: 'POST',
        data: updated,
      });

      if (saveRes && saveRes.settings) {
        setSaveSuccess('Firewall configuration & rules saved successfully!');
        setTimeout(() => setSaveSuccess(null), 4000);
        loadFirewallData(true);
      } else {
        setSaveError('Failed to save firewall settings.');
      }
    } catch (err: any) {
      setSaveError(err?.message || 'Network error while saving rules.');
    } finally {
      setSavingRules(false);
    }
  };

  const handleSaveSingleRule = async (key: string, explicitValue?: any) => {
    try {
      setSavingSingleRuleKey(key);
      const valToSave = explicitValue !== undefined ? explicitValue : (wafSettings as any)[key];
      const res = await apiRequest({
        path: '/firewall/save-rule',
        method: 'POST',
        data: {
          key,
          value: valToSave
        }
      });

      if (res && res.success) {
        setSavedSingleRuleSuccess(prev => ({ ...prev, [key]: true }));
        showFirewallNotice('success', `Rule "${key}" updated successfully.`);
        setTimeout(() => {
          setSavedSingleRuleSuccess(prev => {
            const next = { ...prev };
            delete next[key];
            return next;
          });
        }, 3000);
      } else {
        showFirewallNotice('error', res?.message || `Failed to save rule "${key}".`);
      }
    } catch (err: any) {
      showFirewallNotice('error', `Error saving rule "${key}": ` + (err?.message || 'Network error'));
    } finally {
      setSavingSingleRuleKey(null);
    }
  };

  const handleWhitelistCurrentIp = async () => {
    const clientIp = status?.client_ip?.trim();
    if (!clientIp) {
      showFirewallNotice('warning', 'Unable to detect current IP address.');
      return;
    }

    try {
      setWhitelistingCurrentIp(true);
      const res = await apiRequest({
        path: '/firewall/logs/whitelist-ip',
        method: 'POST',
        data: {
          ip: clientIp,
          reason: 'Current Administrator IP (1-Click Whitelist)'
        }
      });

      if (res && res.success) {
        if (res.whitelisted_ips) {
          setWhitelistedIpsList(res.whitelisted_ips);
        } else {
          await fetchWhitelistData();
        }

        const currentWhitelisted = wafSettings.waf_whitelisted_ips || '';
        const lines = currentWhitelisted.split('\n').map(l => l.trim()).filter(Boolean);
        if (!lines.includes(clientIp)) {
          lines.push(clientIp);
          setWafSettings(prev => ({ ...prev, waf_whitelisted_ips: lines.join('\n') }));
        }

        showFirewallNotice('success', `Successfully whitelisted your IP (${clientIp})! It is now permanently allowed through all firewall rules.`);
      } else {
        showFirewallNotice('error', res?.message || 'Failed to whitelist IP.');
      }
    } catch (err: any) {
      showFirewallNotice('error', err?.message || 'Error whitelisting your IP address.');
    } finally {
      setWhitelistingCurrentIp(false);
    }
  };

  if (loading) {
    return (
      <div className="wcp-page-container" style={{ padding: '60px 20px', textAlign: 'center', color: '#64748b' }}>
        <Loader2 size={36} className="wcp-spin-icon" style={{ margin: '0 auto 16px auto', color: '#0284c7' }} />
        <h3 style={{ fontSize: '18px', color: '#1e293b', margin: 0 }}>Initializing WCP Firewall (WAF Lite)...</h3>
      </div>
    );
  }

  const parsedRateLimitPaths = rateLimitPath
    ? rateLimitPath.split(',').map(s => s.trim().replace(/^\/+/, '')).filter(Boolean)
    : ['wp-login.php'];
  const rateLimitPathDisplay = parsedRateLimitPaths.length > 2
    ? `${parsedRateLimitPaths.slice(0, 2).join(', ')} (+${parsedRateLimitPaths.length - 2} more)`
    : (parsedRateLimitPaths.join(', ') || 'wp-login.php');

  return (
    <div className="wcp-page-container" style={{ width: '100%', maxWidth: '100%', margin: '0' }}>
      {/* Floating In-Page Notification Banner */}
      {firewallNotice && (
        <div
          role="alert"
          style={{
            position: 'sticky',
            top: '32px',
            zIndex: 9999,
            marginBottom: '16px',
            padding: '12px 18px',
            borderRadius: '10px',
            boxShadow: '0 8px 24px -4px rgba(0, 0, 0, 0.15), 0 2px 6px -1px rgba(0, 0, 0, 0.1)',
            display: 'flex',
            alignItems: 'flex-start',
            justifyContent: 'space-between',
            gap: '12px',
            background:
              firewallNotice.type === 'error'
                ? '#fef2f2'
                : firewallNotice.type === 'success'
                ? '#ecfdf5'
                : firewallNotice.type === 'warning'
                ? '#fffbeb'
                : '#eff6ff',
            border: `1px solid ${
              firewallNotice.type === 'error'
                ? '#fca5a5'
                : firewallNotice.type === 'success'
                ? '#6ee7b7'
                : firewallNotice.type === 'warning'
                ? '#fde68a'
                : '#93c5fd'
            }`,
            color:
              firewallNotice.type === 'error'
                ? '#991b1b'
                : firewallNotice.type === 'success'
                ? '#065f46'
                : firewallNotice.type === 'warning'
                ? '#92400e'
                : '#1e40af',
            animation: 'wcpFadeSlideDown 0.25s ease-out'
          }}
        >
          <div style={{ display: 'flex', alignItems: 'flex-start', gap: '10px', flex: 1 }}>
            {firewallNotice.type === 'error' ? (
              <AlertTriangle size={18} style={{ flexShrink: 0, marginTop: '2px', color: '#dc2626' }} />
            ) : firewallNotice.type === 'success' ? (
              <CheckCircle2 size={18} style={{ flexShrink: 0, marginTop: '2px', color: '#16a34a' }} />
            ) : firewallNotice.type === 'warning' ? (
              <AlertCircle size={18} style={{ flexShrink: 0, marginTop: '2px', color: '#d97706' }} />
            ) : (
              <Info size={18} style={{ flexShrink: 0, marginTop: '2px', color: '#2563eb' }} />
            )}
            <div style={{ flex: 1, fontSize: '13px', lineHeight: 1.5 }}>
              {firewallNotice.title && (
                <div style={{ fontWeight: 700, fontSize: '13.5px', marginBottom: '2px' }}>
                  {firewallNotice.title}
                </div>
              )}
              <div style={{ wordBreak: 'break-word', whiteSpace: 'pre-line', fontWeight: 500 }}>
                {firewallNotice.text}
              </div>
            </div>
          </div>
          <button
            type="button"
            onClick={() => setFirewallNotice(null)}
            title="Dismiss notice"
            style={{
              background: 'none',
              border: 'none',
              cursor: 'pointer',
              color: 'inherit',
              padding: '2px',
              display: 'flex',
              alignItems: 'center',
              opacity: 0.75,
              transition: 'opacity 0.15s ease'
            }}
            onMouseEnter={(e) => (e.currentTarget.style.opacity = '1')}
            onMouseLeave={(e) => (e.currentTarget.style.opacity = '0.75')}
          >
            <X size={16} />
          </button>
        </div>
      )}

      {/* Top Hero Banner */}
      <div className="wcp-firewall-hero">
        <div style={{ display: 'flex', alignItems: 'center', gap: '14px' }}>
          <div className="wcp-firewall-hero-icon">
            <ShieldAlert size={26} />
          </div>
          <div>
            <h1 className="wcp-firewall-hero-title">
              Web Application Firewall (WAF Lite)
            </h1>
            <p className="wcp-firewall-hero-desc">
              Virtual patching, SQL injection defense, malicious payload inspection & Cloudflare/Wordfence coexistence.
            </p>
          </div>
        </div>

        <div style={{ display: 'flex', gap: '10px', alignItems: 'center', flexWrap: 'wrap' }}>
          {onNavigateToDashboard && (
            <button
              type="button"
              className="wcp-btn"
              onClick={onNavigateToDashboard}
            >
              ← Back to Scanner Dashboard
            </button>
          )}
          <button
            type="button"
            className="wcp-btn"
            style={{
              background: 'var(--wcp-bg-surface, #f1f5f9)',
              color: 'var(--wcp-text-primary, #0f172a)',
              border: '1px solid var(--wcp-border, #cbd5e1)',
              fontWeight: 600,
              fontSize: '13px',
              padding: '8px 14px',
              borderRadius: '8px',
              display: 'inline-flex',
              alignItems: 'center',
              gap: '6px',
              cursor: 'pointer'
            }}
            onClick={() => {
              if (onNavigateToServerTelemetry) {
                onNavigateToServerTelemetry();
              } else {
                window.location.href = 'admin.php?page=wcp-scanner-server';
              }
            }}
          >
            <Server size={15} />
            Server Telemetry &amp; Host Specs →
          </button>
          <button
            type="button"
            className="wcp-btn"
            style={{
              background: 'linear-gradient(135deg, #4f46e5 0%, #4338ca 100%)',
              color: '#ffffff',
              border: 'none',
              fontWeight: 600,
              fontSize: '13px',
              padding: '8px 16px',
              borderRadius: '8px',
              boxShadow: '0 2px 6px rgba(79, 70, 229, 0.25)',
              display: 'inline-flex',
              alignItems: 'center',
              gap: '6px'
            }}
            onClick={() => {
              if (onNavigateToWafLogs) {
                onNavigateToWafLogs();
              } else {
                window.location.href = 'admin.php?page=wcp-scanner-waf-logs';
              }
            }}
          >
            <FileText size={15} />
            WAF Incident Logs &amp; Forensics →
          </button>
          <button
            type="button"
            className="wcp-btn"
            onClick={() => loadFirewallData(true)}
            disabled={refreshing}
          >
            <RefreshCw size={14} className={refreshing ? 'wcp-spin-icon' : ''} />
            {refreshing ? 'Refreshing...' : 'Refresh Status'}
          </button>
        </div>
      </div>

      {/* Metrics Row */}
      <div className="wcp-firewall-kpi-grid">
        {/* Status Card */}
        {(() => {
          const isFirewallActive = wafSettings.waf_enabled && status?.enabled !== false && wafSettings.waf_mode !== 'disabled';
          const isLearning = isFirewallActive && (wafSettings.waf_mode === 'learning' || status?.active_mode === 'learning');
          const isComplementary = isFirewallActive && (status?.active_mode === 'complementary');

          let statusBadgeColor = '#ef4444';
          let statusText = 'Disabled';
          if (isFirewallActive) {
            if (isLearning) {
              statusBadgeColor = '#f59e0b';
              statusText = 'Learning Mode';
            } else if (isComplementary) {
              statusBadgeColor = '#10b981';
              statusText = 'Active & Shielding (Complementary)';
            } else {
              statusBadgeColor = '#10b981';
              statusText = 'Active & Shielding';
            }
          }

          return (
            <div className="wcp-firewall-kpi-card">
              <div className="wcp-firewall-kpi-label">
                <span>Firewall Status</span>
                <div style={{
                  width: '10px',
                  height: '10px',
                  borderRadius: '50%',
                  background: statusBadgeColor
                }} />
              </div>
              <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: '12px', marginTop: '4px' }}>
                <div className="wcp-firewall-kpi-val" style={{ display: 'flex', alignItems: 'center', gap: '8px', fontSize: '20px' }}>
                  {statusText}
                </div>
                {/* On / Off Toggle Switch Button (Green when ON, Red when OFF) */}
                <button
                  type="button"
                  onClick={() => handleToggleFirewall(!isFirewallActive)}
                  title={isFirewallActive ? 'Firewall is ON. Click to turn OFF.' : 'Firewall is OFF. Click to turn ON.'}
                  style={{
                    display: 'inline-flex',
                    alignItems: 'center',
                    gap: '6px',
                    padding: '4px 10px 4px 6px',
                    borderRadius: '999px',
                    border: isFirewallActive ? '1px solid rgba(16, 185, 129, 0.4)' : '1px solid rgba(239, 68, 68, 0.4)',
                    background: isFirewallActive ? 'rgba(16, 185, 129, 0.14)' : 'rgba(239, 68, 68, 0.14)',
                    cursor: 'pointer',
                    userSelect: 'none',
                    transition: 'all 0.2s ease',
                    color: isFirewallActive ? '#10b981' : '#ef4444',
                    fontWeight: 700,
                    fontSize: '11px',
                    textTransform: 'uppercase',
                    letterSpacing: '0.04em'
                  }}
                >
                  <div
                    style={{
                      width: '36px',
                      height: '20px',
                      borderRadius: '10px',
                      background: isFirewallActive ? '#10b981' : '#ef4444',
                      position: 'relative',
                      transition: 'background 0.2s ease',
                      boxShadow: isFirewallActive
                        ? '0 0 8px rgba(16, 185, 129, 0.4), inset 0 1px 2px rgba(0,0,0,0.1)'
                        : '0 0 8px rgba(239, 68, 68, 0.4), inset 0 1px 2px rgba(0,0,0,0.1)'
                    }}
                  >
                    <div
                      style={{
                        width: '16px',
                        height: '16px',
                        borderRadius: '50%',
                        background: '#ffffff',
                        position: 'absolute',
                        top: '2px',
                        left: isFirewallActive ? '18px' : '2px',
                        transition: 'left 0.2s cubic-bezier(0.16, 1, 0.3, 1)',
                        boxShadow: '0 1px 3px rgba(0,0,0,0.3)'
                      }}
                    />
                  </div>
                  <span>{isFirewallActive ? 'ON' : 'OFF'}</span>
                </button>
              </div>
            </div>
          );
        })()}

        {/* Total Blocks */}
        <div className="wcp-firewall-kpi-card">
          <div className="wcp-firewall-kpi-label">
            <span>Total Blocked Attacks</span>
          </div>
          <div className="wcp-firewall-kpi-val" style={{ color: '#dc2626' }}>
            {(() => {
              const fromStatus = status?.total_blocks ?? 0;
              const fromLogs = logs.filter(l => l.action_taken === 'blocked').length;
              return Math.max(fromStatus, fromLogs).toLocaleString();
            })()}
          </div>
          <span className="wcp-firewall-kpi-sub">Cumulative incidents prevented</span>
        </div>

        {/* 24h Blocks */}
        <div className="wcp-firewall-kpi-card">
          <div className="wcp-firewall-kpi-label">
            <span>Blocked in Past 24 Hours</span>
          </div>
          <div className="wcp-firewall-kpi-val" style={{ color: '#0284c7' }}>
            {(() => {
              const fromStatus = status?.blocks_24h ?? 0;
              const fromLogs = logs.filter(l => l.action_taken === 'blocked').length;
              return Math.max(fromStatus, fromLogs).toLocaleString();
            })()}
          </div>
          <span className="wcp-firewall-kpi-sub">Recent suspicious requests</span>
        </div>

        {/* Whitelist IP Quick Action */}
        <div className="wcp-firewall-kpi-card">
          <div className="wcp-firewall-kpi-label">
            <span>Your IP Safety</span>
          </div>
          <div className="wcp-firewall-kpi-val" style={{ fontSize: '15px', fontFamily: 'monospace' }}>
            {status?.client_ip || '127.0.0.1'}
          </div>
          <button
            type="button"
            className="wcp-btn"
            style={{ marginTop: '10px', fontSize: '12px', padding: '4px 10px', display: 'inline-flex', alignItems: 'center', gap: '6px' }}
            onClick={handleWhitelistCurrentIp}
            disabled={whitelistingCurrentIp}
          >
            {whitelistingCurrentIp ? (
              <>
                <Loader2 size={13} className="wcp-spin-icon" />
                <span>Whitelisting...</span>
              </>
            ) : (
              <span>+ Whitelist My Current IP</span>
            )}
          </button>
        </div>
      </div>

      {/* Navigation Sub-Tabs & Dropdown */}
      <div className="wcp-tabs-bar" style={{ alignItems: 'center', position: 'relative' }}>
        <button
          type="button"
          className={`wcp-tab-link ${activeTab === 'stream' ? 'is-active' : ''}`}
          onClick={() => { setIsMoreMenuOpen(false); handleSwitchTab('stream'); }}
        >
          <Activity size={16} /> Live Incident Stream ({logs.length})
        </button>

        <button
          type="button"
          className={`wcp-tab-link ${activeTab === 'rules' ? 'is-active' : ''}`}
          onClick={() => { setIsMoreMenuOpen(false); handleSwitchTab('rules'); }}
        >
          <Sliders size={16} /> Firewall Rules &amp; Controls
        </button>

        <button
          type="button"
          className={`wcp-tab-link ${activeTab === 'caf' ? 'is-active' : ''}`}
          onClick={() => { setIsMoreMenuOpen(false); handleSwitchTab('caf'); }}
        >
          <Sparkles size={16} color="#0284c7" />
          <span>Adaptive Firewall (CAF)</span>
          <span className="wcp-badge-pill wcp-badge-info" style={{ fontSize: '10px', padding: '1px 6px', marginLeft: '4px' }}>
            StackGuard
          </span>
        </button>

        <button
          type="button"
          className={`wcp-tab-link ${activeTab === 'cloudflare' ? 'is-active' : ''}`}
          onClick={() => { setIsMoreMenuOpen(false); handleSwitchTab('cloudflare'); }}
        >
          <Cloud
            size={16}
            style={{
              color: cfStatus?.configured ? '#F38020' : '#94a3b8',
              strokeWidth: 2.5
            }}
          />
          <span>Cloudflare Edge Defense</span>
          {cfStatus?.configured && (
            <span style={{ color: '#10b981', fontSize: '11px', fontWeight: 700, marginLeft: '2px' }}>
              ● Connected
            </span>
          )}
        </button>

        <button
          type="button"
          className={`wcp-tab-link ${activeTab === 'behavioral' ? 'is-active' : ''}`}
          onClick={() => { setIsMoreMenuOpen(false); handleSwitchTab('behavioral'); }}
        >
          <Sliders size={16} /> Behavioral WAF &amp; Bot Traps
        </button>

        <button
          type="button"
          className={`wcp-tab-link ${activeTab === 'ai_defense' ? 'is-active' : ''}`}
          onClick={() => { setIsMoreMenuOpen(false); handleSwitchTab('ai_defense'); }}
        >
          <Sparkles size={16} /> 2026 AI Defense &amp; Decoy Traps
        </button>

        {/* More Security Tools Dropdown */}
        <div ref={moreMenuRef} style={{ position: 'relative', display: 'inline-block' }}>
          <button
            type="button"
            className={`wcp-tab-link ${['drill', 'supply_chain', 'server_sec', 'intel', 'vpatch'].includes(activeTab) ? 'is-active' : ''}`}
            onClick={() => setIsMoreMenuOpen(!isMoreMenuOpen)}
            style={{ display: 'inline-flex', alignItems: 'center', gap: '6px' }}
            aria-expanded={isMoreMenuOpen}
          >
            <Layers size={16} />
            <span>
              {activeTab === 'drill' && 'Red Team Attack Drill'}
              {activeTab === 'supply_chain' && 'Supply-Chain & SBOM'}
              {activeTab === 'server_sec' && 'Server Security'}
              {activeTab === 'intel' && 'Cloud Threat Intel'}
              {activeTab === 'vpatch' && 'Virtual Patching'}
              {!['drill', 'supply_chain', 'server_sec', 'intel', 'vpatch'].includes(activeTab) && 'Advanced Modules'}
            </span>
            <ChevronDown size={14} style={{ transform: isMoreMenuOpen ? 'rotate(180deg)' : 'none', transition: 'transform 0.2s ease' }} />
          </button>

          {isMoreMenuOpen && (
            <div
              className="wcp-dropdown-menu"
              style={{
                position: 'absolute',
                top: 'calc(100% + 4px)',
                left: 0,
                zIndex: 100,
                minWidth: '240px',
                background: 'var(--wcp-bg-panel, #ffffff)',
                border: '1px solid var(--wcp-border, #e2e8f0)',
                borderRadius: '8px',
                boxShadow: '0 10px 25px -5px rgba(0, 0, 0, 0.1), 0 8px 10px -6px rgba(0, 0, 0, 0.1)',
                padding: '6px 0',
                display: 'flex',
                flexDirection: 'column'
              }}
            >
              <button
                type="button"
                onClick={() => { setIsMoreMenuOpen(false); handleSwitchTab('drill'); }}
                style={{
                  display: 'flex',
                  alignItems: 'center',
                  gap: '10px',
                  padding: '9px 14px',
                  background: activeTab === 'drill' ? 'rgba(79, 70, 229, 0.08)' : 'transparent',
                  color: activeTab === 'drill' ? '#4f46e5' : 'inherit',
                  fontWeight: activeTab === 'drill' ? 600 : 500,
                  border: 'none',
                  textAlign: 'left',
                  cursor: 'pointer',
                  width: '100%',
                  fontSize: '13px'
                }}
              >
                <Target size={15} color="#dc2626" />
                <span>Red Team Attack Drill</span>
              </button>

              <button
                type="button"
                onClick={() => { setIsMoreMenuOpen(false); handleSwitchTab('supply_chain'); }}
                style={{
                  display: 'flex',
                  alignItems: 'center',
                  gap: '10px',
                  padding: '9px 14px',
                  background: activeTab === 'supply_chain' ? 'rgba(79, 70, 229, 0.08)' : 'transparent',
                  color: activeTab === 'supply_chain' ? '#4f46e5' : 'inherit',
                  fontWeight: activeTab === 'supply_chain' ? 600 : 500,
                  border: 'none',
                  textAlign: 'left',
                  cursor: 'pointer',
                  width: '100%',
                  fontSize: '13px'
                }}
              >
                <Layers size={15} color="#7c3aed" />
                <span>Supply-Chain &amp; SBOM</span>
              </button>

              <button
                type="button"
                onClick={() => { setIsMoreMenuOpen(false); handleSwitchTab('server_sec'); }}
                style={{
                  display: 'flex',
                  alignItems: 'center',
                  gap: '10px',
                  padding: '9px 14px',
                  background: activeTab === 'server_sec' ? 'rgba(79, 70, 229, 0.08)' : 'transparent',
                  color: activeTab === 'server_sec' ? '#4f46e5' : 'inherit',
                  fontWeight: activeTab === 'server_sec' ? 600 : 500,
                  border: 'none',
                  textAlign: 'left',
                  cursor: 'pointer',
                  width: '100%',
                  fontSize: '13px'
                }}
              >
                <Server size={15} color="#0284c7" />
                <span>Server Security (Nginx / Apache)</span>
              </button>

              <button
                type="button"
                onClick={() => { setIsMoreMenuOpen(false); handleSwitchTab('intel'); }}
                style={{
                  display: 'flex',
                  alignItems: 'center',
                  gap: '10px',
                  padding: '9px 14px',
                  background: activeTab === 'intel' ? 'rgba(79, 70, 229, 0.08)' : 'transparent',
                  color: activeTab === 'intel' ? '#4f46e5' : 'inherit',
                  fontWeight: activeTab === 'intel' ? 600 : 500,
                  border: 'none',
                  textAlign: 'left',
                  cursor: 'pointer',
                  width: '100%',
                  fontSize: '13px'
                }}
              >
                <Globe size={15} color="#059669" />
                <span>Cloud Threat Intel &amp; Feeds</span>
              </button>

              <button
                type="button"
                onClick={() => { setIsMoreMenuOpen(false); handleSwitchTab('vpatch'); }}
                style={{
                  display: 'flex',
                  alignItems: 'center',
                  gap: '10px',
                  padding: '9px 14px',
                  background: activeTab === 'vpatch' ? 'rgba(79, 70, 229, 0.08)' : 'transparent',
                  color: activeTab === 'vpatch' ? '#4f46e5' : 'inherit',
                  fontWeight: activeTab === 'vpatch' ? 600 : 500,
                  border: 'none',
                  textAlign: 'left',
                  cursor: 'pointer',
                  width: '100%',
                  fontSize: '13px'
                }}
              >
                <ShieldAlert size={15} color="#ea580c" />
                <span>Virtual Patching &amp; 0-Day Shield</span>
              </button>
            </div>
          )}
        </div>

        <button
          type="button"
          className="wcp-tab-link"
          style={{ marginLeft: 'auto', color: 'var(--wcp-status-info, #4f46e5)', fontWeight: 600 }}
          onClick={() => {
            if (onNavigateToWafLogs) {
              onNavigateToWafLogs();
            } else {
              window.location.href = 'admin.php?page=wcp-scanner-waf-logs';
            }
          }}
          title="Open Dedicated Full-Page WAF Incident Logs & Attack Forensics"
        >
          <FileText size={16} /> WAF Incident Logs &amp; Forensics →
        </button>
      </div>

      {/* TAB 1: Live Incident Stream */}
      {activeTab === 'stream' && (
        <>
          <CustomerLockoutCard apiRequest={apiRequest} />
          <div className="wcp-firewall-card">
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '16px', flexWrap: 'wrap', gap: '12px' }}>
            <div>
              <h3 className="wcp-firewall-section-title">Recent Blocked Threats & Security Logs</h3>
              <p className="wcp-firewall-section-desc">
                Real-time log of malicious HTTP probes intercepted before reaching WordPress core.
              </p>
            </div>

            <div style={{ display: 'flex', alignItems: 'center', gap: '8px', flexWrap: 'wrap' }}>
              <button
                type="button"
                className="wcp-btn"
                style={{
                  background: 'var(--wcp-accent-primary, #4f46e5)',
                  color: '#ffffff',
                  border: 'none',
                  fontSize: '13px',
                  fontWeight: 600,
                  display: 'inline-flex',
                  alignItems: 'center',
                  gap: '6px',
                  padding: '7px 14px',
                  borderRadius: '6px',
                  cursor: 'pointer'
                }}
                onClick={() => {
                  if (onNavigateToWafLogs) {
                    onNavigateToWafLogs();
                  } else {
                    window.location.href = 'admin.php?page=wcp-scanner-waf-logs';
                  }
                }}
              >
                <FileText size={14} /> View Dedicated WAF Incident Logs &amp; Forensics →
              </button>

              {logs.length > 0 && (
                <button
                  type="button"
                  className="wcp-btn"
                  style={{ background: '#fef2f2', color: '#dc2626', border: '1px solid #fecaca', fontSize: '13px' }}
                  onClick={handleClearLogs}
                >
                  <Trash2 size={14} /> Clear Incident Logs
                </button>
              )}
            </div>
          </div>

          {logs.length === 0 ? (
            <div className="wcp-empty-state-clean" style={{ margin: 0 }}>
              <div className="wcp-empty-state-icon-wrap">
                <ShieldCheck size={34} />
              </div>
              <h4 className="wcp-empty-state-title">Perimeter Secure · Zero Blocked Incidents</h4>
              <p className="wcp-empty-state-desc">Your real-time WAF rules and edge botnet shields are armed and monitoring incoming web traffic.</p>
            </div>
          ) : (
            <div style={{ overflowX: 'auto' }}>
              <table className="wcp-table" style={{ width: '100%', borderCollapse: 'collapse', fontSize: '13px' }}>
                <thead>
                  <tr style={{ textAlign: 'left' }}>
                    <th style={{ padding: '10px 12px' }}>Timestamp</th>
                    <th style={{ padding: '10px 12px' }}>IP Address</th>
                    <th style={{ padding: '10px 12px' }}>Category</th>
                    <th style={{ padding: '10px 12px' }}>Target Endpoint</th>
                    <th style={{ padding: '10px 12px' }}>Action</th>
                  </tr>
                </thead>
                <tbody>
                  {logs.map((log) => (
                    <tr key={log.id}>
                      <td style={{ padding: '10px 12px', whiteSpace: 'nowrap' }} title={formatTelemetryDateFull(log.created_at_gmt ? (log.created_at_gmt.endsWith('Z') ? log.created_at_gmt : `${log.created_at_gmt}Z`) : (log.timestamp ? new Date(log.timestamp * 1000) : log.created_at)) || log.created_at}>
                        <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
                          <span style={{ fontWeight: 600, color: 'var(--wcp-text-primary, #0f172a)' }}>
                            {formatRelativeTime(log.created_at_gmt ? (log.created_at_gmt.endsWith('Z') ? log.created_at_gmt : `${log.created_at_gmt}Z`) : (log.timestamp ? new Date(log.timestamp * 1000) : log.created_at))}
                          </span>
                          <span style={{ fontSize: '11px', opacity: 0.75 }}>({log.created_at})</span>
                        </div>
                      </td>
                      <td style={{ padding: '10px 12px', fontWeight: 600 }}>
                        <code style={{ padding: '2px 6px', borderRadius: '4px' }}>{log.ip_address}</code>
                      </td>
                      <td style={{ padding: '10px 12px' }}>
                        <span style={{
                          background: '#fee2e2',
                          color: '#991b1b',
                          padding: '2px 8px',
                          borderRadius: '4px',
                          fontSize: '11px',
                          fontWeight: 600
                        }}>
                          {log.rule_category}
                        </span>
                      </td>
                      <td style={{ padding: '10px 12px', maxWidth: '300px', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                        <code style={{ fontSize: '12px', padding: '2px 6px', borderRadius: '4px' }}>{log.request_method} {log.request_uri}</code>
                      </td>
                      <td style={{ padding: '10px 12px' }}>
                        <span style={{
                          background: log.action_taken === 'blocked' ? '#fef2f2' : '#fef3c7',
                          color: log.action_taken === 'blocked' ? '#dc2626' : '#d97706',
                          padding: '2px 8px',
                          borderRadius: '4px',
                          fontSize: '11px',
                          fontWeight: 700,
                          textTransform: 'uppercase'
                        }}>
                          {log.action_taken}
                        </span>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>
        </>
      )}

      {/* TAB 2: Rules & Configuration */}
      {activeTab === 'rules' && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: '24px' }}>
          {/* Site Archetype Intelligence & Adaptive Firewall Advisor */}
          <SiteAdvisorCard
            apiRequest={apiRequest}
            onSettingsUpdated={() => {
              loadFirewallData(true);
            }}
          />

          <div style={{ display: 'grid', gridTemplateColumns: 'minmax(0, 1.45fr) minmax(420px, 1.55fr)', gap: '24px', alignItems: 'start' }}>
          {/* Main Inspection Rules (Left Column) */}
          <div className="wcp-firewall-card" style={{ padding: '24px', minWidth: 0 }}>
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', flexWrap: 'wrap', gap: '12px', marginBottom: '20px', paddingBottom: '16px', borderBottom: '1px solid var(--wcp-border, #e2e8f0)' }}>
              <div>
                <h3 className="wcp-firewall-section-title" style={{ fontSize: '18px', display: 'flex', alignItems: 'center', gap: '8px', margin: 0 }}>
                  <Sliders size={20} color="#0284c7" /> Protection Rules & Security Modes
                </h3>
                <p className="wcp-firewall-section-desc" style={{ marginTop: '4px', fontSize: '12px', margin: 0 }}>
                  Granular control over WCP Web Application Firewall inspection engines, brute force filters, and runtime virtual shielding.
                </p>
              </div>

              <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
                <button
                  type="button"
                  className="wcp-btn wcp-btn-primary"
                  style={{ background: '#0284c7', color: '#fff', fontSize: '12px', padding: '8px 16px', borderRadius: '6px' }}
                  onClick={handleSaveRules}
                  disabled={savingRules}
                  title="Save all firewall rules at once"
                >
                  {savingRules ? <Loader2 size={14} className="wcp-spin-icon" /> : <Check size={14} />}
                  {savingRules ? 'Saving All...' : 'Save All Rules'}
                </button>
              </div>
            </div>

            {saveSuccess && (
              <div style={{ padding: '10px 14px', background: '#ecfdf5', color: '#065f46', border: '1px solid #a7f3d0', borderRadius: '8px', marginBottom: '20px', fontSize: '13px', display: 'flex', alignItems: 'center', gap: '8px' }}>
                <CheckCircle2 size={16} /> {saveSuccess}
              </div>
            )}

            {saveError && (
              <div style={{ padding: '10px 14px', background: '#fef2f2', color: '#991b1b', border: '1px solid #fecaca', borderRadius: '8px', marginBottom: '20px', fontSize: '13px', display: 'flex', alignItems: 'center', gap: '8px' }}>
                <AlertTriangle size={16} /> {saveError}
              </div>
            )}

            <div style={{ display: 'flex', flexDirection: 'column', gap: '20px' }}>
              {/* Firewall Mode & Operating Profile */}
              <div className="wcp-firewall-section-group">
                <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: '12px', flexWrap: 'wrap', marginBottom: '8px' }}>
                  <label style={{ fontSize: '14px', fontWeight: 700, color: 'var(--wcp-text-primary, #0f172a)' }}>
                    Firewall Operating Mode
                  </label>
                  <button
                    type="button"
                    className={`wcp-btn wcp-firewall-rule-save-btn ${savedSingleRuleSuccess['waf_mode'] ? 'is-saved' : ''}`}
                    onClick={() => handleSaveSingleRule('waf_mode', wafSettings.waf_mode)}
                    disabled={savingSingleRuleKey === 'waf_mode'}
                  >
                    {savingSingleRuleKey === 'waf_mode' ? <Loader2 size={11} className="wcp-spin-icon" /> : (savedSingleRuleSuccess['waf_mode'] ? <Check size={11} /> : <Save size={11} />)}
                    {savedSingleRuleSuccess['waf_mode'] ? 'Saved' : 'Save Mode'}
                  </button>
                </div>
                <select
                  value={wafSettings.waf_mode}
                  onChange={(e: any) => setWafSettings({ ...wafSettings, waf_mode: e.target.value })}
                  className="wcp-firewall-select"
                  style={{ width: '100%', padding: '9px 12px', fontSize: '13px' }}
                >
                  <option value="enabled">Enabled & Actively Blocking (Recommended - Drops malicious payloads with 403)</option>
                  <option value="learning">Learning Mode (Audit & Log Only - Zero blocks, safe monitoring)</option>
                  <option value="disabled">Disabled (Bypass all inspection)</option>
                </select>
                <div style={{ fontSize: '12px', color: 'var(--wcp-text-muted, #64748b)', marginTop: '6px' }}>
                  In <strong>Learning Mode</strong>, suspicious exploits and bots are fully logged into forensic logs without dropping traffic, allowing safe baselining.
                </div>

                {/* Coexistence / Complementary Checkbox */}
                <div style={{ marginTop: '14px', paddingTop: '12px', borderTop: '1px solid var(--wcp-border, #e2e8f0)', display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: '12px' }}>
                  <label style={{ display: 'flex', alignItems: 'flex-start', gap: '10px', fontSize: '13px', cursor: 'pointer', flex: 1 }}>
                    <input
                      type="checkbox"
                      checked={wafSettings.waf_complementary_mode}
                      onChange={(e) => setWafSettings({ ...wafSettings, waf_complementary_mode: e.target.checked })}
                      style={{ accentColor: '#0284c7', marginTop: '3px' }}
                    />
                    <div>
                      <strong style={{ color: 'var(--wcp-text-primary, #0f172a)' }}>Auto-Negotiate with External Firewalls (Wordfence / Cloudflare)</strong>
                      <div style={{ fontSize: '12px', color: 'var(--wcp-text-muted, #64748b)', marginTop: '2px' }}>
                        Automatically switches WCP into complementary virtual patching mode when Wordfence or Sucuri is active to prevent hook collisions.
                      </div>
                    </div>
                  </label>
                  <button
                    type="button"
                    className={`wcp-btn wcp-firewall-rule-save-btn ${savedSingleRuleSuccess['waf_complementary_mode'] ? 'is-saved' : ''}`}
                    onClick={() => handleSaveSingleRule('waf_complementary_mode', wafSettings.waf_complementary_mode)}
                    disabled={savingSingleRuleKey === 'waf_complementary_mode'}
                  >
                    {savingSingleRuleKey === 'waf_complementary_mode' ? <Loader2 size={11} className="wcp-spin-icon" /> : (savedSingleRuleSuccess['waf_complementary_mode'] ? <Check size={11} /> : <Save size={11} />)}
                    {savedSingleRuleSuccess['waf_complementary_mode'] ? 'Saved' : 'Save'}
                  </button>
                </div>
              </div>

              {/* SECTION: Smart Shields & Verified Integrations (Zero False-Positive Protection) */}
              <div className="wcp-firewall-section-group">
                <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '12px' }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                    <strong style={{ fontSize: '13px', textTransform: 'uppercase', letterSpacing: '0.04em', color: '#059669', display: 'flex', alignItems: 'center', gap: '6px' }}>
                      <Sparkles size={14} /> Smart Shields & Verified Integrations (False-Positive Prevention)
                    </strong>
                  </div>
                  <span style={{ fontSize: '11px', color: 'var(--wcp-text-muted, #64748b)' }}>
                    Intelligent Bypasses & Cryptographic Authentication
                  </span>
                </div>

                <div style={{ display: 'flex', flexDirection: 'column', gap: '10px' }}>
                  {/* Smart Rule 1: E-Commerce, Membership & Cart Smart Shield */}
                  <div className="wcp-firewall-rule-card" style={{
                    display: 'flex',
                    flexDirection: 'column',
                    gap: '12px',
                    padding: '12px 16px',
                    background: 'var(--wcp-bg-panel, #ffffff)',
                    border: '1px solid var(--wcp-border, #e2e8f0)',
                    borderRadius: '8px'
                  }}>
                    <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: '12px' }}>
                      <label style={{ display: 'flex', alignItems: 'flex-start', gap: '10px', cursor: 'pointer', flex: 1, margin: 0 }}>
                        <input
                          type="checkbox"
                          checked={wafSettings.waf_ecommerce_safe_mode}
                          onChange={(e) => setWafSettings({ ...wafSettings, waf_ecommerce_safe_mode: e.target.checked })}
                          style={{ accentColor: '#10b981', marginTop: '3px' }}
                        />
                        <div>
                          <div style={{ display: 'flex', alignItems: 'center', gap: '8px', flexWrap: 'wrap' }}>
                            <span style={{
                              fontSize: '10px',
                              fontWeight: 700,
                              color: '#059669',
                              background: 'rgba(5, 150, 105, 0.1)',
                              border: '1px solid rgba(5, 150, 105, 0.25)',
                              padding: '1px 5px',
                              borderRadius: '4px'
                            }}>
                              COMMERCE
                            </span>
                            <strong style={{ fontSize: '13px', color: 'var(--wcp-text-primary, #0f172a)' }}>
                              E-Commerce, Membership &amp; Payment Webhook Shield
                            </strong>
                            {status?.commerce_telemetry?.is_active ? (
                              <span className="wcp-smart-shield-pill-detected-emerald">
                                Detected: {status?.commerce_telemetry?.detected_names?.slice(0, 3).join(', ') || 'Active Store/Membership'}
                                {(status?.commerce_telemetry?.detected_names?.length || 0) > 3 ? ` +${(status?.commerce_telemetry?.detected_names?.length || 0) - 3} more` : ''}
                              </span>
                            ) : (
                              <span className="wcp-smart-shield-pill-empty">
                                No Store / Membership Detected
                              </span>
                            )}
                          </div>
                          <div style={{ fontSize: '11px', color: 'var(--wcp-text-muted, #64748b)', marginTop: '3px', lineHeight: 1.45 }}>
                            Safeguards customer shopping carts, checkout forms, customer address fields, and server-to-server payment gateway webhooks across WooCommerce, EDD, SureCart, MemberPress, PMPro, User Registration suites, and payment processors (Stripe, PayPal, Square, Mollie, Klarna, Razorpay, Authorize.Net) via official CIDRs and cryptographic signature validation (<code style={{ color: '#059669', fontSize: '10px' }}>Stripe-Signature</code>, <code style={{ color: '#059669', fontSize: '10px' }}>PayPal-Transmission-Sig</code>).
                          </div>
                        </div>
                      </label>

                      <button
                        type="button"
                        className={`wcp-btn wcp-firewall-rule-save-btn ${savedSingleRuleSuccess['waf_ecommerce_safe_mode'] ? 'is-saved' : ''}`}
                        onClick={() => handleSaveSingleRule('waf_ecommerce_safe_mode', wafSettings.waf_ecommerce_safe_mode)}
                        disabled={savingSingleRuleKey === 'waf_ecommerce_safe_mode'}
                        title="Save setting for E-Commerce Smart Shield"
                      >
                        {savingSingleRuleKey === 'waf_ecommerce_safe_mode' ? <Loader2 size={11} className="wcp-spin-icon" /> : (savedSingleRuleSuccess['waf_ecommerce_safe_mode'] ? <Check size={11} /> : <Save size={11} />)}
                        {savedSingleRuleSuccess['waf_ecommerce_safe_mode'] ? 'Saved' : 'Save'}
                      </button>
                    </div>

                    {/* Recommendation Notice: Store detected but shield is currently OFF */}
                    {status?.commerce_telemetry?.is_active && !wafSettings.waf_ecommerce_safe_mode && (
                      <div className="wcp-smart-shield-rec-banner-emerald">
                        <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
                          <Sparkles size={13} style={{ color: '#059669', flexShrink: 0 }} />
                          <span>
                            <strong>Recommended:</strong> {status?.commerce_telemetry?.detected_names?.join(', ') || 'Active commerce / membership plugin'} detected. Enable this shield to prevent legitimate customer checkouts and Stripe/PayPal webhooks from being blocked.
                          </span>
                        </div>
                        <button
                          type="button"
                          className="wcp-btn wcp-action-btn-clean"
                          style={{ fontSize: '11px', padding: '3px 8px', whiteSpace: 'nowrap' }}
                          onClick={() => {
                            setWafSettings({ ...wafSettings, waf_ecommerce_safe_mode: true });
                            handleSaveSingleRule('waf_ecommerce_safe_mode', true);
                          }}
                        >
                          Enable Shield
                        </button>
                      </div>
                    )}

                    {/* Nested WooCommerce Security Modules Hub (Revealed when WooCommerce / Store is active) */}
                    {status?.commerce_telemetry?.is_active && (
                      <div style={{
                        marginTop: '6px',
                        padding: '12px 14px',
                        background: 'var(--wcp-bg-surface, #f8fafc)',
                        border: '1px solid var(--wcp-border, #e2e8f0)',
                        borderRadius: '8px',
                        display: 'flex',
                        flexDirection: 'column',
                        gap: '10px'
                      }}>
                        {/* Drawer Header */}
                        <div style={{
                          display: 'flex',
                          alignItems: 'center',
                          justifyContent: 'space-between',
                          flexWrap: 'wrap',
                          gap: '10px',
                          cursor: 'pointer',
                          paddingBottom: wooRulesExpanded ? '10px' : '0',
                          borderBottom: wooRulesExpanded ? '1px solid var(--wcp-border, #e2e8f0)' : 'none'
                        }}
                        onClick={() => setWooRulesExpanded(!wooRulesExpanded)}
                        >
                          <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                            <ShoppingBag size={15} style={{ color: '#059669' }} />
                            <div>
                              <strong style={{ fontSize: '12px', color: 'var(--wcp-text-primary, #0f172a)' }}>
                                WooCommerce Security &amp; Anti-Fraud Smart Rules
                              </strong>
                              <span style={{ fontSize: '11px', color: 'var(--wcp-text-muted, #64748b)', marginLeft: '8px' }}>
                                (Rules #38 – #42)
                              </span>
                            </div>
                          </div>

                          <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                            <span className="wcp-badge-pill wcp-badge-pill-emerald" style={{ fontSize: '10px', padding: '1px 8px' }}>
                              {[
                                wafSettings.waf_woo_carding_protection,
                                wafSettings.waf_woo_coupon_protection,
                                wafSettings.waf_woo_registration_protection,
                                wafSettings.waf_woo_cart_flood_protection,
                                wafSettings.waf_woo_scraping_protection
                              ].filter(Boolean).length}/5 Rules Active
                            </span>
                            <button
                              type="button"
                              style={{
                                background: 'transparent',
                                border: 'none',
                                cursor: 'pointer',
                                padding: '2px 4px',
                                display: 'flex',
                                alignItems: 'center',
                                color: 'var(--wcp-text-muted, #64748b)'
                              }}
                              onClick={(e) => {
                                e.stopPropagation();
                                setWooRulesExpanded(!wooRulesExpanded);
                              }}
                              title={wooRulesExpanded ? 'Collapse WooCommerce Rules' : 'Expand WooCommerce Rules'}
                            >
                              {wooRulesExpanded ? <ChevronUp size={15} /> : <ChevronDown size={15} />}
                            </button>
                          </div>
                        </div>

                        {/* Collapsible Sub-Rules Content */}
                        {wooRulesExpanded && (
                          <div style={{ display: 'flex', flexDirection: 'column', gap: '10px', marginTop: '4px' }}>
                            {/* Sub-Rule #38: Checkout Velocity & Carding Attack Shield */}
                            <div className="wcp-firewall-rule-card" style={{
                              display: 'flex',
                              flexDirection: 'column',
                              gap: '10px',
                              padding: '10px 14px',
                              background: 'var(--wcp-bg-panel, #ffffff)',
                              border: '1px solid var(--wcp-border, #e2e8f0)',
                              borderRadius: '6px'
                            }}>
                              <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: '12px' }}>
                                <label style={{ display: 'flex', alignItems: 'flex-start', gap: '10px', cursor: 'pointer', flex: 1, margin: 0 }}>
                                  <input
                                    type="checkbox"
                                    checked={wafSettings.waf_woo_carding_protection}
                                    onChange={(e) => setWafSettings({ ...wafSettings, waf_woo_carding_protection: e.target.checked })}
                                    style={{ accentColor: '#10b981', marginTop: '3px' }}
                                  />
                                  <div>
                                    <div style={{ display: 'flex', alignItems: 'center', gap: '8px', flexWrap: 'wrap' }}>
                                      <span style={{
                                        fontSize: '10px',
                                        fontWeight: 700,
                                        color: '#059669',
                                        background: 'rgba(5, 150, 105, 0.1)',
                                        border: '1px solid rgba(5, 150, 105, 0.25)',
                                        padding: '1px 5px',
                                        borderRadius: '4px'
                                      }}>
                                        RULE #38
                                      </span>
                                      <strong style={{ fontSize: '13px', color: 'var(--wcp-text-primary, #0f172a)' }}>
                                        Checkout Velocity &amp; Carding Attack Shield
                                      </strong>
                                      <span className="wcp-badge-pill wcp-badge-pill-emerald" style={{ fontSize: '10px', padding: '1px 6px' }}>
                                        Anti-Fraud
                                      </span>
                                    </div>
                                    <div style={{ fontSize: '11px', color: 'var(--wcp-text-muted, #64748b)', marginTop: '3px', lineHeight: 1.45 }}>
                                      Mitigates automated credit card testing bots (carding fraud) on Classic Checkout and modern Store API blocks. Tracks rapid payment/validation failures in rolling 5-minute windows and locks out malicious IPs from placing further checkout requests while preserving normal browsing access.
                                    </div>
                                  </div>
                                </label>

                                <button
                                  type="button"
                                  className={`wcp-btn wcp-firewall-rule-save-btn ${savedSingleRuleSuccess['waf_woo_carding_protection'] ? 'is-saved' : ''}`}
                                  onClick={() => {
                                    handleSaveSingleRule('waf_woo_carding_protection', wafSettings.waf_woo_carding_protection);
                                    handleSaveSingleRule('waf_woo_checkout_max_attempts', wafSettings.waf_woo_checkout_max_attempts);
                                    handleSaveSingleRule('waf_woo_carding_lockout_duration', wafSettings.waf_woo_carding_lockout_duration);
                                  }}
                                  disabled={savingSingleRuleKey === 'waf_woo_carding_protection'}
                                  title="Save setting for WooCommerce Carding Shield"
                                >
                                  {savingSingleRuleKey === 'waf_woo_carding_protection' ? <Loader2 size={11} className="wcp-spin-icon" /> : (savedSingleRuleSuccess['waf_woo_carding_protection'] ? <Check size={11} /> : <Save size={11} />)}
                                  {savedSingleRuleSuccess['waf_woo_carding_protection'] ? 'Saved' : 'Save'}
                                </button>
                              </div>

                              {wafSettings.waf_woo_carding_protection && (
                                <div style={{
                                  display: 'flex',
                                  alignItems: 'center',
                                  gap: '16px',
                                  padding: '8px 12px',
                                  background: 'var(--wcp-bg-surface, #f8fafc)',
                                  border: '1px solid var(--wcp-border, #e2e8f0)',
                                  borderRadius: '6px',
                                  fontSize: '11px',
                                  color: 'var(--wcp-text-secondary, #475569)',
                                  flexWrap: 'wrap'
                                }}>
                                  <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
                                    <span>Max Failed Attempts:</span>
                                    <input
                                      type="number"
                                      min={2}
                                      max={20}
                                      value={wafSettings.waf_woo_checkout_max_attempts}
                                      onChange={(e) => setWafSettings({ ...wafSettings, waf_woo_checkout_max_attempts: Math.max(2, Math.min(20, parseInt(e.target.value) || 3)) })}
                                      className="wcp-input"
                                      style={{ width: '56px', padding: '3px 6px', fontSize: '11px', height: '26px' }}
                                    />
                                    <span style={{ color: 'var(--wcp-text-muted, #94a3b8)' }}>fails / 5 min</span>
                                  </div>

                                  <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
                                    <span>Lockout Duration:</span>
                                    <input
                                      type="number"
                                      min={5}
                                      max={1440}
                                      value={wafSettings.waf_woo_carding_lockout_duration}
                                      onChange={(e) => setWafSettings({ ...wafSettings, waf_woo_carding_lockout_duration: Math.max(5, Math.min(1440, parseInt(e.target.value) || 30)) })}
                                      className="wcp-input"
                                      style={{ width: '64px', padding: '3px 6px', fontSize: '11px', height: '26px' }}
                                    />
                                    <span style={{ color: 'var(--wcp-text-muted, #94a3b8)' }}>minutes</span>
                                  </div>
                                </div>
                              )}
                            </div>

                            {/* Sub-Rule #39: Coupon Enumeration & Brute-Force Shield */}
                            <div className="wcp-firewall-rule-card" style={{
                              display: 'flex',
                              flexDirection: 'column',
                              gap: '10px',
                              padding: '10px 14px',
                              background: 'var(--wcp-bg-panel, #ffffff)',
                              border: '1px solid var(--wcp-border, #e2e8f0)',
                              borderRadius: '6px'
                            }}>
                              <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: '12px' }}>
                                <label style={{ display: 'flex', alignItems: 'flex-start', gap: '10px', cursor: 'pointer', flex: 1, margin: 0 }}>
                                  <input
                                    type="checkbox"
                                    checked={wafSettings.waf_woo_coupon_protection}
                                    onChange={(e) => setWafSettings({ ...wafSettings, waf_woo_coupon_protection: e.target.checked })}
                                    style={{ accentColor: '#10b981', marginTop: '3px' }}
                                  />
                                  <div>
                                    <div style={{ display: 'flex', alignItems: 'center', gap: '8px', flexWrap: 'wrap' }}>
                                      <span style={{
                                        fontSize: '10px',
                                        fontWeight: 700,
                                        color: '#059669',
                                        background: 'rgba(5, 150, 105, 0.1)',
                                        border: '1px solid rgba(5, 150, 105, 0.25)',
                                        padding: '1px 5px',
                                        borderRadius: '4px'
                                      }}>
                                        RULE #39
                                      </span>
                                      <strong style={{ fontSize: '13px', color: 'var(--wcp-text-primary, #0f172a)' }}>
                                        Coupon Enumeration &amp; Brute-Force Shield
                                      </strong>
                                      <span className="wcp-badge-pill wcp-badge-pill-emerald" style={{ fontSize: '10px', padding: '1px 6px' }}>
                                        Promo Protection
                                      </span>
                                    </div>
                                    <div style={{ fontSize: '11px', color: 'var(--wcp-text-muted, #64748b)', marginTop: '3px', lineHeight: 1.45 }}>
                                      Thwarts automated scrapers, browser extensions, and coupon brute-force bots guessing promotional discounts on cart and checkout pages. Limits repeated invalid coupon attempts in rolling 5-minute intervals and temporarily disables coupon submission for attacking IPs.
                                    </div>
                                  </div>
                                </label>

                                <button
                                  type="button"
                                  className={`wcp-btn wcp-firewall-rule-save-btn ${savedSingleRuleSuccess['waf_woo_coupon_protection'] ? 'is-saved' : ''}`}
                                  onClick={() => {
                                    handleSaveSingleRule('waf_woo_coupon_protection', wafSettings.waf_woo_coupon_protection);
                                    handleSaveSingleRule('waf_woo_coupon_max_failures', wafSettings.waf_woo_coupon_max_failures);
                                    handleSaveSingleRule('waf_woo_coupon_lockout_duration', wafSettings.waf_woo_coupon_lockout_duration);
                                  }}
                                  disabled={savingSingleRuleKey === 'waf_woo_coupon_protection'}
                                  title="Save setting for WooCommerce Coupon Shield"
                                >
                                  {savingSingleRuleKey === 'waf_woo_coupon_protection' ? <Loader2 size={11} className="wcp-spin-icon" /> : (savedSingleRuleSuccess['waf_woo_coupon_protection'] ? <Check size={11} /> : <Save size={11} />)}
                                  {savedSingleRuleSuccess['waf_woo_coupon_protection'] ? 'Saved' : 'Save'}
                                </button>
                              </div>

                              {wafSettings.waf_woo_coupon_protection && (
                                <div style={{
                                  display: 'flex',
                                  alignItems: 'center',
                                  gap: '16px',
                                  padding: '8px 12px',
                                  background: 'var(--wcp-bg-surface, #f8fafc)',
                                  border: '1px solid var(--wcp-border, #e2e8f0)',
                                  borderRadius: '6px',
                                  fontSize: '11px',
                                  color: 'var(--wcp-text-secondary, #475569)',
                                  flexWrap: 'wrap'
                                }}>
                                  <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
                                    <span>Max Invalid Attempts:</span>
                                    <input
                                      type="number"
                                      min={2}
                                      max={30}
                                      value={wafSettings.waf_woo_coupon_max_failures}
                                      onChange={(e) => setWafSettings({ ...wafSettings, waf_woo_coupon_max_failures: Math.max(2, Math.min(30, parseInt(e.target.value) || 5)) })}
                                      className="wcp-input"
                                      style={{ width: '56px', padding: '3px 6px', fontSize: '11px', height: '26px' }}
                                    />
                                    <span style={{ color: 'var(--wcp-text-muted, #94a3b8)' }}>invalid / 5 min</span>
                                  </div>

                                  <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
                                    <span>Lockout Duration:</span>
                                    <input
                                      type="number"
                                      min={5}
                                      max={1440}
                                      value={wafSettings.waf_woo_coupon_lockout_duration}
                                      onChange={(e) => setWafSettings({ ...wafSettings, waf_woo_coupon_lockout_duration: Math.max(5, Math.min(1440, parseInt(e.target.value) || 15)) })}
                                      className="wcp-input"
                                      style={{ width: '64px', padding: '3px 6px', fontSize: '11px', height: '26px' }}
                                    />
                                    <span style={{ color: 'var(--wcp-text-muted, #94a3b8)' }}>minutes</span>
                                  </div>
                                </div>
                              )}
                            </div>

                            {/* Sub-Rule #40: Fake Customer Registration & Bot Shield */}
                            <div className="wcp-firewall-rule-card" style={{
                              display: 'flex',
                              flexDirection: 'column',
                              gap: '10px',
                              padding: '10px 14px',
                              background: 'var(--wcp-bg-panel, #ffffff)',
                              border: '1px solid var(--wcp-border, #e2e8f0)',
                              borderRadius: '6px'
                            }}>
                              <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: '12px' }}>
                                <label style={{ display: 'flex', alignItems: 'flex-start', gap: '10px', cursor: 'pointer', flex: 1, margin: 0 }}>
                                  <input
                                    type="checkbox"
                                    checked={wafSettings.waf_woo_registration_protection}
                                    onChange={(e) => setWafSettings({ ...wafSettings, waf_woo_registration_protection: e.target.checked })}
                                    style={{ accentColor: '#10b981', marginTop: '3px' }}
                                  />
                                  <div>
                                    <div style={{ display: 'flex', alignItems: 'center', gap: '8px', flexWrap: 'wrap' }}>
                                      <span style={{
                                        fontSize: '10px',
                                        fontWeight: 700,
                                        color: '#059669',
                                        background: 'rgba(5, 150, 105, 0.1)',
                                        border: '1px solid rgba(5, 150, 105, 0.25)',
                                        padding: '1px 5px',
                                        borderRadius: '4px'
                                      }}>
                                        RULE #40
                                      </span>
                                      <strong style={{ fontSize: '13px', color: 'var(--wcp-text-primary, #0f172a)' }}>
                                        Customer Registration &amp; Bot Shield
                                      </strong>
                                      <span className="wcp-badge-pill wcp-badge-pill-emerald" style={{ fontSize: '10px', padding: '1px 6px' }}>
                                        Anti-Spam
                                      </span>
                                    </div>
                                    <div style={{ fontSize: '11px', color: 'var(--wcp-text-muted, #64748b)', marginTop: '3px', lineHeight: 1.45 }}>
                                      Prevents automated spam bots and fraudulent actors from flooding customer databases with fake shopper accounts across my-account, checkout registration, and modern Store API blocks. Enforces per-IP registration rate limiting and blocks throwaway/disposable email services.
                                    </div>
                                  </div>
                                </label>

                                <button
                                  type="button"
                                  className={`wcp-btn wcp-firewall-rule-save-btn ${savedSingleRuleSuccess['waf_woo_registration_protection'] ? 'is-saved' : ''}`}
                                  onClick={() => {
                                    handleSaveSingleRule('waf_woo_registration_protection', wafSettings.waf_woo_registration_protection);
                                    handleSaveSingleRule('waf_woo_reg_max_per_ip', wafSettings.waf_woo_reg_max_per_ip);
                                    handleSaveSingleRule('waf_woo_reg_window_hours', wafSettings.waf_woo_reg_window_hours);
                                    handleSaveSingleRule('waf_woo_reg_block_disposable_emails', wafSettings.waf_woo_reg_block_disposable_emails);
                                  }}
                                  disabled={savingSingleRuleKey === 'waf_woo_registration_protection'}
                                  title="Save setting for WooCommerce Customer Registration Shield"
                                >
                                  {savingSingleRuleKey === 'waf_woo_registration_protection' ? <Loader2 size={11} className="wcp-spin-icon" /> : (savedSingleRuleSuccess['waf_woo_registration_protection'] ? <Check size={11} /> : <Save size={11} />)}
                                  {savedSingleRuleSuccess['waf_woo_registration_protection'] ? 'Saved' : 'Save'}
                                </button>
                              </div>

                              {wafSettings.waf_woo_registration_protection && (
                                <div style={{
                                  display: 'flex',
                                  alignItems: 'center',
                                  gap: '16px',
                                  padding: '8px 12px',
                                  background: 'var(--wcp-bg-surface, #f8fafc)',
                                  border: '1px solid var(--wcp-border, #e2e8f0)',
                                  borderRadius: '6px',
                                  fontSize: '11px',
                                  color: 'var(--wcp-text-secondary, #475569)',
                                  flexWrap: 'wrap'
                                }}>
                                  <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
                                    <span>Max New Accounts:</span>
                                    <input
                                      type="number"
                                      min={1}
                                      max={20}
                                      value={wafSettings.waf_woo_reg_max_per_ip}
                                      onChange={(e) => setWafSettings({ ...wafSettings, waf_woo_reg_max_per_ip: Math.max(1, Math.min(20, parseInt(e.target.value) || 3)) })}
                                      className="wcp-input"
                                      style={{ width: '56px', padding: '3px 6px', fontSize: '11px', height: '26px' }}
                                    />
                                    <span style={{ color: 'var(--wcp-text-muted, #94a3b8)' }}>accounts</span>
                                  </div>

                                  <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
                                    <span>Window:</span>
                                    <input
                                      type="number"
                                      min={1}
                                      max={24}
                                      value={wafSettings.waf_woo_reg_window_hours}
                                      onChange={(e) => setWafSettings({ ...wafSettings, waf_woo_reg_window_hours: Math.max(1, Math.min(24, parseInt(e.target.value) || 1)) })}
                                      className="wcp-input"
                                      style={{ width: '56px', padding: '3px 6px', fontSize: '11px', height: '26px' }}
                                    />
                                    <span style={{ color: 'var(--wcp-text-muted, #94a3b8)' }}>hour(s) per IP</span>
                                  </div>

                                  <label style={{ display: 'flex', alignItems: 'center', gap: '6px', cursor: 'pointer', margin: 0 }}>
                                    <input
                                      type="checkbox"
                                      checked={wafSettings.waf_woo_reg_block_disposable_emails}
                                      onChange={(e) => setWafSettings({ ...wafSettings, waf_woo_reg_block_disposable_emails: e.target.checked })}
                                      style={{ accentColor: '#10b981' }}
                                    />
                                    <span>Block Disposable / Throwaway Email Domains</span>
                                  </label>
                                </div>
                              )}
                            </div>

                            {/* Sub-Rule #41: Cart Flooding & Denial of Inventory (DoI) Defense */}
                            <div className="wcp-firewall-rule-card" style={{
                              display: 'flex',
                              flexDirection: 'column',
                              gap: '10px',
                              padding: '10px 14px',
                              background: 'var(--wcp-bg-panel, #ffffff)',
                              border: '1px solid var(--wcp-border, #e2e8f0)',
                              borderRadius: '6px'
                            }}>
                              <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: '12px' }}>
                                <label style={{ display: 'flex', alignItems: 'flex-start', gap: '10px', cursor: 'pointer', flex: 1, margin: 0 }}>
                                  <input
                                    type="checkbox"
                                    checked={wafSettings.waf_woo_cart_flood_protection}
                                    onChange={(e) => setWafSettings({ ...wafSettings, waf_woo_cart_flood_protection: e.target.checked })}
                                    style={{ accentColor: '#10b981', marginTop: '3px' }}
                                  />
                                  <div>
                                    <div style={{ display: 'flex', alignItems: 'center', gap: '8px', flexWrap: 'wrap' }}>
                                      <span style={{
                                        fontSize: '10px',
                                        fontWeight: 700,
                                        color: '#059669',
                                        background: 'rgba(5, 150, 105, 0.1)',
                                        border: '1px solid rgba(5, 150, 105, 0.25)',
                                        padding: '1px 5px',
                                        borderRadius: '4px'
                                      }}>
                                        RULE #41
                                      </span>
                                      <strong style={{ fontSize: '13px', color: 'var(--wcp-text-primary, #0f172a)' }}>
                                        Cart Flooding &amp; Denial of Inventory Defense
                                      </strong>
                                      <span className="wcp-badge-pill wcp-badge-pill-emerald" style={{ fontSize: '10px', padding: '1px 6px' }}>
                                        Stock Guard
                                      </span>
                                    </div>
                                    <div style={{ fontSize: '11px', color: 'var(--wcp-text-muted, #64748b)', marginTop: '3px', lineHeight: 1.45 }}>
                                      Prevents automated competitor bots, scalper scrapers, and malicious scripts from hoarding limited-stock items in shopping carts to tie up inventory or exhaust server PHP workers. Enforces a maximum item volume per cart and throttles rapid add-to-cart bursts per IP.
                                    </div>
                                  </div>
                                </label>

                                <button
                                  type="button"
                                  className={`wcp-btn wcp-firewall-rule-save-btn ${savedSingleRuleSuccess['waf_woo_cart_flood_protection'] ? 'is-saved' : ''}`}
                                  onClick={() => {
                                    handleSaveSingleRule('waf_woo_cart_flood_protection', wafSettings.waf_woo_cart_flood_protection);
                                    handleSaveSingleRule('waf_woo_max_cart_items', wafSettings.waf_woo_max_cart_items);
                                    handleSaveSingleRule('waf_woo_add_to_cart_rate_limit', wafSettings.waf_woo_add_to_cart_rate_limit);
                                  }}
                                  disabled={savingSingleRuleKey === 'waf_woo_cart_flood_protection'}
                                  title="Save setting for Cart Flooding Defense"
                                >
                                  {savingSingleRuleKey === 'waf_woo_cart_flood_protection' ? <Loader2 size={11} className="wcp-spin-icon" /> : (savedSingleRuleSuccess['waf_woo_cart_flood_protection'] ? <Check size={11} /> : <Save size={11} />)}
                                  {savedSingleRuleSuccess['waf_woo_cart_flood_protection'] ? 'Saved' : 'Save'}
                                </button>
                              </div>

                              {wafSettings.waf_woo_cart_flood_protection && (
                                <div style={{
                                  display: 'flex',
                                  alignItems: 'center',
                                  gap: '16px',
                                  padding: '8px 12px',
                                  background: 'var(--wcp-bg-surface, #f8fafc)',
                                  border: '1px solid var(--wcp-border, #e2e8f0)',
                                  borderRadius: '6px',
                                  fontSize: '11px',
                                  color: 'var(--wcp-text-secondary, #475569)',
                                  flexWrap: 'wrap'
                                }}>
                                  <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
                                    <span>Max Cart Quantity:</span>
                                    <input
                                      type="number"
                                      min={5}
                                      max={500}
                                      value={wafSettings.waf_woo_max_cart_items}
                                      onChange={(e) => setWafSettings({ ...wafSettings, waf_woo_max_cart_items: Math.max(5, Math.min(500, parseInt(e.target.value) || 50)) })}
                                      className="wcp-input"
                                      style={{ width: '56px', padding: '3px 6px', fontSize: '11px', height: '26px' }}
                                    />
                                    <span style={{ color: 'var(--wcp-text-muted, #94a3b8)' }}>items total / cart</span>
                                  </div>

                                  <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
                                    <span>Add-to-Cart Speed Cap:</span>
                                    <input
                                      type="number"
                                      min={3}
                                      max={60}
                                      value={wafSettings.waf_woo_add_to_cart_rate_limit}
                                      onChange={(e) => setWafSettings({ ...wafSettings, waf_woo_add_to_cart_rate_limit: Math.max(3, Math.min(60, parseInt(e.target.value) || 15)) })}
                                      className="wcp-input"
                                      style={{ width: '56px', padding: '3px 6px', fontSize: '11px', height: '26px' }}
                                    />
                                    <span style={{ color: 'var(--wcp-text-muted, #94a3b8)' }}>actions / min per IP</span>
                                  </div>
                                </div>
                              )}
                            </div>

                            {/* Sub-Rule #42: Catalog & Price Scraping Mitigation */}
                            <div className="wcp-firewall-rule-card" style={{
                              display: 'flex',
                              flexDirection: 'column',
                              gap: '10px',
                              padding: '10px 14px',
                              background: 'var(--wcp-bg-panel, #ffffff)',
                              border: '1px solid var(--wcp-border, #e2e8f0)',
                              borderRadius: '6px'
                            }}>
                              <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: '12px' }}>
                                <label style={{ display: 'flex', alignItems: 'flex-start', gap: '10px', cursor: 'pointer', flex: 1, margin: 0 }}>
                                  <input
                                    type="checkbox"
                                    checked={wafSettings.waf_woo_scraping_protection}
                                    onChange={(e) => setWafSettings({ ...wafSettings, waf_woo_scraping_protection: e.target.checked })}
                                    style={{ accentColor: '#10b981', marginTop: '3px' }}
                                  />
                                  <div>
                                    <div style={{ display: 'flex', alignItems: 'center', gap: '8px', flexWrap: 'wrap' }}>
                                      <span style={{
                                        fontSize: '10px',
                                        fontWeight: 700,
                                        color: '#059669',
                                        background: 'rgba(5, 150, 105, 0.1)',
                                        border: '1px solid rgba(5, 150, 105, 0.25)',
                                        padding: '1px 5px',
                                        borderRadius: '4px'
                                      }}>
                                        RULE #42
                                      </span>
                                      <strong style={{ fontSize: '13px', color: 'var(--wcp-text-primary, #0f172a)' }}>
                                        Catalog &amp; Price Scraping Mitigation
                                      </strong>
                                      <span className="wcp-badge-pill wcp-badge-pill-emerald" style={{ fontSize: '10px', padding: '1px 6px' }}>
                                        Anti-Scraping
                                      </span>
                                    </div>
                                    <div style={{ fontSize: '11px', color: 'var(--wcp-text-muted, #64748b)', marginTop: '3px', lineHeight: 1.45 }}>
                                      Prevents automated competitor scrapers and price monitors from rapidly crawling your store catalog, extracting inventory levels, and overloading database queries via product pagination or Store API endpoints. Automatically exempts verified search crawlers (Google, Bing) and authenticated store managers.
                                    </div>
                                  </div>
                                </label>

                                <button
                                  type="button"
                                  className={`wcp-btn wcp-firewall-rule-save-btn ${savedSingleRuleSuccess['waf_woo_scraping_protection'] ? 'is-saved' : ''}`}
                                  onClick={() => {
                                    handleSaveSingleRule('waf_woo_scraping_protection', wafSettings.waf_woo_scraping_protection);
                                    handleSaveSingleRule('waf_woo_scraping_max_requests', wafSettings.waf_woo_scraping_max_requests);
                                    handleSaveSingleRule('waf_woo_scraping_lockout_duration', wafSettings.waf_woo_scraping_lockout_duration);
                                  }}
                                  disabled={savingSingleRuleKey === 'waf_woo_scraping_protection'}
                                  title="Save setting for Catalog Scraping Mitigation"
                                >
                                  {savingSingleRuleKey === 'waf_woo_scraping_protection' ? <Loader2 size={11} className="wcp-spin-icon" /> : (savedSingleRuleSuccess['waf_woo_scraping_protection'] ? <Check size={11} /> : <Save size={11} />)}
                                  {savedSingleRuleSuccess['waf_woo_scraping_protection'] ? 'Saved' : 'Save'}
                                </button>
                              </div>

                              {wafSettings.waf_woo_scraping_protection && (
                                <div style={{
                                  display: 'flex',
                                  alignItems: 'center',
                                  gap: '16px',
                                  padding: '8px 12px',
                                  background: 'var(--wcp-bg-surface, #f8fafc)',
                                  border: '1px solid var(--wcp-border, #e2e8f0)',
                                  borderRadius: '6px',
                                  fontSize: '11px',
                                  color: 'var(--wcp-text-secondary, #475569)',
                                  flexWrap: 'wrap'
                                }}>
                                  <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
                                    <span>Max Catalog Hits:</span>
                                    <input
                                      type="number"
                                      min={10}
                                      max={300}
                                      value={wafSettings.waf_woo_scraping_max_requests}
                                      onChange={(e) => setWafSettings({ ...wafSettings, waf_woo_scraping_max_requests: Math.max(10, Math.min(300, parseInt(e.target.value) || 60)) })}
                                      className="wcp-input"
                                      style={{ width: '56px', padding: '3px 6px', fontSize: '11px', height: '26px' }}
                                    />
                                    <span style={{ color: 'var(--wcp-text-muted, #94a3b8)' }}>requests / min per IP</span>
                                  </div>

                                  <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
                                    <span>Lockout Duration:</span>
                                    <input
                                      type="number"
                                      min={5}
                                      max={1440}
                                      value={wafSettings.waf_woo_scraping_lockout_duration}
                                      onChange={(e) => setWafSettings({ ...wafSettings, waf_woo_scraping_lockout_duration: Math.max(5, Math.min(1440, parseInt(e.target.value) || 15)) })}
                                      className="wcp-input"
                                      style={{ width: '64px', padding: '3px 6px', fontSize: '11px', height: '26px' }}
                                    />
                                    <span style={{ color: 'var(--wcp-text-muted, #94a3b8)' }}>minutes</span>
                                  </div>
                                </div>
                              )}
                            </div>
                          </div>
                        )}
                      </div>
                    )}
                  </div>

                  {/* Smart Rule: Smart Form Plugin Shield & False-Positive Immunity */}
                  <div className="wcp-firewall-rule-card" style={{
                    display: 'flex',
                    flexDirection: 'column',
                    gap: '10px',
                    padding: '10px 14px'
                  }}>
                    <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: '12px' }}>
                      <label style={{ display: 'flex', alignItems: 'flex-start', gap: '10px', cursor: 'pointer', flex: 1, margin: 0 }}>
                        <input
                          type="checkbox"
                          checked={wafSettings.waf_forms_safe_mode}
                          onChange={(e) => setWafSettings({ ...wafSettings, waf_forms_safe_mode: e.target.checked })}
                          style={{ marginTop: '2px' }}
                        />
                        <div>
                          <div style={{ display: 'flex', alignItems: 'center', gap: '8px', flexWrap: 'wrap' }}>
                            <span style={{
                              fontSize: '10px',
                              fontWeight: 700,
                              textTransform: 'uppercase',
                              padding: '2px 7px',
                              borderRadius: '4px',
                              letterSpacing: '0.5px',
                              background: '#ecfdf5',
                              color: '#059669',
                              border: '1px solid #a7f3d0'
                            }}>
                              FORMS
                            </span>
                            <strong style={{ fontSize: '13px', color: 'var(--wcp-text-primary, #0f172a)' }}>
                              Smart Form Plugin Shield & False-Positive Immunity
                            </strong>
                            {status?.forms_telemetry?.is_active ? (
                              <span className="wcp-smart-shield-pill-detected-emerald">
                                Detected: {status?.forms_telemetry?.detected_names?.slice(0, 3).join(', ') || 'Active Forms Plugin'}
                                {(status?.forms_telemetry?.detected_names?.length || 0) > 3 ? ` +${(status?.forms_telemetry?.detected_names?.length || 0) - 3} more` : ''}
                              </span>
                            ) : (
                              <span className="wcp-smart-shield-pill-empty">
                                No Form Plugin Detected
                              </span>
                            )}
                          </div>
                          <div style={{ fontSize: '11px', color: 'var(--wcp-text-muted, #64748b)', marginTop: '3px', lineHeight: 1.45 }}>
                            Guarantees 100% false-positive immunity for Contact Form 7, WPForms, Fluent Forms, Gravity Forms, Ninja Forms, Formidable Forms, WS Form, and HappyForms. Automatically exempts form AJAX actions and REST endpoints (<code style={{ color: '#059669', fontSize: '10px' }}>/wp-json/contact-form-7/v1/</code>, <code style={{ color: '#059669', fontSize: '10px' }}>wpforms_submit</code>, <code style={{ color: '#059669', fontSize: '10px' }}>fluentform_submit</code>) from admin-ajax rate limiting, empty referrer drops, and heuristically normalizes customer message fields (<code style={{ color: '#059669', fontSize: '10px' }}>your-message</code>, <code style={{ color: '#059669', fontSize: '10px' }}>message</code>) so innocent punctuation never trips SQLi rules.
                          </div>
                        </div>
                      </label>

                      <button
                        type="button"
                        className={`wcp-btn wcp-firewall-rule-save-btn ${savedSingleRuleSuccess['waf_forms_safe_mode'] ? 'is-saved' : ''}`}
                        onClick={() => handleSaveSingleRule('waf_forms_safe_mode', wafSettings.waf_forms_safe_mode)}
                        disabled={savingSingleRuleKey === 'waf_forms_safe_mode'}
                        title="Save setting for Smart Form Plugin Shield"
                      >
                        {savingSingleRuleKey === 'waf_forms_safe_mode' ? <Loader2 size={11} className="wcp-spin-icon" /> : (savedSingleRuleSuccess['waf_forms_safe_mode'] ? <Check size={11} /> : <Save size={11} />)}
                        {savedSingleRuleSuccess['waf_forms_safe_mode'] ? 'Saved' : 'Save'}
                      </button>
                    </div>

                    {/* Recommendation Notice: Forms detected but shield is currently OFF */}
                    {status?.forms_telemetry?.is_active && !wafSettings.waf_forms_safe_mode && (
                      <div className="wcp-smart-shield-rec-banner-emerald">
                        <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
                          <Sparkles size={13} style={{ color: '#059669', flexShrink: 0 }} />
                          <span>
                            <strong>Recommended:</strong> {status?.forms_telemetry?.detected_names?.join(', ') || 'Active form plugin'} detected. Enable this shield to ensure customer inquiries, contact submissions, and AJAX forms are never blocked.
                          </span>
                        </div>
                        <button
                          type="button"
                          className="wcp-btn wcp-action-btn-clean"
                          style={{ fontSize: '11px', padding: '3px 8px', whiteSpace: 'nowrap' }}
                          onClick={() => {
                            setWafSettings({ ...wafSettings, waf_forms_safe_mode: true });
                            handleSaveSingleRule('waf_forms_safe_mode', true);
                          }}
                        >
                          Enable Shield
                        </button>
                      </div>
                    )}
                  
                    {/* Universal Smart Form Armor: Anti-Bot Defense Sub-Panel */}
                    {wafSettings.waf_forms_safe_mode && (
                      <div style={{
                        marginTop: '10px',
                        padding: '12px 14px',
                        background: 'var(--wcp-bg-surface, #f8fafc)',
                        border: '1px solid var(--wcp-border-default, #e2e8f0)',
                        borderRadius: '8px',
                        display: 'flex',
                        flexDirection: 'column',
                        gap: '10px'
                      }}>
                        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', flexWrap: 'wrap', gap: '8px', borderBottom: '1px solid var(--wcp-border-default, #e2e8f0)', paddingBottom: '8px' }}>
                          <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
                            <ShieldCheck size={14} style={{ color: '#059669' }} />
                            <strong style={{ fontSize: '12px', color: 'var(--wcp-text-primary, #0f172a)' }}>Smart Form Armor & Anti-Bot Defense</strong>
                            <span style={{ fontSize: '10px', background: '#ecfdf5', color: '#059669', padding: '1px 6px', borderRadius: '4px', fontWeight: 600 }}>Active Defense</span>
                          </div>
                          {typeof status?.forms_telemetry?.stats?.total_blocked === 'number' && (
                            <div style={{ fontSize: '11px', color: '#059669', fontWeight: 600, display: 'flex', alignItems: 'center', gap: '4px' }}>
                              <span>Neutralized Spam:</span>
                              <span style={{ background: '#ecfdf5', padding: '2px 7px', borderRadius: '10px', border: '1px solid #a7f3d0' }}>
                                {status.forms_telemetry.stats.total_blocked.toLocaleString()} Bot Submissions Dropped
                              </span>
                            </div>
                          )}
                        </div>

                        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(280px, 1fr))', gap: '10px' }}>
                          <label style={{ display: 'flex', alignItems: 'flex-start', gap: '8px', fontSize: '11px', cursor: 'pointer', margin: 0 }}>
                            <input
                              type="checkbox"
                              checked={wafSettings.form_block_headless_browsers}
                              onChange={(e) => {
                                const val = e.target.checked;
                                setWafSettings({ ...wafSettings, form_block_headless_browsers: val });
                                handleSaveSingleRule('form_block_headless_browsers', val);
                              }}
                              style={{ marginTop: '2px' }}
                            />
                            <div>
                              <strong style={{ color: 'var(--wcp-text-primary, #0f172a)' }}>Headless Browser & WebDriver Intercept</strong>
                              <div style={{ color: 'var(--wcp-text-muted, #64748b)', fontSize: '10px', marginTop: '1px' }}>Blocks Puppeteer, Selenium, and automated scripts without mouse/touch entropy.</div>
                            </div>
                          </label>

                          <label style={{ display: 'flex', alignItems: 'flex-start', gap: '8px', fontSize: '11px', cursor: 'pointer', margin: 0 }}>
                            <input
                              type="checkbox"
                              checked={wafSettings.form_honeypot_enabled}
                              onChange={(e) => {
                                const val = e.target.checked;
                                setWafSettings({ ...wafSettings, form_honeypot_enabled: val });
                                handleSaveSingleRule('form_honeypot_enabled', val);
                              }}
                              style={{ marginTop: '2px' }}
                            />
                            <div>
                              <strong style={{ color: 'var(--wcp-text-primary, #0f172a)' }}>Polymorphic Invisible Honeypot</strong>
                              <div style={{ color: 'var(--wcp-text-muted, #64748b)', fontSize: '10px', marginTop: '1px' }}>Accessible off-screen decoy trap fields autofilled by bots with zero human friction.</div>
                            </div>
                          </label>

                          <label style={{ display: 'flex', alignItems: 'flex-start', gap: '8px', fontSize: '11px', cursor: 'pointer', margin: 0 }}>
                            <input
                              type="checkbox"
                              checked={wafSettings.form_speed_gate_enabled}
                              onChange={(e) => {
                                const val = e.target.checked;
                                setWafSettings({ ...wafSettings, form_speed_gate_enabled: val });
                                handleSaveSingleRule('form_speed_gate_enabled', val);
                              }}
                              style={{ marginTop: '2px' }}
                            />
                            <div>
                              <strong style={{ color: 'var(--wcp-text-primary, #0f172a)' }}>Cryptographic Speed Gate (2.5s Minimum)</strong>
                              <div style={{ color: 'var(--wcp-text-muted, #64748b)', fontSize: '10px', marginTop: '1px' }}>Rejects instantaneous millisecond form posts from automated scrapers and stale replays.</div>
                            </div>
                          </label>

                          <div style={{ display: 'flex', flexDirection: 'column', gap: '6px' }}>
                            <label style={{ display: 'flex', alignItems: 'flex-start', gap: '8px', fontSize: '11px', cursor: 'pointer', margin: 0 }}>
                              <input
                                type="checkbox"
                                checked={wafSettings.form_flood_limit_enabled}
                                onChange={(e) => {
                                  const val = e.target.checked;
                                  setWafSettings({ ...wafSettings, form_flood_limit_enabled: val });
                                  handleSaveSingleRule('form_flood_limit_enabled', val);
                                }}
                                style={{ marginTop: '2px' }}
                              />
                              <div>
                                <strong style={{ color: 'var(--wcp-text-primary, #0f172a)' }}>
                                  High-Velocity Flood Limiter ({wafSettings.form_max_submits_per_window} submits / {wafSettings.form_flood_window_minutes >= 60 ? `${wafSettings.form_flood_window_minutes / 60}h` : `${wafSettings.form_flood_window_minutes}m`})
                                </strong>
                                <div style={{ color: 'var(--wcp-text-muted, #64748b)', fontSize: '10px', marginTop: '1px' }}>
                                  Protects inbox and server email reputation against automated form blast attacks.
                                </div>
                              </div>
                            </label>

                            {wafSettings.form_flood_limit_enabled && (
                              <div style={{
                                marginLeft: '24px',
                                display: 'flex',
                                alignItems: 'center',
                                gap: '8px',
                                flexWrap: 'wrap',
                                background: 'var(--wcp-bg-deep, #ffffff)',
                                padding: '6px 10px',
                                borderRadius: '6px',
                                border: '1px solid var(--wcp-border-default, #e2e8f0)',
                                fontSize: '11px'
                              }}>
                                <span style={{ color: 'var(--wcp-text-secondary, #475569)', fontSize: '11px' }}>Limit:</span>
                                <input
                                  type="number"
                                  min={1}
                                  max={50}
                                  value={wafSettings.form_max_submits_per_window}
                                  onChange={(e) => {
                                    const val = Math.max(1, Math.min(50, parseInt(e.target.value) || 1));
                                    setWafSettings({ ...wafSettings, form_max_submits_per_window: val });
                                  }}
                                  onBlur={() => handleSaveSingleRule('form_max_submits_per_window', wafSettings.form_max_submits_per_window)}
                                  className="wcp-firewall-input"
                                  style={{ width: '48px', padding: '2px 6px', fontSize: '11px', textAlign: 'center', borderRadius: '4px' }}
                                  title="Maximum allowed submissions per IP within window"
                                />
                                <span style={{ color: 'var(--wcp-text-secondary, #475569)', fontSize: '11px' }}>submits every</span>
                                <select
                                  value={wafSettings.form_flood_window_minutes}
                                  onChange={(e) => {
                                    const val = parseInt(e.target.value) || 10;
                                    setWafSettings({ ...wafSettings, form_flood_window_minutes: val });
                                    handleSaveSingleRule('form_flood_window_minutes', val);
                                  }}
                                  className="wcp-firewall-input"
                                  style={{ padding: '2px 8px', fontSize: '11px', borderRadius: '4px', cursor: 'pointer' }}
                                >
                                  <option value={5}>5 minutes</option>
                                  <option value={10}>10 minutes</option>
                                  <option value={15}>15 minutes</option>
                                  <option value={30}>30 minutes</option>
                                  <option value={60}>1 hour (60 mins)</option>
                                  <option value={120}>2 hours</option>
                                  <option value={360}>6 hours</option>
                                  <option value={1440}>24 hours</option>
                                </select>
                              </div>
                            )}
                          </div>

                          <label style={{ display: 'flex', alignItems: 'flex-start', gap: '8px', fontSize: '11px', cursor: 'pointer', margin: 0 }}>
                            <input
                              type="checkbox"
                              checked={wafSettings.form_content_filtering}
                              onChange={(e) => {
                                const val = e.target.checked;
                                setWafSettings({ ...wafSettings, form_content_filtering: val });
                                handleSaveSingleRule('form_content_filtering', val);
                              }}
                              style={{ marginTop: '2px' }}
                            />
                            <div>
                              <strong style={{ color: 'var(--wcp-text-primary, #0f172a)' }}>Link & Cloaking Heuristics</strong>
                              <div style={{ color: 'var(--wcp-text-muted, #64748b)', fontSize: '10px', marginTop: '1px' }}>Drops spam messages with &gt; 2 links or recognized promotional crypto/pharma keywords.</div>
                            </div>
                          </label>
                        </div>
                      </div>
                    )}
                  </div>

                  {/* Smart Rule 2: Visual Page Builders & In-Admin Editors */}
                  <div className="wcp-firewall-rule-card" style={{
                    display: 'flex',
                    flexDirection: 'column',
                    gap: '10px',
                    padding: '10px 14px'
                  }}>
                    <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: '12px' }}>
                      <label style={{ display: 'flex', alignItems: 'flex-start', gap: '10px', cursor: 'pointer', flex: 1, margin: 0 }}>
                        <input
                          type="checkbox"
                          checked={wafSettings.waf_allow_page_builders}
                          onChange={(e) => setWafSettings({ ...wafSettings, waf_allow_page_builders: e.target.checked })}
                          style={{ accentColor: '#10b981', marginTop: '3px' }}
                        />
                        <div>
                          <div style={{ display: 'flex', alignItems: 'center', gap: '8px', flexWrap: 'wrap' }}>
                            <span style={{
                              fontSize: '10px',
                              fontWeight: 700,
                              color: '#0284c7',
                              background: 'rgba(2, 132, 199, 0.1)',
                              border: '1px solid rgba(2, 132, 199, 0.25)',
                              padding: '1px 5px',
                              borderRadius: '4px'
                            }}>
                              BUILDER
                            </span>
                            <strong style={{ fontSize: '13px', color: 'var(--wcp-text-primary, #0f172a)' }}>
                              Visual Page Builders & In-Admin Editor Smart Pass
                            </strong>
                            {status?.integrations_telemetry?.has_builders ? (
                              <span className="wcp-smart-shield-pill-detected-sky">
                                Detected: {status?.integrations_telemetry?.builder_names?.join(', ') || 'Active Builder'}
                              </span>
                            ) : (
                              <span className="wcp-smart-shield-pill-empty">
                                Standard WP Editor
                              </span>
                            )}
                          </div>
                          <div style={{ fontSize: '11px', color: 'var(--wcp-text-muted, #64748b)', marginTop: '3px', lineHeight: 1.45 }}>
                            Exempts verified authenticated editors using Elementor, Divi, Beaver Builder, Bricks, Breakdance, Oxygen, SeedProd, Brizy, Thrive Architect, WPBakery, Visual Composer, Themify, SiteOrigin, Droip, Live Composer, WP Site Editor (FSE), GenerateBlocks, Kadence, Spectra, and Avada Fusion Builder from AJAX rate-limiters (Rule #33), buffer caps (Rule #34), and heuristic HTML/CSS filters when saving complex design layouts.
                          </div>
                        </div>
                      </label>

                      <button
                        type="button"
                        className={`wcp-btn wcp-firewall-rule-save-btn ${savedSingleRuleSuccess['waf_allow_page_builders'] ? 'is-saved' : ''}`}
                        onClick={() => handleSaveSingleRule('waf_allow_page_builders', wafSettings.waf_allow_page_builders)}
                        disabled={savingSingleRuleKey === 'waf_allow_page_builders'}
                        title="Save setting for Page Builder Smart Pass"
                      >
                        {savingSingleRuleKey === 'waf_allow_page_builders' ? <Loader2 size={11} className="wcp-spin-icon" /> : (savedSingleRuleSuccess['waf_allow_page_builders'] ? <Check size={11} /> : <Save size={11} />)}
                        {savedSingleRuleSuccess['waf_allow_page_builders'] ? 'Saved' : 'Save'}
                      </button>
                    </div>

                    {/* Recommendation Notice: Visual builder detected but pass is currently OFF */}
                    {status?.integrations_telemetry?.has_builders && !wafSettings.waf_allow_page_builders && (
                      <div className="wcp-smart-shield-rec-banner-sky">
                        <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
                          <Sparkles size={13} style={{ color: '#0284c7', flexShrink: 0 }} />
                          <span>
                            <strong>Recommended:</strong> {status?.integrations_telemetry?.builder_names?.join(', ') || 'Visual builder'} detected. Enable this pass to avoid saving errors on complex layouts.
                          </span>
                        </div>
                        <button
                          type="button"
                          className="wcp-btn wcp-action-btn-clean"
                          style={{ fontSize: '11px', padding: '3px 8px', whiteSpace: 'nowrap' }}
                          onClick={() => {
                            setWafSettings({ ...wafSettings, waf_allow_page_builders: true });
                            handleSaveSingleRule('waf_allow_page_builders', true);
                          }}
                        >
                          Enable Pass
                        </button>
                      </div>
                    )}
                  </div>

                  {/* Smart Rule 3: Jetpack by WordPress Smart Pass */}
                  <div className="wcp-firewall-rule-card" style={{
                    display: 'flex',
                    flexDirection: 'column',
                    gap: '10px',
                    padding: '10px 14px'
                  }}>
                    <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: '12px' }}>
                      <label style={{ display: 'flex', alignItems: 'flex-start', gap: '10px', cursor: 'pointer', flex: 1, margin: 0 }}>
                        <input
                          type="checkbox"
                          checked={wafSettings.waf_allow_jetpack_xmlrpc}
                          onChange={(e) => setWafSettings({ ...wafSettings, waf_allow_jetpack_xmlrpc: e.target.checked })}
                          style={{ accentColor: '#10b981', marginTop: '3px' }}
                        />
                        <div>
                          <div style={{ display: 'flex', alignItems: 'center', gap: '8px', flexWrap: 'wrap' }}>
                            <span style={{
                              fontSize: '10px',
                              fontWeight: 700,
                              color: '#10b981',
                              background: 'rgba(16, 185, 129, 0.1)',
                              border: '1px solid rgba(16, 185, 129, 0.25)',
                              padding: '1px 5px',
                              borderRadius: '4px'
                            }}>
                              JETPACK
                            </span>
                            <strong style={{ fontSize: '13px', color: 'var(--wcp-text-primary, #0f172a)' }}>
                              Jetpack by WordPress.com Smart Sync Pass
                            </strong>
                            {status?.integrations_telemetry?.has_jetpack ? (
                              <span className="wcp-smart-shield-pill-detected-emerald">
                                Jetpack Plugin Active
                              </span>
                            ) : (
                              <span className="wcp-smart-shield-pill-empty">
                                Jetpack Not Installed
                              </span>
                            )}
                          </div>
                          <div style={{ fontSize: '11px', color: 'var(--wcp-text-muted, #64748b)', marginTop: '3px', lineHeight: 1.45 }}>
                            Permits official Automattic Jetpack sync through <code style={{ color: '#059669', fontSize: '10px' }}>/xmlrpc.php?for=jetpack</code> by strictly validating incoming IPs against Automattic CIDR subnets and signed timestamps, even when XML-RPC is blocked (Rule #5).
                          </div>
                        </div>
                      </label>

                      <button
                        type="button"
                        className={`wcp-btn wcp-firewall-rule-save-btn ${savedSingleRuleSuccess['waf_allow_jetpack_xmlrpc'] ? 'is-saved' : ''}`}
                        onClick={() => handleSaveSingleRule('waf_allow_jetpack_xmlrpc', wafSettings.waf_allow_jetpack_xmlrpc)}
                        disabled={savingSingleRuleKey === 'waf_allow_jetpack_xmlrpc'}
                        title="Save setting for Jetpack Smart Pass"
                      >
                        {savingSingleRuleKey === 'waf_allow_jetpack_xmlrpc' ? <Loader2 size={11} className="wcp-spin-icon" /> : (savedSingleRuleSuccess['waf_allow_jetpack_xmlrpc'] ? <Check size={11} /> : <Save size={11} />)}
                        {savedSingleRuleSuccess['waf_allow_jetpack_xmlrpc'] ? 'Saved' : 'Save'}
                      </button>
                    </div>

                    {/* Recommendation Notice: Jetpack detected but pass is currently OFF */}
                    {status?.integrations_telemetry?.has_jetpack && !wafSettings.waf_allow_jetpack_xmlrpc && (
                      <div className="wcp-smart-shield-rec-banner-emerald">
                        <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
                          <Sparkles size={13} style={{ color: '#10b981', flexShrink: 0 }} />
                          <span>
                            <strong>Recommended:</strong> Jetpack detected. Enable this pass to allow Automattic sync while keeping generic XML-RPC attacks blocked.
                          </span>
                        </div>
                        <button
                          type="button"
                          className="wcp-btn wcp-action-btn-clean"
                          style={{ fontSize: '11px', padding: '3px 8px', whiteSpace: 'nowrap' }}
                          onClick={() => {
                            setWafSettings({ ...wafSettings, waf_allow_jetpack_xmlrpc: true });
                            handleSaveSingleRule('waf_allow_jetpack_xmlrpc', true);
                          }}
                        >
                          Enable Pass
                        </button>
                      </div>
                    )}
                  </div>

                  {/* Smart Rule 4: Uptime Monitors & Health Checks */}
                  <div className="wcp-firewall-rule-card" style={{
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'space-between',
                    gap: '12px',
                    padding: '10px 14px'
                  }}>
                    <label style={{ display: 'flex', alignItems: 'flex-start', gap: '10px', cursor: 'pointer', flex: 1, margin: 0 }}>
                      <input
                        type="checkbox"
                        checked={wafSettings.waf_allow_uptime_monitors}
                        onChange={(e) => setWafSettings({ ...wafSettings, waf_allow_uptime_monitors: e.target.checked })}
                        style={{ accentColor: '#10b981', marginTop: '3px' }}
                      />
                      <div>
                        <div style={{ display: 'flex', alignItems: 'center', gap: '8px', flexWrap: 'wrap' }}>
                          <span style={{
                            fontSize: '10px',
                            fontWeight: 700,
                            color: '#6366f1',
                            background: 'rgba(99, 102, 241, 0.1)',
                            border: '1px solid rgba(99, 102, 241, 0.25)',
                            padding: '1px 5px',
                            borderRadius: '4px'
                          }}>
                            UPTIME
                          </span>
                          <strong style={{ fontSize: '13px', color: 'var(--wcp-text-primary, #0f172a)' }}>
                            Uptime Monitors & Health Check Immunity
                          </strong>
                        </div>
                        <div style={{ fontSize: '11px', color: 'var(--wcp-text-muted, #64748b)', marginTop: '3px', lineHeight: 1.45 }}>
                          Validates genuine uptime monitors (UptimeRobot, Pingdom, StatusCake, BetterUptime, GTmetrix, NodePing, Site24x7) via 24-hour cached reverse DNS (PTR/A) resolution to eliminate false-positive 404 lockouts during rapid status checks.
                        </div>
                      </div>
                    </label>

                    <button
                      type="button"
                      className={`wcp-btn wcp-firewall-rule-save-btn ${savedSingleRuleSuccess['waf_allow_uptime_monitors'] ? 'is-saved' : ''}`}
                      onClick={() => handleSaveSingleRule('waf_allow_uptime_monitors', wafSettings.waf_allow_uptime_monitors)}
                      disabled={savingSingleRuleKey === 'waf_allow_uptime_monitors'}
                      title="Save setting for Uptime Monitors Smart Pass"
                    >
                      {savingSingleRuleKey === 'waf_allow_uptime_monitors' ? <Loader2 size={11} className="wcp-spin-icon" /> : (savedSingleRuleSuccess['waf_allow_uptime_monitors'] ? <Check size={11} /> : <Save size={11} />)}
                      {savedSingleRuleSuccess['waf_allow_uptime_monitors'] ? 'Saved' : 'Save'}
                    </button>
                  </div>

                  {/* Smart Rule 5: Central WordPress Management Networks */}
                  <div className="wcp-firewall-rule-card" style={{
                    display: 'flex',
                    flexDirection: 'column',
                    gap: '10px',
                    padding: '10px 14px'
                  }}>
                    <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: '12px' }}>
                      <label style={{ display: 'flex', alignItems: 'flex-start', gap: '10px', cursor: 'pointer', flex: 1, margin: 0 }}>
                        <input
                          type="checkbox"
                          checked={wafSettings.waf_allow_central_management}
                          onChange={(e) => setWafSettings({ ...wafSettings, waf_allow_central_management: e.target.checked })}
                          style={{ accentColor: '#10b981', marginTop: '3px' }}
                        />
                        <div>
                          <div style={{ display: 'flex', alignItems: 'center', gap: '8px', flexWrap: 'wrap' }}>
                            <span style={{
                              fontSize: '10px',
                              fontWeight: 700,
                              color: '#7c3aed',
                              background: 'rgba(124, 58, 237, 0.1)',
                              border: '1px solid rgba(124, 58, 237, 0.25)',
                              padding: '1px 5px',
                              borderRadius: '4px'
                            }}>
                              CENTRAL
                            </span>
                            <strong style={{ fontSize: '13px', color: 'var(--wcp-text-primary, #0f172a)' }}>
                              Central Management Networks (ManageWP, MainWP, InfiniteWP)
                            </strong>
                            {status?.integrations_telemetry?.has_central_management ? (
                              <span className="wcp-smart-shield-pill-detected-purple">
                                Worker Active: {status?.integrations_telemetry?.management_names?.join(', ') || 'Child Plugin'}
                              </span>
                            ) : (
                              <span className="wcp-smart-shield-pill-empty">
                                No Worker Plugin Installed
                              </span>
                            )}
                          </div>
                          <div style={{ fontSize: '11px', color: 'var(--wcp-text-muted, #64748b)', marginTop: '3px', lineHeight: 1.45 }}>
                            Authenticates encrypted worker handshakes (<code style={{ color: '#7c3aed', fontSize: '10px' }}>X-MWP-Signature</code>, <code style={{ color: '#7c3aed', fontSize: '10px' }}>X-MainWP-Signature</code>, <code style={{ color: '#7c3aed', fontSize: '10px' }}>IWP_ACTION</code>) alongside active child plugins to ensure remote backups and updates run uninterrupted.
                          </div>
                        </div>
                      </label>

                      <button
                        type="button"
                        className={`wcp-btn wcp-firewall-rule-save-btn ${savedSingleRuleSuccess['waf_allow_central_management'] ? 'is-saved' : ''}`}
                        onClick={() => handleSaveSingleRule('waf_allow_central_management', wafSettings.waf_allow_central_management)}
                        disabled={savingSingleRuleKey === 'waf_allow_central_management'}
                        title="Save setting for Central Management Pass"
                      >
                        {savingSingleRuleKey === 'waf_allow_central_management' ? <Loader2 size={11} className="wcp-spin-icon" /> : (savedSingleRuleSuccess['waf_allow_central_management'] ? <Check size={11} /> : <Save size={11} />)}
                        {savedSingleRuleSuccess['waf_allow_central_management'] ? 'Saved' : 'Save'}
                      </button>
                    </div>

                    {/* Recommendation Notice: Worker detected but pass is currently OFF */}
                    {status?.integrations_telemetry?.has_central_management && !wafSettings.waf_allow_central_management && (
                      <div className="wcp-smart-shield-rec-banner-purple">
                        <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
                          <Sparkles size={13} style={{ color: '#7c3aed', flexShrink: 0 }} />
                          <span>
                            <strong>Recommended:</strong> Remote management worker ({status?.integrations_telemetry?.management_names?.join(', ') || 'Worker'}) detected. Enable this pass to allow remote backups and updates.
                          </span>
                        </div>
                        <button
                          type="button"
                          className="wcp-btn wcp-action-btn-clean"
                          style={{ fontSize: '11px', padding: '3px 8px', whiteSpace: 'nowrap' }}
                          onClick={() => {
                            setWafSettings({ ...wafSettings, waf_allow_central_management: true });
                            handleSaveSingleRule('waf_allow_central_management', true);
                          }}
                        >
                          Enable Pass
                        </button>
                      </div>
                    )}
                  </div>
                </div>
              </div>

              {/* SECTION: Core Web Exploits & Injections */}
              <div className="wcp-firewall-section-group">
                <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '12px' }}>
                  <strong style={{ fontSize: '13px', textTransform: 'uppercase', letterSpacing: '0.04em', color: '#0284c7', display: 'flex', alignItems: 'center', gap: '6px' }}>
                    <Shield size={14} /> Core Web Application Exploits & Injection Defense
                  </strong>
                </div>

                <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
                  {[
                    { num: 1, key: 'waf_block_sqli', label: 'SQL Injection (SQLi) Defense', desc: 'Detects and neutralizes UNION SELECT, schema extraction, blind delays, hex payloads, and subqueries.' },
                    { num: 2, key: 'waf_block_xss', label: 'Cross-Site Scripting (XSS) Filter', desc: 'Blocks <script> injections, javascript: pseudo-protocols, onload handlers, and DOM tampering payloads.' },
                    { num: 3, key: 'waf_block_traversal', label: 'Path Traversal & Local File Inclusion (LFI)', desc: 'Blocks ../ directory hops, /etc/passwd targets, and php://filter source disclosure vectors.' },
                    { num: 4, key: 'waf_block_php_injection', label: 'PHP Script & Webshell Payload Injection', desc: 'Denies <?php tags, eval(), base64_decode(), and system() shell calls inside query or post parameters.' },
                    { num: 5, key: 'waf_disable_xmlrpc', label: 'Disable XML-RPC Endpoint (/xmlrpc.php)', desc: 'Completely blocks xmlrpc.php to neutralize pingback DDoS amplification and automated brute-force.' },
                    { num: 6, key: 'waf_block_malicious_uploads', label: 'Malicious File Upload Armor', desc: 'Real-time intercept for executable extensions, spoofed headers (PE/ELF/Mach-O), SVG XSS, and polyglots.' },
                    { num: 7, key: 'waf_block_empty_post_ua_referer', label: 'Block Blank POST Headers', desc: 'Drops automated POST requests missing both User-Agent and Referer headers (headless bot signature).' },
                    { num: 8, key: 'waf_block_unsafe_http_methods', label: 'Block Unsafe HTTP Methods', desc: 'Rejects TRACE, TRACK, CONNECT, and DEBUG requests used in cross-site tracing and proxy exploits.' },
                    { num: 9, key: 'waf_block_null_byte_attacks', label: 'Null Byte Poison Shield', desc: 'Blocks %00 and null character injection attempts targeting filesystem boundaries and file extensions.' },
                    { num: 10, key: 'waf_block_sensitive_file_probes', label: 'Sensitive File & Backup Probes Shield', desc: 'Drops scans for .env, .git, database dumps (.sql, .sql.gz), wp-config backups, and archive files.' },
                    { num: 11, key: 'waf_block_uploads_php_exec', label: 'Uploads Directory PHP Execution Deny', desc: 'Denies direct HTTP execution of any .php files located within wp-content/uploads/ folder.' },
                    { num: 12, key: 'waf_block_external_cron', label: 'Block External wp-cron.php Abuse', desc: 'Denies external HTTP triggers to wp-cron.php to prevent CPU starvation (allows localhost & CLI).' },
                    { num: 13, key: 'waf_block_open_redirects', label: 'Open Redirect Phishing Guard', desc: 'Detects and drops off-site or protocol-relative redirect payloads inside redirect_to parameters.' },
                    { num: 14, key: 'waf_block_ssrf_metadata', label: 'Cloud Metadata & SSRF Shield', desc: 'Blocks Server-Side Request Forgery attempts probing cloud metadata endpoints (169.254.169.254).' },
                    { num: 15, key: 'waf_block_install_php', label: 'WordPress Installer & Upgrade Lockdown', desc: 'Terminates rogue external requests targeting /wp-admin/install.php or upgrade.php.' },
                    { num: 16, key: 'waf_disallow_phpmyadmin_plugins', label: 'Disallow phpMyAdmin & DB Manager Plugins', desc: 'Prohibits searching, 1-click installing, or updating any phpMyAdmin/Adminer database management plugins.' },
                    { num: 17, key: 'waf_disallow_filemanager_plugins', label: 'Disallow File Manager Plugins', desc: 'Prohibits installing or activating any File Manager or explorer plugins (e.g. WP File Manager, Filester, FileOrganizer).' },
                    { num: 18, key: 'waf_disallow_phpmyadmin_uploads', label: 'Block phpMyAdmin & DB Script Uploads', desc: 'Blocks uploads of standalone database scripts (pma.php, adminer.php, SQL dumpers) in media, themes, or archives.' },
                    { num: 19, key: 'waf_disallow_filemanager_uploads', label: 'Block File Manager & Web Shell Uploads', desc: 'Blocks uploads of standalone file managers and webshells (tinyfilemanager.php, elFinder, c99, WSO, Alfa).' },
                  ].map((rule) => {
                    const isChecked = !!(wafSettings as any)[rule.key];
                    const isSaving = savingSingleRuleKey === rule.key;
                    const isSaved = !!savedSingleRuleSuccess[rule.key];

                    return (
                      <React.Fragment key={rule.key}>
                        <div
                          className="wcp-firewall-rule-card"
                          style={{
                            display: 'flex',
                            alignItems: 'center',
                            justifyContent: 'space-between',
                            gap: '12px',
                            padding: '8px 12px'
                          }}
                        >
                          <label style={{ display: 'flex', alignItems: 'flex-start', gap: '10px', cursor: 'pointer', flex: 1, minWidth: 0, margin: 0 }}>
                            <input
                              type="checkbox"
                              checked={isChecked}
                              onChange={(e) => setWafSettings({ ...wafSettings, [rule.key]: e.target.checked })}
                              style={{ accentColor: '#0284c7', marginTop: '3px' }}
                            />
                            <div style={{ minWidth: 0 }}>
                              <div style={{ display: 'flex', alignItems: 'center', gap: '8px', flexWrap: 'wrap' }}>
                                <span style={{
                                  fontSize: '11px',
                                  fontWeight: 700,
                                  fontFamily: 'monospace',
                                  color: '#0284c7',
                                  background: 'rgba(2, 132, 199, 0.08)',
                                  border: '1px solid rgba(2, 132, 199, 0.25)',
                                  padding: '1px 6px',
                                  borderRadius: '4px',
                                  letterSpacing: '0.02em',
                                  lineHeight: '1.4'
                                }}>
                                  #{rule.num}
                                </span>
                                <strong style={{ fontSize: '13px', color: 'var(--wcp-text-primary, #0f172a)' }}>{rule.label}</strong>
                              </div>
                              <div style={{ fontSize: '11px', color: 'var(--wcp-text-muted, #64748b)', marginTop: '2px', lineHeight: 1.4 }}>
                                {rule.desc}
                              </div>
                            </div>
                          </label>

                          <button
                            type="button"
                            className={`wcp-btn wcp-firewall-rule-save-btn ${isSaved ? 'is-saved' : ''}`}
                            onClick={() => handleSaveSingleRule(rule.key, isChecked)}
                            disabled={isSaving}
                            title={`Save setting for ${rule.label}`}
                          >
                            {isSaving ? <Loader2 size={11} className="wcp-spin-icon" /> : (isSaved ? <Check size={11} /> : <Save size={11} />)}
                            {isSaved ? 'Saved' : 'Save'}
                          </button>
                        </div>

                        {/* Sub-rule: Jetpack Smart Pass (Only relevant when XML-RPC is blocked) */}
                        {rule.key === 'waf_disable_xmlrpc' && isChecked && (
                          <div
                            className="wcp-firewall-subcard-nested"
                            style={{
                              marginLeft: '28px',
                              display: 'flex',
                              alignItems: 'center',
                              justifyContent: 'space-between',
                              gap: '12px',
                              padding: '8px 12px'
                            }}
                          >
                            <label style={{ display: 'flex', alignItems: 'flex-start', gap: '10px', cursor: 'pointer', flex: 1, minWidth: 0, margin: 0 }}>
                              <input
                                type="checkbox"
                                checked={!!wafSettings.waf_allow_jetpack_xmlrpc}
                                onChange={(e) => setWafSettings({ ...wafSettings, waf_allow_jetpack_xmlrpc: e.target.checked })}
                                style={{ accentColor: '#10b981', marginTop: '3px' }}
                              />
                              <div style={{ minWidth: 0 }}>
                                <div style={{ display: 'flex', alignItems: 'center', gap: '8px', flexWrap: 'wrap' }}>
                                  <span style={{
                                    fontSize: '10px',
                                    fontWeight: 700,
                                    color: '#059669',
                                    background: 'rgba(16, 185, 129, 0.1)',
                                    border: '1px solid rgba(16, 185, 129, 0.25)',
                                    padding: '1px 5px',
                                    borderRadius: '4px'
                                  }}>
                                    SMART PASS
                                  </span>
                                  <strong style={{ fontSize: '12px', color: 'var(--wcp-text-primary, #0f172a)' }}>
                                    Allow Verified WordPress.com Jetpack Sync
                                  </strong>
                                </div>
                                <div style={{ fontSize: '11px', color: 'var(--wcp-text-muted, #64748b)', marginTop: '2px', lineHeight: 1.4 }}>
                                  Safely permits legitimate Jetpack synchronization by cryptographically verifying official Automattic IP CIDRs and signed tokens, while keeping generic XML-RPC brute-force attacks blocked.
                                </div>
                              </div>
                            </label>

                            <button
                              type="button"
                              className={`wcp-btn wcp-firewall-rule-save-btn ${savedSingleRuleSuccess['waf_allow_jetpack_xmlrpc'] ? 'is-saved' : ''}`}
                              onClick={() => handleSaveSingleRule('waf_allow_jetpack_xmlrpc', !!wafSettings.waf_allow_jetpack_xmlrpc)}
                              disabled={savingSingleRuleKey === 'waf_allow_jetpack_xmlrpc'}
                              title="Save setting for Jetpack Smart Pass"
                            >
                              {savingSingleRuleKey === 'waf_allow_jetpack_xmlrpc' ? (
                                <Loader2 size={11} className="wcp-spin-icon" />
                              ) : savedSingleRuleSuccess['waf_allow_jetpack_xmlrpc'] ? (
                                <Check size={11} />
                              ) : (
                                <Save size={11} />
                              )}
                              {savedSingleRuleSuccess['waf_allow_jetpack_xmlrpc'] ? 'Saved' : 'Save'}
                            </button>
                          </div>
                        )}
                      </React.Fragment>
                    );
                  })}
                </div>
              </div>

              {/* SECTION: Identity, Authentication & Password Armor */}
              <div className="wcp-firewall-section-group">
                <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '12px' }}>
                  <strong style={{ fontSize: '13px', textTransform: 'uppercase', letterSpacing: '0.04em', color: '#7c3aed', display: 'flex', alignItems: 'center', gap: '6px' }}>
                    <Lock size={14} /> Identity, Authentication & Password Armor
                  </strong>
                </div>

                <div style={{ display: 'flex', flexDirection: 'column', gap: '10px' }}>
                  {/* Mask Login Errors */}
                  <div className="wcp-firewall-rule-card" style={{
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'space-between',
                    gap: '12px',
                    padding: '8px 12px'
                  }}>
                    <label style={{ display: 'flex', alignItems: 'flex-start', gap: '10px', cursor: 'pointer', flex: 1, margin: 0 }}>
                      <input
                        type="checkbox"
                        checked={wafSettings.waf_mask_login_errors}
                        onChange={(e) => setWafSettings({ ...wafSettings, waf_mask_login_errors: e.target.checked })}
                        style={{ accentColor: '#7c3aed', marginTop: '3px' }}
                      />
                      <div>
                        <div style={{ display: 'flex', alignItems: 'center', gap: '8px', flexWrap: 'wrap' }}>
                          <span style={{
                            fontSize: '11px',
                            fontWeight: 700,
                            fontFamily: 'monospace',
                            color: '#7c3aed',
                            background: 'rgba(124, 58, 237, 0.08)',
                            border: '1px solid rgba(124, 58, 237, 0.25)',
                            padding: '1px 6px',
                            borderRadius: '4px',
                            letterSpacing: '0.02em',
                            lineHeight: '1.4'
                          }}>
                            #20
                          </span>
                          <strong style={{ fontSize: '13px', color: 'var(--wcp-text-primary, #0f172a)' }}>Mask Login Errors</strong>
                        </div>
                        <div style={{ fontSize: '11px', color: 'var(--wcp-text-muted, #64748b)', marginTop: '2px' }}>
                          Obscures whether username or password was incorrect to stop automated enumeration.
                        </div>
                      </div>
                    </label>
                    <button
                      type="button"
                      className={`wcp-btn wcp-firewall-rule-save-btn ${savedSingleRuleSuccess['waf_mask_login_errors'] ? 'is-saved' : ''}`}
                      onClick={() => handleSaveSingleRule('waf_mask_login_errors', wafSettings.waf_mask_login_errors)}
                      disabled={savingSingleRuleKey === 'waf_mask_login_errors'}
                    >
                      {savingSingleRuleKey === 'waf_mask_login_errors' ? <Loader2 size={11} className="wcp-spin-icon" /> : (savedSingleRuleSuccess['waf_mask_login_errors'] ? <Check size={11} /> : <Save size={11} />)}
                      {savedSingleRuleSuccess['waf_mask_login_errors'] ? 'Saved' : 'Save'}
                    </button>
                  </div>

                  {/* Block Admin Registration */}
                  <div className="wcp-firewall-rule-card" style={{
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'space-between',
                    gap: '12px',
                    padding: '8px 12px'
                  }}>
                    <label style={{ display: 'flex', alignItems: 'flex-start', gap: '10px', cursor: 'pointer', flex: 1, margin: 0 }}>
                      <input
                        type="checkbox"
                        checked={wafSettings.waf_prevent_admin_registration}
                        onChange={(e) => setWafSettings({ ...wafSettings, waf_prevent_admin_registration: e.target.checked })}
                        style={{ accentColor: '#7c3aed', marginTop: '3px' }}
                      />
                      <div>
                        <div style={{ display: 'flex', alignItems: 'center', gap: '8px', flexWrap: 'wrap' }}>
                          <span style={{
                            fontSize: '11px',
                            fontWeight: 700,
                            fontFamily: 'monospace',
                            color: '#7c3aed',
                            background: 'rgba(124, 58, 237, 0.08)',
                            border: '1px solid rgba(124, 58, 237, 0.25)',
                            padding: '1px 6px',
                            borderRadius: '4px',
                            letterSpacing: '0.02em',
                            lineHeight: '1.4'
                          }}>
                            #21
                          </span>
                          <strong style={{ fontSize: '13px', color: 'var(--wcp-text-primary, #0f172a)' }}>Block 'admin' Registration</strong>
                        </div>
                        <div style={{ fontSize: '11px', color: 'var(--wcp-text-muted, #64748b)', marginTop: '2px' }}>
                          Prohibits new account registration using the username 'admin' even if available.
                        </div>
                      </div>
                    </label>
                    <button
                      type="button"
                      className={`wcp-btn wcp-firewall-rule-save-btn ${savedSingleRuleSuccess['waf_prevent_admin_registration'] ? 'is-saved' : ''}`}
                      onClick={() => handleSaveSingleRule('waf_prevent_admin_registration', wafSettings.waf_prevent_admin_registration)}
                      disabled={savingSingleRuleKey === 'waf_prevent_admin_registration'}
                    >
                      {savingSingleRuleKey === 'waf_prevent_admin_registration' ? <Loader2 size={11} className="wcp-spin-icon" /> : (savedSingleRuleSuccess['waf_prevent_admin_registration'] ? <Check size={11} /> : <Save size={11} />)}
                      {savedSingleRuleSuccess['waf_prevent_admin_registration'] ? 'Saved' : 'Save'}
                    </button>
                  </div>

                  {/* Forbidden Honeypot Usernames */}
                  <div className="wcp-firewall-rule-card" style={{ padding: '12px' }}>
                    <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: '12px' }}>
                      <label style={{ display: 'flex', alignItems: 'flex-start', gap: '10px', cursor: 'pointer', flex: 1, margin: 0 }}>
                        <input
                          type="checkbox"
                          checked={wafSettings.waf_block_forbidden_usernames}
                          onChange={(e) => setWafSettings({ ...wafSettings, waf_block_forbidden_usernames: e.target.checked })}
                          style={{ accentColor: '#7c3aed', marginTop: '3px' }}
                        />
                        <div>
                          <div style={{ display: 'flex', alignItems: 'center', gap: '8px', flexWrap: 'wrap' }}>
                            <span style={{
                              fontSize: '11px',
                              fontWeight: 700,
                              fontFamily: 'monospace',
                              color: '#7c3aed',
                              background: 'rgba(124, 58, 237, 0.08)',
                              border: '1px solid rgba(124, 58, 237, 0.25)',
                              padding: '1px 6px',
                              borderRadius: '4px',
                              letterSpacing: '0.02em',
                              lineHeight: '1.4'
                            }}>
                              #22
                            </span>
                            <strong style={{ fontSize: '13px', color: 'var(--wcp-text-primary, #0f172a)' }}>Forbidden Honeypot Usernames Trap</strong>
                          </div>
                          <div style={{ fontSize: '11px', color: 'var(--wcp-text-muted, #64748b)', marginTop: '2px' }}>
                            Immediately permanently bans the IP of any client attempting to sign in using trap usernames.
                          </div>
                        </div>
                      </label>
                      <button
                        type="button"
                        className={`wcp-btn wcp-firewall-rule-save-btn ${savedSingleRuleSuccess['waf_block_forbidden_usernames'] ? 'is-saved' : ''}`}
                        onClick={() => {
                          handleSaveSingleRule('waf_block_forbidden_usernames', wafSettings.waf_block_forbidden_usernames);
                          handleSaveSingleRule('waf_forbidden_usernames_list', wafSettings.waf_forbidden_usernames_list);
                        }}
                        disabled={savingSingleRuleKey === 'waf_block_forbidden_usernames' || savingSingleRuleKey === 'waf_forbidden_usernames_list'}
                      >
                        {savingSingleRuleKey === 'waf_block_forbidden_usernames' ? <Loader2 size={11} className="wcp-spin-icon" /> : (savedSingleRuleSuccess['waf_block_forbidden_usernames'] ? <Check size={11} /> : <Save size={11} />)}
                        {savedSingleRuleSuccess['waf_block_forbidden_usernames'] ? 'Saved' : 'Save'}
                      </button>
                    </div>

                    {wafSettings.waf_block_forbidden_usernames && (
                      <div style={{ marginTop: '10px', paddingTop: '10px', borderTop: '1px solid var(--wcp-border, #e2e8f0)' }}>
                        <label style={{ display: 'block', fontSize: '11px', fontWeight: 600, color: 'var(--wcp-text-muted, #64748b)', marginBottom: '4px' }}>
                          Forbidden Usernames List (one per line, lowercase):
                        </label>
                        <textarea
                          rows={3}
                          value={wafSettings.waf_forbidden_usernames_list}
                          onChange={(e) => setWafSettings({ ...wafSettings, waf_forbidden_usernames_list: e.target.value })}
                          className="wcp-firewall-textarea"
                          style={{ width: '100%', fontSize: '12px', fontFamily: 'monospace', padding: '6px 8px' }}
                          placeholder="admin&#10;administrator&#10;root"
                        />
                      </div>
                    )}
                  </div>

                  {/* Enforce Strong Passwords (Interactive Role Selector) */}
                  <div className="wcp-firewall-rule-card" style={{ padding: '12px' }}>
                    <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: '12px' }}>
                      <label style={{ display: 'flex', alignItems: 'flex-start', gap: '10px', cursor: 'pointer', flex: 1, margin: 0 }}>
                        <input
                          type="checkbox"
                          checked={wafSettings.waf_enforce_strong_passwords}
                          onChange={(e) => setWafSettings({ ...wafSettings, waf_enforce_strong_passwords: e.target.checked })}
                          style={{ accentColor: '#7c3aed', marginTop: '3px' }}
                        />
                        <div>
                          <div style={{ display: 'flex', alignItems: 'center', gap: '8px', flexWrap: 'wrap' }}>
                            <span style={{
                              fontSize: '11px',
                              fontWeight: 700,
                              fontFamily: 'monospace',
                              color: '#7c3aed',
                              background: 'rgba(124, 58, 237, 0.08)',
                              border: '1px solid rgba(124, 58, 237, 0.25)',
                              padding: '1px 6px',
                              borderRadius: '4px',
                              letterSpacing: '0.02em',
                              lineHeight: '1.4'
                            }}>
                              #23
                            </span>
                            <strong style={{ fontSize: '13px', color: 'var(--wcp-text-primary, #0f172a)' }}>Enforce Strong Passwords</strong>
                          </div>
                          <div style={{ fontSize: '11px', color: 'var(--wcp-text-muted, #64748b)', marginTop: '2px' }}>
                            Mandates 12+ characters, uppercase, lowercase, numbers, and symbols for specified roles.
                          </div>
                        </div>
                      </label>
                      <button
                        type="button"
                        className={`wcp-btn wcp-firewall-rule-save-btn ${savedSingleRuleSuccess['waf_enforce_strong_passwords'] ? 'is-saved' : ''}`}
                        onClick={() => {
                          handleSaveSingleRule('waf_enforce_strong_passwords', wafSettings.waf_enforce_strong_passwords);
                          handleSaveSingleRule('waf_strong_passwords_roles', wafSettings.waf_strong_passwords_roles);
                        }}
                        disabled={savingSingleRuleKey === 'waf_enforce_strong_passwords' || savingSingleRuleKey === 'waf_strong_passwords_roles'}
                      >
                        {savingSingleRuleKey === 'waf_enforce_strong_passwords' ? <Loader2 size={11} className="wcp-spin-icon" /> : (savedSingleRuleSuccess['waf_enforce_strong_passwords'] ? <Check size={11} /> : <Save size={11} />)}
                        {savedSingleRuleSuccess['waf_enforce_strong_passwords'] ? 'Saved' : 'Save'}
                      </button>
                    </div>

                    {wafSettings.waf_enforce_strong_passwords && (
                      <div style={{ marginTop: '12px', paddingTop: '10px', borderTop: '1px solid var(--wcp-border, #e2e8f0)' }}>
                        <label style={{ display: 'block', fontSize: '12px', fontWeight: 600, color: 'var(--wcp-text-primary, #0f172a)', marginBottom: '6px' }}>
                          Active Enforced User Roles:
                        </label>

                        {/* Active Role Badges */}
                        <div style={{ display: 'flex', flexWrap: 'wrap', gap: '6px', marginBottom: '10px' }}>
                          {wafSettings.waf_strong_passwords_roles
                            .split(',')
                            .map(r => r.trim().toLowerCase())
                            .filter(Boolean)
                            .map(roleSlug => {
                              const match = availableRoles.find(ar => ar.slug.toLowerCase() === roleSlug);
                              const displayName = match ? match.name : roleSlug.charAt(0).toUpperCase() + roleSlug.slice(1);
                              return (
                                <span
                                  key={roleSlug}
                                  className="wcp-firewall-role-chip"
                                >
                                  {displayName}
                                  <button
                                    type="button"
                                    onClick={() => {
                                      const currentList = wafSettings.waf_strong_passwords_roles
                                        .split(',')
                                        .map(r => r.trim())
                                        .filter(Boolean);
                                      const updatedList = currentList.filter(r => r.toLowerCase() !== roleSlug);
                                      setWafSettings({
                                        ...wafSettings,
                                        waf_strong_passwords_roles: updatedList.join(', ')
                                      });
                                    }}
                                    title={`Remove ${displayName}`}
                                    style={{
                                      background: 'transparent',
                                      border: 'none',
                                      cursor: 'pointer',
                                      padding: 0,
                                      display: 'flex',
                                      alignItems: 'center',
                                      color: 'inherit'
                                    }}
                                  >
                                    <X size={13} />
                                  </button>
                                </span>
                              );
                            })}
                        </div>

                        {/* Add Role Dropdown Picker */}
                        <div style={{ display: 'flex', alignItems: 'center', gap: '8px', flexWrap: 'wrap' }}>
                          <select
                            value={selectedRoleToAdd}
                            onChange={(e) => setSelectedRoleToAdd(e.target.value)}
                            className="wcp-firewall-select"
                            style={{ flex: 1, minWidth: '160px', padding: '6px 10px', fontSize: '12px' }}
                          >
                            <option value="">-- Select WordPress Role to Enforce --</option>
                            {availableRoles
                              .filter(ar => {
                                const currentList = wafSettings.waf_strong_passwords_roles
                                  .split(',')
                                  .map(r => r.trim().toLowerCase());
                                return !currentList.includes(ar.slug.toLowerCase());
                              })
                              .map(ar => (
                                <option key={ar.slug} value={ar.slug}>
                                  {ar.name} ({ar.slug})
                                </option>
                              ))}
                          </select>

                          <button
                            type="button"
                            className="wcp-btn"
                            disabled={!selectedRoleToAdd}
                            onClick={() => {
                              if (!selectedRoleToAdd) return;
                              const currentList = wafSettings.waf_strong_passwords_roles
                                .split(',')
                                .map(r => r.trim())
                                .filter(Boolean);
                              if (!currentList.map(r => r.toLowerCase()).includes(selectedRoleToAdd.toLowerCase())) {
                                currentList.push(selectedRoleToAdd);
                                setWafSettings({
                                  ...wafSettings,
                                  waf_strong_passwords_roles: currentList.join(', ')
                                });
                              }
                              setSelectedRoleToAdd('');
                            }}
                            style={{
                              display: 'inline-flex',
                              alignItems: 'center',
                              gap: '4px',
                              background: '#4f46e5',
                              color: '#fff',
                              fontSize: '12px',
                              padding: '6px 12px',
                              borderRadius: '6px'
                            }}
                          >
                            <Plus size={14} /> Add Role
                          </button>
                        </div>
                      </div>
                    )}
                  </div>

                  {/* Prevent Leaked Passwords */}
                  <div className="wcp-firewall-rule-card" style={{
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'space-between',
                    gap: '12px',
                    padding: '8px 12px'
                  }}>
                    <label style={{ display: 'flex', alignItems: 'flex-start', gap: '10px', cursor: 'pointer', flex: 1, margin: 0 }}>
                      <input
                        type="checkbox"
                        checked={wafSettings.waf_check_pwned_passwords}
                        onChange={(e) => setWafSettings({ ...wafSettings, waf_check_pwned_passwords: e.target.checked })}
                        style={{ accentColor: '#7c3aed', marginTop: '3px' }}
                      />
                      <div>
                        <div style={{ display: 'flex', alignItems: 'center', gap: '8px', flexWrap: 'wrap' }}>
                          <span style={{
                            fontSize: '11px',
                            fontWeight: 700,
                            fontFamily: 'monospace',
                            color: '#7c3aed',
                            background: 'rgba(124, 58, 237, 0.08)',
                            border: '1px solid rgba(124, 58, 237, 0.25)',
                            padding: '1px 6px',
                            borderRadius: '4px',
                            letterSpacing: '0.02em',
                            lineHeight: '1.4'
                          }}>
                            #24
                          </span>
                          <strong style={{ fontSize: '13px', color: 'var(--wcp-text-primary, #0f172a)' }}>Prevent Leaked Passwords (HaveIBeenPwned API)</strong>
                        </div>
                        <div style={{ fontSize: '11px', color: 'var(--wcp-text-muted, #64748b)', marginTop: '2px' }}>
                          Disallows passwords compromised in known data breaches using k-anonymity SHA-1 hash lookup.
                        </div>
                      </div>
                    </label>
                    <button
                      type="button"
                      className={`wcp-btn wcp-firewall-rule-save-btn ${savedSingleRuleSuccess['waf_check_pwned_passwords'] ? 'is-saved' : ''}`}
                      onClick={() => handleSaveSingleRule('waf_check_pwned_passwords', wafSettings.waf_check_pwned_passwords)}
                      disabled={savingSingleRuleKey === 'waf_check_pwned_passwords'}
                    >
                      {savingSingleRuleKey === 'waf_check_pwned_passwords' ? <Loader2 size={11} className="wcp-spin-icon" /> : (savedSingleRuleSuccess['waf_check_pwned_passwords'] ? <Check size={11} /> : <Save size={11} />)}
                      {savedSingleRuleSuccess['waf_check_pwned_passwords'] ? 'Saved' : 'Save'}
                    </button>
                  </div>
                </div>
              </div>

              {/* SECTION: Bot Recon, AI Scrapers & 404 Scanner Rate-Limiter */}
              <div className="wcp-firewall-section-group">
                <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '12px' }}>
                  <strong style={{ fontSize: '13px', textTransform: 'uppercase', letterSpacing: '0.04em', color: '#059669', display: 'flex', alignItems: 'center', gap: '6px' }}>
                    <Activity size={14} /> Bot Recon, AI Scrapers & 404 Scanner Rate-Limiter
                  </strong>
                </div>

                <div style={{ display: 'flex', flexDirection: 'column', gap: '10px' }}>
                  {/* Fake Search Crawler */}
                  <div className="wcp-firewall-rule-card" style={{
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'space-between',
                    gap: '12px',
                    padding: '8px 12px'
                  }}>
                    <label style={{ display: 'flex', alignItems: 'flex-start', gap: '10px', cursor: 'pointer', flex: 1, margin: 0 }}>
                      <input
                        type="checkbox"
                        checked={wafSettings.waf_block_fake_bots}
                        onChange={(e) => setWafSettings({ ...wafSettings, waf_block_fake_bots: e.target.checked })}
                        style={{ accentColor: '#059669', marginTop: '3px' }}
                      />
                      <div>
                        <div style={{ display: 'flex', alignItems: 'center', gap: '8px', flexWrap: 'wrap' }}>
                          <span style={{
                            fontSize: '11px',
                            fontWeight: 700,
                            fontFamily: 'monospace',
                            color: '#059669',
                            background: 'rgba(5, 150, 105, 0.08)',
                            border: '1px solid rgba(5, 150, 105, 0.25)',
                            padding: '1px 6px',
                            borderRadius: '4px',
                            letterSpacing: '0.02em',
                            lineHeight: '1.4'
                          }}>
                            #25
                          </span>
                          <strong style={{ fontSize: '13px', color: 'var(--wcp-text-primary, #0f172a)' }}>Fake Search Engine Crawler Defense</strong>
                        </div>
                        <div style={{ fontSize: '11px', color: 'var(--wcp-text-muted, #64748b)', marginTop: '2px' }}>
                          Reverse DNS PTR/A verification for Googlebot, Bingbot, and Slurp to drop imposter user-agents.
                        </div>
                      </div>
                    </label>
                    <button
                      type="button"
                      className={`wcp-btn wcp-firewall-rule-save-btn ${savedSingleRuleSuccess['waf_block_fake_bots'] ? 'is-saved' : ''}`}
                      onClick={() => handleSaveSingleRule('waf_block_fake_bots', wafSettings.waf_block_fake_bots)}
                      disabled={savingSingleRuleKey === 'waf_block_fake_bots'}
                    >
                      {savingSingleRuleKey === 'waf_block_fake_bots' ? <Loader2 size={11} className="wcp-spin-icon" /> : (savedSingleRuleSuccess['waf_block_fake_bots'] ? <Check size={11} /> : <Save size={11} />)}
                      {savedSingleRuleSuccess['waf_block_fake_bots'] ? 'Saved' : 'Save'}
                    </button>
                  </div>

                  {/* AI Scraper Block */}
                  <div className="wcp-firewall-rule-card" style={{
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'space-between',
                    gap: '12px',
                    padding: '8px 12px'
                  }}>
                    <label style={{ display: 'flex', alignItems: 'flex-start', gap: '10px', cursor: 'pointer', flex: 1, margin: 0 }}>
                      <input
                        type="checkbox"
                        checked={wafSettings.waf_block_ai_scrapers}
                        onChange={(e) => setWafSettings({ ...wafSettings, waf_block_ai_scrapers: e.target.checked })}
                        style={{ accentColor: '#059669', marginTop: '3px' }}
                      />
                      <div>
                        <div style={{ display: 'flex', alignItems: 'center', gap: '8px', flexWrap: 'wrap' }}>
                          <span style={{
                            fontSize: '11px',
                            fontWeight: 700,
                            fontFamily: 'monospace',
                            color: '#059669',
                            background: 'rgba(5, 150, 105, 0.08)',
                            border: '1px solid rgba(5, 150, 105, 0.25)',
                            padding: '1px 6px',
                            borderRadius: '4px',
                            letterSpacing: '0.02em',
                            lineHeight: '1.4'
                          }}>
                            #26
                          </span>
                          <strong style={{ fontSize: '13px', color: 'var(--wcp-text-primary, #0f172a)' }}>AI Harvester & Scraper Shield</strong>
                        </div>
                        <div style={{ fontSize: '11px', color: 'var(--wcp-text-muted, #64748b)', marginTop: '2px' }}>
                          Blocks LLM data miners (GPTBot, CCBot, Bytespider, ClaudeBot, PerplexityBot) from content harvesting.
                        </div>
                      </div>
                    </label>
                    <button
                      type="button"
                      className={`wcp-btn wcp-firewall-rule-save-btn ${savedSingleRuleSuccess['waf_block_ai_scrapers'] ? 'is-saved' : ''}`}
                      onClick={() => handleSaveSingleRule('waf_block_ai_scrapers', wafSettings.waf_block_ai_scrapers)}
                      disabled={savingSingleRuleKey === 'waf_block_ai_scrapers'}
                    >
                      {savingSingleRuleKey === 'waf_block_ai_scrapers' ? <Loader2 size={11} className="wcp-spin-icon" /> : (savedSingleRuleSuccess['waf_block_ai_scrapers'] ? <Check size={11} /> : <Save size={11} />)}
                      {savedSingleRuleSuccess['waf_block_ai_scrapers'] ? 'Saved' : 'Save'}
                    </button>
                  </div>

                  {/* Virtual Robots AI */}
                  <div className="wcp-firewall-rule-card" style={{
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'space-between',
                    gap: '12px',
                    padding: '8px 12px'
                  }}>
                    <label style={{ display: 'flex', alignItems: 'flex-start', gap: '10px', cursor: 'pointer', flex: 1, margin: 0 }}>
                      <input
                        type="checkbox"
                        checked={wafSettings.waf_dynamic_robots_ai}
                        onChange={(e) => setWafSettings({ ...wafSettings, waf_dynamic_robots_ai: e.target.checked })}
                        style={{ accentColor: '#059669', marginTop: '3px' }}
                      />
                      <div>
                        <div style={{ display: 'flex', alignItems: 'center', gap: '8px', flexWrap: 'wrap' }}>
                          <span style={{
                            fontSize: '11px',
                            fontWeight: 700,
                            fontFamily: 'monospace',
                            color: '#059669',
                            background: 'rgba(5, 150, 105, 0.08)',
                            border: '1px solid rgba(5, 150, 105, 0.25)',
                            padding: '1px 6px',
                            borderRadius: '4px',
                            letterSpacing: '0.02em',
                            lineHeight: '1.4'
                          }}>
                            #27
                          </span>
                          <strong style={{ fontSize: '13px', color: 'var(--wcp-text-primary, #0f172a)' }}>Inject AI Disallow Directives in robots.txt</strong>
                        </div>
                        <div style={{ fontSize: '11px', color: 'var(--wcp-text-muted, #64748b)', marginTop: '2px' }}>
                          Adds Disallow rules for compliant crawler bots directly into virtual robots.txt.
                        </div>
                      </div>
                    </label>
                    <button
                      type="button"
                      className={`wcp-btn wcp-firewall-rule-save-btn ${savedSingleRuleSuccess['waf_dynamic_robots_ai'] ? 'is-saved' : ''}`}
                      onClick={() => handleSaveSingleRule('waf_dynamic_robots_ai', wafSettings.waf_dynamic_robots_ai)}
                      disabled={savingSingleRuleKey === 'waf_dynamic_robots_ai'}
                    >
                      {savingSingleRuleKey === 'waf_dynamic_robots_ai' ? <Loader2 size={11} className="wcp-spin-icon" /> : (savedSingleRuleSuccess['waf_dynamic_robots_ai'] ? <Check size={11} /> : <Save size={11} />)}
                      {savedSingleRuleSuccess['waf_dynamic_robots_ai'] ? 'Saved' : 'Save'}
                    </button>
                  </div>

                  {/* 404 Scanner Rate Limiter */}
                  <div className="wcp-firewall-rule-card" style={{ padding: '12px' }}>
                    <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: '12px' }}>
                      <label style={{ display: 'flex', alignItems: 'flex-start', gap: '10px', cursor: 'pointer', flex: 1, margin: 0 }}>
                        <input
                          type="checkbox"
                          checked={wafSettings.waf_block_404_scanners}
                          onChange={(e) => setWafSettings({ ...wafSettings, waf_block_404_scanners: e.target.checked })}
                          style={{ accentColor: '#059669', marginTop: '3px' }}
                        />
                        <div>
                          <div style={{ display: 'flex', alignItems: 'center', gap: '8px', flexWrap: 'wrap' }}>
                            <span style={{
                              fontSize: '11px',
                              fontWeight: 700,
                              fontFamily: 'monospace',
                              color: '#059669',
                              background: 'rgba(5, 150, 105, 0.08)',
                              border: '1px solid rgba(5, 150, 105, 0.25)',
                              padding: '1px 6px',
                              borderRadius: '4px',
                              letterSpacing: '0.02em',
                              lineHeight: '1.4'
                            }}>
                              #28
                            </span>
                            <strong style={{ fontSize: '13px', color: 'var(--wcp-text-primary, #0f172a)' }}>Smart 404 Scanner Rate-Limiter</strong>
                          </div>
                          <div style={{ fontSize: '11px', color: 'var(--wcp-text-muted, #64748b)', marginTop: '2px' }}>
                            Enforces temporary lockout on IPs triggering rapid 404 scans (verified bots like Googlebot are exempt).
                          </div>
                        </div>
                      </label>
                      <button
                        type="button"
                        className={`wcp-btn wcp-firewall-rule-save-btn ${savedSingleRuleSuccess['waf_block_404_scanners'] ? 'is-saved' : ''}`}
                        onClick={() => {
                          handleSaveSingleRule('waf_block_404_scanners', wafSettings.waf_block_404_scanners);
                          handleSaveSingleRule('waf_404_threshold', wafSettings.waf_404_threshold);
                          handleSaveSingleRule('waf_404_window_seconds', wafSettings.waf_404_window_seconds);
                          handleSaveSingleRule('waf_404_lockout_duration', wafSettings.waf_404_lockout_duration);
                        }}
                        disabled={savingSingleRuleKey === 'waf_block_404_scanners'}
                      >
                        {savingSingleRuleKey === 'waf_block_404_scanners' ? <Loader2 size={11} className="wcp-spin-icon" /> : (savedSingleRuleSuccess['waf_block_404_scanners'] ? <Check size={11} /> : <Save size={11} />)}
                        {savedSingleRuleSuccess['waf_block_404_scanners'] ? 'Saved' : 'Save'}
                      </button>
                    </div>

                    {wafSettings.waf_block_404_scanners && (
                      <div style={{
                        marginTop: '10px',
                        paddingTop: '10px',
                        borderTop: '1px solid var(--wcp-border, #e2e8f0)',
                        display: 'grid',
                        gridTemplateColumns: 'repeat(auto-fit, minmax(130px, 1fr))',
                        gap: '12px'
                      }}>
                        <div>
                          <label style={{ display: 'block', fontSize: '11px', fontWeight: 600, color: 'var(--wcp-text-muted, #64748b)', marginBottom: '4px' }}>
                            404 Threshold (Probes)
                          </label>
                          <input
                            type="number"
                            min={3}
                            max={100}
                            value={wafSettings.waf_404_threshold}
                            onChange={(e) => setWafSettings({ ...wafSettings, waf_404_threshold: Math.max(3, Number(e.target.value)) })}
                            className="wcp-input"
                            style={{ width: '100%', fontSize: '12px', padding: '5px 8px' }}
                          />
                        </div>

                        <div>
                          <label style={{ display: 'block', fontSize: '11px', fontWeight: 600, color: 'var(--wcp-text-muted, #64748b)', marginBottom: '4px' }}>
                            Time Window (Seconds)
                          </label>
                          <input
                            type="number"
                            min={10}
                            max={600}
                            value={wafSettings.waf_404_window_seconds}
                            onChange={(e) => setWafSettings({ ...wafSettings, waf_404_window_seconds: Math.max(10, Number(e.target.value)) })}
                            className="wcp-input"
                            style={{ width: '100%', fontSize: '12px', padding: '5px 8px' }}
                          />
                        </div>

                        <div>
                          <label style={{ display: 'block', fontSize: '11px', fontWeight: 600, color: 'var(--wcp-text-muted, #64748b)', marginBottom: '4px' }}>
                            Lockout Period (Minutes)
                          </label>
                          <input
                            type="number"
                            min={1}
                            max={1440}
                            value={wafSettings.waf_404_lockout_duration}
                            onChange={(e) => setWafSettings({ ...wafSettings, waf_404_lockout_duration: Math.max(1, Number(e.target.value)) })}
                            className="wcp-input"
                            style={{ width: '100%', fontSize: '12px', padding: '5px 8px' }}
                          />
                        </div>
                      </div>
                    )}
                  </div>
                </div>
              </div>

              {/* SECTION: Advanced API, Protocol & Abuse Defense */}
              <div className="wcp-firewall-section-group">
                <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '12px' }}>
                  <strong style={{ fontSize: '13px', textTransform: 'uppercase', letterSpacing: '0.04em', color: '#4f46e5', display: 'flex', alignItems: 'center', gap: '6px' }}>
                    <ShieldAlert size={14} /> Advanced API, Protocol & Abuse Defense
                  </strong>
                </div>

                <div style={{ display: 'flex', flexDirection: 'column', gap: '10px' }}>
                  {/* Rule #29: REST API User Enumeration Interceptor */}
                  <div className="wcp-firewall-rule-card" style={{
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'space-between',
                    gap: '12px',
                    padding: '8px 12px'
                  }}>
                    <label style={{ display: 'flex', alignItems: 'flex-start', gap: '10px', cursor: 'pointer', flex: 1, margin: 0 }}>
                      <input
                        type="checkbox"
                        checked={wafSettings.waf_block_rest_user_enum}
                        onChange={(e) => setWafSettings({ ...wafSettings, waf_block_rest_user_enum: e.target.checked })}
                        style={{ accentColor: '#4f46e5', marginTop: '3px' }}
                      />
                      <div>
                        <div style={{ display: 'flex', alignItems: 'center', gap: '8px', flexWrap: 'wrap' }}>
                          <span style={{
                            fontSize: '11px',
                            fontWeight: 700,
                            fontFamily: 'monospace',
                            color: '#4f46e5',
                            background: 'rgba(79, 70, 229, 0.08)',
                            border: '1px solid rgba(79, 70, 229, 0.25)',
                            padding: '1px 6px',
                            borderRadius: '4px',
                            letterSpacing: '0.02em',
                            lineHeight: '1.4'
                          }}>
                            #29
                          </span>
                          <strong style={{ fontSize: '13px', color: 'var(--wcp-text-primary, #0f172a)' }}>REST API User Enumeration Interceptor</strong>
                        </div>
                        <div style={{ fontSize: '11px', color: 'var(--wcp-text-muted, #64748b)', marginTop: '2px' }}>
                          Blocks unauthenticated GET queries to <code>/wp/v2/users</code> and <code>?rest_route=/wp/v2/users</code> (allows <code>users/me</code> for logged-in users).
                        </div>
                      </div>
                    </label>
                    <button
                      type="button"
                      className={`wcp-btn wcp-firewall-rule-save-btn ${savedSingleRuleSuccess['waf_block_rest_user_enum'] ? 'is-saved' : ''}`}
                      onClick={() => handleSaveSingleRule('waf_block_rest_user_enum', wafSettings.waf_block_rest_user_enum)}
                      disabled={savingSingleRuleKey === 'waf_block_rest_user_enum'}
                    >
                      {savingSingleRuleKey === 'waf_block_rest_user_enum' ? <Loader2 size={11} className="wcp-spin-icon" /> : (savedSingleRuleSuccess['waf_block_rest_user_enum'] ? <Check size={11} /> : <Save size={11} />)}
                      {savedSingleRuleSuccess['waf_block_rest_user_enum'] ? 'Saved' : 'Save'}
                    </button>
                  </div>

                  {/* Rule #30: Author Permalink Query Suppression */}
                  <div className="wcp-firewall-rule-card" style={{
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'space-between',
                    gap: '12px',
                    padding: '8px 12px'
                  }}>
                    <label style={{ display: 'flex', alignItems: 'flex-start', gap: '10px', cursor: 'pointer', flex: 1, margin: 0 }}>
                      <input
                        type="checkbox"
                        checked={wafSettings.waf_block_author_scan}
                        onChange={(e) => setWafSettings({ ...wafSettings, waf_block_author_scan: e.target.checked })}
                        style={{ accentColor: '#4f46e5', marginTop: '3px' }}
                      />
                      <div>
                        <div style={{ display: 'flex', alignItems: 'center', gap: '8px', flexWrap: 'wrap' }}>
                          <span style={{
                            fontSize: '11px',
                            fontWeight: 700,
                            fontFamily: 'monospace',
                            color: '#4f46e5',
                            background: 'rgba(79, 70, 229, 0.08)',
                            border: '1px solid rgba(79, 70, 229, 0.25)',
                            padding: '1px 6px',
                            borderRadius: '4px',
                            letterSpacing: '0.02em',
                            lineHeight: '1.4'
                          }}>
                            #30
                          </span>
                          <strong style={{ fontSize: '13px', color: 'var(--wcp-text-primary, #0f172a)' }}>Author Permalink Query Suppression</strong>
                        </div>
                        <div style={{ fontSize: '11px', color: 'var(--wcp-text-muted, #64748b)', marginTop: '2px' }}>
                          Intercepts query scans like <code>/?author=1</code> for unauthenticated visitors and redirects cleanly to home without leaking author slugs.
                        </div>
                      </div>
                    </label>
                    <button
                      type="button"
                      className={`wcp-btn wcp-firewall-rule-save-btn ${savedSingleRuleSuccess['waf_block_author_scan'] ? 'is-saved' : ''}`}
                      onClick={() => handleSaveSingleRule('waf_block_author_scan', wafSettings.waf_block_author_scan)}
                      disabled={savingSingleRuleKey === 'waf_block_author_scan'}
                    >
                      {savingSingleRuleKey === 'waf_block_author_scan' ? <Loader2 size={11} className="wcp-spin-icon" /> : (savedSingleRuleSuccess['waf_block_author_scan'] ? <Check size={11} /> : <Save size={11} />)}
                      {savedSingleRuleSuccess['waf_block_author_scan'] ? 'Saved' : 'Save'}
                    </button>
                  </div>

                  {/* Rule #31: Lost-Password & Auth Flood Guard */}
                  <div className="wcp-firewall-rule-card" style={{
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'space-between',
                    gap: '12px',
                    padding: '8px 12px'
                  }}>
                    <label style={{ display: 'flex', alignItems: 'flex-start', gap: '10px', cursor: 'pointer', flex: 1, margin: 0 }}>
                      <input
                        type="checkbox"
                        checked={wafSettings.waf_limit_lostpassword}
                        onChange={(e) => setWafSettings({ ...wafSettings, waf_limit_lostpassword: e.target.checked })}
                        style={{ accentColor: '#4f46e5', marginTop: '3px' }}
                      />
                      <div>
                        <div style={{ display: 'flex', alignItems: 'center', gap: '8px', flexWrap: 'wrap' }}>
                          <span style={{
                            fontSize: '11px',
                            fontWeight: 700,
                            fontFamily: 'monospace',
                            color: '#4f46e5',
                            background: 'rgba(79, 70, 229, 0.08)',
                            border: '1px solid rgba(79, 70, 229, 0.25)',
                            padding: '1px 6px',
                            borderRadius: '4px',
                            letterSpacing: '0.02em',
                            lineHeight: '1.4'
                          }}>
                            #31
                          </span>
                          <strong style={{ fontSize: '13px', color: 'var(--wcp-text-primary, #0f172a)' }}>Lost-Password & Auth Flood Guard</strong>
                        </div>
                        <div style={{ fontSize: '11px', color: 'var(--wcp-text-muted, #64748b)', marginTop: '2px' }}>
                          Limits password reset submissions to max 3 per 15 minutes per IP and per target username to prevent email quota burn and user spam.
                        </div>
                      </div>
                    </label>
                    <button
                      type="button"
                      className={`wcp-btn wcp-firewall-rule-save-btn ${savedSingleRuleSuccess['waf_limit_lostpassword'] ? 'is-saved' : ''}`}
                      onClick={() => handleSaveSingleRule('waf_limit_lostpassword', wafSettings.waf_limit_lostpassword)}
                      disabled={savingSingleRuleKey === 'waf_limit_lostpassword'}
                    >
                      {savingSingleRuleKey === 'waf_limit_lostpassword' ? <Loader2 size={11} className="wcp-spin-icon" /> : (savedSingleRuleSuccess['waf_limit_lostpassword'] ? <Check size={11} /> : <Save size={11} />)}
                      {savedSingleRuleSuccess['waf_limit_lostpassword'] ? 'Saved' : 'Save'}
                    </button>
                  </div>

                  {/* Rule #32: Strict Host Header Allowlist */}
                  <div className="wcp-firewall-rule-card" style={{ padding: '12px' }}>
                    <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: '12px' }}>
                      <label style={{ display: 'flex', alignItems: 'flex-start', gap: '10px', cursor: 'pointer', flex: 1, margin: 0 }}>
                        <input
                          type="checkbox"
                          checked={wafSettings.waf_enforce_host_allowlist}
                          onChange={(e) => setWafSettings({ ...wafSettings, waf_enforce_host_allowlist: e.target.checked })}
                          style={{ accentColor: '#4f46e5', marginTop: '3px' }}
                        />
                        <div>
                          <div style={{ display: 'flex', alignItems: 'center', gap: '8px', flexWrap: 'wrap' }}>
                            <span style={{
                              fontSize: '11px',
                              fontWeight: 700,
                              fontFamily: 'monospace',
                              color: '#4f46e5',
                              background: 'rgba(79, 70, 229, 0.08)',
                              border: '1px solid rgba(79, 70, 229, 0.25)',
                              padding: '1px 6px',
                              borderRadius: '4px',
                              letterSpacing: '0.02em',
                              lineHeight: '1.4'
                            }}>
                              #32
                            </span>
                            <strong style={{ fontSize: '13px', color: 'var(--wcp-text-primary, #0f172a)' }}>Strict Host Header Allowlist</strong>
                          </div>
                          <div style={{ fontSize: '11px', color: 'var(--wcp-text-muted, #64748b)', marginTop: '2px' }}>
                            Enforces <code>HTTP_HOST</code> and <code>X-Forwarded-Host</code> validation against WordPress site URL to prevent cache and password-reset poisoning.
                          </div>
                        </div>
                      </label>
                      <button
                        type="button"
                        className={`wcp-btn wcp-firewall-rule-save-btn ${(savedSingleRuleSuccess['waf_enforce_host_allowlist'] || savedSingleRuleSuccess['waf_allowed_host_aliases']) ? 'is-saved' : ''}`}
                        onClick={() => {
                          handleSaveSingleRule('waf_enforce_host_allowlist', wafSettings.waf_enforce_host_allowlist);
                          handleSaveSingleRule('waf_allowed_host_aliases', wafSettings.waf_allowed_host_aliases);
                        }}
                        disabled={savingSingleRuleKey === 'waf_enforce_host_allowlist' || savingSingleRuleKey === 'waf_allowed_host_aliases'}
                      >
                        {savingSingleRuleKey === 'waf_enforce_host_allowlist' ? <Loader2 size={11} className="wcp-spin-icon" /> : ((savedSingleRuleSuccess['waf_enforce_host_allowlist'] || savedSingleRuleSuccess['waf_allowed_host_aliases']) ? <Check size={11} /> : <Save size={11} />)}
                        {(savedSingleRuleSuccess['waf_enforce_host_allowlist'] || savedSingleRuleSuccess['waf_allowed_host_aliases']) ? 'Saved' : 'Save'}
                      </button>
                    </div>

                    {wafSettings.waf_enforce_host_allowlist && (
                      <div style={{ marginTop: '10px', paddingTop: '10px', borderTop: '1px solid var(--wcp-border, #e2e8f0)' }}>
                        <label style={{ display: 'block', fontSize: '11px', fontWeight: 600, color: 'var(--wcp-text-muted, #64748b)', marginBottom: '4px' }}>
                          Additional Allowed Hostnames / Aliases (one per line, e.g. staging.example.com):
                        </label>
                        <textarea
                          rows={2}
                          value={wafSettings.waf_allowed_host_aliases}
                          onChange={(e) => setWafSettings({ ...wafSettings, waf_allowed_host_aliases: e.target.value })}
                          className="wcp-firewall-textarea"
                          style={{ width: '100%', fontSize: '12px', fontFamily: 'monospace', padding: '6px 8px' }}
                          placeholder="staging.mysite.com&#10;app.mysite.com"
                        />
                      </div>
                    )}
                  </div>

                  {/* Rule #33: admin-ajax.php Burst Rate-Limiter */}
                  <div className="wcp-firewall-rule-card" style={{ padding: '12px' }}>
                    <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: '12px' }}>
                      <label style={{ display: 'flex', alignItems: 'flex-start', gap: '10px', cursor: 'pointer', flex: 1, margin: 0 }}>
                        <input
                          type="checkbox"
                          checked={wafSettings.waf_limit_admin_ajax}
                          onChange={(e) => setWafSettings({ ...wafSettings, waf_limit_admin_ajax: e.target.checked })}
                          style={{ accentColor: '#4f46e5', marginTop: '3px' }}
                        />
                        <div>
                          <div style={{ display: 'flex', alignItems: 'center', gap: '8px', flexWrap: 'wrap' }}>
                            <span style={{
                              fontSize: '11px',
                              fontWeight: 700,
                              fontFamily: 'monospace',
                              color: '#4f46e5',
                              background: 'rgba(79, 70, 229, 0.08)',
                              border: '1px solid rgba(79, 70, 229, 0.25)',
                              padding: '1px 6px',
                              borderRadius: '4px',
                              letterSpacing: '0.02em',
                              lineHeight: '1.4'
                            }}>
                              #33
                            </span>
                            <strong style={{ fontSize: '13px', color: 'var(--wcp-text-primary, #0f172a)' }}>admin-ajax.php Unauthenticated Burst Guard</strong>
                          </div>
                          <div style={{ fontSize: '11px', color: 'var(--wcp-text-muted, #64748b)', marginTop: '2px' }}>
                            Restricts rapid unauthenticated AJAX flooding (WooCommerce customer cart actions automatically exempt).
                          </div>
                        </div>
                      </label>
                      <button
                        type="button"
                        className={`wcp-btn wcp-firewall-rule-save-btn ${(savedSingleRuleSuccess['waf_limit_admin_ajax'] || savedSingleRuleSuccess['waf_admin_ajax_limit_per_min']) ? 'is-saved' : ''}`}
                        onClick={() => {
                          handleSaveSingleRule('waf_limit_admin_ajax', wafSettings.waf_limit_admin_ajax);
                          handleSaveSingleRule('waf_admin_ajax_limit_per_min', wafSettings.waf_admin_ajax_limit_per_min);
                        }}
                        disabled={savingSingleRuleKey === 'waf_limit_admin_ajax' || savingSingleRuleKey === 'waf_admin_ajax_limit_per_min'}
                      >
                        {savingSingleRuleKey === 'waf_limit_admin_ajax' ? <Loader2 size={11} className="wcp-spin-icon" /> : ((savedSingleRuleSuccess['waf_limit_admin_ajax'] || savedSingleRuleSuccess['waf_admin_ajax_limit_per_min']) ? <Check size={11} /> : <Save size={11} />)}
                        {(savedSingleRuleSuccess['waf_limit_admin_ajax'] || savedSingleRuleSuccess['waf_admin_ajax_limit_per_min']) ? 'Saved' : 'Save'}
                      </button>
                    </div>

                    {wafSettings.waf_limit_admin_ajax && (
                      <div style={{ marginTop: '10px', paddingTop: '10px', borderTop: '1px solid var(--wcp-border, #e2e8f0)', display: 'flex', alignItems: 'center', gap: '12px' }}>
                        <label style={{ fontSize: '11px', fontWeight: 600, color: 'var(--wcp-text-muted, #64748b)' }}>
                          Max Unauthenticated Requests / Minute:
                        </label>
                        <input
                          type="number"
                          min={10}
                          max={300}
                          value={wafSettings.waf_admin_ajax_limit_per_min}
                          onChange={(e) => setWafSettings({ ...wafSettings, waf_admin_ajax_limit_per_min: Math.max(10, Number(e.target.value)) })}
                          className="wcp-input"
                          style={{ width: '90px', fontSize: '12px', padding: '4px 8px' }}
                        />
                      </div>
                    )}
                  </div>

                  {/* Rule #34: Oversized Request Buffer & Payload Guard */}
                  <div className="wcp-firewall-rule-card" style={{
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'space-between',
                    gap: '12px',
                    padding: '8px 12px'
                  }}>
                    <label style={{ display: 'flex', alignItems: 'flex-start', gap: '10px', cursor: 'pointer', flex: 1, margin: 0 }}>
                      <input
                        type="checkbox"
                        checked={wafSettings.waf_block_oversized_requests}
                        onChange={(e) => setWafSettings({ ...wafSettings, waf_block_oversized_requests: e.target.checked })}
                        style={{ accentColor: '#4f46e5', marginTop: '3px' }}
                      />
                      <div>
                        <div style={{ display: 'flex', alignItems: 'center', gap: '8px', flexWrap: 'wrap' }}>
                          <span style={{
                            fontSize: '11px',
                            fontWeight: 700,
                            fontFamily: 'monospace',
                            color: '#4f46e5',
                            background: 'rgba(79, 70, 229, 0.08)',
                            border: '1px solid rgba(79, 70, 229, 0.25)',
                            padding: '1px 6px',
                            borderRadius: '4px',
                            letterSpacing: '0.02em',
                            lineHeight: '1.4'
                          }}>
                            #34
                          </span>
                          <strong style={{ fontSize: '13px', color: 'var(--wcp-text-primary, #0f172a)' }}>Oversized Request Buffer & Payload Guard</strong>
                        </div>
                        <div style={{ fontSize: '11px', color: 'var(--wcp-text-muted, #64748b)', marginTop: '2px' }}>
                          Prevents buffer overflow & parameter flooding (URI &gt; 2048, Query &gt; 1024, POST vars &gt; 1000; media uploads safely exempt).
                        </div>
                      </div>
                    </label>
                    <button
                      type="button"
                      className={`wcp-btn wcp-firewall-rule-save-btn ${savedSingleRuleSuccess['waf_block_oversized_requests'] ? 'is-saved' : ''}`}
                      onClick={() => handleSaveSingleRule('waf_block_oversized_requests', wafSettings.waf_block_oversized_requests)}
                      disabled={savingSingleRuleKey === 'waf_block_oversized_requests'}
                    >
                      {savingSingleRuleKey === 'waf_block_oversized_requests' ? <Loader2 size={11} className="wcp-spin-icon" /> : (savedSingleRuleSuccess['waf_block_oversized_requests'] ? <Check size={11} /> : <Save size={11} />)}
                      {savedSingleRuleSuccess['waf_block_oversized_requests'] ? 'Saved' : 'Save'}
                    </button>
                  </div>

                  {/* Rule #35: AI Prompt Injection & Agent Poisoning Shield */}
                  <div className="wcp-firewall-rule-card" style={{
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'space-between',
                    gap: '12px',
                    padding: '8px 12px'
                  }}>
                    <label style={{ display: 'flex', alignItems: 'flex-start', gap: '10px', cursor: 'pointer', flex: 1, margin: 0 }}>
                      <input
                        type="checkbox"
                        checked={wafSettings.waf_block_ai_prompt_injection}
                        onChange={(e) => setWafSettings({ ...wafSettings, waf_block_ai_prompt_injection: e.target.checked })}
                        style={{ accentColor: '#4f46e5', marginTop: '3px' }}
                      />
                      <div>
                        <div style={{ display: 'flex', alignItems: 'center', gap: '8px', flexWrap: 'wrap' }}>
                          <span style={{
                            fontSize: '11px',
                            fontWeight: 700,
                            fontFamily: 'monospace',
                            color: '#7c3aed',
                            background: 'rgba(124, 58, 237, 0.08)',
                            border: '1px solid rgba(124, 58, 237, 0.25)',
                            padding: '1px 6px',
                            borderRadius: '4px',
                            letterSpacing: '0.02em',
                            lineHeight: '1.4'
                          }}>
                            #35
                          </span>
                          <strong style={{ fontSize: '13px', color: 'var(--wcp-text-primary, #0f172a)' }}>AI Prompt Injection &amp; Agent Poisoning Shield</strong>
                          <span style={{
                            fontSize: '10px',
                            fontWeight: 700,
                            padding: '1px 7px',
                            borderRadius: '10px',
                            background: 'rgba(124, 58, 237, 0.12)',
                            color: '#7c3aed',
                            border: '1px solid rgba(124, 58, 237, 0.25)'
                          }}>
                            AI Shield
                          </span>
                        </div>
                        <div style={{ fontSize: '11px', color: 'var(--wcp-text-muted, #64748b)', marginTop: '2px' }}>
                          Neutralizes adversarial LLM jailbreaks, system instruction overrides (&ldquo;ignore previous instructions&rdquo;, &ldquo;reveal prompt&rdquo;), and payload hijacking targeting AI tools &amp; MCP agents.
                        </div>
                      </div>
                    </label>
                    <button
                      type="button"
                      className={`wcp-btn wcp-firewall-rule-save-btn ${savedSingleRuleSuccess['waf_block_ai_prompt_injection'] ? 'is-saved' : ''}`}
                      onClick={() => handleSaveSingleRule('waf_block_ai_prompt_injection', wafSettings.waf_block_ai_prompt_injection)}
                      disabled={savingSingleRuleKey === 'waf_block_ai_prompt_injection'}
                    >
                      {savingSingleRuleKey === 'waf_block_ai_prompt_injection' ? <Loader2 size={11} className="wcp-spin-icon" /> : (savedSingleRuleSuccess['waf_block_ai_prompt_injection'] ? <Check size={11} /> : <Save size={11} />)}
                      {savedSingleRuleSuccess['waf_block_ai_prompt_injection'] ? 'Saved' : 'Save'}
                    </button>
                  </div>

                  {/* Rule #36 & #37: Guest admin-ajax.php / admin-post.php & REST Action Matrix */}
                  <div className="wcp-firewall-rule-card" style={{ padding: '14px', marginTop: '12px', borderLeft: '3px solid #0284c7' }}>
                    <div style={{ display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between', gap: '12px' }}>
                      <div style={{ flex: 1 }}>
                        <div style={{ display: 'flex', alignItems: 'center', gap: '8px', flexWrap: 'wrap' }}>
                          <span style={{
                            fontSize: '11px',
                            fontWeight: 700,
                            fontFamily: 'monospace',
                            color: '#0284c7',
                            background: 'rgba(2, 132, 199, 0.08)',
                            border: '1px solid rgba(2, 132, 199, 0.25)',
                            padding: '1px 6px',
                            borderRadius: '4px',
                            letterSpacing: '0.02em',
                            lineHeight: '1.4'
                          }}>
                            #36 &amp; #37
                          </span>
                          <strong style={{ fontSize: '13px', color: 'var(--wcp-text-primary, #0f172a)' }}>
                            Guest admin-ajax.php &amp; REST Endpoint Security Matrix
                          </strong>
                          <span style={{
                            fontSize: '10px',
                            fontWeight: 700,
                            textTransform: 'uppercase',
                            padding: '1px 7px',
                            borderRadius: '10px',
                            background: 'rgba(2, 132, 199, 0.12)',
                            color: '#0284c7',
                            border: '1px solid rgba(2, 132, 199, 0.25)'
                          }}>
                            Next-Gen WAF
                          </span>
                        </div>
                        <div style={{ fontSize: '11px', color: 'var(--wcp-text-muted, #64748b)', marginTop: '4px', lineHeight: '1.5' }}>
                          Evaluates unauthenticated visitors hitting <code>admin-ajax.php</code>, <code>admin-post.php</code>, and REST API mutation routes. Tier 1 core actions (WooCommerce cart, checkout, supported form plugins, search) are always permitted.
                        </div>
                      </div>

                      <button
                        type="button"
                        className={`wcp-btn wcp-firewall-rule-save-btn ${(savedSingleRuleSuccess['waf_guest_ajax_policy'] || savedSingleRuleSuccess['waf_guest_ajax_custom_allowlist'] || savedSingleRuleSuccess['waf_guest_rest_policy']) ? 'is-saved' : ''}`}
                        onClick={() => {
                          handleSaveSingleRule('waf_guest_ajax_policy', wafSettings.waf_guest_ajax_policy);
                          handleSaveSingleRule('waf_guest_ajax_custom_allowlist', wafSettings.waf_guest_ajax_custom_allowlist);
                          handleSaveSingleRule('waf_guest_rest_policy', wafSettings.waf_guest_rest_policy);
                        }}
                        disabled={savingSingleRuleKey === 'waf_guest_ajax_policy' || savingSingleRuleKey === 'waf_guest_ajax_custom_allowlist' || savingSingleRuleKey === 'waf_guest_rest_policy'}
                      >
                        {(savingSingleRuleKey === 'waf_guest_ajax_policy' || savingSingleRuleKey === 'waf_guest_ajax_custom_allowlist' || savingSingleRuleKey === 'waf_guest_rest_policy') ? (
                          <Loader2 size={11} className="wcp-spin-icon" />
                        ) : ((savedSingleRuleSuccess['waf_guest_ajax_policy'] || savedSingleRuleSuccess['waf_guest_ajax_custom_allowlist'] || savedSingleRuleSuccess['waf_guest_rest_policy']) ? <Check size={11} /> : <Save size={11} />)}
                        {(savedSingleRuleSuccess['waf_guest_ajax_policy'] || savedSingleRuleSuccess['waf_guest_ajax_custom_allowlist'] || savedSingleRuleSuccess['waf_guest_rest_policy']) ? 'Saved' : 'Save'}
                      </button>
                    </div>

                    {/* Policy Selectors & Custom Allowlist */}
                    <div style={{ marginTop: '14px', display: 'flex', flexDirection: 'column', gap: '12px', borderTop: '1px solid var(--wcp-border, #e2e8f0)', paddingTop: '12px' }}>
                      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(260px, 1fr))', gap: '12px' }}>
                        <div>
                          <label style={{ fontSize: '11px', fontWeight: 600, color: 'var(--wcp-text-primary, #0f172a)', display: 'block', marginBottom: '4px' }}>
                            Guest AJAX Action Policy (Rule #36):
                          </label>
                          <select
                            value={wafSettings.waf_guest_ajax_policy}
                            onChange={(e) => setWafSettings({ ...wafSettings, waf_guest_ajax_policy: e.target.value as 'monitor' | 'block' | 'off' })}
                            className="wcp-input"
                            style={{ width: '100%', fontSize: '12px', padding: '6px 10px' }}
                          >
                            <option value="monitor">Monitor &amp; Record Telemetry (Recommended - Safe Baselining)</option>
                            <option value="block">Strict Block (Terminates Unknown Guest AJAX Probes with HTTP 403)</option>
                            <option value="off">Disabled (Allow All Guest AJAX Probes)</option>
                          </select>
                          <span style={{ fontSize: '10px', color: 'var(--wcp-text-muted, #64748b)', marginTop: '2px', display: 'block' }}>
                            {wafSettings.waf_guest_ajax_policy === 'monitor' && 'Records unauthorized/unknown guest actions into WAF logs with status "monitored" without dropping legitimate traffic.'}
                            {wafSettings.waf_guest_ajax_policy === 'block' && 'Terminates any unregistered guest action or empty action with HTTP 403 / 400.'}
                            {wafSettings.waf_guest_ajax_policy === 'off' && 'Policy inspection bypassed.'}
                          </span>
                        </div>

                        <div>
                          <label style={{ fontSize: '11px', fontWeight: 600, color: 'var(--wcp-text-primary, #0f172a)', display: 'block', marginBottom: '4px' }}>
                            Guest REST API Mutation Guard (Rule #37):
                          </label>
                          <select
                            value={wafSettings.waf_guest_rest_policy}
                            onChange={(e) => setWafSettings({ ...wafSettings, waf_guest_rest_policy: e.target.value as 'monitor' | 'off' })}
                            className="wcp-input"
                            style={{ width: '100%', fontSize: '12px', padding: '6px 10px' }}
                          >
                            <option value="monitor">Monitor &amp; Baseline Guest Write Mutations (Safe)</option>
                            <option value="off">Disabled</option>
                          </select>
                          <span style={{ fontSize: '10px', color: 'var(--wcp-text-muted, #64748b)', marginTop: '2px', display: 'block' }}>
                            Logs unauthenticated POST, PUT, PATCH, and DELETE calls targeting non-public REST routes.
                          </span>
                        </div>
                      </div>

                      {wafSettings.waf_guest_ajax_policy !== 'off' && (
                        <div>
                          <label style={{ fontSize: '11px', fontWeight: 600, color: 'var(--wcp-text-primary, #0f172a)', display: 'block', marginBottom: '4px' }}>
                            Custom Allowed Guest AJAX Actions (One per line):
                          </label>
                          <textarea
                            value={wafSettings.waf_guest_ajax_custom_allowlist}
                            onChange={(e) => setWafSettings({ ...wafSettings, waf_guest_ajax_custom_allowlist: e.target.value })}
                            placeholder="e.g.&#10;my_custom_theme_filter&#10;get_store_locations&#10;custom_lead_capture"
                            rows={3}
                            className="wcp-input"
                            style={{ width: '100%', fontSize: '11px', fontFamily: 'monospace', resize: 'vertical' }}
                          />
                          <span style={{ fontSize: '10px', color: 'var(--wcp-text-muted, #64748b)', marginTop: '2px', display: 'block' }}>
                            Permits bespoke frontend theme or plugin AJAX actions invoked by unauthenticated visitors without triggering policy flags.
                          </span>
                        </div>
                      )}
                    </div>
                  </div>

                  {/* Rule #44: Runtime Privilege Escalation Guard (In-Memory RASP Hook Firewall) */}
                  <div className="wcp-firewall-rule-card">
                    <label style={{ display: 'flex', alignItems: 'flex-start', gap: '10px', cursor: 'pointer', flex: 1 }}>
                      <input
                        type="checkbox"
                        checked={wafSettings.waf_runtime_rasp_privilege_guard}
                        onChange={(e) => setWafSettings({ ...wafSettings, waf_runtime_rasp_privilege_guard: e.target.checked })}
                        style={{ marginTop: '2px' }}
                      />
                      <div>
                        <div style={{ display: 'flex', alignItems: 'center', gap: '8px', flexWrap: 'wrap' }}>
                          <span style={{ fontSize: '13px', fontWeight: 600, color: 'var(--wcp-text-primary, #0f172a)' }}>
                            Runtime Privilege Escalation Guard &mdash; RASP Hook Firewall (Rule #44)
                          </span>
                          <span style={{
                            fontSize: '10px',
                            fontWeight: 700,
                            padding: '1px 7px',
                            borderRadius: '10px',
                            background: 'rgba(16, 185, 129, 0.12)',
                            color: '#059669',
                            border: '1px solid rgba(16, 185, 129, 0.25)'
                          }}>
                            In-Memory RASP
                          </span>
                        </div>
                        <div style={{ fontSize: '11px', color: 'var(--wcp-text-muted, #64748b)', marginTop: '2px' }}>
                          Deep in-memory hook defense intercepting guest and unprivileged execution attempts to mutate core options (<code style={{ fontSize: '10px' }}>users_can_register</code>, <code style={{ fontSize: '10px' }}>default_role</code>, <code style={{ fontSize: '10px' }}>siteurl</code>) or assign administrator capabilities via zero-day form/booking plugin exploits before database commit.
                        </div>
                      </div>
                    </label>
                    <button
                      type="button"
                      className={`wcp-btn wcp-firewall-rule-save-btn ${savedSingleRuleSuccess['waf_runtime_rasp_privilege_guard'] ? 'is-saved' : ''}`}
                      onClick={() => handleSaveSingleRule('waf_runtime_rasp_privilege_guard', wafSettings.waf_runtime_rasp_privilege_guard)}
                      disabled={savingSingleRuleKey === 'waf_runtime_rasp_privilege_guard'}
                      title="Save Runtime RASP Privilege Guard"
                    >
                      {savingSingleRuleKey === 'waf_runtime_rasp_privilege_guard' ? <Loader2 size={11} className="wcp-spin-icon" /> : (savedSingleRuleSuccess['waf_runtime_rasp_privilege_guard'] ? <Check size={11} /> : <Save size={11} />)}
                      {savedSingleRuleSuccess['waf_runtime_rasp_privilege_guard'] ? 'Saved' : 'Save'}
                    </button>
                  </div>

                  {/* Rule #47: Deep MIME & Zip-Slip Polyglot Upload Armor */}
                  <div className="wcp-firewall-rule-card">
                    <label style={{ display: 'flex', alignItems: 'flex-start', gap: '10px', cursor: 'pointer', flex: 1 }}>
                      <input
                        type="checkbox"
                        checked={wafSettings.waf_upload_deep_mime_sanitizer}
                        onChange={(e) => setWafSettings({ ...wafSettings, waf_upload_deep_mime_sanitizer: e.target.checked })}
                        style={{ marginTop: '2px' }}
                      />
                      <div>
                        <div style={{ display: 'flex', alignItems: 'center', gap: '8px', flexWrap: 'wrap' }}>
                          <span style={{ fontSize: '13px', fontWeight: 600, color: 'var(--wcp-text-primary, #0f172a)' }}>
                            Deep MIME &amp; Zip-Slip Polyglot Upload Armor (Rule #47)
                          </span>
                          <span style={{
                            fontSize: '10px',
                            fontWeight: 700,
                            padding: '1px 7px',
                            borderRadius: '10px',
                            background: 'rgba(2, 132, 199, 0.12)',
                            color: '#0284c7',
                            border: '1px solid rgba(2, 132, 199, 0.25)'
                          }}>
                            Upload Armor
                          </span>
                        </div>
                        <div style={{ fontSize: '11px', color: 'var(--wcp-text-muted, #64748b)', marginTop: '2px' }}>
                          Stops Zip-Slip path-traversal (<code style={{ fontSize: '10px' }}>../</code>) and null-byte filename injection, inspects binary magic bytes, and defeats disguised PHP polyglots and Phar deserialization headers inside image/media uploads.
                        </div>
                      </div>
                    </label>
                    <button
                      type="button"
                      className={`wcp-btn wcp-firewall-rule-save-btn ${savedSingleRuleSuccess['waf_upload_deep_mime_sanitizer'] ? 'is-saved' : ''}`}
                      onClick={() => handleSaveSingleRule('waf_upload_deep_mime_sanitizer', wafSettings.waf_upload_deep_mime_sanitizer)}
                      disabled={savingSingleRuleKey === 'waf_upload_deep_mime_sanitizer'}
                      title="Save Deep MIME & Zip-Slip Upload Armor"
                    >
                      {savingSingleRuleKey === 'waf_upload_deep_mime_sanitizer' ? <Loader2 size={11} className="wcp-spin-icon" /> : (savedSingleRuleSuccess['waf_upload_deep_mime_sanitizer'] ? <Check size={11} /> : <Save size={11} />)}
                      {savedSingleRuleSuccess['waf_upload_deep_mime_sanitizer'] ? 'Saved' : 'Save'}
                    </button>
                  </div>
                </div>
              </div>

              {/* Master Save Bar */}
              <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'flex-end', gap: '12px', paddingTop: '8px' }}>
                <button
                  type="button"
                  className="wcp-btn wcp-btn-primary"
                  style={{ background: '#0284c7', color: '#fff', fontSize: '13px', padding: '10px 24px', borderRadius: '6px' }}
                  onClick={handleSaveRules}
                  disabled={savingRules}
                >
                  {savingRules ? <Loader2 size={15} className="wcp-spin-icon" /> : <Check size={15} />}
                  {savingRules ? 'Saving Firewall Rules...' : 'Save All Firewall Rules'}
                </button>
              </div>
            </div>
          </div>

          {/* Whitelisted IPs & Allowlisted URLs in ONE Single Column */}
          <div style={{ display: 'flex', flexDirection: 'column', gap: '20px', minWidth: 0 }}>
            {/* Blocked IP Addresses & Subnets (Central Blocklist Card) */}
            <div className="wcp-firewall-card" style={{ padding: '20px' }}>
              <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '12px', flexWrap: 'wrap', gap: '8px' }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                  <h3 className="wcp-firewall-section-title" style={{ fontSize: '16px', display: 'flex', alignItems: 'center', gap: '8px', margin: 0 }}>
                    <Ban size={18} color="#dc2626" /> Blocked IP Addresses & Subnets
                  </h3>
                  <span style={{
                    fontSize: '11px',
                    fontWeight: 700,
                    padding: '2px 8px',
                    borderRadius: '10px',
                    background: lockedIpsList.length > 0 ? 'rgba(220, 38, 38, 0.1)' : 'var(--wcp-bg-elevated, #f1f5f9)',
                    color: lockedIpsList.length > 0 ? '#dc2626' : 'var(--wcp-text-muted, #64748b)',
                    border: `1px solid ${lockedIpsList.length > 0 ? 'rgba(220, 38, 38, 0.25)' : 'var(--wcp-border, #e2e8f0)'}`
                  }}>
                    {lockedIpsList.length} Active
                  </span>
                </div>
                <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                  <button
                    type="button"
                    className="wcp-btn"
                    onClick={() => {
                      fetchBlocklistData();
                      setBlocklistModalOpen(true);
                    }}
                    style={{
                      fontSize: '11px',
                      padding: '5px 12px',
                      background: 'var(--wcp-bg-surface, #f1f5f9)',
                      border: '1px solid var(--wcp-border-strong, #cbd5e1)',
                      color: 'var(--wcp-text-primary, #0f172a)',
                      borderRadius: '5px',
                      display: 'flex',
                      alignItems: 'center',
                      gap: '5px',
                      fontWeight: 600,
                      cursor: 'pointer'
                    }}
                  >
                    <List size={12} color="#dc2626" /> Detailed Lockouts Modal
                  </button>
                  <button
                    type="button"
                    className="wcp-btn"
                    onClick={fetchBlocklistData}
                    disabled={loadingBlocklist}
                    style={{
                      fontSize: '11px',
                      padding: '5px 10px',
                      background: 'none',
                      border: '1px solid var(--wcp-border, #e2e8f0)',
                      color: 'var(--wcp-text-muted, #64748b)',
                      borderRadius: '5px',
                      display: 'flex',
                      alignItems: 'center',
                      gap: '4px',
                      cursor: 'pointer'
                    }}
                    title="Refresh blocked IPs list"
                  >
                    <RefreshCw size={11} className={loadingBlocklist ? 'wcp-spin' : ''} />
                  </button>
                </div>
              </div>

              <p className="wcp-firewall-section-desc" style={{ marginBottom: '14px', fontSize: '12px', lineHeight: 1.45 }}>
                Connections originating from these IPs are rejected immediately with HTTP 403 Forbidden before reaching WordPress. Add single IPv4/IPv6 addresses or CIDR subnets (e.g. <code>203.0.113.0/24</code>) with an administrative reason.
              </p>

              {/* Add Blocked IP Form Strip */}
              <form onSubmit={handleAddBlockedIpInline} style={{
                background: 'var(--wcp-bg-elevated, #f8fafc)',
                border: '1px solid var(--wcp-border, #e2e8f0)',
                borderRadius: '8px',
                padding: '12px 14px',
                marginBottom: '16px',
                display: 'flex',
                flexDirection: 'column',
                gap: '8px'
              }}>
                <div style={{ fontSize: '11.5px', fontWeight: 600, color: 'var(--wcp-text-primary, #0f172a)', display: 'flex', alignItems: 'center', gap: '6px' }}>
                  <Plus size={13} color="#dc2626" />
                  <span>Add IP or Subnet to Blocklist</span>
                </div>
                <div style={{ display: 'grid', gridTemplateColumns: 'minmax(180px, 1.2fr) minmax(220px, 2fr) auto', gap: '10px', alignItems: 'center' }}>
                  <div>
                    <input
                      type="text"
                      placeholder="IP or Subnet (e.g. 198.51.100.26 or 203.0.113.0/24)"
                      value={newBlockIp}
                      onChange={(e) => setNewBlockIp(e.target.value)}
                      className="wcp-firewall-input"
                      style={{ width: '100%', fontSize: '12px', padding: '7px 10px', fontFamily: 'monospace' }}
                      required
                    />
                  </div>
                  <div>
                    <input
                      type="text"
                      placeholder="Reason (e.g. Malicious scanning detected, brute-force bot)"
                      value={newBlockReason}
                      onChange={(e) => setNewBlockReason(e.target.value)}
                      className="wcp-firewall-input"
                      style={{ width: '100%', fontSize: '12px', padding: '7px 10px' }}
                    />
                  </div>
                  <button
                    type="submit"
                    className="wcp-btn"
                    disabled={addingBlockIp || !newBlockIp.trim()}
                    style={{
                      padding: '7px 16px',
                      background: '#dc2626',
                      color: '#ffffff',
                      border: 'none',
                      borderRadius: '5px',
                      fontSize: '12px',
                      fontWeight: 600,
                      cursor: (addingBlockIp || !newBlockIp.trim()) ? 'not-allowed' : 'pointer',
                      display: 'flex',
                      alignItems: 'center',
                      gap: '5px',
                      whiteSpace: 'nowrap'
                    }}
                  >
                    {addingBlockIp ? <Loader2 size={12} className="wcp-spin" /> : <Ban size={12} />}
                    Block IP
                  </button>
                </div>
              </form>

              {/* Blocked IPs Table Header / Filter Bar */}
              {(() => {
                const filteredBlocked = lockedIpsList.filter(item => {
                  if (!blockedTableSearch.trim()) return true;
                  const q = blockedTableSearch.toLowerCase();
                  return item.ip.toLowerCase().includes(q) || item.reason?.toLowerCase().includes(q) || item.incident_id?.toLowerCase().includes(q);
                });
                // Sort descending by latest ban timestamp so the latest banned IP appears first
                const sortedBlocked = [...filteredBlocked].sort((a, b) => {
                  const tsA = typeof a.blocked_at_raw === 'number' ? a.blocked_at_raw : 0;
                  const tsB = typeof b.blocked_at_raw === 'number' ? b.blocked_at_raw : 0;
                  return tsB - tsA;
                });
                const totalBlockedPages = Math.max(1, Math.ceil(sortedBlocked.length / blockedPageSize));
                const currentBlockedPage = Math.min(blockedPage, totalBlockedPages);
                const startIndex = (currentBlockedPage - 1) * blockedPageSize;
                const pagedBlocked = sortedBlocked.slice(startIndex, startIndex + blockedPageSize);

                return (
                  <>
                    <div style={{
                      display: 'flex',
                      alignItems: 'center',
                      justifyContent: 'space-between',
                      gap: '10px',
                      marginBottom: '8px',
                      flexWrap: 'wrap'
                    }}>
                      <div style={{ position: 'relative', maxWidth: '320px', flex: 1, minWidth: '220px' }}>
                        <Search size={13} style={{ position: 'absolute', left: '8px', top: '50%', transform: 'translateY(-50%)', color: 'var(--wcp-text-muted, #94a3b8)' }} />
                        <input
                          type="text"
                          placeholder="Filter blocked IPs, reason, or incident..."
                          value={blockedTableSearch}
                          onChange={(e) => {
                            setBlockedTableSearch(e.target.value);
                            setBlockedPage(1);
                          }}
                          className="wcp-firewall-input"
                          style={{
                            width: '100%',
                            padding: '5px 8px 5px 26px',
                            fontSize: '11px',
                            borderRadius: '4px'
                          }}
                        />
                        {blockedTableSearch && (
                          <button
                            type="button"
                            onClick={() => {
                              setBlockedTableSearch('');
                              setBlockedPage(1);
                            }}
                            style={{
                              position: 'absolute',
                              right: '6px',
                              top: '50%',
                              transform: 'translateY(-50%)',
                              background: 'none',
                              border: 'none',
                              cursor: 'pointer',
                              color: 'var(--wcp-text-muted, #94a3b8)',
                              padding: 0
                            }}
                          >
                            <X size={12} />
                          </button>
                        )}
                      </div>

                      <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
                        <div style={{ display: 'flex', alignItems: 'center', gap: '6px', fontSize: '11px', color: 'var(--wcp-text-muted, #64748b)' }}>
                          <span>Per page:</span>
                          <select
                            value={blockedPageSize}
                            onChange={(e) => {
                              setBlockedPageSize(Number(e.target.value));
                              setBlockedPage(1);
                            }}
                            className="wcp-firewall-input"
                            style={{ padding: '3px 6px', fontSize: '11px', borderRadius: '4px' }}
                          >
                            <option value={10}>10</option>
                            <option value={25}>25</option>
                            <option value={50}>50</option>
                            <option value={100}>100</option>
                          </select>
                        </div>
                        <span style={{ fontSize: '11px', color: 'var(--wcp-text-muted, #64748b)' }}>
                          {filteredBlocked.length} of {lockedIpsList.length} IPs listed
                        </span>
                      </div>
                    </div>

                    {/* Blocked IPs Table */}
                    <div style={{
                      borderRadius: '6px',
                      border: '1px solid var(--wcp-border, #e2e8f0)',
                      overflow: 'hidden',
                      marginBottom: '10px',
                      background: 'var(--wcp-bg-surface, #ffffff)'
                    }}>
                      <table className="wcp-table" style={{ width: '100%', borderCollapse: 'collapse', fontSize: '12px', margin: 0 }}>
                        <thead>
                          <tr style={{ background: 'var(--wcp-bg-elevated, #f8fafc)', borderBottom: '1px solid var(--wcp-border, #e2e8f0)' }}>
                            <th style={{ padding: '8px 12px', textAlign: 'left', fontWeight: 600, color: 'var(--wcp-text-secondary, #475569)', width: '24%' }}>IP Address / Subnet</th>
                            <th style={{ padding: '8px 12px', textAlign: 'left', fontWeight: 600, color: 'var(--wcp-text-secondary, #475569)', width: '32%' }}>Reason & Violation Attribution</th>
                            <th style={{ padding: '8px 12px', textAlign: 'left', fontWeight: 600, color: 'var(--wcp-text-secondary, #475569)', width: '22%' }}>Ban Issued & Timing</th>
                            <th style={{ padding: '8px 12px', textAlign: 'right', fontWeight: 600, color: 'var(--wcp-text-secondary, #475569)', width: '22%' }}>Actions</th>
                          </tr>
                        </thead>
                        <tbody>
                          {loadingBlocklist ? (
                            <tr>
                              <td colSpan={4} style={{ padding: '24px', textAlign: 'center', color: 'var(--wcp-text-muted, #64748b)' }}>
                                <Loader2 size={16} className="wcp-spin" style={{ margin: '0 auto 6px', color: '#4f46e5' }} />
                                <span style={{ fontSize: '12px' }}>Loading blocked addresses...</span>
                              </td>
                            </tr>
                          ) : filteredBlocked.length === 0 ? (
                            <tr>
                              <td colSpan={4} style={{ padding: '28px 16px', textAlign: 'center', color: 'var(--wcp-text-muted, #64748b)' }}>
                                <ShieldCheck size={28} color="#16a34a" style={{ margin: '0 auto 6px' }} />
                                <div style={{ fontWeight: 600, color: 'var(--wcp-text-primary, #0f172a)', fontSize: '13px' }}>
                                  {blockedTableSearch ? 'No Matching Blocked IPs' : 'No Blocked IP Addresses'}
                                </div>
                                <p style={{ margin: '2px 0 0', fontSize: '11px' }}>
                                  {blockedTableSearch
                                    ? 'Try modifying your filter keyword or click clear.'
                                    : 'Your firewall blocklist is empty. Add abusive IPs above to deny access immediately.'}
                                </p>
                              </td>
                            </tr>
                          ) : (
                            pagedBlocked.map((item, idx) => {
                              const isManual = item.type === 'manual_admin' || !!item.admin_user;
                              const isPermanent = item.is_permanent || item.duration === 'Permanent';
                              const rawItemIp = (item.ip || '').trim().toLowerCase();
                              const isCfBlocked = bannedIpsList.some(r => (r.ip || '').trim().toLowerCase() === rawItemIp);
                              return (
                                <tr key={item.ip || idx} style={{ borderBottom: '1px solid var(--wcp-border, #e2e8f0)' }}>
                                  <td style={{ padding: '10px 12px', verticalAlign: 'middle' }}>
                                    <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
                                      <code style={{
                                        fontSize: '12.5px',
                                        fontWeight: 700,
                                        color: '#dc2626',
                                        background: 'rgba(220, 38, 38, 0.08)',
                                        padding: '2px 6px',
                                        borderRadius: '4px',
                                        fontFamily: 'monospace'
                                      }}>
                                        {item.ip}
                                      </code>
                                      <button
                                        type="button"
                                        onClick={() => copyIncidentToClipboard(item.ip)}
                                        title="Copy IP"
                                        style={{
                                          background: 'none',
                                          border: 'none',
                                          cursor: 'pointer',
                                          color: 'var(--wcp-text-muted, #94a3b8)',
                                          padding: '2px'
                                        }}
                                      >
                                        <Copy size={11} />
                                      </button>
                                    </div>
                                    <div style={{ display: 'flex', alignItems: 'center', gap: '4px', marginTop: '4px' }}>
                                      <span className={`wcp-lockout-badge-pill ${isManual ? 'is-manual' : 'is-danger'}`} style={{ fontSize: '9.5px', padding: '1px 5px', borderRadius: '3px' }}>
                                        {item.badge}
                                      </span>
                                      {item.incident_id && (
                                        <button
                                          type="button"
                                          onClick={() => copyIncidentToClipboard(item.incident_id!)}
                                          className="wcp-lockout-incident-pill"
                                          style={{ fontSize: '9.5px', padding: '1px 5px', borderRadius: '3px', cursor: 'pointer', border: 'none' }}
                                          title="Copy incident ID"
                                        >
                                          {copiedIncidentId === item.incident_id ? 'Copied!' : item.incident_id}
                                        </button>
                                      )}
                                    </div>
                                  </td>

                                  <td style={{ padding: '10px 12px', verticalAlign: 'middle' }}>
                                    <div style={{ fontSize: '11.5px', color: 'var(--wcp-text-primary, #0f172a)', lineHeight: 1.4 }}>
                                      {isManual && item.admin_user && (
                                        <span style={{ fontWeight: 600, color: '#1d4ed8' }}>By {item.admin_user}: </span>
                                      )}
                                      {item.reason}
                                    </div>
                                  </td>

                                  <td style={{ padding: '10px 12px', verticalAlign: 'middle', fontSize: '11px' }}>
                                    <div style={{ display: 'flex', alignItems: 'center', gap: '5px' }}>
                                      <Clock size={11} color="var(--wcp-text-muted, #64748b)" />
                                      <span style={{ fontWeight: 600, color: 'var(--wcp-text-primary, #0f172a)' }}>
                                        {item.blocked_at}
                                      </span>
                                    </div>
                                    <div style={{ display: 'flex', alignItems: 'center', gap: '6px', marginTop: '3px' }}>
                                      <span style={{ color: 'var(--wcp-text-muted, #64748b)', fontSize: '10px' }}>
                                        {item.ban_ago}
                                      </span>
                                      <span style={{ fontSize: '9px', color: 'var(--wcp-border, #cbd5e1)' }}>•</span>
                                      <span style={{
                                        fontSize: '10px',
                                        fontWeight: 600,
                                        color: isPermanent ? '#475569' : '#dc2626'
                                      }}>
                                        {isPermanent ? 'Permanent Ban' : item.time_remaining || item.duration}
                                      </span>
                                    </div>
                                  </td>

                                  <td style={{ padding: '10px 12px', textAlign: 'right', verticalAlign: 'middle' }}>
                                    <div style={{ display: 'inline-flex', alignItems: 'center', gap: '5px', flexWrap: 'wrap', justifyContent: 'flex-end' }}>
                                      {/* Cloudflare Edge Toggle Button: Show Block if not blocked on Edge, or Unblock if currently blocked on Edge */}
                                      {!isCfBlocked ? (
                                        <button
                                          type="button"
                                          className="wcp-btn"
                                          onClick={() => handlePushIpToCloudflareEdge(item.ip, item.reason)}
                                          disabled={cfActionIp === `push-${item.ip}`}
                                          style={{
                                            fontSize: '10.5px',
                                            padding: '4px 8px',
                                            borderRadius: '4px',
                                            background: '#ea580c',
                                            color: '#ffffff',
                                            border: 'none',
                                            cursor: cfActionIp === `push-${item.ip}` ? 'not-allowed' : 'pointer',
                                            display: 'inline-flex',
                                            alignItems: 'center',
                                            gap: '4px',
                                            fontWeight: 600
                                          }}
                                          title="Push IP to Cloudflare Edge Blocklist"
                                        >
                                          {cfActionIp === `push-${item.ip}` ? (
                                            <Loader2 size={10} className="wcp-spin" />
                                          ) : (
                                            <Cloud size={10} />
                                          )}
                                          CF Edge Block
                                        </button>
                                      ) : (
                                        <button
                                          type="button"
                                          className="wcp-btn"
                                          onClick={() => handleUnblockIpFromCloudflareEdge(item.ip)}
                                          disabled={cfActionIp === `unblock-${item.ip}`}
                                          style={{
                                            fontSize: '10.5px',
                                            padding: '4px 8px',
                                            borderRadius: '4px',
                                            background: 'rgba(234, 88, 12, 0.1)',
                                            color: '#c2410c',
                                            border: '1px solid rgba(234, 88, 12, 0.3)',
                                            cursor: cfActionIp === `unblock-${item.ip}` ? 'not-allowed' : 'pointer',
                                            display: 'inline-flex',
                                            alignItems: 'center',
                                            gap: '4px',
                                            fontWeight: 600
                                          }}
                                          title="Unblock IP from Cloudflare Edge"
                                        >
                                          {cfActionIp === `unblock-${item.ip}` ? (
                                            <Loader2 size={10} className="wcp-spin" />
                                          ) : (
                                            <Unlock size={10} />
                                          )}
                                          CF Edge Unblock
                                        </button>
                                      )}

                                      {/* Modify / Edit Block Policy Button */}
                                      <button
                                        type="button"
                                        className="wcp-btn"
                                        onClick={() => handleOpenEditBlocklistModal(item)}
                                        style={{
                                          fontSize: '10.5px',
                                          padding: '4px 8px',
                                          borderRadius: '4px',
                                          background: 'none',
                                          color: 'var(--wcp-text-secondary, #475569)',
                                          border: '1px solid var(--wcp-border, #cbd5e1)',
                                          cursor: 'pointer',
                                          display: 'inline-flex',
                                          alignItems: 'center',
                                          gap: '4px',
                                          fontWeight: 600
                                        }}
                                        title="Modify duration or reason for this banned IP"
                                      >
                                        <Edit2 size={10} />
                                        Edit
                                      </button>

                                      {/* Local Origin Firewall Unblock Button */}
                                      <button
                                        type="button"
                                        className="wcp-btn"
                                        onClick={() => handleUnblockIpFromModal(item.ip)}
                                        disabled={unblockingIp === item.ip}
                                        style={{
                                          fontSize: '10.5px',
                                          padding: '4px 8px',
                                          borderRadius: '4px',
                                          background: '#0284c7',
                                          color: '#ffffff',
                                          border: 'none',
                                          cursor: unblockingIp === item.ip ? 'not-allowed' : 'pointer',
                                          display: 'inline-flex',
                                          alignItems: 'center',
                                          gap: '4px',
                                          fontWeight: 600
                                        }}
                                        title="Unblock this IP locally from WordPress"
                                      >
                                        {unblockingIp === item.ip ? <Loader2 size={10} className="wcp-spin" /> : <Unlock size={10} />}
                                        Unblock
                                      </button>
                                    </div>
                                  </td>
                                </tr>
                              );
                            })
                          )}
                        </tbody>
                      </table>
                    </div>

                    {/* Pagination Bar for Blocked IPs */}
                    {filteredBlocked.length > 0 && (
                      <div className="wcp-waf-pagination-bar" style={{
                        borderRadius: '6px',
                        marginBottom: '14px',
                        border: '1px solid var(--wcp-border, #e2e8f0)',
                        padding: '8px 14px'
                      }}>
                        <div style={{ fontSize: '11.5px', color: 'var(--wcp-text-muted, #64748b)' }}>
                          Showing <strong>{filteredBlocked.length > 0 ? (currentBlockedPage - 1) * blockedPageSize + 1 : 0}</strong> &ndash; <strong>{Math.min(filteredBlocked.length, currentBlockedPage * blockedPageSize)}</strong> of <strong>{filteredBlocked.length}</strong> blocked entries
                        </div>

                        {totalBlockedPages > 1 && (
                          <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
                            <button
                              type="button"
                              className="wcp-btn-micro"
                              disabled={currentBlockedPage <= 1}
                              onClick={() => setBlockedPage(prev => Math.max(1, prev - 1))}
                              style={{ display: 'inline-flex', alignItems: 'center', gap: '3px', fontSize: '11px', padding: '3px 8px' }}
                            >
                              <ChevronLeft size={12} /> Prev
                            </button>

                            <span style={{ fontSize: '11.5px', color: 'var(--wcp-text-secondary, #475569)', padding: '0 4px' }}>
                              Page <strong>{currentBlockedPage}</strong> of <strong>{totalBlockedPages}</strong>
                            </span>

                            <button
                              type="button"
                              className="wcp-btn-micro"
                              disabled={currentBlockedPage >= totalBlockedPages}
                              onClick={() => setBlockedPage(prev => Math.min(totalBlockedPages, prev + 1))}
                              style={{ display: 'inline-flex', alignItems: 'center', gap: '3px', fontSize: '11px', padding: '3px 8px' }}
                            >
                              Next <ChevronRight size={12} />
                            </button>
                          </div>
                        )}
                      </div>
                    )}
                  </>
                );
              })()}

              <div className="wcp-firewall-callout" style={{ fontSize: '11px', padding: '10px 12px', marginBottom: '12px' }}>
                <strong style={{ display: 'block', marginBottom: '2px', color: 'var(--wcp-text-primary, #0f172a)' }}>Blocklist Policy:</strong>
                Removing an IP unblocks it to allow normal browsing while preserving 100% of WAF firewall rules. Do not whitelist an attacker.
              </div>

              {/* 1-Click Cloudflare Edge Blocklist Sync */}
              <div className="wcp-firewall-rule-card" style={{
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'space-between',
                flexWrap: 'wrap',
                gap: '10px',
                padding: '12px 14px'
              }}>
                <div>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
                    <Cloud size={14} color="#dc2626" />
                    <strong style={{ fontSize: '12.5px', color: 'var(--wcp-text-primary, #0f172a)' }}>
                      Cloudflare Edge Sync for IP Blocklist
                    </strong>
                  </div>
                  <div style={{ fontSize: '11px', color: 'var(--wcp-text-muted, #64748b)', marginTop: '2px' }}>
                    Creates <code>mode: block</code> IP Access Rules at Cloudflare Edge so malicious traffic is rejected before reaching your origin server.
                  </div>
                </div>

                <div style={{ display: 'flex', alignItems: 'center', gap: '8px', flexWrap: 'wrap' }}>
                  <button
                    type="button"
                    className="wcp-btn"
                    onClick={handleOpenBannedIpsModal}
                    style={{
                      background: 'var(--wcp-bg-surface, #ffffff)',
                      color: 'var(--wcp-text-primary, #0f172a)',
                      border: '1px solid var(--wcp-border, #cbd5e1)',
                      padding: '6px 12px',
                      borderRadius: '6px',
                      fontWeight: 600,
                      fontSize: '12px',
                      display: 'inline-flex',
                      alignItems: 'center',
                      gap: '5px',
                      cursor: 'pointer'
                    }}
                    title="View existing blocklisted IPs active at Cloudflare Edge and manage/unblock them"
                  >
                    <ListFilter size={13} color="#dc2626" />
                    View Cloudflare Blocklisted IPs
                  </button>

                  <button
                    type="button"
                    className="wcp-btn"
                    onClick={handleSyncBlocklistToCloudflare}
                    disabled={syncingBlocklistToCf || lockedIpsList.length === 0}
                    style={{
                      background: '#dc2626',
                      color: '#ffffff',
                      border: 'none',
                      padding: '6px 14px',
                      borderRadius: '6px',
                      fontWeight: 600,
                      fontSize: '12px',
                      display: 'inline-flex',
                      alignItems: 'center',
                      gap: '5px',
                      cursor: (syncingBlocklistToCf || lockedIpsList.length === 0) ? 'not-allowed' : 'pointer'
                    }}
                  >
                    {syncingBlocklistToCf ? <Loader2 size={13} className="wcp-spin" /> : <RefreshCw size={13} />}
                    Sync Blocklist to Cloudflare Edge
                  </button>
                </div>
              </div>

              {blocklistSyncResult && (
                <div style={{
                  padding: '10px 14px',
                  borderRadius: '6px',
                  fontSize: '12px',
                  marginTop: '12px',
                  background: blocklistSyncResult.success ? '#ecfdf5' : '#fef2f2',
                  border: blocklistSyncResult.success ? '1px solid #a7f3d0' : '1px solid #fecaca',
                  color: blocklistSyncResult.success ? '#065f46' : '#991b1b'
                }}>
                  {blocklistSyncResult.message}
                </div>
              )}
            </div>

            {/* Whitelisted IP Addresses */}
            <div className="wcp-firewall-card" style={{ padding: '20px' }}>
              <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '12px', flexWrap: 'wrap', gap: '8px' }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                  <h3 className="wcp-firewall-section-title" style={{ fontSize: '16px', display: 'flex', alignItems: 'center', gap: '8px', margin: 0 }}>
                    <Lock size={18} color="#16a34a" /> Whitelisted IP Addresses
                  </h3>
                  <span style={{
                    fontSize: '11px',
                    fontWeight: 700,
                    padding: '2px 8px',
                    borderRadius: '10px',
                    background: whitelistedIpsList.length > 0 ? 'rgba(22, 163, 74, 0.1)' : 'var(--wcp-bg-elevated, #f1f5f9)',
                    color: whitelistedIpsList.length > 0 ? '#15803d' : 'var(--wcp-text-muted, #64748b)',
                    border: `1px solid ${whitelistedIpsList.length > 0 ? 'rgba(22, 163, 74, 0.25)' : 'var(--wcp-border, #e2e8f0)'}`
                  }}>
                    {whitelistedIpsList.length} Trusted
                  </span>
                </div>
                <button
                  type="button"
                  className="wcp-btn"
                  onClick={fetchWhitelistData}
                  disabled={loadingWhitelist}
                  style={{
                    fontSize: '11px',
                    padding: '5px 10px',
                    background: 'none',
                    border: '1px solid var(--wcp-border, #e2e8f0)',
                    color: 'var(--wcp-text-muted, #64748b)',
                    borderRadius: '5px',
                    display: 'flex',
                    alignItems: 'center',
                    gap: '4px',
                    cursor: 'pointer'
                  }}
                  title="Refresh whitelisted IPs"
                >
                  <RefreshCw size={11} className={loadingWhitelist ? 'wcp-spin' : ''} />
                </button>
              </div>

              <p className="wcp-firewall-section-desc" style={{ marginBottom: '14px', fontSize: '12px', lineHeight: 1.45 }}>
                Requests originating from these IPs are granted high-trust access. Pre-auth traffic bypasses login rate limits and diagnostic tripwires; active admin sessions bypass all inspection. Add single IPs or entire subnets with a documented reason.
              </p>

              {/* Add Whitelisted IP Form Strip */}
              <form onSubmit={handleAddWhitelistIp} style={{
                background: 'var(--wcp-bg-elevated, #f8fafc)',
                border: '1px solid var(--wcp-border, #e2e8f0)',
                borderRadius: '8px',
                padding: '14px 16px',
                marginBottom: '16px',
                display: 'flex',
                flexDirection: 'column',
                gap: '12px'
              }}>
                <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', flexWrap: 'wrap', gap: '8px' }}>
                  <div style={{ fontSize: '12px', fontWeight: 700, color: 'var(--wcp-text-primary, #0f172a)', display: 'flex', alignItems: 'center', gap: '6px' }}>
                    <Plus size={14} color="#16a34a" />
                    <span>Add IP or Subnet to Allowlist</span>
                  </div>
                  <div style={{ fontSize: '11px', color: 'var(--wcp-text-muted, #64748b)' }}>
                    Granular Least-Privilege Exemption Policy
                  </div>
                </div>

                {/* Primary Row: IP, Scope Selector, Reason */}
                <div style={{ display: 'grid', gridTemplateColumns: 'minmax(180px, 1.2fr) minmax(180px, 1.1fr) minmax(200px, 1.8fr)', gap: '10px', alignItems: 'center' }}>
                  <div>
                    <label style={{ display: 'block', fontSize: '11px', fontWeight: 600, color: 'var(--wcp-text-secondary, #475569)', marginBottom: '3px' }}>
                      IP Address or CIDR Subnet:
                    </label>
                    <input
                      type="text"
                      placeholder="e.g. 192.168.1.100 or 10.0.0.0/24"
                      value={newWhitelistIp}
                      onChange={(e) => setNewWhitelistIp(e.target.value)}
                      className="wcp-firewall-input"
                      style={{ width: '100%', fontSize: '12px', padding: '7px 10px', fontFamily: 'monospace' }}
                      required
                    />
                  </div>

                  <div>
                    <label style={{ display: 'block', fontSize: '11px', fontWeight: 600, color: 'var(--wcp-text-secondary, #475569)', marginBottom: '3px' }}>
                      Exemption Scope:
                    </label>
                    <select
                      value={newWhitelistScope}
                      onChange={(e) => setNewWhitelistScope(e.target.value as any)}
                      className="wcp-firewall-input"
                      style={{ width: '100%', fontSize: '12px', padding: '7px 10px' }}
                    >
                      <option value="global">All Firewall Rules (Global Pass)</option>
                      <option value="rule">Single Firewall Rule (Safest)</option>
                      <option value="category">Group Category (e.g. Identity Defense)</option>
                    </select>
                  </div>

                  <div>
                    <label style={{ display: 'block', fontSize: '11px', fontWeight: 600, color: 'var(--wcp-text-secondary, #475569)', marginBottom: '3px' }}>
                      Audit Justification / Description:
                    </label>
                    <input
                      type="text"
                      placeholder="e.g. Office static IP, VPN gateway, dev workstation"
                      value={newWhitelistReason}
                      onChange={(e) => setNewWhitelistReason(e.target.value)}
                      className="wcp-firewall-input"
                      style={{ width: '100%', fontSize: '12px', padding: '7px 10px' }}
                    />
                  </div>
                </div>

                {/* Secondary Row: Specific Rule or Category Group Dropdown + TTL Expiration + Action Button */}
                <div style={{ display: 'grid', gridTemplateColumns: newWhitelistScope === 'global' ? 'minmax(200px, 1fr) auto' : 'minmax(240px, 2fr) minmax(180px, 1fr) auto', gap: '10px', alignItems: 'flex-end', paddingTop: '4px', borderTop: '1px dashed var(--wcp-border, #e2e8f0)' }}>
                  {newWhitelistScope === 'rule' && (
                    <div>
                      <label style={{ display: 'block', fontSize: '11px', fontWeight: 600, color: 'var(--wcp-text-secondary, #475569)', marginBottom: '3px' }}>
                        Select Specific Rule to Exempt:
                      </label>
                      <select
                        value={newWhitelistSelectedRule}
                        onChange={(e) => {
                          const rId = e.target.value;
                          setNewWhitelistSelectedRule(rId);
                          if (!newWhitelistReason) {
                            const found = rulesCatalog.find(r => r.id === rId);
                            if (found) {
                              setNewWhitelistReason(`Allowed for rule ${found.name}`);
                            }
                          }
                        }}
                        className="wcp-firewall-input"
                        style={{ width: '100%', fontSize: '12px', padding: '7px 10px' }}
                        required
                      >
                        <option value="">-- Choose Firewall Rule ({rulesCatalog.length || 30}+ Available) --</option>
                        {Array.from(new Set(rulesCatalog.map(r => r.category))).map(cat => (
                          <optgroup key={cat} label={`📂 ${cat}`}>
                            {rulesCatalog.filter(r => r.category === cat).map(r => (
                              <option key={r.id} value={r.id}>
                                {r.name} [{r.id}]
                              </option>
                            ))}
                          </optgroup>
                        ))}
                      </select>
                    </div>
                  )}

                  {newWhitelistScope === 'category' && (
                    <div>
                      <label style={{ display: 'block', fontSize: '11px', fontWeight: 600, color: 'var(--wcp-text-secondary, #475569)', marginBottom: '3px' }}>
                        Select Rule Group Category to Exempt:
                      </label>
                      <select
                        value={newWhitelistSelectedCat}
                        onChange={(e) => {
                          const cat = e.target.value;
                          setNewWhitelistSelectedCat(cat);
                          if (!newWhitelistReason && cat) {
                            setNewWhitelistReason(`Allowed for category group ${cat}`);
                          }
                        }}
                        className="wcp-firewall-input"
                        style={{ width: '100%', fontSize: '12px', padding: '7px 10px' }}
                        required
                      >
                        <option value="">-- Choose Category Group --</option>
                        {Array.from(new Set(rulesCatalog.map(r => r.category))).map(cat => {
                          const count = rulesCatalog.filter(r => r.category === cat).length;
                          return (
                            <option key={cat} value={cat}>
                              {cat} ({count} {count === 1 ? 'rule' : 'rules'})
                            </option>
                          );
                        })}
                      </select>
                    </div>
                  )}

                  <div>
                    <label style={{ display: 'block', fontSize: '11px', fontWeight: 600, color: 'var(--wcp-text-secondary, #475569)', marginBottom: '3px' }}>
                      Exemption Expiration Schedule:
                    </label>
                    <select
                      value={newWhitelistExpiresIn}
                      onChange={(e) => setNewWhitelistExpiresIn(Number(e.target.value))}
                      className="wcp-firewall-input"
                      style={{ width: '100%', fontSize: '12px', padding: '7px 10px' }}
                    >
                      <option value={86400}>24 Hours (Temporary Client Testing)</option>
                      <option value={604800}>7 Days (Transient Integration Setup)</option>
                      <option value={2592000}>30 Days (Extended Evaluation)</option>
                      <option value={0}>Permanent (Active until manually removed)</option>
                    </select>
                  </div>

                  <div>
                    <button
                      type="submit"
                      className="wcp-btn"
                      disabled={addingWhitelistIp || !newWhitelistIp.trim()}
                      style={{
                        padding: '7px 18px',
                        background: '#16a34a',
                        color: '#ffffff',
                        border: 'none',
                        borderRadius: '5px',
                        fontSize: '12px',
                        fontWeight: 600,
                        cursor: (addingWhitelistIp || !newWhitelistIp.trim()) ? 'not-allowed' : 'pointer',
                        display: 'flex',
                        alignItems: 'center',
                        gap: '6px',
                        whiteSpace: 'nowrap',
                        height: '34px'
                      }}
                    >
                      {addingWhitelistIp ? <Loader2 size={13} className="wcp-spin" /> : <Lock size={13} />}
                      Whitelist IP
                    </button>
                  </div>
                </div>
              </form>

              {/* Whitelist Search / Counter Bar */}
              <div style={{
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'space-between',
                gap: '10px',
                marginBottom: '8px'
              }}>
                <div style={{ position: 'relative', maxWidth: '320px', flex: 1 }}>
                  <Search size={13} style={{ position: 'absolute', left: '8px', top: '50%', transform: 'translateY(-50%)', color: 'var(--wcp-text-muted, #94a3b8)' }} />
                  <input
                    type="text"
                    placeholder="Filter whitelisted IPs or reason..."
                    value={whitelistSearch}
                    onChange={(e) => setWhitelistSearch(e.target.value)}
                    className="wcp-firewall-input"
                    style={{
                      width: '100%',
                      padding: '5px 8px 5px 26px',
                      fontSize: '11px',
                      borderRadius: '4px'
                    }}
                  />
                  {whitelistSearch && (
                    <button
                      type="button"
                      onClick={() => setWhitelistSearch('')}
                      style={{
                        position: 'absolute',
                        right: '6px',
                        top: '50%',
                        transform: 'translateY(-50%)',
                        background: 'none',
                        border: 'none',
                        cursor: 'pointer',
                        color: 'var(--wcp-text-muted, #94a3b8)',
                        padding: 0
                      }}
                    >
                      <X size={12} />
                    </button>
                  )}
                </div>
                <span style={{ fontSize: '11px', color: 'var(--wcp-text-muted, #64748b)' }}>
                  {whitelistedIpsList.filter(item => {
                    if (!whitelistSearch.trim()) return true;
                    const q = whitelistSearch.toLowerCase();
                    return item.ip.toLowerCase().includes(q) || item.reason?.toLowerCase().includes(q) || item.added_by?.toLowerCase().includes(q);
                  }).length} of {whitelistedIpsList.length} IPs listed
                </span>
              </div>

              {/* Whitelisted IPs Table */}
              <div style={{
                borderRadius: '6px',
                border: '1px solid var(--wcp-border, #e2e8f0)',
                overflow: 'hidden',
                marginBottom: '14px',
                background: 'var(--wcp-bg-surface, #ffffff)'
              }}>
                <table className="wcp-table" style={{ width: '100%', borderCollapse: 'collapse', fontSize: '12px', margin: 0 }}>
                  <thead>
                    <tr style={{ background: 'var(--wcp-bg-elevated, #f8fafc)', borderBottom: '1px solid var(--wcp-border, #e2e8f0)' }}>
                      <th style={{ padding: '8px 12px', textAlign: 'left', fontWeight: 600, color: 'var(--wcp-text-secondary, #475569)', width: '22%' }}>IP Address / Subnet</th>
                      <th style={{ padding: '8px 12px', textAlign: 'left', fontWeight: 600, color: 'var(--wcp-text-secondary, #475569)', width: '22%' }}>Scope &amp; Exemption</th>
                      <th style={{ padding: '8px 12px', textAlign: 'left', fontWeight: 600, color: 'var(--wcp-text-secondary, #475569)', width: '28%' }}>Reason &amp; Description</th>
                      <th style={{ padding: '8px 12px', textAlign: 'left', fontWeight: 600, color: 'var(--wcp-text-secondary, #475569)', width: '16%' }}>Added By &amp; Date</th>
                      <th style={{ padding: '8px 12px', textAlign: 'right', fontWeight: 600, color: 'var(--wcp-text-secondary, #475569)', width: '12%' }}>Action</th>
                    </tr>
                  </thead>
                  <tbody>
                    {loadingWhitelist ? (
                      <tr>
                        <td colSpan={5} style={{ padding: '24px', textAlign: 'center', color: 'var(--wcp-text-muted, #64748b)' }}>
                          <Loader2 size={16} className="wcp-spin" style={{ margin: '0 auto 6px', color: '#16a34a' }} />
                          <span style={{ fontSize: '12px' }}>Loading whitelisted addresses...</span>
                        </td>
                      </tr>
                    ) : whitelistedIpsList.length === 0 ? (
                      <tr>
                        <td colSpan={5} style={{ padding: '28px 16px', textAlign: 'center', color: 'var(--wcp-text-muted, #64748b)' }}>
                          <Shield size={28} color="#0284c7" style={{ margin: '0 auto 6px' }} />
                          <div style={{ fontWeight: 600, color: 'var(--wcp-text-primary, #0f172a)', fontSize: '13px' }}>No Whitelisted IP Addresses</div>
                          <p style={{ margin: '2px 0 0', fontSize: '11px' }}>Your whitelist is empty. Add trusted static IPs above to bypass rate limits and diagnostic checks.</p>
                        </td>
                      </tr>
                    ) : (
                      whitelistedIpsList
                        .filter(item => {
                          if (!whitelistSearch.trim()) return true;
                          const q = whitelistSearch.toLowerCase();
                          return item.ip.toLowerCase().includes(q) || item.reason?.toLowerCase().includes(q) || item.added_by?.toLowerCase().includes(q);
                        })
                        .map((item, idx) => (
                          <tr key={idx} style={{ borderBottom: '1px solid var(--wcp-border, #e2e8f0)' }}>
                            <td style={{ padding: '10px 12px', verticalAlign: 'middle' }}>
                              <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
                                <code style={{
                                  fontSize: '12.5px',
                                  fontWeight: 700,
                                  color: '#059669',
                                  background: 'rgba(16, 185, 129, 0.08)',
                                  padding: '2px 6px',
                                  borderRadius: '4px',
                                  fontFamily: 'monospace'
                                }}>
                                  {item.ip}
                                </code>
                                <button
                                  type="button"
                                  onClick={() => copyIncidentToClipboard(item.ip)}
                                  title="Copy IP"
                                  style={{
                                    background: 'none',
                                    border: 'none',
                                    cursor: 'pointer',
                                    color: 'var(--wcp-text-muted, #94a3b8)',
                                    padding: '2px'
                                  }}
                                >
                                  <Copy size={11} />
                                </button>
                              </div>
                              <div style={{ marginTop: '3px' }}>
                                {item.is_expired ? (
                                  <span className="wcp-badge-pill wcp-badge-warn" style={{ fontSize: '9px', padding: '1px 5px' }}>
                                    Expired
                                  </span>
                                ) : (
                                  <span className="wcp-badge-pill wcp-badge-clean" style={{ fontSize: '9px', padding: '1px 5px' }}>
                                    Active Exemption
                                  </span>
                                )}
                              </div>
                            </td>

                            <td style={{ padding: '10px 12px', verticalAlign: 'middle' }}>
                              {item.scope === 'rule' ? (
                                <div>
                                  <span className="wcp-badge-pill wcp-badge-info" style={{ fontSize: '10px', padding: '2px 6px', fontWeight: 600 }}>
                                    Rule: {(item.allowed_rules || []).join(', ') || 'Specific Rule'}
                                  </span>
                                  {item.allowed_rules && item.allowed_rules.length > 0 && (
                                    <div style={{ fontSize: '11px', color: 'var(--wcp-text-primary, #0f172a)', fontWeight: 500, marginTop: '3px' }}>
                                      {item.allowed_rules.map(rId => item.allowed_rule_names?.[rId] || rulesCatalog.find(rc => rc.id === rId)?.name || rId).join(', ')}
                                    </div>
                                  )}
                                  {item.endpoint && (
                                    <div style={{ fontSize: '10px', color: '#0284c7', fontFamily: 'monospace', marginTop: '3px' }}>
                                      Path: {item.endpoint}
                                    </div>
                                  )}
                                </div>
                              ) : item.scope === 'category' ? (
                                <div>
                                  <span className="wcp-badge-pill wcp-badge-info" style={{ fontSize: '10px', padding: '2px 6px', background: 'rgba(124, 58, 237, 0.1)', color: '#7c3aed', border: '1px solid rgba(124, 58, 237, 0.3)', fontWeight: 600 }}>
                                    Group Category
                                  </span>
                                  <div style={{ fontSize: '11px', color: 'var(--wcp-text-primary, #0f172a)', fontWeight: 600, marginTop: '3px' }}>
                                    {(item.allowed_cats || []).join(', ') || 'Category Group'}
                                  </div>
                                  {item.endpoint && (
                                    <div style={{ fontSize: '10px', color: '#0284c7', fontFamily: 'monospace', marginTop: '3px' }}>
                                      Path: {item.endpoint}
                                    </div>
                                  )}
                                </div>
                              ) : (
                                <div>
                                  <span className="wcp-badge-pill wcp-badge-clean" style={{ fontSize: '10px', padding: '2px 6px', fontWeight: 600 }}>
                                    Global Full Bypass
                                  </span>
                                  <div style={{ fontSize: '10.5px', color: 'var(--wcp-text-muted, #64748b)', marginTop: '2px' }}>
                                    All 30+ Firewall Rules
                                  </div>
                                </div>
                              )}
                            </td>

                            <td style={{ padding: '10px 12px', verticalAlign: 'middle' }}>
                              <div style={{ fontSize: '11.5px', color: 'var(--wcp-text-primary, #0f172a)', lineHeight: 1.4 }}>
                                {item.reason}
                              </div>
                            </td>

                            <td style={{ padding: '10px 12px', verticalAlign: 'middle', fontSize: '11px' }}>
                              <div style={{ fontWeight: 600, color: 'var(--wcp-text-primary, #0f172a)' }}>
                                {item.added_by ? `Admin (${item.added_by})` : 'Administrator'}
                              </div>
                              <div style={{ color: 'var(--wcp-text-muted, #64748b)', fontSize: '10px', marginTop: '2px' }}>
                                {item.added_at} ({item.added_ago})
                              </div>
                            </td>

                            <td style={{ padding: '10px 12px', textAlign: 'right', verticalAlign: 'middle' }}>
                              <div style={{ display: 'inline-flex', alignItems: 'center', gap: '5px', justifyContent: 'flex-end' }}>
                                <button
                                  type="button"
                                  className="wcp-btn"
                                  onClick={() => handleOpenEditWhitelistModal(item)}
                                  style={{
                                    fontSize: '11px',
                                    padding: '4px 8px',
                                    borderRadius: '4px',
                                    background: 'none',
                                    color: 'var(--wcp-text-secondary, #475569)',
                                    border: '1px solid var(--wcp-border, #cbd5e1)',
                                    cursor: 'pointer',
                                    display: 'inline-flex',
                                    alignItems: 'center',
                                    gap: '4px',
                                    fontWeight: 600
                                  }}
                                  title="Modify rule scope, reason, or expiration"
                                >
                                  <Edit2 size={10} />
                                  Edit
                                </button>
                                <button
                                  type="button"
                                  className="wcp-btn"
                                  onClick={() => handleRemoveWhitelistIp(item.ip)}
                                  disabled={removingWhitelistIp === item.ip}
                                  style={{
                                    fontSize: '11px',
                                    padding: '4px 10px',
                                    borderRadius: '4px',
                                    background: 'none',
                                    color: '#dc2626',
                                    border: '1px solid rgba(220, 38, 38, 0.3)',
                                    cursor: removingWhitelistIp === item.ip ? 'not-allowed' : 'pointer',
                                    display: 'inline-flex',
                                    alignItems: 'center',
                                    gap: '4px',
                                    fontWeight: 600
                                  }}
                                  title="Remove IP from whitelist"
                                >
                                  {removingWhitelistIp === item.ip ? <Loader2 size={10} className="wcp-spin" /> : <Trash2 size={10} />}
                                  Remove
                                </button>
                              </div>
                            </td>
                          </tr>
                        ))
                    )}
                  </tbody>
                </table>
              </div>

              {/* Tiered Zero-Trust Whitelist Security Controls */}
              <div style={{ display: 'flex', flexDirection: 'column', gap: '8px', marginBottom: '12px' }}>
                <div className="wcp-firewall-rule-card" style={{
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'space-between',
                  padding: '10px 14px',
                  borderRadius: '6px'
                }}>
                  <div style={{ flex: 1, paddingRight: '12px' }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
                      <Lock size={13} color="#4f46e5" />
                      <strong style={{ fontSize: '12px', color: 'var(--wcp-text-primary, #0f172a)' }}>
                        Require Administrator Login for Complete WAF Bypass
                      </strong>
                      <span className="wcp-badge-pill wcp-badge-clean" style={{ fontSize: '10px', padding: '1px 5px' }}>Zero-Trust</span>
                    </div>
                    <div style={{ fontSize: '11px', color: 'var(--wcp-text-muted, #64748b)', marginTop: '2px', lineHeight: 1.35 }}>
                      When enabled, unauthenticated visitors from whitelisted IPs can only bypass login brute force lockouts and diagnostic probes. Destructive exploits (SQLi, Webshells, RCE) remain strictly blocked until verified as a logged-in Administrator.
                    </div>
                  </div>
                  <label className="wcp-switch" style={{ margin: 0, flexShrink: 0 }}>
                    <input
                      type="checkbox"
                      checked={wafSettings.waf_whitelist_require_admin}
                      onChange={(e) => {
                        const updated = e.target.checked;
                        setWafSettings({ ...wafSettings, waf_whitelist_require_admin: updated });
                        handleSaveSingleRule('waf_whitelist_require_admin', updated);
                      }}
                    />
                    <span className="wcp-slider round"></span>
                  </label>
                </div>

                <div className="wcp-firewall-rule-card" style={{
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'space-between',
                  padding: '10px 14px',
                  borderRadius: '6px'
                }}>
                  <div style={{ flex: 1, paddingRight: '12px' }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
                      <Activity size={13} color="#0284c7" />
                      <strong style={{ fontSize: '12px', color: 'var(--wcp-text-primary, #0f172a)' }}>
                        Log All Whitelisted IP Telemetry to WAF Incident Logs
                      </strong>
                    </div>
                    <div style={{ fontSize: '11px', color: 'var(--wcp-text-muted, #64748b)', marginTop: '2px', lineHeight: 1.35 }}>
                      Retain 100% forensic visibility. Whenever an action from a whitelisted IP matches an inspection rule, record an audit entry with status <code>BYPASSED (WHITELIST)</code> instead of silently dropping telemetry.
                    </div>
                  </div>
                  <label className="wcp-switch" style={{ margin: 0, flexShrink: 0 }}>
                    <input
                      type="checkbox"
                      checked={wafSettings.waf_whitelist_log_telemetry}
                      onChange={(e) => {
                        const updated = e.target.checked;
                        setWafSettings({ ...wafSettings, waf_whitelist_log_telemetry: updated });
                        handleSaveSingleRule('waf_whitelist_log_telemetry', updated);
                      }}
                    />
                    <span className="wcp-slider round"></span>
                  </label>
                </div>
              </div>

              {/* 1-Click Cloudflare Edge Whitelist Sync */}
              <div className="wcp-firewall-rule-card" style={{
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'space-between',
                flexWrap: 'wrap',
                gap: '10px',
                padding: '12px 14px',
                marginBottom: '12px'
              }}>
                <div>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
                    <Cloud size={14} color="#ea580c" />
                    <strong style={{ fontSize: '12.5px', color: 'var(--wcp-text-primary, #0f172a)' }}>
                      Cloudflare Edge Sync for IP Whitelist
                    </strong>
                  </div>
                  <div style={{ fontSize: '11px', color: 'var(--wcp-text-muted, #64748b)', marginTop: '2px' }}>
                    Creates <code>mode: allow</code> IP Access Rules at Cloudflare Edge so edge rules will never challenge or block site admins or developers.
                  </div>
                </div>

                <div style={{ display: 'flex', alignItems: 'center', gap: '8px', flexWrap: 'wrap' }}>
                  <button
                    type="button"
                    className="wcp-btn"
                    onClick={handleOpenCfWhitelistModal}
                    style={{
                      background: 'var(--wcp-bg-surface, #ffffff)',
                      color: 'var(--wcp-text-primary, #0f172a)',
                      border: '1px solid var(--wcp-border, #cbd5e1)',
                      padding: '6px 12px',
                      borderRadius: '6px',
                      fontWeight: 600,
                      fontSize: '12px',
                      display: 'inline-flex',
                      alignItems: 'center',
                      gap: '5px',
                      cursor: 'pointer'
                    }}
                    title="View existing whitelisted IPs active at Cloudflare Edge and manage/remove them"
                  >
                    <ListFilter size={13} color="#0284c7" />
                    View Cloudflare Whitelisted IPs
                  </button>

                  <button
                    type="button"
                    className="wcp-btn"
                    onClick={handleSyncWhitelistToCloudflare}
                    disabled={syncingWhitelistToCf || !wafSettings.waf_whitelisted_ips.trim()}
                    style={{
                      background: '#ea580c',
                      color: '#ffffff',
                      border: 'none',
                      padding: '6px 14px',
                      borderRadius: '6px',
                      fontWeight: 600,
                      fontSize: '12px',
                      display: 'inline-flex',
                      alignItems: 'center',
                      gap: '5px',
                      cursor: (syncingWhitelistToCf || !wafSettings.waf_whitelisted_ips.trim()) ? 'not-allowed' : 'pointer'
                    }}
                  >
                    {syncingWhitelistToCf ? <Loader2 size={13} className="wcp-spin" /> : <RefreshCw size={13} />}
                    Sync Whitelist to Cloudflare Edge
                  </button>
                </div>
              </div>

              {whitelistSyncResult && (
                <div style={{
                  padding: '10px 14px',
                  borderRadius: '6px',
                  fontSize: '12px',
                  marginBottom: '12px',
                  background: whitelistSyncResult.success ? '#ecfdf5' : '#fef2f2',
                  border: whitelistSyncResult.success ? '1px solid #a7f3d0' : '1px solid #fecaca',
                  color: whitelistSyncResult.success ? '#065f46' : '#991b1b'
                }}>
                  {whitelistSyncResult.message}
                </div>
              )}

              <div className="wcp-firewall-callout" style={{ fontSize: '11px', padding: '10px 12px' }}>
                <strong style={{ display: 'block', marginBottom: '2px', color: 'var(--wcp-text-primary, #0f172a)' }}>Pro-Tip:</strong>
                When Cloudflare is active, WCP Firewall automatically inspects <code>CF-Connecting-IP</code> instead of the proxy peer.
              </div>
            </div>

            {/* Allowlisted URLs / Endpoints */}
            <div className="wcp-firewall-card" style={{ padding: '20px' }}>
              <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '12px' }}>
                <h3 className="wcp-firewall-section-title" style={{ fontSize: '16px', display: 'flex', alignItems: 'center', gap: '8px', margin: 0 }}>
                  <Globe size={18} color="#0284c7" /> Allowlisted URLs / Endpoints
                </h3>
                <button
                  type="button"
                  className={`wcp-btn wcp-firewall-rule-save-btn ${savedSingleRuleSuccess['waf_whitelisted_urls'] ? 'is-saved' : ''}`}
                  onClick={() => handleSaveSingleRule('waf_whitelisted_urls', wafSettings.waf_whitelisted_urls)}
                  disabled={savingSingleRuleKey === 'waf_whitelisted_urls'}
                >
                  {savingSingleRuleKey === 'waf_whitelisted_urls' ? <Loader2 size={11} className="wcp-spin-icon" /> : (savedSingleRuleSuccess['waf_whitelisted_urls'] ? <Check size={11} /> : <Save size={11} />)}
                  {savedSingleRuleSuccess['waf_whitelisted_urls'] ? 'Saved' : 'Save URLs'}
                </button>
              </div>

              <p className="wcp-firewall-section-desc" style={{ marginBottom: '12px', fontSize: '12px', lineHeight: 1.4 }}>
                Requests targeting these URL paths bypass all inspection rules. Ideal for payment webhooks (Stripe, PayPal) or external APIs. Enter one relative path prefix per line.
              </p>

              <textarea
                rows={7}
                value={wafSettings.waf_whitelisted_urls}
                onChange={(e) => setWafSettings({ ...wafSettings, waf_whitelisted_urls: e.target.value })}
                placeholder="e.g.&#10;/wp-json/my-custom-plugin/v1/webhook&#10;/wc-api/v3/stripe_ipn&#10;/custom-endpoint/"
                className="wcp-firewall-textarea"
                style={{
                  width: '100%',
                  padding: '10px',
                  fontFamily: 'monospace',
                  fontSize: '12px',
                  marginBottom: '12px'
                }}
              />

              <div className="wcp-firewall-callout" style={{ fontSize: '11px', padding: '10px 12px' }}>
                <strong style={{ display: 'block', marginBottom: '2px', color: 'var(--wcp-text-primary, #0f172a)' }}>Security Note:</strong>
                URLs listed here bypass SQLi, XSS, and Traversal filtering. Only allowlist trusted external callback paths.
              </div>
            </div>

            {/* Targeted User-Agent, Endpoint & IP Allowlist Rules */}
            <TargetedAllowlistManagerCard
              rulesJson={wafSettings.waf_targeted_allowlist_rules}
              onChange={(newJson) => setWafSettings({ ...wafSettings, waf_targeted_allowlist_rules: newJson })}
              onSave={(newJson) => handleSaveSingleRule('waf_targeted_allowlist_rules', newJson)}
              isSaving={savingSingleRuleKey === 'waf_targeted_allowlist_rules'}
              isSaved={!!savedSingleRuleSuccess['waf_targeted_allowlist_rules']}
              activePluginSlugs={status?.active_plugin_slugs || []}
            />
          </div>
        </div>
      </div>
      )}

      {/* TAB: Context-Adaptive Firewall (CAF) & StackGuard Cockpit */}
      {activeTab === 'caf' && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: '24px' }}>
          {/* Phase 1: Smart Protection Profiles & StackGuard Engine */}
          <CafAdvisorPanel
            apiRequest={apiRequest}
            onSettingsUpdated={() => {
              loadFirewallData(true);
            }}
          />

          {/* Phase 2: Cloudflare Free-Plan 3-Slot Edge Offload & Origin Survival Mode */}
          <CloudflareSlotVisualizer apiRequest={apiRequest} />

          {/* Phase 3: Behavioral Intelligence, Multi-Bucket Velocity & WebCrypto PoW */}
          <CafBehavioralCockpit apiRequest={apiRequest} />
        </div>
      )}

      {/* TAB: Red Team Attack Drill & Defensibility Benchmarking */}
      {activeTab === 'drill' && (
        <div style={{ marginTop: '10px' }}>
          <AttackSimulationCard apiRequest={apiRequest} />
        </div>
      )}

      {/* TAB: Supply-Chain Defense & SBOM Sentinel */}
      {activeTab === 'supply_chain' && (
        <div style={{ marginTop: '10px' }}>
          <SbomSupplyChainCard
              apiRequest={apiRequest}
              initialSubTab={initialSupplyChainSubTab}
              onSubTabChange={(childTab) => {
                if (onSubTabChange) {
                  onSubTabChange('supply_chain', childTab);
                }
              }}
            />
        </div>
      )}

      {/* TAB: Behavioral WAF & Anti-Automated Abuse */}
      {activeTab === 'behavioral' && (
        <div style={{ marginTop: '10px' }}>
          {/* CAF Phase 3: Action-Type Velocity Monitor, WebCrypto PoW & 1-Click Exemption Synthesizer */}
          <CafBehavioralCockpit apiRequest={apiRequest} />

          <BehavioralWafCard
            apiRequest={apiRequest}
            initialSubTab={initialBehavioralSubTab}
            onSubTabChange={(childTab) => {
              if (onSubTabChange) {
                onSubTabChange('behavioral', childTab);
              }
            }}
          />
        </div>
      )}

      {/* TAB: 2026 AI Threat Defense, MCP Governance & Decoy Ghost Routes */}
      {activeTab === 'ai_defense' && (
        <div style={{ marginTop: '10px' }}>
          <AiDefenseCard
            apiRequest={apiRequest}
            initialSubTab={initialAiDefenseSubTab}
            onSubTabChange={(childTab) => {
              if (onSubTabChange) {
                onSubTabChange('ai_defense', childTab);
              }
            }}
          />
        </div>
      )}

      {/* TAB 3: Cloud Threat Intelligence & Botnet Feeds */}
      {activeTab === 'intel' && (
        <ThreatIntelCockpitCard
          apiRequest={apiRequest}
          clientIp={status?.client_ip}
        />
      )}

      {/* TAB 4: Cloudflare Edge Defense */}
      {activeTab === 'cloudflare' && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: '20px' }}>
          {/* Cloudflare Connection Header Banner */}
          <div
            className="wcp-firewall-edge-banner is-shared"
            style={{
              padding: '20px 24px',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'space-between',
              flexWrap: 'wrap',
              gap: '16px'
            }}
          >
            <div style={{ display: 'flex', alignItems: 'center', gap: '16px' }}>
              <div style={{
                width: '48px',
                height: '48px',
                borderRadius: '10px',
                background: '#ea580c',
                color: '#fff',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
                boxShadow: '0 4px 12px rgba(234, 88, 12, 0.25)'
              }}>
                <Cloud size={28} />
              </div>
              <div>
                <h3 className="wcp-firewall-section-title" style={{ fontSize: '18px', color: '#ea580c' }}>
                  Cloudflare Edge WAF &amp; Zero-Resource Defense
                  <span style={{
                    fontSize: '11px',
                    fontWeight: 700,
                    textTransform: 'uppercase',
                    padding: '2px 8px',
                    borderRadius: '999px',
                    background: cfStatus?.configured ? '#dcfce7' : '#f1f5f9',
                    color: cfStatus?.configured ? '#166534' : '#64748b'
                  }}>
                    {cfStatus?.configured ? 'Connected' : 'Not Configured'}
                  </span>
                  {cfStatus?.proxy_status && (
                    <span style={{
                      fontSize: '11px',
                      fontWeight: 700,
                      textTransform: 'uppercase',
                      padding: '2px 8px',
                      borderRadius: '999px',
                      background: cfStatus.proxy_status.is_proxied ? '#ffedd5' : '#fee2e2',
                      color: cfStatus.proxy_status.is_proxied ? '#c2410c' : '#991b1b',
                      border: cfStatus.proxy_status.is_proxied ? '1px solid #fdba74' : '1px solid #fecaca',
                      display: 'inline-flex',
                      alignItems: 'center',
                      gap: '4px'
                    }}>
                      <span style={{
                        width: '7px',
                        height: '7px',
                        borderRadius: '50%',
                        background: cfStatus.proxy_status.is_proxied ? '#ea580c' : '#dc2626',
                        display: 'inline-block'
                      }} />
                      {cfStatus.proxy_status.is_proxied ? 'Proxy: Orange Cloud ☁ (Active)' : 'Proxy: Grey Cloud (DNS Only ⚠️)'}
                    </span>
                  )}
                </h3>
                <p className="wcp-firewall-section-desc">
                  {cfStatus?.proxy_status?.details ? (
                    <span>
                      <strong style={{
                        display: 'inline-flex',
                        alignItems: 'center',
                        gap: '4px',
                        padding: '1px 7px',
                        background: 'rgba(234, 88, 12, 0.12)',
                        color: '#c2410c',
                        border: '1px solid rgba(234, 88, 12, 0.3)',
                        borderRadius: '5px',
                        fontFamily: 'ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace',
                        fontSize: '12px',
                        marginRight: '6px'
                      }}>
                        {cfStatus.proxy_status.hostname}
                      </strong>
                      {cfStatus.proxy_status.details}
                    </span>
                  ) : (
                    'Block malicious probes at Cloudflare\'s Global Anycast Edge before requests ever reach your server or boot WordPress PHP.'
                  )}
                </p>
              </div>
            </div>

            <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
              <button
                type="button"
                className="wcp-btn"
                style={{
                  background: '#ea580c',
                  color: '#fff',
                  border: 'none',
                  padding: '8px 16px',
                  fontWeight: 600,
                  fontSize: '13px',
                  display: 'flex',
                  alignItems: 'center',
                  gap: '6px'
                }}
                disabled={cfPurging || !cfStatus?.configured}
                onClick={handlePurgeCloudflare}
              >
                {cfPurging ? <Loader2 size={15} className="wcp-spin" /> : <RefreshCw size={15} />}
                Purge Cloudflare Cache
              </button>
            </div>
          </div>

          {cfPurgeMessage && (
            <div style={{ background: '#ecfdf5', border: '1px solid #a7f3d0', color: '#065f46', padding: '10px 16px', borderRadius: '8px', fontSize: '13px' }}>
              {cfPurgeMessage}
            </div>
          )}

          {/* Cloudflare Connection Status & Settings Link Card */}
          <div className="wcp-firewall-card" style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', flexWrap: 'wrap', gap: '16px', padding: '18px 22px' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
              <div style={{
                width: '40px',
                height: '40px',
                borderRadius: '10px',
                background: cfStatus?.configured ? '#ecfdf5' : '#fff7ed',
                color: cfStatus?.configured ? '#059669' : '#ea580c',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
                flexShrink: 0
              }}>
                {cfStatus?.configured ? <CheckCircle2 size={22} /> : <AlertTriangle size={22} />}
              </div>
              <div>
                <h4 style={{ margin: 0, fontSize: '15px', color: 'var(--wcp-text-primary, #0f172a)' }}>
                  Cloudflare API Credentials: {cfStatus?.configured ? 'Connected & Verified' : 'Not Connected'}
                </h4>
                <div style={{ margin: '5px 0 0 0', fontSize: '13px', color: 'var(--wcp-text-secondary, #64748b)', display: 'flex', alignItems: 'center', flexWrap: 'wrap', gap: '8px' }}>
                  {cfStatus?.configured ? (
                    <>
                      <span>Connected to Zone:</span>
                      <span style={{
                        display: 'inline-flex',
                        alignItems: 'center',
                        gap: '5px',
                        padding: '2px 9px',
                        background: 'rgba(2, 132, 199, 0.1)',
                        color: '#0284c7',
                        border: '1px solid rgba(2, 132, 199, 0.28)',
                        borderRadius: '6px',
                        fontWeight: 700,
                        fontFamily: 'ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace',
                        fontSize: '12px',
                        letterSpacing: '0.2px'
                      }}>
                        <Globe size={12} style={{ flexShrink: 0 }} />
                        {cfStatus.zone_name || 'Active'}
                      </span>
                      <span style={{ color: 'var(--wcp-text-muted, #94a3b8)' }}>•</span>
                      <span>Plan:</span>
                      <span style={{
                        display: 'inline-flex',
                        alignItems: 'center',
                        gap: '4px',
                        padding: '2px 9px',
                        background: 'rgba(79, 70, 229, 0.1)',
                        color: '#4f46e5',
                        border: '1px solid rgba(79, 70, 229, 0.28)',
                        borderRadius: '6px',
                        fontWeight: 700,
                        fontSize: '11.5px',
                        textTransform: 'uppercase',
                        letterSpacing: '0.3px'
                      }}>
                        <Sparkles size={11} style={{ flexShrink: 0 }} />
                        {cfStatus.plan || 'Free Website'}
                      </span>
                      <span style={{ color: 'var(--wcp-text-muted, #94a3b8)' }}>•</span>
                      <span style={{ fontSize: '12px' }}>Managed via Plugin Settings</span>
                    </>
                  ) : (
                    <span>Connect your Cloudflare API Bearer Token in Settings to enable 1-Click Edge WAF rules, Rate Limiting, and IP auto-bans.</span>
                  )}
                </div>
              </div>
            </div>

            <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
              <button
                type="button"
                className="wcp-btn"
                onClick={() => onNavigateToSettings ? onNavigateToSettings('cloudflare') : (window.location.href = 'admin.php?page=wcp-scanner-settings&tab=cloudflare')}
                style={{
                  background: cfStatus?.configured ? '#f8fafc' : 'linear-gradient(135deg, #f97316 0%, #ea580c 100%)',
                  color: cfStatus?.configured ? '#0f172a' : '#ffffff',
                  border: cfStatus?.configured ? '1px solid #cbd5e1' : 'none',
                  padding: '8px 16px',
                  borderRadius: '8px',
                  fontWeight: 600,
                  fontSize: '13px',
                  display: 'inline-flex',
                  alignItems: 'center',
                  gap: '6px',
                  cursor: 'pointer',
                  boxShadow: cfStatus?.configured ? 'none' : '0 2px 4px rgba(234, 88, 12, 0.25)'
                }}
              >
                <Key size={14} />
                {cfStatus?.configured ? 'Manage API Credentials in Settings ↗' : 'Configure Cloudflare API in Settings ↗'}
              </button>
            </div>
          </div>

          {/* Manual Copy-Paste Free Cloudflare Rules (Zero API Token Required) */}
          <div className="wcp-firewall-card">
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', flexWrap: 'wrap', gap: '12px', marginBottom: showManualCfRules ? '20px' : '0' }}>
              <div>
                <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                  <h4 className="wcp-firewall-section-title" style={{ fontSize: '16px' }}>
                    <FileCode size={20} color="#ea580c" /> Manual Cloudflare Free Rules (Zero API Token Required)
                  </h4>
                  <span style={{ fontSize: '11px', fontWeight: 700, padding: '2px 8px', borderRadius: '999px', background: '#ffedd5', color: '#c2410c', border: '1px solid #fdba74' }}>
                    4 Master Compound Rules
                  </span>
                </div>
                <p className="wcp-firewall-section-desc" style={{ maxWidth: '800px', marginBottom: 0 }}>
                  Ideal for shared cPanel hosting or restricted client setups where you prefer not to store an API token. Copy these 4 high-density compound expressions directly into your Cloudflare Dashboard to stop 95%+ of automated probes and SQL injections at the edge with zero hosting resource consumption.
                </p>
              </div>

              <div style={{ display: 'flex', alignItems: 'center', gap: '10px', flexWrap: 'wrap' }}>
                <button
                  type="button"
                  onClick={() => setShowManualCfRules(prev => !prev)}
                  className="wcp-btn"
                  style={{
                    fontSize: '12.5px',
                    fontWeight: 600,
                    padding: '7px 14px',
                    borderRadius: '6px',
                    display: 'inline-flex',
                    alignItems: 'center',
                    gap: '6px',
                    cursor: 'pointer',
                    background: showManualCfRules ? 'rgba(234, 88, 12, 0.12)' : 'linear-gradient(135deg, #ea580c 0%, #c2410c 100%)',
                    color: showManualCfRules ? '#ea580c' : '#ffffff',
                    border: showManualCfRules ? '1px solid #fdba74' : 'none',
                    boxShadow: showManualCfRules ? 'none' : '0 2px 4px rgba(234, 88, 12, 0.25)',
                    transition: 'all 0.15s ease'
                  }}
                  title={showManualCfRules ? 'Collapse manual rules' : 'Expand manual rules'}
                >
                  {showManualCfRules ? (
                    <>
                      <ChevronUp size={15} color="#ea580c" /> Collapse Rules
                    </>
                  ) : (
                    <>
                      <ChevronDown size={15} /> Expand Rules
                    </>
                  )}
                </button>

                <a
                  href="https://dash.cloudflare.com/"
                  target="_blank"
                  rel="noreferrer"
                  className="wcp-btn"
                  style={{
                    fontSize: '12px',
                    color: '#ea580c',
                    fontWeight: 600,
                    textDecoration: 'none',
                    display: 'inline-flex',
                    alignItems: 'center',
                    gap: '5px',
                    padding: '7px 14px',
                    borderRadius: '6px'
                  }}
                >
                  Open Cloudflare Dashboard <ExternalLink size={13} />
                </a>
              </div>
            </div>

            {showManualCfRules && (
              <>
                {/* Quick 3-Step Setup Instructions */}
                <div className="wcp-firewall-callout" style={{ marginBottom: '20px' }}>
                  <div style={{ fontWeight: 700, marginBottom: '6px', display: 'flex', alignItems: 'center', gap: '6px' }}>
                    <CheckCircle2 size={15} color="#16a34a" /> 30-Second Manual Cloudflare Setup:
                  </div>
                  <ol style={{ margin: 0, paddingLeft: '18px', lineHeight: 1.6 }}>
                    <li>Log in to <strong>Cloudflare Dashboard</strong> &gt; Select your domain &gt; Click <strong>Security</strong> &gt; <strong>WAF</strong> &gt; <strong>Custom Rules</strong>.</li>
                    <li>Click <strong>Create rule</strong> &gt; Give it a name &gt; Click <strong>"Edit expression"</strong> &gt; Paste the copied rule expression below.</li>
                    <li>Choose the required <strong>Action</strong> (Block or Managed Challenge) &gt; Click <strong>Deploy</strong>.</li>
                  </ol>
                </div>

                {/* Master Compound Rule Items */}
                <div style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
                  {Object.entries(compoundRules).map(([key, rule]) => (
                    <div
                      key={key}
                      className="wcp-firewall-callout"
                      style={{
                        display: 'flex',
                        flexDirection: 'column',
                        gap: '10px',
                        padding: '16px 20px'
                      }}
                    >
                      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', flexWrap: 'wrap', gap: '10px' }}>
                        <div>
                          <div style={{ display: 'flex', alignItems: 'center', gap: '8px', flexWrap: 'wrap' }}>
                            <strong style={{ fontSize: '14px' }}>{rule.title}</strong>
                            <span style={{ fontSize: '10px', fontWeight: 700, padding: '2px 7px', borderRadius: '4px', background: 'rgba(100, 116, 139, 0.15)', textTransform: 'uppercase' }}>
                              {rule.badge}
                            </span>
                            <span
                              style={{
                                fontSize: '11px',
                                fontWeight: 700,
                                padding: '2px 8px',
                                borderRadius: '4px',
                                background: rule.action === 'block' ? '#fee2e2' : '#fef3c7',
                                color: rule.action === 'block' ? '#991b1b' : '#92400e',
                                textTransform: 'uppercase',
                              }}
                            >
                              Action: {rule.action_label}
                            </span>
                          </div>
                          <p className="wcp-firewall-section-desc" style={{ fontSize: '12.5px' }}>
                            {rule.description}
                          </p>
                        </div>

                        <button
                          type="button"
                          onClick={() => handleCopyExpression(rule.id, rule.expression)}
                          className="wcp-btn"
                          style={{
                            background: copiedRuleId === rule.id ? '#16a34a' : undefined,
                            color: copiedRuleId === rule.id ? '#ffffff' : undefined,
                            padding: '6px 14px',
                            fontSize: '12px',
                            fontWeight: 600
                          }}
                        >
                          {copiedRuleId === rule.id ? (
                            <>
                              <Check size={13} /> Expression Copied!
                            </>
                          ) : (
                            <>
                              <Copy size={13} /> Copy Expression
                            </>
                          )}
                        </button>
                      </div>

                      {/* Expression Box */}
                      <div style={{ position: 'relative' }}>
                        <pre
                          style={{
                            margin: 0,
                            background: '#090d16',
                            color: '#38bdf8',
                            padding: '12px 16px',
                            borderRadius: '6px',
                            fontSize: '11.5px',
                            fontFamily: 'ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace',
                            overflowX: 'auto',
                            whiteSpace: 'pre-wrap',
                            wordBreak: 'break-all',
                            lineHeight: 1.55,
                            border: '1px solid #1e293b',
                          }}
                        >
                          {rule.expression}
                        </pre>
                      </div>
                    </div>
                  ))}
                </div>
              </>
            )}
          </div>

          {/* Context-Adaptive Firewall (CAF) Cloudflare Free-Plan 5-Slot Optimizer & Origin Survival Mode */}
          <CloudflareSlotVisualizer apiRequest={apiRequest} />

          {/* 1-Click Cloudflare Free Edge WAF Rules Deployer */}
          <div className="wcp-firewall-card">
            {/* Dynamic Edge Slot Usage & Plan Quota Meter */}
            {(() => {
              const inspection = cfInspectionData || cfStatus?.edge_inspection;
              const plan = inspection?.plan || cfStatus?.plan || 'Free';
              const maxSlots = inspection?.max_slots || (plan.toLowerCase().includes('pro') ? 20 : plan.toLowerCase().includes('business') ? 50 : 5);
              const totalUsed = inspection?.total_used !== undefined ? inspection.total_used : Object.keys(cfStatus?.active_rules || {}).length;
              const freeSlots = Math.max(0, maxSlots - totalUsed);
              const userRulesCount = inspection?.user_rules?.length || 0;
              const wcpRulesCount = inspection?.wcp_rules?.length || Object.keys(cfStatus?.active_rules || {}).length;

              return (
                <div
                  className="wcp-firewall-inset-box"
                  style={{
                    padding: '14px 18px',
                    marginBottom: '16px',
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'space-between',
                    flexWrap: 'wrap',
                    gap: '12px'
                  }}
                >
                  <div style={{ display: 'flex', alignItems: 'center', gap: '14px', flexWrap: 'wrap' }}>
                    <div>
                      <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                        <span className="wcp-smart-shield-pill-detected-sky" style={{ borderRadius: '4px', textTransform: 'uppercase' }}>
                          {plan} Tier Quota
                        </span>
                        <strong style={{ fontSize: '13px', color: 'var(--wcp-text-primary, #0f172a)' }}>
                          {totalUsed} of {maxSlots} Edge Slots Used
                        </strong>
                        <span className={freeSlots > 0 ? 'wcp-smart-shield-pill-detected-emerald' : 'wcp-smart-shield-pill-empty'}>
                          {freeSlots > 0 ? `${freeSlots} Free Slots Remaining` : 'No Free Slots Left ⚠️'}
                        </span>
                      </div>
                      <div style={{ fontSize: '12px', color: 'var(--wcp-text-muted, #64748b)', marginTop: '4px' }}>
                        Active: <strong>{wcpRulesCount}</strong> WCP Managed • <strong>{userRulesCount}</strong> Custom User-defined Rules in Cloudflare Dashboard
                      </div>
                    </div>
                  </div>

                  <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                    <button
                      type="button"
                      className="wcp-btn wcp-firewall-rule-card"
                      onClick={handleOpenExistingRulesModal}
                      disabled={!cfStatus?.configured || inspectingRules}
                      style={{
                        padding: '6px 12px',
                        fontSize: '12px',
                        fontWeight: 600,
                        color: 'var(--wcp-text-primary, #0f172a)',
                        display: 'inline-flex',
                        alignItems: 'center',
                        gap: '6px',
                        cursor: (!cfStatus?.configured || inspectingRules) ? 'not-allowed' : 'pointer'
                      }}
                    >
                      {inspectingRules ? <Loader2 size={13} className="wcp-spin" /> : <Eye size={13} />}
                      View Existing Cloudflare Rules ({totalUsed})
                    </button>
                  </div>
                </div>
              );
            })()}

            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '16px', flexWrap: 'wrap', gap: '12px' }}>
              <div>
                <div style={{ display: 'flex', alignItems: 'center', gap: '8px', flexWrap: 'wrap' }}>
                  <h4 className="wcp-firewall-section-title" style={{ fontSize: '16px', margin: 0 }}>
                    <ShieldCheck size={18} color="#ea580c" /> 1-Click Cloudflare Edge WAF Rules Deployer
                  </h4>
                  <span className="wcp-cf-badge-free">
                    4 Master Compound Rules
                  </span>
                </div>
                <p className="wcp-firewall-section-desc">
                  Deploy high-density compound WordPress firewall rules directly into Cloudflare's Edge Rulesets. Inspect existing dashboard rules before deploying so you never exceed your plan slot quota.
                </p>
              </div>

              <button
                type="button"
                className="wcp-btn"
                style={{ background: '#ea580c', color: '#fff', border: 'none', padding: '8px 20px', fontWeight: 600, fontSize: '13px', display: 'flex', alignItems: 'center', gap: '6px' }}
                disabled={cfDeploying || !cfStatus?.configured}
                onClick={handleDeployCloudflareRules}
              >
                {cfDeploying ? <Loader2 size={15} className="wcp-spin" /> : <Zap size={15} />}
                Deploy Selected Rules to Edge
              </button>
            </div>

            {cfDeployMessage && (
              <div style={{
                background: cfDeployMessage.type === 'success' ? '#ecfdf5' : '#fef2f2',
                border: cfDeployMessage.type === 'success' ? '1px solid #a7f3d0' : '1px solid #fecaca',
                color: cfDeployMessage.type === 'success' ? '#065f46' : '#991b1b',
                padding: '12px 16px',
                borderRadius: '8px',
                fontSize: '13px',
                marginBottom: '16px',
                lineHeight: 1.5
              }}>
                {typeof cfDeployMessage.text === 'string' && cfDeployMessage.text.includes('<')
                  ? cfDeployMessage.text.replace(/<style[^>]*>[\s\S]*?<\/style>/gi, '').replace(/<[^>]+>/g, ' ').replace(/\s+/g, ' ').trim()
                  : cfDeployMessage.text}
              </div>
            )}

            <div style={{ display: 'flex', flexDirection: 'column', gap: '14px' }}>
              {Object.entries(cfDefinitions).map(([key, def]: [string, any]) => {
                const isSelected = !!cfSelectedRules[key];
                const isDeployed = cfStatus?.active_rules && !!cfStatus.active_rules[key];
                const custom = cfRuleCustomizations[key] || {};
                const currentAction = custom.action || def.action;
                const currentExpr = custom.expression !== undefined ? custom.expression : def.expression;
                const currentBypass = custom.bypass_ips || '';
                const isEditing = !!custom.isEditing;

                return (
                  <div key={key} className="wcp-firewall-callout" style={{
                    padding: '16px 20px',
                    borderRadius: '10px',
                    border: isSelected ? '1px solid #fdba74' : '1px solid #e2e8f0',
                    transition: 'all 0.2s ease',
                  }}>
                    <div style={{ display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between', gap: '16px', flexWrap: 'wrap' }}>
                      <div style={{ flex: 1 }}>
                        <div style={{ display: 'flex', alignItems: 'center', gap: '10px', marginBottom: '6px', flexWrap: 'wrap' }}>
                          <span style={{ fontSize: '14.5px', fontWeight: 600 }}>{def.title}</span>
                          
                          {/* Customizable Action Selector */}
                          <select
                            className="wcp-firewall-select"
                            value={currentAction}
                            onChange={(e) => {
                              const newAction = e.target.value;
                              setCfRuleCustomizations(prev => ({
                                ...prev,
                                [key]: { ...(prev[key] || {}), action: newAction }
                              }));
                            }}
                            style={{
                              fontSize: '11px',
                              fontWeight: 700,
                              padding: '2px 28px 2px 8px',
                              borderRadius: '4px',
                              border: '1px solid #cbd5e1',
                              background: currentAction === 'block' ? '#fee2e2' : currentAction === 'managed_challenge' ? '#fef3c7' : '#e0f2fe',
                              color: currentAction === 'block' ? '#991b1b' : currentAction === 'managed_challenge' ? '#92400e' : '#0369a1',
                              textTransform: 'uppercase',
                              cursor: 'pointer'
                            }}
                          >
                            <option value="block">BLOCK</option>
                            <option value="managed_challenge">MANAGED CHALLENGE (Turnstile)</option>
                            <option value="js_challenge">JS CHALLENGE</option>
                            <option value="challenge">INTERACTIVE CAPTCHA</option>
                            <option value="log">LOG ONLY (MONITOR)</option>
                          </select>

                          {/* Individual Push / Update / Remove Buttons */}
                          {isDeployed ? (
                            <div style={{ display: 'inline-flex', alignItems: 'center', gap: '6px', flexWrap: 'wrap' }}>
                              <span style={{ fontSize: '11px', fontWeight: 600, color: '#16a34a', display: 'flex', alignItems: 'center', gap: '3px' }}>
                                <Check size={13} /> Active on Edge
                              </span>
                              <button
                                type="button"
                                className="wcp-btn wcp-cf-single-push-btn"
                                disabled={!cfStatus?.configured || deployingSingleRuleKey === key}
                                onClick={() => handleDeploySingleRule(key, true)}
                                title="Push current rule customizations directly to Cloudflare Edge"
                              >
                                {deployingSingleRuleKey === key ? <Loader2 size={12} className="wcp-spin" /> : <Zap size={12} />}
                                Update on Edge
                              </button>
                              <button
                                type="button"
                                className="wcp-btn wcp-cf-single-remove-btn"
                                disabled={!cfStatus?.configured || deployingSingleRuleKey === key}
                                onClick={() => handleDeploySingleRule(key, false)}
                                title="Remove only this rule from Cloudflare Edge"
                              >
                                {deployingSingleRuleKey === key ? <Loader2 size={12} className="wcp-spin" /> : <Trash2 size={12} />}
                                Remove
                              </button>
                            </div>
                          ) : (
                            <button
                              type="button"
                              className="wcp-btn wcp-cf-single-push-btn"
                              disabled={!cfStatus?.configured || deployingSingleRuleKey === key}
                              onClick={() => handleDeploySingleRule(key, true)}
                              title="Deploy this individual rule directly to Cloudflare Edge"
                            >
                              {deployingSingleRuleKey === key ? <Loader2 size={12} className="wcp-spin" /> : <Cloud size={12} />}
                              Push Rule to Edge
                            </button>
                          )}

                          <button
                            type="button"
                            className={`wcp-btn wcp-cf-tune-toggle-btn ${isEditing ? 'active' : ''}`}
                            onClick={() => {
                              setCfRuleCustomizations(prev => ({
                                ...prev,
                                [key]: { ...(prev[key] || {}), isEditing: !isEditing }
                              }));
                            }}
                          >
                            <Sliders size={12} style={{ marginRight: '4px' }} />
                            {isEditing ? 'Close Tuning' : 'Customize Rule'}
                          </button>
                        </div>

                        <p className="wcp-firewall-section-desc" style={{ fontSize: '12.5px', margin: '4px 0 8px 0' }}>{def.description}</p>
                      </div>

                      <label style={{ display: 'flex', alignItems: 'center', cursor: 'pointer', gap: '6px' }} title="Include in bulk deploy">
                        <input
                          type="checkbox"
                          checked={isSelected}
                          onChange={(e) => setCfSelectedRules(prev => ({ ...prev, [key]: e.target.checked }))}
                          style={{ width: '18px', height: '18px', cursor: 'pointer', accentColor: '#ea580c' }}
                        />
                      </label>
                    </div>

                    {/* Standard Expression Display */}
                    {!isEditing && (
                      <code style={{ display: 'inline-block', marginTop: '6px', fontSize: '11px', padding: '4px 8px', borderRadius: '4px', wordBreak: 'break-all' }}>
                        {currentExpr}
                        {currentBypass && <span style={{ color: '#16a34a', fontWeight: 600 }}> and not (ip.src in &#123;{currentBypass}&#125;)</span>}
                      </code>
                    )}

                    {/* Customizer Drawer */}
                    {isEditing && (
                      <div className="wcp-cf-tuning-drawer">
                        <div>
                          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '4px' }}>
                            <strong className="wcp-cf-tuning-label" style={{ marginBottom: 0 }}>Cloudflare Wirefilter Expression:</strong>
                            <button
                              type="button"
                              className="wcp-cf-reset-link"
                              onClick={() => {
                                setCfRuleCustomizations(prev => ({
                                  ...prev,
                                  [key]: { ...(prev[key] || {}), expression: def.expression }
                                }));
                              }}
                            >
                              Reset to Default
                            </button>
                          </div>
                          <textarea
                            rows={3}
                            value={currentExpr}
                            onChange={(e) => {
                              const val = e.target.value;
                              setCfRuleCustomizations(prev => ({
                                ...prev,
                                [key]: { ...(prev[key] || {}), expression: val }
                              }));
                            }}
                            className="wcp-cf-input wcp-cf-mono-input"
                            style={{
                              width: '100%',
                              fontSize: '11.5px',
                              padding: '8px',
                              borderRadius: '6px'
                            }}
                          />
                        </div>

                        <div>
                          <strong className="wcp-cf-tuning-label" style={{ marginBottom: 0 }}>Whitelist / Bypass Safe IPs (Optional):</strong>
                          <div style={{ display: 'flex', gap: '8px', marginTop: '4px', alignItems: 'center' }}>
                            <input
                              type="text"
                              placeholder="e.g. 192.0.2.1, 198.51.100.4"
                              value={currentBypass}
                              onChange={(e) => {
                                const val = e.target.value;
                                setCfRuleCustomizations(prev => ({
                                  ...prev,
                                  [key]: { ...(prev[key] || {}), bypass_ips: val }
                                }));
                              }}
                              className="wcp-cf-input"
                              style={{
                                flex: 1,
                                fontSize: '12px',
                                padding: '6px 10px',
                                borderRadius: '6px'
                              }}
                            />
                            {status?.client_ip && (
                              <button
                                type="button"
                                className="wcp-cf-add-ip-btn"
                                onClick={() => {
                                  const existing = currentBypass ? currentBypass.split(',').map(s => s.trim()) : [];
                                  if (!existing.includes(status.client_ip)) {
                                    existing.push(status.client_ip);
                                    setCfRuleCustomizations(prev => ({
                                      ...prev,
                                      [key]: { ...(prev[key] || {}), bypass_ips: existing.join(', ') }
                                    }));
                                  }
                                }}
                              >
                                + Add My IP ({status.client_ip})
                              </button>
                            )}
                          </div>
                          <span className="wcp-cf-hint">
                            Traffic matching these IPs will bypass this rule at Cloudflare edge to prevent developer lockout.
                          </span>
                        </div>
                      </div>
                    )}
                  </div>
                );
              })}
            </div>
          </div>

          {/* Rate Limiting & Auto-Ban Sync Cards */}
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(320px, 1fr))', gap: '20px' }}>
            {/* Free Rate Limiter */}
            <div className="wcp-firewall-card" style={{ padding: '20px' }}>
              <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '8px', flexWrap: 'wrap', gap: '8px' }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: '8px', flexWrap: 'wrap' }}>
                  <h4 className="wcp-firewall-section-title" style={{ margin: 0, display: 'flex', alignItems: 'center', gap: '8px' }}>
                    <Zap size={18} color="#ea580c" /> Cloudflare Free Rate Limiting ({rateLimitPathDisplay})
                  </h4>
                  <span className="wcp-cf-badge-free">
                    Free Plan Standard
                  </span>
                </div>
                <button
                  type="button"
                  className={`wcp-btn wcp-cf-tune-toggle-btn ${isEditingRateLimit ? 'active' : ''}`}
                  onClick={() => setIsEditingRateLimit(!isEditingRateLimit)}
                >
                  <Sliders size={12} />
                  {isEditingRateLimit ? 'Hide Tuning' : 'Customize Rate Limit'}
                </button>
              </div>

              <p className="wcp-firewall-section-desc" style={{ marginBottom: '14px' }}>
                Protects <code>{rateLimitPathDisplay}</code> against high-frequency brute force attacks at the Cloudflare Edge before PHP boots or consumes server resources.
                Currently configured for <strong>{rateLimitRequests} requests</strong> per <strong>{rateLimitPeriod} seconds</strong> with action <strong>{rateLimitAction.toUpperCase()}</strong> and <strong>{rateLimitTimeout}s</strong> edge penalty.
              </p>

              {/* Rate Limit Customization Drawer */}
              {isEditingRateLimit && (
                <div className="wcp-cf-tuning-drawer">
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '8px', paddingBottom: '6px', borderBottom: '1px solid var(--wcp-border, #e2e8f0)' }}>
                    <span style={{ fontSize: '11px', color: 'var(--wcp-text-muted, #64748b)' }}>
                      Free Tier Calibration for WordPress Login:
                    </span>
                    <button
                      type="button"
                      className="wcp-cf-preset-btn"
                      onClick={() => {
                        setRateLimitRequests(5);
                        setRateLimitPeriod(10);
                        setRateLimitTimeout(10);
                        setRateLimitAction('block');
                        setRateLimitPath('wp-login.php');
                      }}
                    >
                      <Zap size={12} color="#ea580c" /> Reset to Recommended Free Defaults
                    </button>
                  </div>

                  <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(130px, 1fr))', gap: '10px' }}>
                    {/* Action Selector */}
                    <div>
                      <label className="wcp-cf-tuning-label">
                        Mitigation Action
                      </label>
                      <select
                        className={`wcp-firewall-select wcp-cf-action-select wcp-action-${rateLimitAction}`}
                        value={rateLimitAction}
                        onChange={(e) => setRateLimitAction(e.target.value)}
                        style={{
                          fontSize: '11px',
                          fontWeight: 700,
                          padding: '4px 8px',
                          borderRadius: '4px',
                          width: '100%',
                          textTransform: 'uppercase'
                        }}
                      >
                        <option value="block">BLOCK</option>
                        <option value="managed_challenge">MANAGED CHALLENGE (Turnstile)</option>
                        <option value="js_challenge">JS CHALLENGE</option>
                        <option value="challenge">INTERACTIVE CAPTCHA</option>
                      </select>
                    </div>

                    {/* Request Threshold */}
                    <div>
                      <label className="wcp-cf-tuning-label">
                        Request Threshold: <strong>{rateLimitRequests} reqs</strong>
                      </label>
                      <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
                        <input
                          type="range"
                          min={2}
                          max={60}
                          step={1}
                          value={rateLimitRequests}
                          onChange={(e) => setRateLimitRequests(Number(e.target.value))}
                          style={{ width: '100%', accentColor: '#ea580c' }}
                        />
                        <span className="wcp-cf-slider-val">
                          {rateLimitRequests}
                        </span>
                      </div>
                    </div>

                    {/* Time Window */}
                    <div>
                      <label className="wcp-cf-tuning-label">
                        Counting Window
                      </label>
                      <select
                        className="wcp-firewall-select wcp-cf-input"
                        value={rateLimitPeriod}
                        onChange={(e) => setRateLimitPeriod(Number(e.target.value))}
                        style={{ fontSize: '11px', padding: '4px 8px', borderRadius: '4px', width: '100%' }}
                      >
                        <option value={10}>10 Seconds (Strict Burst Defense — Recommended)</option>
                        <option value={60}>60 Seconds (1 Minute Sustained)</option>
                      </select>
                    </div>

                    {/* Mitigation Timeout */}
                    <div>
                      <label className="wcp-cf-tuning-label">
                        Penalty Duration
                      </label>
                      <select
                        className="wcp-firewall-select wcp-cf-input"
                        value={rateLimitTimeout}
                        onChange={(e) => setRateLimitTimeout(Number(e.target.value))}
                        style={{ fontSize: '11px', padding: '4px 8px', borderRadius: '4px', width: '100%' }}
                      >
                        <option value={10}>10 Seconds (Cloudflare Free Standard — Required)</option>
                        <option value={60}>60 Seconds (Pro / Enterprise Plan)</option>
                        <option value={300}>300 Seconds / 5 Mins (Pro / Enterprise Plan)</option>
                        <option value={900}>900 Seconds / 15 Mins (Pro / Enterprise Plan)</option>
                        <option value={3600}>3600 Seconds / 1 Hour (Business / Enterprise)</option>
                        <option value={86400}>86400 Seconds / 24 Hours (Enterprise Plan)</option>
                      </select>
                    </div>
                  </div>

                  <span className="wcp-cf-hint" style={{ marginTop: '2px' }}>
                    Note: Cloudflare Free plans strictly enforce a 10s edge rate mitigation timeout. To enforce prolonged 12h–24h bans for repeated brute-force attacks, enable <strong>Real-time WAF Auto-Ban Sync</strong> below.
                  </span>

                  {/* Target Endpoint & Whitelist */}
                  <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(220px, 1fr))', gap: '10px' }}>
                    <div>
                      <label className="wcp-cf-tuning-label">
                        Target URI Path
                      </label>
                      <input
                        type="text"
                        className="wcp-cf-input wcp-cf-mono-input"
                        value={rateLimitPath}
                        placeholder="wp-login.php, my-account, wp-custom-login, xmlrpc.php"
                        onChange={(e) => setRateLimitPath(e.target.value)}
                        style={{
                          width: '100%',
                          fontSize: '11.5px',
                          padding: '5px 8px',
                          borderRadius: '4px'
                        }}
                      />
                      <span className="wcp-cf-hint">
                        Target path (defaults to <code>wp-login.php</code>). Supports multiple comma-separated paths or custom login slugs without leading slashes.
                      </span>

                      {/* Quick Target Endpoint Chips */}
                      <div className="wcp-cf-chips-container">
                        <span style={{ fontSize: '11px', color: 'var(--wcp-text-muted, #64748b)', display: 'inline-flex', alignItems: 'center' }}>
                          Quick Endpoints:
                        </span>
                        {[
                          { slug: 'wp-login.php', label: 'wp-login.php' },
                          { slug: 'wp-custom-login', label: 'wp-custom-login' },
                          { slug: 'my-account', label: 'my-account' },
                          { slug: 'xmlrpc.php', label: 'xmlrpc.php' },
                          { slug: 'register', label: 'register' },
                          { slug: 'login', label: 'login' },
                        ].map((chip) => {
                          const isChipActive = parsedRateLimitPaths.includes(chip.slug);
                          return (
                            <button
                              key={chip.slug}
                              type="button"
                              className={`wcp-cf-path-chip ${isChipActive ? 'active' : ''}`}
                              title={isChipActive ? `Remove ${chip.slug} from rate limit targets` : `Add ${chip.slug} to rate limit targets`}
                              onClick={() => {
                                let updated: string[];
                                if (isChipActive) {
                                  updated = parsedRateLimitPaths.filter(s => s !== chip.slug);
                                  if (updated.length === 0) updated = ['wp-login.php'];
                                } else {
                                  updated = [...parsedRateLimitPaths, chip.slug];
                                }
                                setRateLimitPath(updated.join(', '));
                              }}
                            >
                              {isChipActive ? '✓ ' : '+ '}
                              {chip.label}
                            </button>
                          );
                        })}
                      </div>

                      {/* WooCommerce & Member Caution Banner */}
                      {parsedRateLimitPaths.some(p => ['my-account', 'register', 'membership', 'login'].includes(p)) && rateLimitAction === 'block' && (
                        <div className="wcp-cf-warning-banner">
                          <span>
                            ⚠️ <strong>WooCommerce / Registration Caution:</strong> Mitigation action is set to <strong>BLOCK</strong> for account/portal endpoints (<code>{parsedRateLimitPaths.filter(p => ['my-account', 'register', 'membership', 'login'].includes(p)).join(', ')}</code>). Rapid browsing by real customers could trigger an unexpected block. Recommended: switch action to <strong>Managed Challenge</strong>.
                          </span>
                          <button
                            type="button"
                            onClick={() => setRateLimitAction('managed_challenge')}
                            style={{
                              background: '#d97706',
                              color: '#ffffff',
                              border: 'none',
                              borderRadius: '4px',
                              padding: '3px 10px',
                              fontSize: '11px',
                              fontWeight: 700,
                              cursor: 'pointer',
                              whiteSpace: 'nowrap'
                            }}
                          >
                            Switch to Managed Challenge
                          </button>
                        </div>
                      )}
                    </div>

                    <div>
                      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '4px' }}>
                        <label className="wcp-cf-tuning-label">
                          Bypass Safe IPs
                        </label>
                        {status?.client_ip && (
                          <button
                            type="button"
                            className="wcp-cf-add-ip-btn"
                            onClick={() => {
                              const ip = status.client_ip;
                              if (!rateLimitBypassIps.includes(ip)) {
                                setRateLimitBypassIps(rateLimitBypassIps ? `${rateLimitBypassIps}, ${ip}` : ip);
                              }
                            }}
                          >
                            + Add My IP ({status.client_ip})
                          </button>
                        )}
                      </div>
                      <input
                        type="text"
                        className="wcp-cf-input wcp-cf-mono-input"
                        value={rateLimitBypassIps}
                        placeholder="e.g. 203.0.113.195, 198.51.100.4"
                        onChange={(e) => setRateLimitBypassIps(e.target.value)}
                        style={{
                          width: '100%',
                          fontSize: '11.5px',
                          padding: '5px 8px',
                          borderRadius: '4px'
                        }}
                      />
                      <span className="wcp-cf-hint">
                        Traffic from these IPs will not trigger the rate limit.
                      </span>
                    </div>
                  </div>

                  {cfRateLimitEnabled && (
                    <div style={{ display: 'flex', justifyContent: 'flex-end', marginTop: '4px' }}>
                      <button
                        type="button"
                        className="wcp-btn"
                        style={{
                          background: '#ea580c',
                          color: '#ffffff',
                          border: 'none',
                          fontSize: '11px',
                          fontWeight: 600,
                          padding: '5px 12px',
                          borderRadius: '4px',
                          cursor: 'pointer',
                          display: 'flex',
                          alignItems: 'center',
                          gap: '6px'
                        }}
                        disabled={cfRateLimitLoading}
                        onClick={() => handleToggleRateLimiting(true)}
                      >
                        {cfRateLimitLoading && <Loader2 size={12} className="wcp-spin" />}
                        Apply & Update Edge Rule
                      </button>
                    </div>
                  )}
                </div>
              )}

              {cfRateLimitMessage && (
                <div style={{
                  background: cfRateLimitMessage.type === 'success' ? '#ecfdf5' : '#fef2f2',
                  border: cfRateLimitMessage.type === 'success' ? '1px solid #a7f3d0' : '1px solid #fecaca',
                  color: cfRateLimitMessage.type === 'success' ? '#065f46' : '#991b1b',
                  padding: '10px 14px',
                  borderRadius: '6px',
                  fontSize: '12px',
                  marginBottom: '14px',
                  lineHeight: 1.4
                }}>
                  {cfRateLimitMessage.text}
                </div>
              )}

              <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', paddingTop: '10px', borderTop: '1px solid var(--wcp-border, #e2e8f0)' }}>
                <span style={{ fontSize: '13px', fontWeight: 600, color: cfRateLimitEnabled ? '#166534' : undefined }}>
                  {cfRateLimitEnabled ? '✓ Rate Limiting Active' : 'Rate Limiting Disabled'}
                </span>
                <button
                  type="button"
                  className={cfRateLimitEnabled ? 'wcp-cf-btn-deactivate' : 'wcp-cf-btn-activate'}
                  disabled={!cfStatus?.configured || cfRateLimitLoading}
                  onClick={() => handleToggleRateLimiting()}
                >
                  {cfRateLimitLoading && <Loader2 size={13} className="wcp-spin" />}
                  {cfRateLimitEnabled ? 'Deactivate Rate Limiting' : 'Activate Rate Limiting'}
                </button>
              </div>
            </div>

            {/* Edge Auto-Ban Sync */}
            <div className="wcp-firewall-card" style={{ padding: '20px' }}>
              <h4 className="wcp-firewall-section-title" style={{ marginBottom: '8px' }}>
                <ShieldAlert size={18} color="#ea580c" /> Real-time WAF Auto-Ban Sync
              </h4>
              <p className="wcp-firewall-section-desc" style={{ marginBottom: '16px' }}>
                When WCP Local WAF or Login Hardening detects critical attacks (SQLi, webshell uploads, repeated login brute force), it automatically syncs the attacking IP to Cloudflare Edge IP Access Rules for prolonged edge blocking.
              </p>

              <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', flexWrap: 'wrap', gap: '10px', paddingTop: '10px', borderTop: '1px solid var(--wcp-border, #e2e8f0)' }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
                  <span style={{ fontSize: '13px', fontWeight: 600, color: cfAutoSyncBans ? '#166534' : undefined }}>
                    {cfAutoSyncBans ? '✓ Cloudflare Sync Enabled' : 'Auto-Sync Disabled'}
                  </span>
                  {cfStatus?.configured && (
                    <span style={{ fontSize: '12px', color: 'var(--wcp-text-muted, #64748b)' }}>
                      • ({cfStatus?.ip_rules_count || 0} active bans)
                    </span>
                  )}
                </div>
                <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                  <button
                    type="button"
                    className="wcp-btn"
                    style={{
                      background: 'var(--wcp-bg-surface, #ffffff)',
                      color: 'var(--wcp-text-primary, #0f172a)',
                      border: '1px solid var(--wcp-border, #cbd5e1)',
                      padding: '6px 14px',
                      borderRadius: '6px',
                      fontSize: '12.5px',
                      fontWeight: 600,
                      display: 'inline-flex',
                      alignItems: 'center',
                      gap: '6px'
                    }}
                    disabled={!cfStatus?.configured}
                    onClick={handleOpenBannedIpsModal}
                  >
                    <List size={14} color="#ea580c" /> View Banned IP List
                  </button>
                  <button
                    type="button"
                    className={cfAutoSyncBans ? 'wcp-cf-btn-deactivate' : 'wcp-cf-btn-activate'}
                    disabled={!cfStatus?.configured}
                    onClick={handleToggleAutoSyncBans}
                  >
                    {cfAutoSyncBans ? 'Disable Sync' : 'Enable Auto-Sync'}
                  </button>
                </div>
              </div>
            </div>
          </div>

          {/* Manual Edge IP Block Tool */}
          <div className="wcp-firewall-card" style={{ padding: '20px' }}>
            <h4 className="wcp-firewall-section-title" style={{ marginBottom: '8px' }}>
              <Lock size={18} color="#ea580c" /> Manual Cloudflare Edge IP Block
            </h4>
            <p className="wcp-firewall-section-desc" style={{ marginBottom: '16px' }}>
              Block a specific malicious IP or subnet at the Cloudflare Edge. Currently managing <strong>{cfStatus?.ip_rules_count || 0}</strong> active Edge IP rules.
            </p>

            <div style={{ display: 'flex', gap: '12px', flexWrap: 'wrap' }}>
              <input
                type="text"
                value={manualBlockIp}
                onChange={(e) => setManualBlockIp(e.target.value)}
                placeholder="IP Address (e.g. 198.51.100.4)"
                className="wcp-firewall-input"
                style={{ flex: 1, minWidth: '200px', padding: '8px 12px' }}
              />
              <input
                type="text"
                value={manualBlockReason}
                onChange={(e) => setManualBlockReason(e.target.value)}
                placeholder="Reason / Note (optional)"
                className="wcp-firewall-input"
                style={{ flex: 1, minWidth: '200px', padding: '8px 12px' }}
              />
              <button
                type="button"
                className="wcp-btn"
                style={{ background: '#dc2626', color: '#fff', border: 'none', padding: '8px 18px', fontWeight: 600, fontSize: '13px' }}
                disabled={manualBlocking || !cfStatus?.configured || !manualBlockIp.trim()}
                onClick={handleManualBlockIp}
              >
                {manualBlocking ? <Loader2 size={15} className="wcp-spin" /> : 'Block at Edge'}
              </button>
            </div>
          </div>
        </div>
      )}

      {/* TAB: Server Security (Nginx / Apache Web Server Armor) */}
      {activeTab === 'server_sec' && (
        <ServerSecurityTab
          apiRequest={apiRequest}
          serverSoftwareType={status?.server_telemetry?.server_software_type || 'nginx'}
          serverSoftwareRaw={status?.server_telemetry?.server_software || 'Web Server'}
        />
      )}

      {/* TAB 5: Virtual Patching & Zero-Day Shield */}
      {activeTab === 'vpatch' && (
        <VirtualPatchCard
          apiRequest={apiRequest}
          onNavigateToSettings={() => setActiveTab('cloudflare')}
        />
      )}

      {/* Modal: View Existing Cloudflare Rules & Slots Allocation */}
      {showExistingRulesModal && (
        <div
          style={{
            position: 'fixed',
            inset: 0,
            background: 'rgba(15, 23, 42, 0.65)',
            backdropFilter: 'blur(4px)',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            zIndex: 999999,
            padding: '20px'
          }}
          onClick={() => setShowExistingRulesModal(false)}
        >
          <div
            style={{
              background: 'var(--wcp-bg-card, #ffffff)',
              borderRadius: '14px',
              border: '1px solid var(--wcp-border, #e2e8f0)',
              width: '100%',
              maxWidth: '820px',
              maxHeight: '90vh',
              display: 'flex',
              flexDirection: 'column',
              boxShadow: '0 20px 25px -5px rgba(0, 0, 0, 0.2), 0 10px 10px -5px rgba(0, 0, 0, 0.04)',
              overflow: 'hidden'
            }}
            onClick={(e) => e.stopPropagation()}
          >
            {/* Modal Header */}
            <div style={{
              padding: '18px 22px',
              borderBottom: '1px solid var(--wcp-border, #e2e8f0)',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'space-between',
              background: 'var(--wcp-bg-elevated, #f8fafc)'
            }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
                <Cloud size={20} color="#ea580c" />
                <h3 style={{ margin: 0, fontSize: '16px', color: 'var(--wcp-text-primary, #0f172a)' }}>
                  Active Cloudflare Edge Rules &amp; Slot Allocation
                </h3>
              </div>
              <button
                type="button"
                onClick={() => setShowExistingRulesModal(false)}
                style={{
                  background: 'none',
                  border: 'none',
                  cursor: 'pointer',
                  color: 'var(--wcp-text-muted, #64748b)',
                  padding: '4px',
                  display: 'flex'
                }}
              >
                <X size={18} />
              </button>
            </div>

            {/* Modal Body */}
            <div style={{ padding: '22px', overflowY: 'auto', flex: 1, display: 'flex', flexDirection: 'column', gap: '20px' }}>
              {inspectingRules ? (
                <div style={{ padding: '40px', textAlign: 'center', color: 'var(--wcp-text-muted, #64748b)' }}>
                  <Loader2 size={24} className="wcp-spin" style={{ margin: '0 auto 12px auto' }} />
                  <div>Querying Cloudflare Edge Custom Rulesets API...</div>
                </div>
              ) : (
                <>
                  {/* Summary Strip */}
                  {(() => {
                    const inspection = cfInspectionData || cfStatus?.edge_inspection;
                    const plan = inspection?.plan || cfStatus?.plan || 'Free';
                    const maxSlots = inspection?.max_slots || 5;
                    const totalUsed = inspection?.total_used !== undefined ? inspection.total_used : Object.keys(cfStatus?.active_rules || {}).length;
                    const freeSlots = Math.max(0, maxSlots - totalUsed);
                    const userRules = inspection?.user_rules || [];
                    const wcpRules = inspection?.wcp_rules || [];

                    return (
                      <>
                        <div style={{
                          display: 'grid',
                          gridTemplateColumns: 'repeat(auto-fit, minmax(180px, 1fr))',
                          gap: '12px'
                        }}>
                          <div className="wcp-firewall-inset-box" style={{ padding: '12px' }}>
                            <div style={{ fontSize: '11px', color: 'var(--wcp-text-muted, #64748b)', textTransform: 'uppercase', fontWeight: 600 }}>Plan Limit</div>
                            <div style={{ fontSize: '18px', fontWeight: 700, color: 'var(--wcp-text-primary, #0f172a)', marginTop: '2px' }}>
                              {maxSlots} Max Rules ({plan})
                            </div>
                          </div>
                          <div className="wcp-firewall-inset-box" style={{ padding: '12px' }}>
                            <div style={{ fontSize: '11px', color: 'var(--wcp-text-muted, #64748b)', textTransform: 'uppercase', fontWeight: 600 }}>Active Rules Total</div>
                            <div style={{ fontSize: '18px', fontWeight: 700, color: 'var(--wcp-status-cyan, #0284c7)', marginTop: '2px' }}>
                              {totalUsed} Rules Deployed
                            </div>
                          </div>
                          <div className={freeSlots > 0 ? 'wcp-smart-shield-rec-banner-emerald' : 'wcp-smart-shield-rec-banner-purple'} style={{ padding: '12px', borderRadius: '8px', display: 'block' }}>
                            <div style={{ fontSize: '11px', textTransform: 'uppercase', fontWeight: 600 }}>Free Slots</div>
                            <div style={{ fontSize: '18px', fontWeight: 700, marginTop: '2px' }}>
                              {freeSlots} Remaining
                            </div>
                          </div>
                        </div>

                        {/* User Dashboard Rules Section */}
                        <div>
                          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '8px' }}>
                            <strong style={{ fontSize: '14px', color: 'var(--wcp-text-primary, #0f172a)' }}>
                              Custom User-Created Rules in Cloudflare ({userRules.length})
                            </strong>
                            <span style={{ fontSize: '11px', color: 'var(--wcp-text-muted, #64748b)' }}>
                              Created directly in dash.cloudflare.com
                            </span>
                          </div>

                          {userRules.length === 0 ? (
                            <div className="wcp-firewall-inset-box" style={{ padding: '16px', fontSize: '13px', color: 'var(--wcp-text-muted, #64748b)' }}>
                              ✓ No non-WCP custom rules detected. All {maxSlots} slots are fully available for your site!
                            </div>
                          ) : (
                            <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
                              {userRules.map((r: any, idx: number) => (
                                <div
                                  key={idx}
                                  className="wcp-firewall-rule-card"
                                  style={{
                                    padding: '12px 14px',
                                    display: 'flex',
                                    flexDirection: 'column',
                                    gap: '6px'
                                  }}
                                >
                                  <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: '8px' }}>
                                    <strong style={{ fontSize: '13px', color: 'var(--wcp-text-primary, #0f172a)' }}>{r.description}</strong>
                                    <span className={r.action === 'block' ? 'wcp-smart-shield-pill-empty' : 'wcp-smart-shield-pill-detected-sky'} style={{ textTransform: 'uppercase' }}>
                                      {r.action}
                                    </span>
                                  </div>
                                  <code style={{ fontSize: '11.5px', background: 'var(--wcp-bg-deep, #090d16)', padding: '6px 8px', borderRadius: '4px', color: 'var(--wcp-status-cyan, #38bdf8)', wordBreak: 'break-all' }}>
                                    {r.expression}
                                  </code>
                                </div>
                              ))}
                            </div>
                          )}
                        </div>

                        {/* WCP Managed Rules Section */}
                        <div>
                          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '8px' }}>
                            <strong style={{ fontSize: '14px', color: 'var(--wcp-text-primary, #0f172a)' }}>
                              WCP Security Scanner Managed Rules ({wcpRules.length})
                            </strong>
                            <span style={{ fontSize: '11px', color: 'var(--wcp-text-muted, #64748b)' }}>
                              Synchronized with in-plugin 1-Click deployer
                            </span>
                          </div>

                          {wcpRules.length === 0 ? (
                            <div className="wcp-firewall-inset-box" style={{ padding: '16px', fontSize: '13px', color: 'var(--wcp-text-muted, #64748b)' }}>
                              No WCP compound rules currently deployed. Select rules below and click "Deploy Selected Rules to Edge".
                            </div>
                          ) : (
                            <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
                              {wcpRules.map((r: any, idx: number) => (
                                <div
                                  key={idx}
                                  className="wcp-firewall-rule-card"
                                  style={{
                                    padding: '12px 14px',
                                    display: 'flex',
                                    flexDirection: 'column',
                                    gap: '6px'
                                  }}
                                >
                                  <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: '8px' }}>
                                    <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                                      <span style={{ width: '8px', height: '8px', borderRadius: '50%', background: '#16a34a' }} />
                                      <strong style={{ fontSize: '13px', color: 'var(--wcp-text-primary, #0f172a)' }}>{r.description}</strong>
                                    </div>
                                    <span className="wcp-smart-shield-pill-detected-emerald" style={{ textTransform: 'uppercase' }}>
                                      {r.action}
                                    </span>
                                  </div>
                                  <code style={{ fontSize: '11.5px', background: 'var(--wcp-bg-deep, #090d16)', padding: '6px 8px', borderRadius: '4px', color: 'var(--wcp-status-cyan, #38bdf8)', wordBreak: 'break-all' }}>
                                    {r.expression}
                                  </code>
                                </div>
                              ))}
                            </div>
                          )}
                        </div>
                      </>
                    );
                  })()}
                </>
              )}
            </div>

            {/* Modal Footer */}
            <div style={{
              padding: '14px 22px',
              borderTop: '1px solid var(--wcp-border, #e2e8f0)',
              background: 'var(--wcp-bg-elevated, #f8fafc)',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'space-between'
            }}>
              <a
                href="https://dash.cloudflare.com/"
                target="_blank"
                rel="noreferrer"
                style={{ fontSize: '12px', color: '#ea580c', fontWeight: 600, textDecoration: 'none', display: 'inline-flex', alignItems: 'center', gap: '4px' }}
              >
                Open Cloudflare Dashboard ↗
              </a>
              <button
                type="button"
                className="wcp-btn"
                onClick={() => setShowExistingRulesModal(false)}
                style={{ background: '#0f172a', color: '#fff', border: 'none', padding: '7px 16px', borderRadius: '6px', fontSize: '12.5px', fontWeight: 600 }}
              >
                Close Inspector
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Modal: View & Manage Existing Cloudflare Whitelisted IPs */}
      {showCfWhitelistModal && (
        <div
          style={{
            position: 'fixed',
            inset: 0,
            background: 'rgba(15, 23, 42, 0.65)',
            backdropFilter: 'blur(4px)',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            zIndex: 999999,
            padding: '20px'
          }}
          onClick={() => setShowCfWhitelistModal(false)}
        >
          <div
            style={{
              background: 'var(--wcp-bg-card, #ffffff)',
              borderRadius: '14px',
              border: '1px solid var(--wcp-border, #e2e8f0)',
              width: '100%',
              maxWidth: '850px',
              maxHeight: '90vh',
              display: 'flex',
              flexDirection: 'column',
              boxShadow: '0 20px 25px -5px rgba(0, 0, 0, 0.2), 0 10px 10px -5px rgba(0, 0, 0, 0.04)',
              overflow: 'hidden'
            }}
            onClick={(e) => e.stopPropagation()}
          >
            {/* Modal Header */}
            <div style={{
              padding: '18px 22px',
              borderBottom: '1px solid var(--wcp-border, #e2e8f0)',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'space-between',
              background: 'var(--wcp-bg-elevated, #f8fafc)'
            }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
                <div style={{
                  width: '32px',
                  height: '32px',
                  borderRadius: '8px',
                  background: 'rgba(16, 185, 129, 0.15)',
                  border: '1px solid rgba(16, 185, 129, 0.3)',
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'center'
                }}>
                  <ShieldCheck size={18} color="#10b981" />
                </div>
                <div>
                  <h3 style={{ margin: 0, fontSize: '16px', color: 'var(--wcp-text-primary, #0f172a)' }}>
                    Existing Cloudflare Edge Whitelisted IPs ({cfWhitelistTotal})
                  </h3>
                  <div style={{ fontSize: '12px', color: 'var(--wcp-text-muted, #64748b)' }}>
                    Active <code>mode: whitelist</code> IP Access Rules deployed on your Cloudflare Zone
                  </div>
                </div>
              </div>
              <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                <button
                  type="button"
                  onClick={loadCfWhitelist}
                  disabled={loadingCfWhitelist}
                  title="Refresh Whitelist from Cloudflare Edge"
                  style={{
                    background: 'var(--wcp-bg-card, #ffffff)',
                    border: '1px solid var(--wcp-border, #cbd5e1)',
                    padding: '6px 12px',
                    borderRadius: '6px',
                    fontSize: '12px',
                    fontWeight: 600,
                    color: 'var(--wcp-text-primary, #0f172a)',
                    display: 'inline-flex',
                    alignItems: 'center',
                    gap: '5px',
                    cursor: loadingCfWhitelist ? 'not-allowed' : 'pointer'
                  }}
                >
                  <RefreshCw size={13} className={loadingCfWhitelist ? 'wcp-spin' : ''} />
                  Refresh
                </button>
                <button
                  type="button"
                  onClick={() => setShowCfWhitelistModal(false)}
                  style={{
                    background: 'none',
                    border: 'none',
                    color: 'var(--wcp-text-muted, #64748b)',
                    cursor: 'pointer',
                    padding: '4px'
                  }}
                >
                  <X size={18} />
                </button>
              </div>
            </div>

            {/* Search Filter Bar */}
            <div style={{
              padding: '12px 22px',
              borderBottom: '1px solid var(--wcp-border, #e2e8f0)',
              background: 'var(--wcp-bg-surface, #ffffff)',
              display: 'flex',
              alignItems: 'center',
              gap: '10px'
            }}>
              <Search size={16} color="var(--wcp-text-muted, #64748b)" />
              <input
                type="text"
                placeholder="Search whitelisted IP address, subnet, or description..."
                value={cfWhitelistSearch}
                onChange={(e) => setCfWhitelistSearch(e.target.value)}
                style={{
                  border: 'none',
                  outline: 'none',
                  width: '100%',
                  fontSize: '13px',
                  background: 'transparent',
                  color: 'var(--wcp-text-primary, #0f172a)'
                }}
              />
              {cfWhitelistSearch && (
                <button
                  type="button"
                  onClick={() => setCfWhitelistSearch('')}
                  style={{
                    background: 'none',
                    border: 'none',
                    color: 'var(--wcp-text-muted, #64748b)',
                    cursor: 'pointer',
                    fontSize: '11px'
                  }}
                >
                  Clear
                </button>
              )}
            </div>

            {/* Modal Body */}
            <div style={{ padding: '22px', overflowY: 'auto', flex: 1, display: 'flex', flexDirection: 'column', gap: '12px' }}>
              {loadingCfWhitelist ? (
                <div style={{ padding: '50px 20px', textAlign: 'center', color: 'var(--wcp-text-muted, #64748b)' }}>
                  <Loader2 size={26} className="wcp-spin" style={{ margin: '0 auto 12px auto', color: '#10b981' }} />
                  <div>Querying Cloudflare Edge IP Access Rules API...</div>
                </div>
              ) : (
                (() => {
                  const filtered = cfWhitelistList.filter(item => {
                    if (!cfWhitelistSearch.trim()) return true;
                    const query = cfWhitelistSearch.toLowerCase();
                    return (
                      (item.ip && item.ip.toLowerCase().includes(query)) ||
                      (item.notes && item.notes.toLowerCase().includes(query))
                    );
                  });

                  if (filtered.length === 0) {
                    return (
                      <div className="wcp-firewall-inset-box" style={{ padding: '36px 20px', textAlign: 'center' }}>
                        <Globe size={36} color="#0284c7" style={{ margin: '0 auto 10px auto' }} />
                        <h4 style={{ margin: '0 0 6px 0', fontSize: '15px', color: 'var(--wcp-text-primary, #0f172a)' }}>
                          {cfWhitelistSearch ? 'No matching whitelisted IPs found' : 'No active Cloudflare Edge whitelist rules'}
                        </h4>
                        <p style={{ margin: 0, fontSize: '12.5px', color: 'var(--wcp-text-muted, #64748b)' }}>
                          {cfWhitelistSearch
                            ? 'Try refining your search keyword.'
                            : 'When you sync your IPs using "Sync Whitelist to Cloudflare Edge", they appear here with instant unblock and removal controls.'}
                        </p>
                      </div>
                    );
                  }

                  return (
                    <div style={{ display: 'flex', flexDirection: 'column', gap: '10px' }}>
                      {filtered.map((item) => (
                        <div
                          key={item.id}
                          className="wcp-firewall-rule-card"
                          style={{
                            padding: '14px 16px',
                            display: 'flex',
                            alignItems: 'center',
                            justifyContent: 'space-between',
                            gap: '14px',
                            borderRadius: '10px'
                          }}
                        >
                          <div style={{ display: 'flex', alignItems: 'flex-start', gap: '12px', flex: 1, minWidth: 0 }}>
                            <div style={{
                              width: '32px',
                              height: '32px',
                              borderRadius: '8px',
                              background: '#ecfdf5',
                              border: '1px solid #a7f3d0',
                              display: 'flex',
                              alignItems: 'center',
                              justifyContent: 'center',
                              flexShrink: 0,
                              marginTop: '2px'
                            }}>
                              <CheckCircle size={16} color="#059669" />
                            </div>
                            <div style={{ display: 'flex', flexDirection: 'column', gap: '4px', minWidth: 0 }}>
                              <div style={{ display: 'flex', alignItems: 'center', gap: '8px', flexWrap: 'wrap' }}>
                                <span style={{ fontFamily: 'monospace', fontWeight: 700, fontSize: '14px', color: 'var(--wcp-text-primary, #0f172a)' }}>
                                  {item.ip}
                                </span>
                                <span className="wcp-badge-pill" style={{ background: '#ecfdf5', color: '#047857', border: '1px solid #a7f3d0', fontSize: '11px', padding: '1px 8px' }}>
                                  Mode: Whitelist (Allow)
                                </span>
                                {item.target && (
                                  <span style={{ fontSize: '11px', color: 'var(--wcp-text-muted, #64748b)' }}>
                                    ({item.target.toUpperCase()})
                                  </span>
                                )}
                              </div>
                              <div style={{ fontSize: '12.5px', color: 'var(--wcp-text-secondary, #475569)', lineHeight: '1.4', wordBreak: 'break-word' }}>
                                <strong>Description:</strong> {item.notes}
                              </div>
                              {item.created_on && (
                                <div style={{ fontSize: '11px', color: 'var(--wcp-text-muted, #64748b)' }}>
                                  Created at Edge: {new Date(item.created_on).toLocaleString()}
                                </div>
                              )}
                            </div>
                          </div>

                          <div style={{ flexShrink: 0 }}>
                            <button
                              type="button"
                              className="wcp-btn"
                              style={{
                                background: '#f8fafc',
                                color: '#dc2626',
                                border: '1px solid #fecaca',
                                padding: '6px 12px',
                                borderRadius: '6px',
                                fontSize: '12px',
                                fontWeight: 600,
                                display: 'inline-flex',
                                alignItems: 'center',
                                gap: '5px'
                              }}
                              disabled={removingCfWhitelistId === item.id}
                              onClick={() => handleRemoveCfWhitelistIp(item.id, item.ip)}
                            >
                              {removingCfWhitelistId === item.id ? (
                                <Loader2 size={13} className="wcp-spin" />
                              ) : (
                                <Trash2 size={13} />
                              )}
                              Remove Whitelist IP
                            </button>
                          </div>
                        </div>
                      ))}
                    </div>
                  );
                })()
              )}
            </div>

            {/* Modal Footer */}
            <div style={{
              padding: '14px 22px',
              borderTop: '1px solid var(--wcp-border, #e2e8f0)',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'space-between',
              background: 'var(--wcp-bg-elevated, #f8fafc)'
            }}>
              <span style={{ fontSize: '12px', color: 'var(--wcp-text-muted, #64748b)' }}>
                Removing a rule here immediately purges it from Cloudflare Edge IP Access Rules.
              </span>
              <button
                type="button"
                className="wcp-btn"
                style={{
                  background: 'var(--wcp-bg-card, #ffffff)',
                  border: '1px solid var(--wcp-border, #cbd5e1)',
                  padding: '6px 16px',
                  borderRadius: '6px',
                  fontSize: '12.5px',
                  fontWeight: 600,
                  color: 'var(--wcp-text-primary, #0f172a)',
                  cursor: 'pointer'
                }}
                onClick={() => setShowCfWhitelistModal(false)}
              >
                Close
              </button>
            </div>
          </div>
        </div>
      )}


      {/* Modal: View Banned IP List & Ban Reasons */}
      {showBannedIpsModal && (
        <div
          style={{
            position: 'fixed',
            inset: 0,
            background: 'rgba(15, 23, 42, 0.65)',
            backdropFilter: 'blur(4px)',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            zIndex: 999999,
            padding: '20px'
          }}
          onClick={() => setShowBannedIpsModal(false)}
        >
          <div
            style={{
              background: 'var(--wcp-bg-card, #ffffff)',
              borderRadius: '14px',
              border: '1px solid var(--wcp-border, #e2e8f0)',
              width: '100%',
              maxWidth: '850px',
              maxHeight: '90vh',
              display: 'flex',
              flexDirection: 'column',
              boxShadow: '0 20px 25px -5px rgba(0, 0, 0, 0.2), 0 10px 10px -5px rgba(0, 0, 0, 0.04)',
              overflow: 'hidden'
            }}
            onClick={(e) => e.stopPropagation()}
          >
            {/* Modal Header */}
            <div style={{
              padding: '18px 22px',
              borderBottom: '1px solid var(--wcp-border, #e2e8f0)',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'space-between',
              background: 'var(--wcp-bg-elevated, #f8fafc)'
            }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
                <Ban size={20} color="#dc2626" />
                <div>
                  <h3 style={{ margin: 0, fontSize: '16px', color: 'var(--wcp-text-primary, #0f172a)' }}>
                    Active Cloudflare Edge Banned IPs ({bannedIpsTotal})
                  </h3>
                  <div style={{ fontSize: '12px', color: 'var(--wcp-text-muted, #64748b)' }}>
                    IPs automatically synchronized or manually banned at Cloudflare Edge via WCP Security Scanner
                  </div>
                </div>
              </div>
              <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                <button
                  type="button"
                  onClick={loadBannedIps}
                  disabled={loadingBannedIps}
                  title="Refresh Banned IP list"
                  style={{
                    background: 'var(--wcp-bg-surface, #ffffff)',
                    border: '1px solid var(--wcp-border, #cbd5e1)',
                    borderRadius: '6px',
                    padding: '6px 10px',
                    cursor: 'pointer',
                    color: 'var(--wcp-text-primary, #0f172a)',
                    display: 'flex',
                    alignItems: 'center',
                    gap: '6px',
                    fontSize: '12px'
                  }}
                >
                  <RefreshCw size={14} className={loadingBannedIps ? 'wcp-spin' : ''} /> Refresh
                </button>
                <button
                  type="button"
                  onClick={() => setShowBannedIpsModal(false)}
                  style={{
                    background: 'none',
                    border: 'none',
                    cursor: 'pointer',
                    color: 'var(--wcp-text-muted, #64748b)',
                    padding: '4px',
                    display: 'flex'
                  }}
                >
                  <X size={18} />
                </button>
              </div>
            </div>

            {/* Search Filter Bar */}
            <div style={{
              padding: '12px 22px',
              borderBottom: '1px solid var(--wcp-border, #e2e8f0)',
              background: 'var(--wcp-bg-surface, #ffffff)',
              display: 'flex',
              alignItems: 'center',
              gap: '10px'
            }}>
              <Search size={16} color="var(--wcp-text-muted, #64748b)" />
              <input
                type="text"
                placeholder="Search banned IP address or reason..."
                value={bannedIpSearch}
                onChange={(e) => setBannedIpSearch(e.target.value)}
                style={{
                  border: 'none',
                  outline: 'none',
                  width: '100%',
                  fontSize: '13px',
                  background: 'transparent',
                  color: 'var(--wcp-text-primary, #0f172a)'
                }}
              />
              {bannedIpSearch && (
                <button
                  type="button"
                  onClick={() => setBannedIpSearch('')}
                  style={{
                    background: 'none',
                    border: 'none',
                    color: 'var(--wcp-text-muted, #64748b)',
                    cursor: 'pointer',
                    fontSize: '11px'
                  }}
                >
                  Clear
                </button>
              )}
            </div>

            {/* Modal Body */}
            <div style={{ padding: '22px', overflowY: 'auto', flex: 1, display: 'flex', flexDirection: 'column', gap: '12px' }}>
              {loadingBannedIps ? (
                <div style={{ padding: '50px 20px', textAlign: 'center', color: 'var(--wcp-text-muted, #64748b)' }}>
                  <Loader2 size={26} className="wcp-spin" style={{ margin: '0 auto 12px auto', color: '#ea580c' }} />
                  <div>Querying Cloudflare Edge IP Access Rules API...</div>
                </div>
              ) : (
                (() => {
                  const filtered = bannedIpsList.filter(item => {
                    if (!bannedIpSearch.trim()) return true;
                    const query = bannedIpSearch.toLowerCase();
                    return (
                      (item.ip && item.ip.toLowerCase().includes(query)) ||
                      (item.reason && item.reason.toLowerCase().includes(query))
                    );
                  });

                  if (filtered.length === 0) {
                    return (
                      <div className="wcp-firewall-inset-box" style={{ padding: '36px 20px', textAlign: 'center' }}>
                        <ShieldCheck size={36} color="#10b981" style={{ margin: '0 auto 10px auto' }} />
                        <h4 style={{ margin: '0 0 6px 0', fontSize: '15px', color: 'var(--wcp-text-primary, #0f172a)' }}>
                          {bannedIpSearch ? 'No matching banned IPs found' : 'No active Cloudflare Edge IP bans'}
                        </h4>
                        <p style={{ margin: 0, fontSize: '12.5px', color: 'var(--wcp-text-muted, #64748b)' }}>
                          {bannedIpSearch 
                            ? 'Try refining your search keyword.' 
                            : 'When attackers attempt SQL injection, webshell execution, or brute force, their IPs are synced here automatically.'}
                        </p>
                      </div>
                    );
                  }

                  return (
                    <div style={{ display: 'flex', flexDirection: 'column', gap: '10px' }}>
                      {filtered.map((item) => (
                        <div
                          key={item.id}
                          className="wcp-firewall-rule-card"
                          style={{
                            padding: '14px 16px',
                            display: 'flex',
                            alignItems: 'center',
                            justifyContent: 'space-between',
                            gap: '14px',
                            borderRadius: '10px'
                          }}
                        >
                          <div style={{ display: 'flex', alignItems: 'flex-start', gap: '12px', flex: 1, minWidth: 0 }}>
                            <div style={{
                              width: '32px',
                              height: '32px',
                              borderRadius: '8px',
                              background: '#fef2f2',
                              border: '1px solid #fecaca',
                              display: 'flex',
                              alignItems: 'center',
                              justifyContent: 'center',
                              flexShrink: 0,
                              marginTop: '2px'
                            }}>
                              <Ban size={16} color="#dc2626" />
                            </div>
                            <div style={{ display: 'flex', flexDirection: 'column', gap: '4px', minWidth: 0 }}>
                              <div style={{ display: 'flex', alignItems: 'center', gap: '8px', flexWrap: 'wrap' }}>
                                <span style={{ fontFamily: 'monospace', fontWeight: 700, fontSize: '14px', color: 'var(--wcp-text-primary, #0f172a)' }}>
                                  {item.ip}
                                </span>
                                <span className="wcp-badge-pill" style={{ background: '#fef2f2', color: '#dc2626', border: '1px solid #fecaca', fontSize: '11px', padding: '1px 8px' }}>
                                  Mode: Block
                                </span>
                                {item.target && (
                                  <span style={{ fontSize: '11px', color: 'var(--wcp-text-muted, #64748b)' }}>
                                    ({item.target.toUpperCase()})
                                  </span>
                                )}
                              </div>
                              <div style={{ fontSize: '12.5px', color: 'var(--wcp-text-secondary, #475569)', lineHeight: '1.4', wordBreak: 'break-word' }}>
                                <strong>Ban Reason:</strong> {item.reason}
                              </div>
                              {item.created_on && (
                                <div style={{ fontSize: '11px', color: 'var(--wcp-text-muted, #64748b)' }}>
                                  Banned: {new Date(item.created_on).toLocaleString()}
                                </div>
                              )}
                            </div>
                          </div>

                          <div style={{ flexShrink: 0 }}>
                            <button
                              type="button"
                              className="wcp-btn"
                              style={{
                                background: '#f8fafc',
                                color: '#dc2626',
                                border: '1px solid #fecaca',
                                padding: '6px 12px',
                                borderRadius: '6px',
                                fontSize: '12px',
                                fontWeight: 600,
                                display: 'inline-flex',
                                alignItems: 'center',
                                gap: '5px'
                              }}
                              disabled={unbanningRuleId === item.id}
                              onClick={() => handleUnbanIp(item.id, item.ip)}
                            >
                              {unbanningRuleId === item.id ? (
                                <Loader2 size={13} className="wcp-spin" />
                              ) : (
                                <Unlock size={13} />
                              )}
                              Unban IP
                            </button>
                          </div>
                        </div>
                      ))}
                    </div>
                  );
                })()
              )}
            </div>

            {/* Modal Footer */}
            <div style={{
              padding: '14px 22px',
              borderTop: '1px solid var(--wcp-border, #e2e8f0)',
              background: 'var(--wcp-bg-elevated, #f8fafc)',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'space-between'
            }}>
              <span style={{ fontSize: '12px', color: 'var(--wcp-text-muted, #64748b)' }}>
                Showing {bannedIpsList.length} of {bannedIpsTotal} banned rules
              </span>
              <button
                type="button"
                className="wcp-btn"
                onClick={() => setShowBannedIpsModal(false)}
                style={{
                  background: '#0f172a',
                  color: '#fff',
                  border: 'none',
                  padding: '7px 16px',
                  borderRadius: '6px',
                  fontSize: '12.5px',
                  fontWeight: 600
                }}
              >
                Close
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Edit Whitelist Policy Modal */}
      {editWhitelistItem.isOpen && (
        <div style={{
          position: 'fixed',
          top: 0,
          left: 0,
          right: 0,
          bottom: 0,
          background: 'rgba(0, 0, 0, 0.65)',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'center',
          zIndex: 100000,
          padding: '20px'
        }}>
          <div style={{
            background: 'var(--wcp-bg-surface, #ffffff)',
            borderRadius: '12px',
            width: '100%',
            maxWidth: '560px',
            boxShadow: '0 20px 25px -5px rgba(0, 0, 0, 0.25)',
            border: '1px solid var(--wcp-border, #e2e8f0)',
            overflow: 'hidden'
          }}>
            <div style={{
              padding: '16px 20px',
              borderBottom: '1px solid var(--wcp-border, #e2e8f0)',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'space-between',
              background: 'var(--wcp-bg-elevated, #f8fafc)'
            }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                <div style={{ width: '28px', height: '28px', borderRadius: '6px', background: 'rgba(16, 185, 129, 0.12)', display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
                  <ShieldCheck size={16} color="#16a34a" />
                </div>
                <div>
                  <h3 style={{ margin: 0, fontSize: '14px', fontWeight: 700, color: 'var(--wcp-text-primary, #0f172a)' }}>
                    Modify Allowlist Policy
                  </h3>
                  <div style={{ fontSize: '11px', color: 'var(--wcp-text-muted, #64748b)', fontFamily: 'monospace' }}>
                    {editWhitelistItem.ip}
                  </div>
                </div>
              </div>
              <button
                type="button"
                onClick={() => setEditWhitelistItem(prev => ({ ...prev, isOpen: false }))}
                style={{ background: 'none', border: 'none', cursor: 'pointer', color: 'var(--wcp-text-muted, #94a3b8)', padding: '4px' }}
              >
                <X size={16} />
              </button>
            </div>

            <div style={{ padding: '20px', display: 'flex', flexDirection: 'column', gap: '14px' }}>
              <div>
                <label style={{ display: 'block', fontSize: '12px', fontWeight: 600, color: 'var(--wcp-text-primary, #0f172a)', marginBottom: '5px' }}>
                  Exemption Scope:
                </label>
                <select
                  value={editWhitelistItem.scope}
                  onChange={(e) => setEditWhitelistItem(prev => ({ ...prev, scope: e.target.value as any }))}
                  className="wcp-firewall-input"
                  style={{ width: '100%', fontSize: '12.5px', padding: '8px 10px' }}
                >
                  <option value="global">All Firewall Rules (Global Full Bypass)</option>
                  <option value="rule">Single Firewall Rule (Safest)</option>
                  <option value="category">Group Category (e.g. Identity Defense)</option>
                </select>
              </div>

              {editWhitelistItem.scope === 'rule' && (
                <div>
                  <label style={{ display: 'block', fontSize: '12px', fontWeight: 600, color: 'var(--wcp-text-primary, #0f172a)', marginBottom: '5px' }}>
                    Specific Rule to Exempt:
                  </label>
                  <select
                    value={editWhitelistItem.selectedRule}
                    onChange={(e) => setEditWhitelistItem(prev => ({ ...prev, selectedRule: e.target.value }))}
                    className="wcp-firewall-input"
                    style={{ width: '100%', fontSize: '12px', padding: '8px 10px' }}
                  >
                    <option value="">-- Choose Firewall Rule ({rulesCatalog.length || 50}+ Available) --</option>
                    {Array.from(new Set(rulesCatalog.map(r => r.category))).map(cat => (
                      <optgroup key={cat} label={`📂 ${cat}`}>
                        {rulesCatalog.filter(r => r.category === cat).map(r => (
                          <option key={r.id} value={r.id}>
                            {r.name} [{r.id}]
                          </option>
                        ))}
                      </optgroup>
                    ))}
                  </select>
                </div>
              )}

              {editWhitelistItem.scope === 'category' && (
                <div>
                  <label style={{ display: 'block', fontSize: '12px', fontWeight: 600, color: 'var(--wcp-text-primary, #0f172a)', marginBottom: '5px' }}>
                    Rule Group Category to Exempt:
                  </label>
                  <select
                    value={editWhitelistItem.selectedCat}
                    onChange={(e) => setEditWhitelistItem(prev => ({ ...prev, selectedCat: e.target.value }))}
                    className="wcp-firewall-input"
                    style={{ width: '100%', fontSize: '12.5px', padding: '8px 10px' }}
                  >
                    <option value="">-- Choose Category Group --</option>
                    {Array.from(new Set(rulesCatalog.map(r => r.category))).map(cat => {
                      const count = rulesCatalog.filter(r => r.category === cat).length;
                      return (
                        <option key={cat} value={cat}>
                          {cat} ({count} {count === 1 ? 'rule' : 'rules'})
                        </option>
                      );
                    })}
                  </select>
                </div>
              )}

              <div>
                <label style={{ display: 'block', fontSize: '12px', fontWeight: 600, color: 'var(--wcp-text-primary, #0f172a)', marginBottom: '5px' }}>
                  Optional Request Path Restriction:
                </label>
                <input
                  type="text"
                  placeholder="e.g. /xmlrpc.php or /wp-json/wc/v3/* (leave empty for all endpoints)"
                  value={editWhitelistItem.endpoint}
                  onChange={(e) => setEditWhitelistItem(prev => ({ ...prev, endpoint: e.target.value }))}
                  className="wcp-firewall-input"
                  style={{ width: '100%', fontSize: '12px', padding: '8px 10px', fontFamily: 'monospace' }}
                />
              </div>

              <div>
                <label style={{ display: 'block', fontSize: '12px', fontWeight: 600, color: 'var(--wcp-text-primary, #0f172a)', marginBottom: '5px' }}>
                  Exemption Expiration Schedule:
                </label>
                <select
                  value={editWhitelistItem.expiresIn}
                  onChange={(e) => setEditWhitelistItem(prev => ({ ...prev, expiresIn: Number(e.target.value) }))}
                  className="wcp-firewall-input"
                  style={{ width: '100%', fontSize: '12.5px', padding: '8px 10px' }}
                >
                  <option value={86400}>24 Hours (Temporary Client Testing)</option>
                  <option value={604800}>7 Days (Transient Integration Setup)</option>
                  <option value={2592000}>30 Days (Extended Evaluation)</option>
                  <option value={0}>Permanent (Active until manually removed)</option>
                </select>
              </div>

              <div>
                <label style={{ display: 'block', fontSize: '12px', fontWeight: 600, color: 'var(--wcp-text-primary, #0f172a)', marginBottom: '5px' }}>
                  Audit Justification / Note:
                </label>
                <input
                  type="text"
                  placeholder="e.g. Authorized client integration or office static IP"
                  value={editWhitelistItem.reason}
                  onChange={(e) => setEditWhitelistItem(prev => ({ ...prev, reason: e.target.value }))}
                  className="wcp-firewall-input"
                  style={{ width: '100%', fontSize: '12px', padding: '8px 10px' }}
                />
              </div>
            </div>

            <div style={{
              padding: '12px 20px',
              borderTop: '1px solid var(--wcp-border, #e2e8f0)',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'flex-end',
              gap: '10px',
              background: 'var(--wcp-bg-elevated, #f8fafc)'
            }}>
              <button
                type="button"
                className="wcp-btn"
                onClick={() => setEditWhitelistItem(prev => ({ ...prev, isOpen: false }))}
                style={{ padding: '7px 14px', background: 'none', border: '1px solid var(--wcp-border, #cbd5e1)', color: 'var(--wcp-text-secondary, #475569)', fontSize: '12px' }}
              >
                Cancel
              </button>
              <button
                type="button"
                className="wcp-btn"
                onClick={handleSaveEditWhitelist}
                disabled={editWhitelistItem.isSubmitting}
                style={{ padding: '7px 18px', background: '#16a34a', border: 'none', color: '#ffffff', fontWeight: 600, fontSize: '12px', display: 'flex', alignItems: 'center', gap: '6px' }}
              >
                {editWhitelistItem.isSubmitting ? <Loader2 size={13} className="wcp-spin" /> : <Save size={13} />}
                Save Changes
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Edit Blocklist / Ban Policy Modal */}
      {editBlocklistItem.isOpen && (
        <div style={{
          position: 'fixed',
          top: 0,
          left: 0,
          right: 0,
          bottom: 0,
          background: 'rgba(0, 0, 0, 0.65)',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'center',
          zIndex: 100000,
          padding: '20px'
        }}>
          <div style={{
            background: 'var(--wcp-bg-surface, #ffffff)',
            borderRadius: '12px',
            width: '100%',
            maxWidth: '520px',
            boxShadow: '0 20px 25px -5px rgba(0, 0, 0, 0.25)',
            border: '1px solid var(--wcp-border, #e2e8f0)',
            overflow: 'hidden'
          }}>
            <div style={{
              padding: '16px 20px',
              borderBottom: '1px solid var(--wcp-border, #e2e8f0)',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'space-between',
              background: 'var(--wcp-bg-elevated, #f8fafc)'
            }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                <div style={{ width: '28px', height: '28px', borderRadius: '6px', background: 'rgba(220, 38, 38, 0.12)', display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
                  <Ban size={16} color="#dc2626" />
                </div>
                <div>
                  <h3 style={{ margin: 0, fontSize: '14px', fontWeight: 700, color: 'var(--wcp-text-primary, #0f172a)' }}>
                    Modify Ban / Blocklist Entry
                  </h3>
                  <div style={{ fontSize: '11px', color: 'var(--wcp-text-muted, #64748b)', fontFamily: 'monospace' }}>
                    {editBlocklistItem.ip}
                  </div>
                </div>
              </div>
              <button
                type="button"
                onClick={() => setEditBlocklistItem(prev => ({ ...prev, isOpen: false }))}
                style={{ background: 'none', border: 'none', cursor: 'pointer', color: 'var(--wcp-text-muted, #94a3b8)', padding: '4px' }}
              >
                <X size={16} />
              </button>
            </div>

            <div style={{ padding: '20px', display: 'flex', flexDirection: 'column', gap: '14px' }}>
              <div>
                <label style={{ display: 'block', fontSize: '12px', fontWeight: 600, color: 'var(--wcp-text-primary, #0f172a)', marginBottom: '5px' }}>
                  Ban Duration:
                </label>
                <select
                  value={editBlocklistItem.durationSeconds}
                  onChange={(e) => setEditBlocklistItem(prev => ({ ...prev, durationSeconds: Number(e.target.value) }))}
                  className="wcp-firewall-input"
                  style={{ width: '100%', fontSize: '12.5px', padding: '8px 10px' }}
                >
                  <option value={0}>Permanent Ban (Active until manually removed)</option>
                  <option value={900}>15 Minutes (Temporary Quarantine)</option>
                  <option value={3600}>1 Hour (Short-Term Lockdown)</option>
                  <option value={86400}>24 Hours (Daily Lockout)</option>
                  <option value={604800}>7 Days (Extended Threat Quarantine)</option>
                  <option value={2592000}>30 Days (Monthly Suspension)</option>
                </select>
              </div>

              <div>
                <label style={{ display: 'block', fontSize: '12px', fontWeight: 600, color: 'var(--wcp-text-primary, #0f172a)', marginBottom: '5px' }}>
                  Audit Reason / Description:
                </label>
                <input
                  type="text"
                  placeholder="e.g. Repeated credential stuffing or hostile reconnaissance"
                  value={editBlocklistItem.reason}
                  onChange={(e) => setEditBlocklistItem(prev => ({ ...prev, reason: e.target.value }))}
                  className="wcp-firewall-input"
                  style={{ width: '100%', fontSize: '12px', padding: '8px 10px' }}
                />
              </div>
            </div>

            <div style={{
              padding: '12px 20px',
              borderTop: '1px solid var(--wcp-border, #e2e8f0)',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'flex-end',
              gap: '10px',
              background: 'var(--wcp-bg-elevated, #f8fafc)'
            }}>
              <button
                type="button"
                className="wcp-btn"
                onClick={() => setEditBlocklistItem(prev => ({ ...prev, isOpen: false }))}
                style={{ padding: '7px 14px', background: 'none', border: '1px solid var(--wcp-border, #cbd5e1)', color: 'var(--wcp-text-secondary, #475569)', fontSize: '12px' }}
              >
                Cancel
              </button>
              <button
                type="button"
                className="wcp-btn"
                onClick={handleSaveEditBlocklist}
                disabled={editBlocklistItem.isSubmitting}
                style={{ padding: '7px 18px', background: '#dc2626', border: 'none', color: '#ffffff', fontWeight: 600, fontSize: '12px', display: 'flex', alignItems: 'center', gap: '6px' }}
              >
                {editBlocklistItem.isSubmitting ? <Loader2 size={13} className="wcp-spin" /> : <Save size={13} />}
                Update Ban Policy
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Central Blocklist & Lockout Manager Modal */}
      {blocklistModalOpen && (
        <div style={{
          position: 'fixed',
          top: 0,
          left: 0,
          right: 0,
          bottom: 0,
          background: 'rgba(0, 0, 0, 0.65)',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'center',
          zIndex: 100000,
          backdropFilter: 'blur(3px)'
        }}>
          <div className="wcp-firewall-card" style={{
            maxWidth: '840px',
            width: '95%',
            maxHeight: '88vh',
            display: 'flex',
            flexDirection: 'column',
            overflow: 'hidden',
            borderRadius: '10px',
            boxShadow: '0 20px 25px -5px rgba(0, 0, 0, 0.25), 0 10px 10px -5px rgba(0, 0, 0, 0.1)'
          }}>
            {/* Modal Header */}
            <div style={{
              padding: '16px 20px',
              borderBottom: '1px solid var(--wcp-border, #e2e8f0)',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'space-between',
              background: 'var(--wcp-bg-surface, #ffffff)'
            }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
                <div style={{
                  width: '36px',
                  height: '36px',
                  borderRadius: '8px',
                  background: 'rgba(220, 38, 38, 0.1)',
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'center'
                }}>
                  <Ban size={20} color="#dc2626" />
                </div>
                <div>
                  <h3 style={{ margin: 0, fontSize: '16px', fontWeight: 700, color: 'var(--wcp-text-primary, #0f172a)' }}>
                    Active Lockouts & Central Blocklist
                  </h3>
                  <span style={{ fontSize: '11px', color: 'var(--wcp-text-muted, #64748b)' }}>
                    {lockedIpsList.length} currently restricted {lockedIpsList.length === 1 ? 'address' : 'addresses'} across WAF engines with forensic timing & incident attribution
                  </span>
                </div>
              </div>
              <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                <button
                  type="button"
                  className="wcp-btn"
                  onClick={() => setShowManualBlockForm(!showManualBlockForm)}
                  style={{
                    fontSize: '11px',
                    padding: '5px 10px',
                    borderRadius: '5px',
                    background: showManualBlockForm ? 'var(--wcp-border, #e2e8f0)' : '#4f46e5',
                    color: showManualBlockForm ? 'var(--wcp-text-primary, #0f172a)' : '#ffffff',
                    border: 'none',
                    fontWeight: 600,
                    cursor: 'pointer',
                    display: 'flex',
                    alignItems: 'center',
                    gap: '4px'
                  }}
                >
                  <Plus size={12} />
                  {showManualBlockForm ? 'Cancel Add' : 'Block IP'}
                </button>
                <button
                  type="button"
                  onClick={() => setBlocklistModalOpen(false)}
                  style={{
                    background: 'none',
                    border: 'none',
                    cursor: 'pointer',
                    color: 'var(--wcp-text-muted, #64748b)',
                    padding: '4px'
                  }}
                  title="Close modal"
                >
                  <X size={18} />
                </button>
              </div>
            </div>

            {/* Quick Filter & Search Bar */}
            <div style={{
              padding: '10px 20px',
              background: 'var(--wcp-bg-elevated, #f8fafc)',
              borderBottom: '1px solid var(--wcp-border, #e2e8f0)',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'space-between',
              gap: '12px'
            }}>
              <div style={{ position: 'relative', flex: 1, maxWidth: '420px' }}>
                <Search size={14} style={{ position: 'absolute', left: '10px', top: '50%', transform: 'translateY(-50%)', color: 'var(--wcp-text-muted, #94a3b8)' }} />
                <input
                  type="text"
                  placeholder="Filter by IP, incident ID (WCP-), rule, or reason..."
                  value={blocklistSearch}
                  onChange={(e) => setBlocklistSearch(e.target.value)}
                  className="wcp-firewall-input"
                  style={{
                    width: '100%',
                    padding: '6px 10px 6px 30px',
                    fontSize: '12px',
                    borderRadius: '5px'
                  }}
                />
                {blocklistSearch && (
                  <button
                    type="button"
                    onClick={() => setBlocklistSearch('')}
                    style={{
                      position: 'absolute',
                      right: '8px',
                      top: '50%',
                      transform: 'translateY(-50%)',
                      background: 'none',
                      border: 'none',
                      cursor: 'pointer',
                      color: 'var(--wcp-text-muted, #94a3b8)',
                      padding: 0
                    }}
                  >
                    <X size={13} />
                  </button>
                )}
              </div>
              <div style={{ fontSize: '11px', color: 'var(--wcp-text-muted, #64748b)' }}>
                Showing {lockedIpsList.filter(item => {
                  if (!blocklistSearch.trim()) return true;
                  const q = blocklistSearch.toLowerCase();
                  return (
                    item.ip.toLowerCase().includes(q) ||
                    (item.incident_id && item.incident_id.toLowerCase().includes(q)) ||
                    (item.reason && item.reason.toLowerCase().includes(q)) ||
                    (item.rule_name && item.rule_name.toLowerCase().includes(q)) ||
                    (item.admin_user && item.admin_user.toLowerCase().includes(q))
                  );
                }).length} of {lockedIpsList.length}
              </div>
            </div>

            {/* Manual Block Expander Form */}
            {showManualBlockForm && (
              <form onSubmit={handleAddManualBlock} style={{
                padding: '14px 20px',
                background: 'var(--wcp-bg-surface, #ffffff)',
                borderBottom: '1px solid var(--wcp-border, #e2e8f0)',
                display: 'flex',
                flexDirection: 'column',
                gap: '10px'
              }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
                  <ShieldAlert size={14} color="#dc2626" />
                  <span style={{ fontSize: '12px', fontWeight: 600, color: 'var(--wcp-text-primary, #0f172a)' }}>
                    Add Custom Administrator Block
                  </span>
                </div>
                <div style={{ display: 'grid', gridTemplateColumns: '1.4fr 1fr', gap: '10px' }}>
                  <div>
                    <label style={{ display: 'block', fontSize: '11px', fontWeight: 500, marginBottom: '3px', color: 'var(--wcp-text-muted, #64748b)' }}>
                      IP Address or CIDR Range:
                    </label>
                    <input
                      type="text"
                      placeholder="e.g. 198.51.100.42 or 203.0.113.0/24"
                      value={modalNewBlockIp}
                      onChange={(e) => setModalNewBlockIp(e.target.value)}
                      className="wcp-firewall-input"
                      style={{ width: '100%', fontSize: '12px', padding: '6px 8px' }}
                      required
                    />
                  </div>
                  <div>
                    <label style={{ display: 'block', fontSize: '11px', fontWeight: 500, marginBottom: '3px', color: 'var(--wcp-text-muted, #64748b)' }}>
                      Ban Duration:
                    </label>
                    <select
                      value={modalNewBlockDuration}
                      onChange={(e) => setModalNewBlockDuration(parseInt(e.target.value, 10))}
                      className="wcp-firewall-input"
                      style={{ width: '100%', fontSize: '12px', padding: '6px 8px' }}
                    >
                      <option value={0}>Permanent (Indefinite)</option>
                      <option value={3600}>1 Hour</option>
                      <option value={21600}>6 Hours</option>
                      <option value={86400}>24 Hours (1 Day)</option>
                      <option value={604800}>7 Days</option>
                      <option value={2592000}>30 Days (1 Month)</option>
                      <option value={31536000}>1 Year</option>
                    </select>
                  </div>
                </div>
                <div>
                  <label style={{ display: 'block', fontSize: '11px', fontWeight: 500, marginBottom: '3px', color: 'var(--wcp-text-muted, #64748b)' }}>
                    Reason / Administrative Note:
                  </label>
                  <input
                    type="text"
                    placeholder="e.g. Malicious scanning detected, unauthorized pentest probing, credential stuffing"
                    value={modalNewBlockReason}
                    onChange={(e) => setModalNewBlockReason(e.target.value)}
                    className="wcp-firewall-input"
                    style={{ width: '100%', fontSize: '12px', padding: '6px 8px' }}
                  />
                </div>
                <div style={{ display: 'flex', justifyContent: 'flex-end', gap: '8px' }}>
                  <button
                    type="button"
                    className="wcp-btn"
                    onClick={() => setShowManualBlockForm(false)}
                    style={{
                      fontSize: '11px',
                      padding: '5px 12px',
                      background: 'none',
                      border: '1px solid var(--wcp-border, #e2e8f0)',
                      color: 'var(--wcp-text-secondary, #475569)',
                      borderRadius: '4px',
                      cursor: 'pointer'
                    }}
                  >
                    Cancel
                  </button>
                  <button
                    type="submit"
                    className="wcp-btn"
                    disabled={savingManualBlock}
                    style={{
                      fontSize: '11px',
                      padding: '5px 14px',
                      background: '#dc2626',
                      color: '#ffffff',
                      border: 'none',
                      borderRadius: '4px',
                      fontWeight: 600,
                      cursor: savingManualBlock ? 'not-allowed' : 'pointer',
                      display: 'flex',
                      alignItems: 'center',
                      gap: '4px'
                    }}
                  >
                    {savingManualBlock ? <Loader2 size={11} className="wcp-spin" /> : <Ban size={11} />}
                    Confirm Block
                  </button>
                </div>
              </form>
            )}

            {/* Modal Body */}
            <div style={{ padding: '16px 20px', overflowY: 'auto', flex: 1 }}>
              <div className="wcp-firewall-callout" style={{ fontSize: '11.5px', padding: '8px 12px', marginBottom: '14px', display: 'flex', alignItems: 'center', gap: '8px' }}>
                <Info size={14} style={{ flexShrink: 0, color: '#4f46e5' }} />
                <div>
                  <strong>How Unblocking Works:</strong> Unblocking immediately restores ordinary visitor access while keeping all 35+ WAF inspection shields 100% active.
                </div>
              </div>

              {loadingBlocklist ? (
                <div style={{ textAlign: 'center', padding: '40px 0' }}>
                  <Loader2 size={24} className="wcp-spin" style={{ color: '#4f46e5', margin: '0 auto 10px' }} />
                  <p style={{ fontSize: '12px', color: 'var(--wcp-text-muted, #64748b)' }}>Loading locked addresses...</p>
                </div>
              ) : lockedIpsList.length === 0 ? (
                <div style={{ textAlign: 'center', padding: '36px 0', color: 'var(--wcp-text-muted, #64748b)' }}>
                  <ShieldCheck size={36} color="#16a34a" style={{ margin: '0 auto 10px' }} />
                  <h4 style={{ margin: '0 0 4px', fontSize: '14px', color: 'var(--wcp-text-primary, #0f172a)' }}>No Active Lockouts</h4>
                  <p style={{ margin: 0, fontSize: '12px' }}>There are currently no IPs on the central blocklist or locked by brute-force defense.</p>
                </div>
              ) : (
                <div style={{ display: 'flex', flexDirection: 'column', gap: '10px' }}>
                  {lockedIpsList
                    .filter(item => {
                      if (!blocklistSearch.trim()) return true;
                      const q = blocklistSearch.toLowerCase();
                      return (
                        item.ip.toLowerCase().includes(q) ||
                        (item.incident_id && item.incident_id.toLowerCase().includes(q)) ||
                        (item.reason && item.reason.toLowerCase().includes(q)) ||
                        (item.rule_name && item.rule_name.toLowerCase().includes(q)) ||
                        (item.admin_user && item.admin_user.toLowerCase().includes(q))
                      );
                    })
                    .sort((a, b) => ((b.blocked_at_raw || 0) - (a.blocked_at_raw || 0)))
                    .map((item, idx) => {
                      const isExpanded = !!expandedHistoryIps[item.ip];
                      const historyCount = item.recent_history ? item.recent_history.length : 0;
                      const isPermanent = item.is_permanent || item.duration === 'Permanent';
                      const isManual = item.type === 'manual_admin' || !!item.admin_user;
                      const rawModalIp = (item.ip || '').trim().toLowerCase();
                      const isModalCfBlocked = bannedIpsList.some(r => (r.ip || '').trim().toLowerCase() === rawModalIp);

                      return (
                        <div
                          key={idx}
                          className="wcp-waf-ip-row"
                          style={{
                            display: 'flex',
                            flexDirection: 'column',
                            padding: '12px 14px',
                            borderRadius: '8px',
                            border: '1px solid var(--wcp-border, #e2e8f0)',
                            background: 'var(--wcp-bg-surface, #ffffff)',
                            gap: '8px'
                          }}
                        >
                          {/* Top Row: IP + Badges + Countdown + Unblock Button */}
                          <div style={{ display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between', gap: '12px' }}>
                            <div style={{ flex: 1, minWidth: 0 }}>
                              <div style={{ display: 'flex', alignItems: 'center', flexWrap: 'wrap', gap: '6px', marginBottom: '4px' }}>
                                <code style={{
                                  fontSize: '13px',
                                  fontWeight: 700,
                                  color: '#dc2626',
                                  letterSpacing: '0.3px',
                                  background: 'rgba(220, 38, 38, 0.08)',
                                  padding: '2px 7px',
                                  borderRadius: '4px',
                                  fontFamily: 'monospace'
                                }}>
                                  {item.ip}
                                </code>

                                {/* Type Badge */}
                                <span
                                  className={`wcp-lockout-badge-pill ${isManual ? 'is-manual' : (item.type === 'custom_blocklist' ? 'is-danger' : 'is-warn')}`}
                                  style={{
                                    fontSize: '10px',
                                    fontWeight: 600,
                                    padding: '2px 6px',
                                    borderRadius: '4px',
                                    background: isManual ? '#eff6ff' : (item.type === 'custom_blocklist' ? '#fee2e2' : '#fef3c7'),
                                    color: isManual ? '#1d4ed8' : (item.type === 'custom_blocklist' ? '#991b1b' : '#92400e'),
                                    border: `1px solid ${isManual ? '#bfdbfe' : (item.type === 'custom_blocklist' ? '#fecaca' : '#fde68a')}`,
                                    display: 'inline-flex',
                                    alignItems: 'center',
                                    gap: '3px'
                                  }}
                                >
                                  {isManual && <User size={9} />}
                                  {item.badge}
                                </span>

                                {/* Incident ID Tag */}
                                {item.incident_id && (
                                  <button
                                    type="button"
                                    onClick={() => copyIncidentToClipboard(item.incident_id!)}
                                    title="Click to copy Incident ID"
                                    className="wcp-lockout-incident-pill"
                                    style={{
                                      fontSize: '10px',
                                      fontWeight: 600,
                                      padding: '2px 6px',
                                      borderRadius: '4px',
                                      background: 'rgba(79, 70, 229, 0.08)',
                                      color: '#4f46e5',
                                      border: '1px solid rgba(79, 70, 229, 0.25)',
                                      cursor: 'pointer',
                                      display: 'inline-flex',
                                      alignItems: 'center',
                                      gap: '4px',
                                      fontFamily: 'monospace'
                                    }}
                                  >
                                    <Copy size={9} />
                                    {copiedIncidentId === item.incident_id ? 'Copied!' : item.incident_id}
                                  </button>
                                )}

                                {/* Ban Duration Pill */}
                                <span
                                  className="wcp-lockout-duration-pill"
                                  style={{
                                    fontSize: '10px',
                                    fontWeight: 600,
                                    padding: '2px 6px',
                                    borderRadius: '4px',
                                    background: isPermanent ? '#f1f5f9' : '#fef2f2',
                                    color: isPermanent ? '#475569' : '#dc2626',
                                    border: `1px solid ${isPermanent ? '#e2e8f0' : '#fecaca'}`,
                                    display: 'inline-flex',
                                    alignItems: 'center',
                                    gap: '3px'
                                  }}
                                >
                                  <Clock size={9} />
                                  {isPermanent ? 'Permanent' : `Duration: ${item.duration}`}
                                </span>
                              </div>

                              {/* Rule / Reason line */}
                              <div style={{
                                fontSize: '11.5px',
                                color: 'var(--wcp-text-primary, #0f172a)',
                                lineHeight: 1.45,
                                marginTop: '4px'
                              }}>
                                {isManual ? (
                                  <span>
                                    <strong style={{ color: '#1d4ed8' }}>
                                      {item.admin_user ? `Custom block by ${item.admin_user}` : 'Custom block by administrator'}:
                                    </strong>{' '}
                                    {item.reason}
                                  </span>
                                ) : (
                                  <span>
                                    {item.rule_name && (
                                      <strong style={{ color: '#dc2626' }}>
                                        {item.rule_name}{item.rule_category ? ` (${item.rule_category})` : ''}:{' '}
                                      </strong>
                                    )}
                                    {item.reason}
                                  </span>
                                )}
                              </div>
                            </div>

                            {/* Action Buttons: CF Edge Block / Unblock Toggle + Local Unblock */}
                            <div style={{ display: 'flex', alignItems: 'center', gap: '5px', flexShrink: 0, flexWrap: 'wrap', justifyContent: 'flex-end' }}>
                              {!isModalCfBlocked ? (
                                <button
                                  type="button"
                                  className="wcp-btn"
                                  onClick={() => handlePushIpToCloudflareEdge(item.ip, item.reason)}
                                  disabled={cfActionIp === `push-${item.ip}`}
                                  style={{
                                    fontSize: '10.5px',
                                    padding: '5px 8px',
                                    borderRadius: '4px',
                                    background: '#ea580c',
                                    color: '#ffffff',
                                    border: 'none',
                                    cursor: cfActionIp === `push-${item.ip}` ? 'not-allowed' : 'pointer',
                                    display: 'flex',
                                    alignItems: 'center',
                                    gap: '4px',
                                    fontWeight: 600
                                  }}
                                  title="Push IP to Cloudflare Edge Blocklist"
                                >
                                  {cfActionIp === `push-${item.ip}` ? (
                                    <Loader2 size={10} className="wcp-spin" />
                                  ) : (
                                    <Cloud size={10} />
                                  )}
                                  CF Edge Block
                                </button>
                              ) : (
                                <button
                                  type="button"
                                  className="wcp-btn"
                                  onClick={() => handleUnblockIpFromCloudflareEdge(item.ip)}
                                  disabled={cfActionIp === `unblock-${item.ip}`}
                                  style={{
                                    fontSize: '10.5px',
                                    padding: '5px 8px',
                                    borderRadius: '4px',
                                    background: 'rgba(234, 88, 12, 0.1)',
                                    color: '#c2410c',
                                    border: '1px solid rgba(234, 88, 12, 0.3)',
                                    cursor: cfActionIp === `unblock-${item.ip}` ? 'not-allowed' : 'pointer',
                                    display: 'flex',
                                    alignItems: 'center',
                                    gap: '4px',
                                    fontWeight: 600
                                  }}
                                  title="Unblock IP from Cloudflare Edge"
                                >
                                  {cfActionIp === `unblock-${item.ip}` ? (
                                    <Loader2 size={10} className="wcp-spin" />
                                  ) : (
                                    <Unlock size={10} />
                                  )}
                                  CF Edge Unblock
                                </button>
                              )}

                              <button
                                type="button"
                                className="wcp-btn"
                                onClick={() => handleUnblockIpFromModal(item.ip)}
                                disabled={unblockingIp === item.ip}
                                style={{
                                  fontSize: '11px',
                                  padding: '5px 10px',
                                  borderRadius: '4px',
                                  background: '#0284c7',
                                  color: '#ffffff',
                                  border: 'none',
                                  cursor: unblockingIp === item.ip ? 'not-allowed' : 'pointer',
                                  display: 'flex',
                                  alignItems: 'center',
                                  gap: '4px',
                                  fontWeight: 600
                                }}
                                title="Unblock this IP locally"
                              >
                                {unblockingIp === item.ip ? (
                                  <Loader2 size={11} className="wcp-spin" />
                                ) : (
                                  <Unlock size={11} />
                                )}
                                Unblock IP
                              </button>
                            </div>
                          </div>

                          {/* Forensic Timing Details Row */}
                          <div
                            className="wcp-lockout-timing-box"
                            style={{
                              display: 'grid',
                              gridTemplateColumns: 'repeat(auto-fit, minmax(180px, 1fr))',
                              gap: '8px',
                              padding: '8px 10px',
                              borderRadius: '6px',
                              background: 'var(--wcp-bg-elevated, #f8fafc)',
                              border: '1px solid var(--wcp-border, #e2e8f0)',
                              fontSize: '11px',
                              marginTop: '2px'
                            }}
                          >
                            <div>
                              <span style={{ color: 'var(--wcp-text-muted, #64748b)', display: 'block', fontSize: '10px' }}>
                                Ban Time:
                              </span>
                              <strong style={{ color: 'var(--wcp-text-primary, #0f172a)' }}>
                                {item.blocked_at || 'Recorded previously'}
                              </strong>{' '}
                              <span style={{ color: 'var(--wcp-text-muted, #64748b)' }}>
                                ({item.ban_ago || 'earlier'})
                              </span>
                            </div>

                            <div>
                              <span style={{ color: 'var(--wcp-text-muted, #64748b)', display: 'block', fontSize: '10px' }}>
                                Ban Duration:
                              </span>
                              <strong style={{ color: isPermanent ? '#dc2626' : 'var(--wcp-text-primary, #0f172a)' }}>
                                {item.duration || 'Permanent'}
                              </strong>
                            </div>

                            <div>
                              <span style={{ color: 'var(--wcp-text-muted, #64748b)', display: 'block', fontSize: '10px' }}>
                                Unban Time & Countdown:
                              </span>
                              {isPermanent ? (
                                <strong style={{ color: '#475569' }}>Never (Permanent)</strong>
                              ) : (
                                <div>
                                  <strong style={{ color: '#16a34a' }}>
                                    {item.time_remaining || item.expires_at}
                                  </strong>
                                  <div style={{ fontSize: '10px', color: 'var(--wcp-text-muted, #64748b)' }}>
                                    Target: {item.expires_at}
                                  </div>
                                </div>
                              )}
                            </div>
                          </div>

                          {/* Bottom Row: History Toggle Button */}
                          {historyCount > 0 && (
                            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginTop: '2px' }}>
                              <button
                                type="button"
                                onClick={() => toggleHistoryExpansion(item.ip)}
                                style={{
                                  background: 'none',
                                  border: 'none',
                                  color: '#4f46e5',
                                  fontSize: '11px',
                                  fontWeight: 600,
                                  cursor: 'pointer',
                                  padding: 0,
                                  display: 'inline-flex',
                                  alignItems: 'center',
                                  gap: '4px'
                                }}
                              >
                                <History size={11} />
                                {isExpanded ? 'Hide Attack History' : `View Recent Attack History (${historyCount})`}
                                {isExpanded ? <ChevronUp size={11} /> : <ChevronDown size={11} />}
                              </button>
                              <span style={{ fontSize: '10px', color: 'var(--wcp-text-muted, #64748b)' }}>
                                Forensic logs available
                              </span>
                            </div>
                          )}

                          {/* Expandable Attack History Drawer */}
                          {isExpanded && item.recent_history && (
                            <div style={{
                              marginTop: '4px',
                              padding: '8px 10px',
                              borderRadius: '6px',
                              background: 'var(--wcp-bg-surface, #ffffff)',
                              border: '1px solid var(--wcp-border, #e2e8f0)',
                              display: 'flex',
                              flexDirection: 'column',
                              gap: '6px'
                            }}>
                              <div style={{ fontSize: '10.5px', fontWeight: 700, color: 'var(--wcp-text-muted, #64748b)', textTransform: 'uppercase', letterSpacing: '0.5px' }}>
                                Last {item.recent_history.length} Intercepted Incidents
                              </div>
                              {item.recent_history.map((hist, hIdx) => (
                                <div
                                  key={hIdx}
                                  className="wcp-lockout-history-item"
                                  style={{
                                    padding: '6px 8px',
                                    borderRadius: '4px',
                                    background: 'var(--wcp-bg-elevated, #f8fafc)',
                                    border: '1px solid var(--wcp-border, #e2e8f0)',
                                    fontSize: '11px',
                                    display: 'flex',
                                    flexDirection: 'column',
                                    gap: '2px'
                                  }}
                                >
                                  <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: '8px' }}>
                                    <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
                                      {hist.incident_id && (
                                        <code style={{ fontSize: '10px', fontWeight: 700, color: '#4f46e5' }}>
                                          {hist.incident_id}
                                        </code>
                                      )}
                                      <span style={{
                                        fontSize: '9.5px',
                                        padding: '1px 5px',
                                        borderRadius: '3px',
                                        background: 'rgba(220, 38, 38, 0.1)',
                                        color: '#dc2626',
                                        fontWeight: 600
                                      }}>
                                        {hist.category || 'Security Alert'}
                                      </span>
                                    </div>
                                    <span style={{ fontSize: '10px', color: 'var(--wcp-text-muted, #64748b)' }}>
                                      {hist.created_at}
                                    </span>
                                  </div>
                                  <div style={{ color: 'var(--wcp-text-primary, #0f172a)', fontWeight: 500 }}>
                                    {hist.description}
                                  </div>
                                  {hist.uri && (
                                    <div style={{ fontSize: '10px', color: 'var(--wcp-text-muted, #64748b)', fontFamily: 'monospace', wordBreak: 'break-all' }}>
                                      <span style={{ color: '#0284c7', fontWeight: 600 }}>{hist.method || 'GET'}</span> {hist.uri}
                                    </div>
                                  )}
                                  {hist.payload && (
                                    <div style={{ fontSize: '9.5px', color: 'var(--wcp-text-secondary, #475569)', background: 'var(--wcp-bg-surface, #ffffff)', padding: '3px 6px', borderRadius: '3px', border: '1px dashed var(--wcp-border, #e2e8f0)', wordBreak: 'break-all', fontFamily: 'monospace' }}>
                                      {hist.payload}
                                    </div>
                                  )}
                                </div>
                              ))}
                            </div>
                          )}
                        </div>
                      );
                    })}
                </div>
              )}
            </div>

            {/* Modal Footer */}
            <div style={{
              padding: '12px 20px',
              borderTop: '1px solid var(--wcp-border, #e2e8f0)',
              background: 'var(--wcp-bg-elevated, #f8fafc)',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'space-between'
            }}>
              <button
                type="button"
                className="wcp-btn"
                onClick={fetchBlocklistData}
                disabled={loadingBlocklist}
                style={{
                  background: 'none',
                  border: 'none',
                  color: 'var(--wcp-text-muted, #64748b)',
                  fontSize: '12px',
                  display: 'flex',
                  alignItems: 'center',
                  gap: '4px',
                  cursor: 'pointer'
                }}
              >
                <RefreshCw size={12} className={loadingBlocklist ? 'wcp-spin' : ''} /> Refresh List
              </button>
              <button
                type="button"
                className="wcp-btn"
                onClick={() => setBlocklistModalOpen(false)}
                style={{
                  background: '#0f172a',
                  color: '#fff',
                  border: 'none',
                  padding: '7px 16px',
                  borderRadius: '6px',
                  fontSize: '12.5px',
                  fontWeight: 600,
                  cursor: 'pointer'
                }}
              >
                Done
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Confirmation Modal */}
      <ConfirmDialog
        isOpen={firewallConfirmDialog.isOpen}
        title={firewallConfirmDialog.title}
        message={firewallConfirmDialog.message}
        targetItem={firewallConfirmDialog.targetItem}
        confirmLabel={firewallConfirmDialog.confirmLabel}
        variant={firewallConfirmDialog.variant}
        isLoading={firewallConfirmDialog.isLoading}
        onConfirm={firewallConfirmDialog.onConfirm || (() => {})}
        onClose={() => setFirewallConfirmDialog((prev) => ({ ...prev, isOpen: false }))}
      />
    </div>
  );
};

export default FirewallPage;
