import { lazy, Suspense, useEffect, useState } from 'react';
import { Search } from 'lucide-react';
import { AppSidebar, CATEGORY_LABELS } from './components/AppSidebar';
const EventConstellationView = lazy(() => import('./components/visual/EventConstellationView'));
import { ChatPage } from './pages/ChatPage';
import { HostsPage } from './pages/HostsPage';
import { HostOverviewPage } from './pages/HostOverviewPage';
import { SnipenPage } from './pages/SnipenPage';
import { TasksPage } from './pages/TasksPage';
import FullScanTab from './pages/FullScanTab';
import FleetOverviewPage from './pages/FleetOverviewPage';
import { BaselinePage } from './pages/BaselinePage';
import { UnifiedHostsPage } from './pages/UnifiedHostsPage';
import { ServerPage } from './pages/ServerPage';
import { ScriptLibraryPage } from './pages/ScriptLibraryPage';
import { TrustCenterPage } from './pages/TrustCenterPage';
import { WazuhIntegrationPage } from './pages/WazuhIntegrationPage';
import { FluidWaves } from './components/FluidWaves';
import { AppStartOverlay, type PreflightCheck } from './components/AppStartOverlay';
import { SettingsModal } from './components/SettingsModal';
import { VideoBackground } from './components/VideoBackground';
import { LiquidBackground } from './components/LiquidBackground';
import { ErrorBoundary } from './components/ErrorBoundary';
import { getAIServiceStatus, getActiveConnection, getAllProfileAssignments, getAnalysisProfile, getBackendHealth, getHostsCentral, getIndexerHealth, getOllamaHealth, getProfiles, saveAnalysisProfile, sendChatMessage, startAIService } from './services/api';
import type { AIServiceStatus, AnalysisProfileConfig, ChatMessage, HostProfile, HostProfileAssignment } from './types';

const LOOKBACK_PRESETS = [24, 168, 720] as const;
const DEFAULT_ANALYSIS_PROFILE: AnalysisProfileConfig = {
  event_ids: [],
  min_rule_level: 0,
  max_findings: 200,
  max_events_per_host: 0,
  include_commandline: false,
  include_full_log: false,
  include_agent_info: true,
  include_mitre_mapping: false,
};

function createInitialPreflightChecks(): PreflightCheck[] {
  return [
    { key: 'backend', label: 'Backend API', detail: 'Waiting for backend heartbeat', state: 'pending', required: true },
    { key: 'connection', label: 'Active connection', detail: 'Loading active Wazuh connection', state: 'pending', required: true },
    { key: 'indexer', label: 'Indexer', detail: 'Testing indexer reachability', state: 'pending', required: true },
    { key: 'hosts', label: 'Host feed', detail: 'Sampling central host feed', state: 'pending' },
    { key: 'profile', label: 'Analysis profile', detail: 'Loading analyst defaults', state: 'pending' },
    { key: 'ollama', label: 'Ollama endpoint', detail: 'Checking model endpoint', state: 'pending' },
    { key: 'ai', label: 'AI runtime', detail: 'Validating local AI service', state: 'pending' },
  ];
}

function describeError(error: unknown, fallback: string): string {
  if (error instanceof Error && error.message.trim()) {
    return error.message.trim();
  }
  return fallback;
}

function isHealthy(status: { status: string; reachable?: boolean }): boolean {
  if (status.reachable === false) {
    return false;
  }

  const normalized = status.status.trim().toLowerCase();
  return normalized === 'ok' || normalized === 'healthy' || normalized === 'running';
}

const TAB_LABELS: Record<string, string> = {
  dashboard:           'Dashboard',
  chat:                'Chat',
  tasks:               'Incidents',
  hosts:               'Hosts',
  'host-overview':     'Host Overview',
  'unified-hosts':     'Unified Hosts',
  snipen:              'Investigation',
  fullscan:            'Full Scan',
  baseline:            'Baseline',
  server:              'Server Operations',
  scripts:             'Script Library',
  trust:               'Trust Center',
  constellation:       'Event Map',
  'wazuh-integration': 'Wazuh Integration',
};

function fmtClock(): string {
  return new Date().toLocaleTimeString('de-DE', { hour: '2-digit', minute: '2-digit', second: '2-digit' });
}

function App() {
  const [activeTab, setActiveTab] = useState<'chat' | 'tasks' | 'dashboard' | 'hosts' | 'host-overview' | 'unified-hosts' | 'snipen' | 'fullscan' | 'baseline' | 'server' | 'scripts' | 'trust' | 'constellation' | 'wazuh-integration'>('dashboard');
  const [overviewHost, setOverviewHost] = useState<string | null>(null);
  const [constellationHost, setConstellationHost] = useState<string | null>(null);
  const [clockStr, setClockStr] = useState(fmtClock);

  useEffect(() => {
    const id = setInterval(() => setClockStr(fmtClock()), 1000);
    return () => clearInterval(id);
  }, []);
  const [theme, setTheme] = useState<'light' | 'dark'>(
    () => (localStorage.getItem('theme') as 'light' | 'dark') ?? 'dark'
  );
  const [aiStatus, setAIStatus] = useState<AIServiceStatus | null>(null);
  const [chatMessages, setChatMessages] = useState<ChatMessage[]>([]);
  const [chatBusy, setChatBusy] = useState(false);
  const [chatReportContext, setChatReportContext] = useState<string | null>(null);
  const [selectedLookbackHours, setSelectedLookbackHours] = useState<number>(24);
  const [lastScriptSummary, setLastScriptSummary] = useState<{ lookback_hours: number; total_alerts: number; relevant_alerts: number } | null>(null);
  const [lastReportTxt, setLastReportTxt] = useState<string | null>(null);
  const [lastReportJson, setLastReportJson] = useState<string | null>(null);
  const [generatedTasks, setGeneratedTasks] = useState<Array<{ task_id: string; host: string; severity: string; title: string; details: string; recommended_checks: string[]; event_id?: string | null; rule_id?: string | null; rule_description?: string | null; platform?: string | null; count?: number; reason?: string | null; local_score?: number | null; mitre_ids?: string[]; }>>([]);
  const [snipenPrefillHost, setSnipenPrefillHost] = useState<string | null>(null);
  const [snipenPrefillEventTs, setSnipenPrefillEventTs] = useState<string | null>(null);
  const [settingsOpen, setSettingsOpen] = useState(false);
  const [videoSource, setVideoSource] = useState<string | null>(null);
  const [analysisProfile, setAnalysisProfile] = useState<AnalysisProfileConfig>(DEFAULT_ANALYSIS_PROFILE);
  const [bootReady, setBootReady] = useState(false);
  const [introMinElapsed, setIntroMinElapsed] = useState(false);
  const [introVisible, setIntroVisible] = useState(true);
  const [introMounted, setIntroMounted] = useState(true);
  const [bootStatusText, setBootStatusText] = useState('Initialisiere Analyseumgebung');
  const [preflightChecks, setPreflightChecks] = useState<PreflightCheck[]>(() => createInitialPreflightChecks());
  const [bootAttempt, setBootAttempt] = useState(0);
  const [profiles, setProfiles] = useState<HostProfile[]>([]);
  const [profileAssignments, setProfileAssignments] = useState<Record<string, HostProfileAssignment>>({});
  const [startingBackend, setStartingBackend] = useState(false);
  const [restartingBackend, setRestartingBackend] = useState(false);

  const hasBlockingFailure = preflightChecks.some((check) => check.required && check.state === 'error');
  const preflightSettled = preflightChecks.every((check) => check.state !== 'pending' && check.state !== 'running');
  const canEnter = bootReady && preflightSettled && !hasBlockingFailure;

  useEffect(() => {
    return () => {
      if (videoSource?.startsWith('blob:')) {
        URL.revokeObjectURL(videoSource);
      }
    };
  }, [videoSource]);

  useEffect(() => {
    const isDark = theme === 'dark';
    document.documentElement.classList.toggle('dark', isDark);
    document.documentElement.classList.toggle('theme-dark', isDark);
    document.body.classList.toggle('theme-dark', isDark);

    return () => {
      document.documentElement.classList.remove('dark', 'theme-dark');
      document.body.classList.remove('theme-dark');
    };
  }, [theme]);

  function handleVideoSelect(file: File) {
    if (videoSource?.startsWith('blob:')) {
      URL.revokeObjectURL(videoSource);
    }

    const objectUrl = URL.createObjectURL(file);
    setVideoSource(objectUrl);
  }

  function handleClearVideo() {
    if (videoSource?.startsWith('blob:')) {
      URL.revokeObjectURL(videoSource);
    }

    setVideoSource(null);
  }

  async function refreshAIStatus() {
    try {
      setAIStatus(await getAIServiceStatus());
    } catch {
      setAIStatus(null);
    }
  }

  useEffect(() => {
    const timer = window.setTimeout(() => {
      setIntroMinElapsed(true);
    }, 2200);
    return () => window.clearTimeout(timer);
  }, []);

  useEffect(() => {
    if (!canEnter || !introMinElapsed || !introVisible) return;
    setBootStatusText('Launch sequence complete');
    const timer = window.setTimeout(() => {
      setIntroVisible(false);
    }, 700);
    return () => window.clearTimeout(timer);
  }, [canEnter, introMinElapsed, introVisible]);

  useEffect(() => {
    let active = true;

    const setCheck = (key: string, state: PreflightCheck['state'], detail: string) => {
      if (!active) return;
      setPreflightChecks((current) =>
        current.map((check) => (check.key === key ? { ...check, state, detail } : check))
      );
    };

    async function boot() {
      setPreflightChecks(createInitialPreflightChecks());
      setBootReady(false);
      setChatBusy(true);
      setBootStatusText('Initialisiere Systempruefung');

      let blockingFailure = false;
      let runtimeStatus: AIServiceStatus | null = null;

      try {
        setBootStatusText('Pruefe Backend API');
        setCheck('backend', 'running', 'Requesting backend health endpoint');
        try {
          const backend = await getBackendHealth();
          if (isHealthy(backend)) {
            setCheck('backend', 'success', backend.detail || 'Backend API responded successfully');
          } else {
            blockingFailure = true;
            setCheck('backend', 'error', backend.detail || 'Backend health check reported an unhealthy state');
          }
        } catch (error) {
          blockingFailure = true;
          setCheck('backend', 'error', describeError(error, 'Backend health request failed'));
        }

        setBootStatusText('Lade aktive Verbindung');
        setCheck('connection', 'running', 'Resolving configured Wazuh connection');
        try {
          const connection = await getActiveConnection();
          const connectionLabel = connection.name || connection.indexer_url;
          setCheck('connection', 'success', `Using ${connectionLabel}`);
        } catch (error) {
          blockingFailure = true;
          setCheck('connection', 'error', describeError(error, 'No active connection available'));
        }

        setBootStatusText('Pruefe Indexer');
        setCheck('indexer', 'running', 'Contacting Wazuh indexer');
        try {
          const indexer = await getIndexerHealth();
          if (isHealthy(indexer)) {
            setCheck('indexer', 'success', indexer.detail || 'Indexer is reachable');
          } else {
            blockingFailure = true;
            setCheck('indexer', 'error', indexer.detail || 'Indexer health check failed');
          }
        } catch (error) {
          blockingFailure = true;
          setCheck('indexer', 'error', describeError(error, 'Indexer health request failed'));
        }

        setBootStatusText('Pruefe Host-Datenstrom');
        setCheck('hosts', 'running', 'Sampling /hosts/central feed');
        try {
          const hosts = await getHostsCentral(24);
          if (hosts.length > 0) {
            setCheck('hosts', 'success', `${hosts.length} hosts detected in the last 24h feed`);
          } else {
            setCheck('hosts', 'warning', 'No hosts returned by the central feed');
          }
        } catch (error) {
          setCheck('hosts', 'warning', describeError(error, 'Host feed check failed'));
        }

        // Load profiles + assignments (best-effort, never blocks boot)
        try {
          const [profileList, assignmentList] = await Promise.all([getProfiles(), getAllProfileAssignments()]);
          if (active) {
            setProfiles(profileList);
            const amap: Record<string, HostProfileAssignment> = {};
            for (const asgn of assignmentList) amap[asgn.host] = asgn;
            setProfileAssignments(amap);
          }
        } catch {
          // non-blocking
        }

        setBootStatusText('Lade Analyseprofil');
        setCheck('profile', 'running', 'Loading analysis profile defaults');
        try {
          const profile = await getAnalysisProfile();
          if (!active) return;
          setAnalysisProfile(profile);
          setCheck('profile', 'success', `Profile ready with min rule level ${profile.min_rule_level}`);
        } catch (error) {
          if (!active) return;
          setAnalysisProfile(DEFAULT_ANALYSIS_PROFILE);
          setCheck('profile', 'warning', describeError(error, 'Using default analysis profile'));
        }

        setBootStatusText('Pruefe Ollama Endpoint');
        setCheck('ollama', 'running', 'Contacting configured model endpoint');
        try {
          const ollama = await getOllamaHealth();
          if (isHealthy(ollama)) {
            setCheck('ollama', 'success', ollama.detail || 'Ollama endpoint responded');
          } else {
            setCheck('ollama', 'warning', ollama.detail || 'Ollama endpoint is not fully reachable');
          }
        } catch (error) {
          setCheck('ollama', 'warning', describeError(error, 'Ollama health request failed'));
        }

        setBootStatusText('Pruefe AI Runtime');
        setCheck('ai', 'running', 'Checking local AI process state');
        try {
          runtimeStatus = await getAIServiceStatus();
          if (!runtimeStatus.running) {
            if (!active) return;
            setCheck('ai', 'running', 'Runtime offline, attempting startup');
            runtimeStatus = await startAIService();
          }
          if (!active) return;
          setAIStatus(runtimeStatus);
          if (runtimeStatus.running) {
            setCheck('ai', 'success', 'AI runtime is online');
          } else {
            setCheck('ai', 'warning', runtimeStatus.last_error || 'AI runtime did not confirm as running');
          }
        } catch (error) {
          if (!active) return;
          setAIStatus(null);
          setCheck('ai', 'warning', describeError(error, 'AI runtime startup failed'));
        }

        if (!active) return;
        setChatMessages([
          {
            role: 'assistant',
            content: runtimeStatus?.running
              ? 'Startup checks abgeschlossen. Die AI-Laufzeit ist online.'
              : 'Startup checks abgeschlossen. Die App ist verfuegbar, aber die AI-Laufzeit ist nur eingeschraenkt erreichbar.',
          },
        ]);
        setBootStatusText(blockingFailure ? 'Kritische Pruefung fehlgeschlagen' : 'Startup checks abgeschlossen');
      } catch (error) {
        if (!active) return;
        const detail = describeError(error, 'Startup preflight failed unexpectedly');
        setBootStatusText('Startup checks abgebrochen');
        setChatMessages([{ role: 'assistant', content: `Startup-Pruefung fehlgeschlagen: ${detail}` }]);
      } finally {
        if (active) {
          setBootReady(true);
          setChatBusy(false);
        }
      }
    }

    void boot();
    const timer = setInterval(() => {
      void refreshAIStatus();
    }, 2000);

    return () => {
      active = false;
      clearInterval(timer);
    };
  }, [bootAttempt]);

  function handleProfileAssignmentChanged(host: string, assignment: HostProfileAssignment | null) {
    setProfileAssignments((prev) => {
      const next = { ...prev };
      if (assignment === null) {
        delete next[host];
      } else {
        next[host] = assignment;
      }
      return next;
    });
  }

  async function handleSaveAnalysisProfile(next: AnalysisProfileConfig) {    setAnalysisProfile(next);
    try {
      const saved = await saveAnalysisProfile(next);
      setAnalysisProfile(saved);
    } catch {
    }
  }

  async function handleChatSend(message: string, runScript: boolean) {
    if (!message.trim() && !runScript) {
      return;
    }

    const userText = message || (runScript ? 'Bitte starte das Remote-Skript und fasse das Ergebnis zusammen.' : '');
    const nextMessages: ChatMessage[] = userText
      ? [...chatMessages, { role: 'user', content: userText }]
      : [...chatMessages];

    if (userText) {
      setChatMessages(nextMessages);
    }

    setChatBusy(true);
    try {
      let status = await getAIServiceStatus();
      if (!status.running) {
        status = await startAIService();
      }
      setAIStatus(status);

      const response = await sendChatMessage({
        message,
        run_script: runScript,
        lookback_hours: runScript ? selectedLookbackHours : undefined,
        history: nextMessages,
        report_context: chatReportContext,
        report_json_content: lastReportJson,
        analysis_profile: analysisProfile,
      });

      setChatReportContext(response.report_context || chatReportContext);
      if (response.script_summary) {
        setLastScriptSummary(response.script_summary);
      }
      if (response.report_txt_content) {
        setLastReportTxt(response.report_txt_content);
      }
      if (response.report_json_content) {
        setLastReportJson(response.report_json_content);
      }
      if (response.generated_tasks) {
        setGeneratedTasks(response.generated_tasks);
      }
      setChatMessages([
        ...nextMessages,
        { role: 'assistant', content: response.reply },
      ]);
    } catch (error) {
      const detail = error instanceof Error ? error.message : 'Chat request failed';
      setChatMessages([
        ...nextMessages,
        { role: 'assistant', content: `Fehler: ${detail}` },
      ]);
    } finally {
      setChatBusy(false);
    }
  }

  async function handleStartBackend() {
    setStartingBackend(true);
    try {
      // Use Tauri IPC if running inside the desktop app (withGlobalTauri = true)
      const tauri = (window as unknown as { __TAURI__?: { core?: { invoke: (cmd: string) => Promise<unknown> } } }).__TAURI__;
      if (tauri?.core?.invoke) {
        await tauri.core.invoke('start_backend');
      }
    } catch {
      // not in Tauri context or command failed – fall through to retry anyway
    }
    // Give the backend ~3 s to bind the port, then re-run preflight
    window.setTimeout(() => {
      setStartingBackend(false);
      setPreflightChecks(createInitialPreflightChecks());
      setBootReady(false);
      setBootAttempt((n) => n + 1);
    }, 3000);
  }

  async function handleRestartBackend() {
    setRestartingBackend(true);
    try {
      const tauri = (window as unknown as { __TAURI__?: { core?: { invoke: (cmd: string) => Promise<unknown> } } }).__TAURI__;
      if (tauri?.core?.invoke) {
        await tauri.core.invoke('restart_backend');
      }
    } catch {
      // not in Tauri context or command failed – fall through to retry anyway
    }
    // Give the backend ~4 s to kill, restart and bind the port, then re-run preflight
    window.setTimeout(() => {
      setRestartingBackend(false);
      setPreflightChecks(createInitialPreflightChecks());
      setBootReady(false);
      setBootAttempt((n) => n + 1);
    }, 4000);
  }

  return (
    <div className="flex h-screen overflow-hidden font-mono" style={{ background: 'var(--soc-background)', color: 'var(--soc-foreground)' }}>
      {introMounted && (
        <AppStartOverlay
          theme={theme}
          visible={introVisible}
          statusText={bootStatusText}
          checks={preflightChecks}
          canEnter={canEnter}
          hasBlockingFailure={hasBlockingFailure}
          onRetry={() => {
            setIntroVisible(true);
            setIntroMounted(true);
            setBootAttempt((current) => current + 1);
          }}
          onContinue={() => setIntroVisible(false)}
          onExited={() => setIntroMounted(false)}
          onStartBackend={handleStartBackend}
          startingBackend={startingBackend}
          onRestartBackend={handleRestartBackend}
          restartingBackend={restartingBackend}
        />
      )}

      {/* ── Sidebar ────────────────────────────────────────────────────── */}
      <AppSidebar
        activeTab={activeTab}
        onNavigate={tab => setActiveTab(tab)}
        onSettingsOpen={() => setSettingsOpen(true)}
        taskBadge={generatedTasks.length > 0 ? String(generatedTasks.length) : null}
        aiOnline={aiStatus?.running ?? false}
        clockStr={clockStr}
      />

      {/* Main content */}
      <main className="relative z-10 flex flex-col flex-1 overflow-hidden">
        {/* SOC topbar matching redesign */}
        <header className="h-10 shrink-0 border-b flex items-center px-3 gap-3" style={{ borderColor: 'var(--soc-border)', background: 'var(--soc-panel)' }}>
          <div className="flex items-baseline gap-1.5">
            {CATEGORY_LABELS[activeTab] && (
              <>
                <span className="text-[11px]" style={{ color: 'var(--soc-muted-fg)' }}>{CATEGORY_LABELS[activeTab]}</span>
                <span className="text-[11px]" style={{ color: 'var(--soc-muted-fg)' }}>/</span>
              </>
            )}
            <span className="text-[12.5px] font-semibold tracking-wide">{TAB_LABELS[activeTab] ?? activeTab}</span>
          </div>

          <div className="ml-4 flex items-center gap-2 flex-1 max-w-[480px]">
            <div className="flex items-center gap-2 h-7 w-full px-2 rounded-sm border" style={{ background: 'var(--soc-input)', borderColor: 'var(--soc-border)' }}>
              <Search size={14} style={{ color: 'var(--soc-muted-fg)' }} />
              <input
                placeholder="host:, user:, eid:, hash:, ip:…"
                className="bg-transparent flex-1 outline-none text-[12px] font-mono"
                style={{ color: 'var(--soc-foreground)' }}
              />
            </div>
          </div>

          <div className="ml-auto flex items-center gap-2">
            {generatedTasks.length > 0 && (
              <button
                type="button"
                onClick={() => setActiveTab('tasks')}
                className="flex items-center gap-1 font-mono text-[10.5px]"
                style={{ color: 'var(--soc-critical)' }}
              >
                <span className="h-1.5 w-1.5 rounded-full animate-pulse" style={{ background: 'var(--soc-critical)' }} />
                {generatedTasks.length} ALERT{generatedTasks.length !== 1 ? 'S' : ''}
              </button>
            )}
            <span className="flex items-center gap-1.5 text-[11px] font-mono" style={{ color: 'var(--soc-muted-fg)' }}>
              <span className="h-1.5 w-1.5 rounded-full animate-pulse" style={{ background: aiStatus?.running ? 'var(--soc-success)' : chatBusy ? 'var(--soc-warning)' : 'var(--soc-critical)' }} />
              {aiStatus?.running ? 'live' : chatBusy ? 'running' : 'offline'} · {clockStr}
            </span>
          </div>
        </header>
        {/* Page content area — only the active page is mounted */}
        <div className="relative flex-1 overflow-hidden">
          {activeTab === 'chat' && (
            <ErrorBoundary label="Chat">
              <ChatPage
                active
                theme={theme}
                onThemeToggle={() => setTheme(theme === 'light' ? 'dark' : 'light')}
                messages={chatMessages}
                busy={chatBusy}
                aiStatus={aiStatus}
                reportContext={chatReportContext}
                selectedLookbackHours={selectedLookbackHours}
                lookbackPresets={[...LOOKBACK_PRESETS]}
                onSelectLookback={setSelectedLookbackHours}
                lastScriptSummary={lastScriptSummary}
                lastReportTxt={lastReportTxt}
                lastReportJson={lastReportJson}
                generatedTasks={generatedTasks}
                onSwitchTab={(tab) => setActiveTab(tab)}
                onSend={(message, runScript) => void handleChatSend(message, runScript)}
              />
            </ErrorBoundary>
          )}
          {activeTab === 'dashboard' && (
            <ErrorBoundary label="Dashboard">
              <FleetOverviewPage
                active
                onSwitchTab={(tab, payload) => {
                  if (tab === 'hosts' && payload && typeof payload === 'object' && 'host' in payload) {
                    setOverviewHost((payload as { host: string }).host);
                    setActiveTab('host-overview');
                  } else if (tab === 'findings' || tab === 'tasks') {
                    setActiveTab('tasks');
                  } else {
                    setActiveTab(tab as typeof activeTab);
                  }
                }}
              />
            </ErrorBoundary>
          )}
          {activeTab === 'tasks' && (
            <ErrorBoundary label="Tasks">
              <TasksPage
                active
                theme={theme}
                onThemeToggle={() => setTheme(theme === 'light' ? 'dark' : 'light')}
                generatedTasks={generatedTasks}
                profileAssignments={profileAssignments}
                onSwitchTab={(tab, context) => {
                  if (context?.host) setSnipenPrefillHost(context.host);
                  setActiveTab(tab);
                }}
              />
            </ErrorBoundary>
          )}
          {activeTab === 'hosts' && (
            <ErrorBoundary label="Hosts">
              <HostsPage
                active
                theme={theme}
                profiles={profiles}
                profileAssignments={profileAssignments}
                onProfileAssignmentChanged={handleProfileAssignmentChanged}
                onSwitchTab={(tab) => setActiveTab(tab)}
                onOpenOverview={(host) => { setOverviewHost(host); setActiveTab('host-overview'); }}
              />
            </ErrorBoundary>
          )}
          {activeTab === 'host-overview' && overviewHost && (
            <ErrorBoundary label="HostOverview">
              <HostOverviewPage
                host={overviewHost}
                onBack={() => setActiveTab('hosts')}
                onGoBaseline={(host) => {
                  // BaselinePage will pick up the host via its own host list
                  // Pass it as prefill context if needed — for now just navigate
                  void host;
                  setActiveTab('baseline');
                }}
                onGoSnipen={(host) => {
                  setSnipenPrefillHost(host);
                  setActiveTab('snipen');
                }}
                onGoFullScan={() => setActiveTab('fullscan')}
              />
            </ErrorBoundary>
          )}
          {activeTab === 'snipen' && (
            <ErrorBoundary label="Snipen">
              <SnipenPage
                active
                theme={theme}
                profileAssignments={profileAssignments}
                prefillHost={snipenPrefillHost}
                prefillEventTs={snipenPrefillEventTs}
                onPrefillConsumed={() => { setSnipenPrefillHost(null); setSnipenPrefillEventTs(null); }}
              />
            </ErrorBoundary>
          )}
          {activeTab === 'fullscan' && (
            <ErrorBoundary label="FullScan">
              <FullScanTab theme={theme} profileAssignments={profileAssignments} />
            </ErrorBoundary>
          )}

          {activeTab === 'baseline' && (
            <ErrorBoundary label="Baseline">
              <BaselinePage
                active
                theme={theme}
                onSwitchTab={(tab, context) => {
                  if (context?.host) setSnipenPrefillHost(context.host);
                  setActiveTab(tab as typeof activeTab);
                }}
              />
            </ErrorBoundary>
          )}
          {activeTab === 'server' && (
            <ErrorBoundary label="Server">
              <ServerPage active theme={theme} />
            </ErrorBoundary>
          )}
          {activeTab === 'unified-hosts' && (
            <ErrorBoundary label="UnifiedHosts">
              <UnifiedHostsPage active />
            </ErrorBoundary>
          )}
          {activeTab === 'scripts' && (
            <ErrorBoundary label="Scripts">
              <ScriptLibraryPage />
            </ErrorBoundary>
          )}
          {activeTab === 'trust' && (
            <ErrorBoundary label="Trust">
              <TrustCenterPage />
            </ErrorBoundary>
          )}
          {activeTab === 'wazuh-integration' && (
            <ErrorBoundary label="Wazuh Integration">
              <WazuhIntegrationPage />
            </ErrorBoundary>
          )}
          {activeTab === 'constellation' && (
            <ErrorBoundary label="Constellation">
              <Suspense fallback={
                <div className="flex h-full items-center justify-center" style={{ color: 'var(--soc-muted-fg)', fontFamily: 'monospace', fontSize: 12 }}>
                  Loading constellation…
                </div>
              }>
                <EventConstellationView
                  initialHost={constellationHost ?? undefined}
                  onNavigate={(tab, host) => {
                    if (tab === 'hosts') {
                      if (host) { setOverviewHost(host); setActiveTab('host-overview'); }
                      else setActiveTab('hosts');
                    } else {
                      setActiveTab(tab as typeof activeTab);
                    }
                  }}
                />
              </Suspense>
            </ErrorBoundary>
          )}
        </div>
      </main>

      {/* Settings Modal */}
      <SettingsModal
        isOpen={settingsOpen}
        onClose={() => setSettingsOpen(false)}
        theme={theme}
        currentVideoSource={videoSource}
        onVideoSelect={handleVideoSelect}
        onClearVideo={handleClearVideo}
        analysisProfile={analysisProfile}
        onSaveAnalysisProfile={handleSaveAnalysisProfile}
      />
    </div>
  );
}

export default App;
