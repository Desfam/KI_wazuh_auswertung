import { useEffect, useState } from 'react';
import { ChatPage } from './pages/ChatPage';
import { DashboardPage } from './pages/DashboardPage';
import { SnipenPage } from './pages/SnipenPage';
import { TasksPage } from './pages/TasksPage';
import { FluidWaves } from './components/FluidWaves';
import { SettingsModal } from './components/SettingsModal';
import { VideoBackground } from './components/VideoBackground';
import { getAIServiceStatus, getAnalysisProfile, saveAnalysisProfile, sendChatMessage, startAIService } from './services/api';
import type { AIServiceStatus, AnalysisProfileConfig, ChatMessage } from './types';

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

function App() {
  const [activeTab, setActiveTab] = useState<'chat' | 'tasks' | 'dashboard' | 'snipen'>('chat');
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
  const [generatedTasks, setGeneratedTasks] = useState<Array<{ task_id: string; host: string; severity: string; title: string; details: string; recommended_checks: string[] }>>([]);
  const [settingsOpen, setSettingsOpen] = useState(false);
  const [videoSource, setVideoSource] = useState<string | null>(null);
  const [analysisProfile, setAnalysisProfile] = useState<AnalysisProfileConfig>(DEFAULT_ANALYSIS_PROFILE);

  useEffect(() => {
    return () => {
      if (videoSource?.startsWith('blob:')) {
        URL.revokeObjectURL(videoSource);
      }
    };
  }, [videoSource]);

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
    let active = true;

    async function boot() {
      setChatBusy(true);
      try {
        let status = await getAIServiceStatus();
        if (!status.running) {
          status = await startAIService();
        }
        if (!active) return;
        setAIStatus(status);
        setChatMessages([
          {
            role: 'assistant',
            content: status.running
              ? 'Ollama ist verbunden. Du kannst direkt losschreiben.'
              : 'Ollama wurde angefordert. Wenn der Start noch laeuft, kannst du trotzdem schon schreiben.',
          },
        ]);
      } catch (error) {
        if (!active) return;
        const detail = error instanceof Error ? error.message : 'AI startup failed';
        setChatMessages([{ role: 'assistant', content: `AI-Start fehlgeschlagen: ${detail}` }]);
      } finally {
        if (active) {
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
  }, []);

  useEffect(() => {
    let active = true;
    async function loadProfile() {
      try {
        const profile = await getAnalysisProfile();
        if (!active) return;
        setAnalysisProfile(profile);
      } catch {
      }
    }
    void loadProfile();
    return () => {
      active = false;
    };
  }, []);

  async function handleSaveAnalysisProfile(next: AnalysisProfileConfig) {
    setAnalysisProfile(next);
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

  return (
    <div className={`flex h-screen overflow-hidden ${theme === 'dark' ? 'theme-dark-accent' : ''}`}>
      {/* Dark background layer */}
      {theme === 'dark' && (
        <div className="fixed inset-0 z-0 bg-[#0f1117]">
          {videoSource && (
            <>
              <VideoBackground videoSource={videoSource} />
              <div className="absolute inset-0 bg-black/40" />
            </>
          )}
        </div>
      )}

      {/* Sidebar */}
      <aside className={`relative z-10 flex h-full w-16 flex-shrink-0 flex-col border-r lg:w-[var(--app-sidebar-expanded)] ${theme === 'dark' ? 'border-slate-700/60 bg-[#151823]' : 'border-ink/10 bg-white/95'}`}>
        {/* Logo */}
        <div className={`flex items-center gap-3 border-b px-3 py-4 ${theme === 'dark' ? 'dark-divider' : 'border-ink/10'}`}>
          <span className="flex-shrink-0 text-2xl">🛡️</span>
          <span className={`hidden truncate text-sm font-bold lg:block ${theme === 'dark' ? 'dark-text-main' : 'text-ink'}`}>Wazuh AI</span>
        </div>

        {/* Nav */}
        <nav className="flex flex-1 flex-col gap-1 p-2 pt-4">
          <button
            type="button"
            onClick={() => setActiveTab('dashboard')}
            className={`flex w-full items-center gap-3 rounded-xl px-3 py-2.5 text-sm font-medium transition hover:-translate-y-0.5 ${
              activeTab === 'dashboard'
                ? theme === 'dark' ? 'bg-amber-600/25 text-amber-200' : 'bg-ember/10 text-ember'
                : theme === 'dark' ? 'dark-text-soft hover:bg-white/5 hover:text-slate-200' : 'text-slate hover:bg-shell hover:text-ink'
            }`}
          >
            <span className="flex-shrink-0 text-lg">📊</span>
            <span className="hidden lg:block">Dashboard</span>
            {lastReportJson && (
              <span className={`hidden rounded-full px-2 py-0.5 text-[0.6rem] font-bold lg:block ${
                theme === 'dark' ? 'bg-emerald-900/30 text-emerald-300' : 'bg-emerald-100 text-emerald-700'
              }`}>●</span>
            )}
          </button>
          <button
            type="button"
            onClick={() => setActiveTab('chat')}
            className={`flex w-full items-center gap-3 rounded-xl px-3 py-2.5 text-sm font-medium transition hover:-translate-y-0.5 ${
              activeTab === 'chat'
                ? theme === 'dark' ? 'bg-amber-600/25 text-amber-200' : 'bg-ember/10 text-ember'
                : theme === 'dark' ? 'dark-text-soft hover:bg-white/5 hover:text-slate-200' : 'text-slate hover:bg-shell hover:text-ink'
            }`}
          >
            <span className="flex-shrink-0 text-lg">💬</span>
            <span className="hidden lg:block">Chat</span>
          </button>
          <button
            type="button"
            onClick={() => setActiveTab('tasks')}
            className={`flex w-full items-center gap-3 rounded-xl px-3 py-2.5 text-sm font-medium transition hover:-translate-y-0.5 ${
              activeTab === 'tasks'
                ? theme === 'dark' ? 'bg-amber-600/25 text-amber-200' : 'bg-ember/10 text-ember'
                : theme === 'dark' ? 'dark-text-soft hover:bg-white/5 hover:text-slate-200' : 'text-slate hover:bg-shell hover:text-ink'
            }`}
          >
            <span className="flex-shrink-0 text-lg">✅</span>
            <span className="hidden flex-1 text-left lg:block">Tasks</span>
            {generatedTasks.length > 0 && (
              <span className={`hidden rounded-full px-2 py-0.5 text-[0.6rem] font-bold lg:block ${
                theme === 'dark' ? 'bg-amber-500/25 text-amber-200' : 'bg-ember/15 text-ember'
              }`}>
                {generatedTasks.length}
              </span>
            )}
          </button>
          <button
            type="button"
            onClick={() => setActiveTab('snipen')}
            className={`flex w-full items-center gap-3 rounded-xl px-3 py-2.5 text-sm font-medium transition hover:-translate-y-0.5 ${
              activeTab === 'snipen'
                ? theme === 'dark' ? 'bg-amber-600/25 text-amber-200' : 'bg-ember/10 text-ember'
                : theme === 'dark' ? 'dark-text-soft hover:bg-white/5 hover:text-slate-200' : 'text-slate hover:bg-shell hover:text-ink'
            }`}
          >
            <span className="flex-shrink-0 text-lg">🎯</span>
            <span className="hidden lg:block">Snipen</span>
          </button>
        </nav>

        {/* Bottom controls */}
        <div className={`space-y-1 border-t p-2 ${theme === 'dark' ? 'dark-divider' : 'border-ink/10'}`}>
          {/* AI status */}
          <div className={`flex items-center gap-3 rounded-xl px-3 py-2 text-xs ${theme === 'dark' ? 'dark-text-soft' : 'text-slate'}`}>
            <span className={`h-2 w-2 flex-shrink-0 rounded-full ${
              aiStatus?.running ? 'bg-emerald-400' : chatBusy ? 'bg-amber-400' : 'bg-rose-400'
            }`} />
            <span className="hidden lg:block">{aiStatus?.running ? 'AI online' : chatBusy ? 'Laeuft...' : 'AI offline'}</span>
          </div>
          {/* Theme toggle */}
          <button
            type="button"
            onClick={() => { const next = theme === 'light' ? 'dark' : 'light'; setTheme(next); localStorage.setItem('theme', next); }}
            className={`flex w-full items-center gap-3 rounded-xl px-3 py-2 text-sm transition hover:-translate-y-0.5 ${
              theme === 'dark' ? 'dark-text-soft hover:bg-white/5 hover:text-slate-200' : 'text-slate hover:bg-shell hover:text-ink'
            }`}
          >
            <span className="flex-shrink-0">{theme === 'light' ? '🌙' : '☀️'}</span>
            <span className="hidden lg:block">{theme === 'light' ? 'Dark Mode' : 'Light Mode'}</span>
          </button>
          {/* Settings */}
          <button
            type="button"
            onClick={() => setSettingsOpen(true)}
            className={`flex w-full items-center gap-3 rounded-xl px-3 py-2 text-sm transition hover:-translate-y-0.5 ${
              theme === 'dark' ? 'dark-text-soft hover:bg-white/5 hover:text-slate-200' : 'text-slate hover:bg-shell hover:text-ink'
            }`}
          >
            <span className="flex-shrink-0">⚙️</span>
            <span className="hidden lg:block">Einstellungen</span>
          </button>
        </div>
      </aside>

      {/* Main content */}
      <main className="relative z-10 flex-1 overflow-hidden">
        <ChatPage
          active={activeTab === 'chat'}
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
        <DashboardPage
          active={activeTab === 'dashboard'}
          theme={theme}
          reportJson={lastReportJson}
          scriptSummary={lastScriptSummary}
        />
        <TasksPage
          active={activeTab === 'tasks'}
          theme={theme}
          onThemeToggle={() => setTheme(theme === 'light' ? 'dark' : 'light')}
          generatedTasks={generatedTasks}
          onSwitchTab={(tab) => setActiveTab(tab)}
        />
        <SnipenPage
          active={activeTab === 'snipen'}
          theme={theme}
        />
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
