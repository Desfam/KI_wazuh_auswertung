import { useEffect, useRef, useState } from 'react';
import ReactMarkdown from 'react-markdown';
import remarkGfm from 'remark-gfm';
import type { AIServiceStatus, ChatMessage } from '../types';

type ChatPageProps = {
  active: boolean;
  theme: 'light' | 'dark';
  onThemeToggle: () => void;
  messages: ChatMessage[];
  busy: boolean;
  aiStatus: AIServiceStatus | null;
  reportContext?: string | null;
  selectedLookbackHours: number;
  lookbackPresets: number[];
  onSelectLookback: (hours: number) => void;
  lastScriptSummary?: {
    lookback_hours: number;
    total_alerts: number;
    relevant_alerts: number;
  } | null;
  lastReportTxt?: string | null;
  lastReportJson?: string | null;
  generatedTasks: Array<{
    task_id: string;
    host: string;
    severity: string;
    title: string;
    details: string;
    recommended_checks: string[];
  }>;
  onSend: (message: string, runScript: boolean) => void;
  onSwitchTab: (tab: 'chat' | 'tasks') => void;
};

export function ChatPage({
  active,
  theme,
  onThemeToggle,
  messages,
  busy,
  aiStatus,
  reportContext,
  selectedLookbackHours,
  lookbackPresets,
  onSelectLookback,
  lastScriptSummary,
  lastReportTxt,
  lastReportJson,
  generatedTasks,
  onSend,
  onSwitchTab,
}: ChatPageProps) {
  const [input, setInput] = useState('');
  const [drawerOpen, setDrawerOpen] = useState(false);
  const [drawerTab, setDrawerTab] = useState<'txt' | 'json'>('txt');
  const scrollerRef = useRef<HTMLDivElement | null>(null);
  const bottomRef = useRef<HTMLDivElement | null>(null);
  const shouldAutoScrollRef = useRef(true);
  const hasReportFiles = Boolean(lastReportTxt || lastReportJson);

  let formattedReportJson = lastReportJson ?? '(keine Daten)';
  if (lastReportJson) {
    try {
      formattedReportJson = JSON.stringify(JSON.parse(lastReportJson), null, 2);
    } catch {
      formattedReportJson = lastReportJson;
    }
  }

  useEffect(() => {
    if (!shouldAutoScrollRef.current) {
      return;
    }
    bottomRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [messages, generatedTasks, busy]);

  function handleScroll() {
    const node = scrollerRef.current;
    if (!node) {
      return;
    }
    const distanceFromBottom = node.scrollHeight - node.scrollTop - node.clientHeight;
    shouldAutoScrollRef.current = distanceFromBottom < 120;
  }

  function submit(runScript: boolean) {
    const trimmed = input.trim();
    if (!trimmed && !runScript) return;
    shouldAutoScrollRef.current = true;
    onSend(trimmed, runScript);
    setInput('');
  }

  return (
    <div className={`flex h-full flex-col ${theme === 'dark' ? 'bg-transparent text-slate-50' : 'bg-shell bg-grid bg-[size:26px_26px] text-ink'} ${!active ? 'hidden' : ''}`}>

      <section className={`page-shell-x grid gap-3 border-b py-3 md:grid-cols-4 ${theme === 'dark' ? 'dark-panel dark-divider' : 'border-ink/10 bg-white/70'}`}>
        <article className={`ui-fade-up ui-fade-up-delay-1 rounded-2xl border px-4 py-3 transition hover:-translate-y-0.5 hover:shadow-sm ${theme === 'dark' ? 'dark-panel-soft dark-text-main' : 'border-ink/10 bg-white text-ink'}`}>
          <p className={`text-xs uppercase tracking-[0.2em] ${theme === 'dark' ? 'dark-kicker' : 'text-slate'}`}>Mode</p>
          <p className="mt-2 text-sm font-medium">VM Script + Chat</p>
        </article>
        <article className={`ui-fade-up ui-fade-up-delay-2 rounded-2xl border px-4 py-3 transition hover:-translate-y-0.5 hover:shadow-sm ${theme === 'dark' ? 'dark-panel-soft dark-text-main' : 'border-ink/10 bg-white text-ink'}`}>
          <p className={`text-xs uppercase tracking-[0.2em] ${theme === 'dark' ? 'dark-kicker' : 'text-slate'}`}>Lookback</p>
          <p className="mt-2 text-sm font-medium">{selectedLookbackHours}h</p>
        </article>
        <article className={`ui-fade-up ui-fade-up-delay-3 rounded-2xl border px-4 py-3 transition hover:-translate-y-0.5 hover:shadow-sm ${theme === 'dark' ? 'dark-panel-soft dark-text-main' : 'border-ink/10 bg-white text-ink'}`}>
          <p className={`text-xs uppercase tracking-[0.2em] ${theme === 'dark' ? 'dark-kicker' : 'text-slate'}`}>Relevant Alerts</p>
          <p className="mt-2 text-sm font-medium">{lastScriptSummary?.relevant_alerts ?? 0}</p>
        </article>
        <article className={`ui-fade-up ui-fade-up-delay-4 rounded-2xl border px-4 py-3 transition hover:-translate-y-0.5 hover:shadow-sm ${theme === 'dark' ? 'dark-panel-soft dark-text-main' : 'border-ink/10 bg-white text-ink'}`}>
          <p className={`text-xs uppercase tracking-[0.2em] ${theme === 'dark' ? 'dark-kicker' : 'text-slate'}`}>Total Alerts</p>
          <p className="mt-2 text-sm font-medium">{lastScriptSummary?.total_alerts ?? 0}</p>
        </article>
        {hasReportFiles && (
          <div className="ui-fade-up ui-fade-up-delay-4 col-span-full flex justify-end">
            <button
              type="button"
              onClick={() => { setDrawerOpen(true); setDrawerTab('txt'); }}
              title="Report-Dateien anzeigen"
              className={`rounded-xl border px-4 py-2 text-xs font-medium transition hover:-translate-y-0.5 ${theme === 'dark' ? 'dark-outline-button' : 'border-ink/15 bg-shell text-ink hover:bg-ink hover:text-shell'}`}
            >
              Report-Dateien anzeigen (.txt / .json)
            </button>
          </div>
        )}
      </section>

      {/* ── Narrow file-viewer drawer ─────────────────────────────── */}
      {drawerOpen && (
        <div className="fixed inset-0 z-50 flex justify-end">
          {/* translucent backdrop */}
          <div
            className="drawer-backdrop flex-1 bg-black/20"
            onClick={() => setDrawerOpen(false)}
          />
          {/* drawer panel */}
          <div className={`drawer-panel flex w-[420px] flex-col border-l shadow-2xl ${theme === 'dark' ? 'dark-panel-strong' : 'border-ink/20 bg-white'}`}>
            {/* header */}
            <div className={`flex items-center justify-between border-b px-4 py-3 ${theme === 'dark' ? 'dark-divider' : 'border-ink/10'}`}>
              <div className="flex gap-1">
                <button
                  type="button"
                  onClick={() => setDrawerTab('txt')}
                  className={`rounded-lg px-3 py-1.5 text-xs font-medium transition ${drawerTab === 'txt' ? 'bg-ember text-white' : theme === 'dark' ? 'dark-text-soft hover:text-white' : 'text-slate hover:text-ink'}`}
                >
                  .txt
                </button>
                <button
                  type="button"
                  onClick={() => setDrawerTab('json')}
                  className={`rounded-lg px-3 py-1.5 text-xs font-medium transition ${drawerTab === 'json' ? 'bg-ember text-white' : theme === 'dark' ? 'dark-text-soft hover:text-white' : 'text-slate hover:text-ink'}`}
                >
                  .json
                </button>
              </div>
              <button
                type="button"
                onClick={() => setDrawerOpen(false)}
                className={`rounded-lg px-3 py-1.5 text-xs transition ${theme === 'dark' ? 'dark-text-soft hover:text-white' : 'text-slate hover:text-ink'}`}
              >
                ✕ Schließen
              </button>
            </div>
            {/* label */}
            <p className={`border-b px-4 py-2 text-[0.65rem] uppercase tracking-widest ${theme === 'dark' ? 'dark-panel-faint dark-text-main dark-divider' : 'border-ink/5 bg-shell text-slate'}`}>
              {drawerTab === 'txt' ? 'ai_wazuh_24h_report.txt' : 'ai_wazuh_24h_report.json'}
            </p>
            {/* scrollable content */}
            <div className="flex-1 overflow-auto p-4">
              <pre className={`whitespace-pre-wrap break-words rounded-xl px-3 py-3 font-mono text-[0.76rem] leading-6 ${theme === 'dark' ? 'dark-code-block' : 'text-ink'}`}>
                {drawerTab === 'txt' ? (lastReportTxt ?? '(keine Daten)') : formattedReportJson}
              </pre>
            </div>
          </div>
        </div>
      )}


      <div className="flex min-h-0 flex-1 flex-col">
        <div ref={scrollerRef} onScroll={handleScroll} className="page-shell-x flex-1 overflow-auto py-4">
          <div className="page-content-max mx-auto flex w-full flex-col gap-4">
            {messages.length ? messages.map((message, index) => (
              <div
                key={`${message.role}-${index}`}
                className={message.role === 'user' ? `message-enter ml-auto max-w-[85%] rounded-2xl px-4 py-3 text-sm ${theme === 'dark' ? 'dark-message-user backdrop-blur' : 'bg-ink text-shell'}` : `message-enter self-start mr-auto ml-0 w-fit max-w-[85%] rounded-2xl border px-4 py-3 text-sm shadow-sm text-left ${theme === 'dark' ? 'dark-message-assistant backdrop-blur' : 'border-ink/10 bg-white text-ink'}`}
              >
                <p className={`mb-2 text-[0.65rem] uppercase tracking-[0.2em] ${theme === 'dark' ? 'dark-kicker' : 'text-slate'}`}>{message.role}</p>
                {message.role === 'assistant' ? (
                  <div className="chat-markdown">
                    <ReactMarkdown remarkPlugins={[remarkGfm]}>
                      {message.content}
                    </ReactMarkdown>
                  </div>
                ) : (
                  <p className="whitespace-pre-wrap leading-6">{message.content}</p>
                )}
              </div>
            )) : (
              <div className={`self-start mr-auto ml-0 w-fit max-w-[85%] rounded-2xl border border-dashed p-5 text-sm text-left backdrop-blur ${theme === 'dark' ? 'dark-panel-soft dark-text-main' : 'border-ink/15 bg-white text-slate'}`}>
                Die App verbindet sich automatisch mit Ollama. Schreibe eine Nachricht oder starte direkt das Remote-Skript.
              </div>
            )}
            {generatedTasks.length > 0 && (
              <div className={`message-enter self-start mr-auto ml-0 w-fit max-w-[85%] rounded-2xl border-2 px-4 py-3 text-sm shadow-md backdrop-blur text-left ${theme === 'dark' ? 'dark-attention-panel' : 'border-amber-300 bg-amber-50 text-ink'}`}>
                <p className={`mb-3 text-[0.65rem] uppercase tracking-[0.2em] font-bold ${theme === 'dark' ? 'text-amber-400' : 'text-amber-700'}`}>⚡ Automatische Tasks erstellt</p>
                <div className="space-y-2 mb-4">
                  {generatedTasks.slice(0, 10).map((task) => {
                    const severityColors: Record<string, { bg: string; text: string }> = theme === 'dark'
                      ? {
                          critical: { bg: 'bg-red-900/40', text: 'text-red-300' },
                          high: { bg: 'bg-orange-900/40', text: 'text-orange-300' },
                          medium: { bg: 'bg-yellow-900/40', text: 'text-yellow-300' },
                          low: { bg: 'bg-green-900/40', text: 'text-green-300' },
                        }
                      : {
                          critical: { bg: 'bg-red-100', text: 'text-red-700' },
                          high: { bg: 'bg-orange-100', text: 'text-orange-700' },
                          medium: { bg: 'bg-yellow-100', text: 'text-yellow-700' },
                          low: { bg: 'bg-green-100', text: 'text-green-700' },
                        };
                    const colors = severityColors[task.severity.toLowerCase()] || severityColors.low;
                    return (
                      <div key={task.task_id} className={`text-xs ${colors.bg} ${colors.text} rounded-lg px-2 py-1.5 whitespace-nowrap truncate ${theme === 'dark' ? 'font-medium brightness-125' : ''}`}>
                        <span className="font-semibold">[{task.severity.toUpperCase()}]</span> {task.host} - {task.title.slice(0, 40)}
                      </div>
                    );
                  })}
                  {generatedTasks.length > 10 && (
                    <div className={`text-xs italic ${theme === 'dark' ? 'dark-text-soft' : 'text-slate'}`}>
                      {generatedTasks.length - 10} weitere Tasks...
                    </div>
                  )}
                </div>
                <button
                  type="button"
                  onClick={() => onSwitchTab('tasks')}
                  className={`w-full rounded-xl px-4 py-2.5 text-sm font-semibold transition hover:-translate-y-0.5 animate-pulse hover:animate-none ${theme === 'dark' ? 'bg-amber-600 text-amber-100' : 'bg-amber-400 text-amber-900'}`}
                >
                  → Alle Tasks anzeigen ({generatedTasks.length} gesamt)
                </button>
              </div>
            )}
            {busy && (
                <div className={`message-enter self-start mr-auto ml-0 w-fit max-w-[85%] rounded-2xl border px-4 py-3 text-sm shadow-sm backdrop-blur text-left ${theme === 'dark' ? 'dark-message-assistant' : 'border-ink/10 bg-white text-ink'}`}>
                <p className={`mb-2 text-[0.65rem] uppercase tracking-[0.2em] ${theme === 'dark' ? 'dark-kicker' : 'text-slate'}`}>assistant</p>
                <div className="typing-indicator">
                  <span />
                  <span />
                  <span />
                  <span className={`ml-2 text-sm ${theme === 'dark' ? 'dark-text-main' : 'text-slate'}`}>KI analysiert...</span>
                </div>
              </div>
            )}
            <div ref={bottomRef} />
          </div>
        </div>

        <div className={`page-shell-x border-t py-3 backdrop-blur ${theme === 'dark' ? 'dark-panel-strong dark-divider' : 'border-ink/10 bg-white/80'}`}>
          <div className="page-content-max mx-auto flex w-full flex-col gap-3">
            <div className="flex flex-wrap items-center gap-2">
              {lookbackPresets.map((hours) => (
                <button
                  key={hours}
                  type="button"
                  onClick={() => onSelectLookback(hours)}
                  className={`rounded-2xl px-4 py-2 text-sm font-medium transition ${selectedLookbackHours === hours ? 'bg-ember text-white' : theme === 'dark' ? 'dark-outline-button' : 'border border-ink/15 bg-white text-ink hover:bg-shell'}`}
                  disabled={busy}
                >
                  {hours === 24 ? 'Last 24h' : hours === 168 ? 'Last 7 days' : 'Last 30 days'}
                </button>
              ))}
            </div>

            <div className={`rounded-2xl border p-3 shadow-sm backdrop-blur ${theme === 'dark' ? 'dark-panel-strong' : 'border-ink/10 bg-white'}`}>
              <textarea
                value={input}
                onChange={(event) => setInput(event.target.value)}
                placeholder="Schreibe direkt an die KI..."
                className={`min-h-28 w-full resize-none rounded-xl border px-4 py-3 text-sm outline-none transition ${theme === 'dark' ? 'dark-input focus:border-amber-400' : 'border-ink/10 text-ink focus:border-ember'}`}
                disabled={busy}
              />
              <div className="mt-3 flex flex-wrap items-center gap-3">
                <button
                  type="button"
                  onClick={() => submit(true)}
                  disabled={busy}
                  className={`rounded-2xl px-4 py-3 text-sm font-medium transition hover:-translate-y-0.5 disabled:opacity-50 ${theme === 'dark' ? 'dark-outline-button' : 'bg-ink text-shell'}`}
                >
                  {busy ? 'Laeuft...' : `Skript starten (${selectedLookbackHours}h)`}
                </button>
                <button
                  type="button"
                  onClick={() => submit(false)}
                  disabled={busy}
                  className="rounded-2xl bg-ember px-4 py-3 text-sm font-medium text-white transition hover:-translate-y-0.5 disabled:opacity-50"
                >
                  {busy ? 'Warten...' : 'Senden'}
                </button>
                <span className={`text-sm ${theme === 'dark' ? 'dark-text-soft' : 'text-slate'}`}>{reportContext?.trim() ? 'Report-Kontext geladen' : 'Kein Report-Kontext geladen'}</span>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}