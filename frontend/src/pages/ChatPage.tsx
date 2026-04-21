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
    event_id?: string | null;
    rule_id?: string | null;
    rule_description?: string | null;
    platform?: string | null;
    count?: number;
    reason?: string | null;
    local_score?: number | null;
    mitre_ids?: string[];
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

  const dark = theme === 'dark';

  const D = {
    bg:       'var(--soc-background)',
    surface:  'var(--soc-panel)',
    surface2: 'var(--soc-card)',
    border:   'var(--soc-border)',
    text:     'var(--soc-foreground)',
    muted:    'var(--soc-muted-fg)',
  };
  const accent = 'var(--soc-warning)';
  const accentCyan = 'var(--soc-success)';

  let formattedReportJson = lastReportJson ?? '(keine Daten)';
  if (lastReportJson) {
    try {
      formattedReportJson = JSON.stringify(JSON.parse(lastReportJson), null, 2);
    } catch {
      formattedReportJson = lastReportJson;
    }
  }

  useEffect(() => {
    if (!shouldAutoScrollRef.current) return;
    bottomRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [messages, generatedTasks, busy]);

  function handleScroll() {
    const node = scrollerRef.current;
    if (!node) return;
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

  const hasContext = Boolean(reportContext?.trim());

  if (!active) return null;

  return (
    <div className="flex h-full flex-col" style={{ background: D.bg, color: D.text }}>

      {/* ── Messages area ── */}
      <div ref={scrollerRef} onScroll={handleScroll}
        className="flex-1 overflow-y-auto px-5 py-5 min-h-0">
        <div className="flex w-full flex-col gap-3">

          {/* Empty state */}
          {messages.length === 0 && !busy && (
            <div className="flex flex-col items-center justify-center py-16 text-center">
              <div className="mb-4 flex h-16 w-16 items-center justify-center rounded-2xl"
                style={{ background: `${accent}15`, border: `1px solid ${accent}33` }}>
                <span className="text-3xl">🤖</span>
              </div>
              <p className="text-sm font-semibold mb-1" style={{ color: D.text }}>
                {hasContext ? 'Report-Kontext geladen' : 'KI Chat bereit'}
              </p>
              <p className="text-xs max-w-sm" style={{ color: D.muted }}>
                {hasContext
                  ? 'Stelle Fragen zu den Findings oder lass Tasks generieren.'
                  : 'Kein Report-Kontext. Stelle SOC/Wazuh-Fragen oder starte das Skript für eine Analyse.'}
              </p>
            </div>
          )}

          {/* Messages */}
          {messages.map((message, index) => {
            const isUser = message.role === 'user';
            return (
              <div key={`${message.role}-${index}`}
                className={`flex ${isUser ? 'justify-end' : 'justify-start'}`}>
                <div className="max-w-[82%]">
                  <div className="mb-1 flex items-center gap-2"
                    style={{ justifyContent: isUser ? 'flex-end' : 'flex-start' }}>
                    {!isUser && (
                      <div className="flex h-5 w-5 flex-shrink-0 items-center justify-center rounded-full text-[0.6rem]"
                        style={{ background: `${accent}20`, border: `1px solid ${accent}40` }}>
                        🤖
                      </div>
                    )}
                    <span className="text-[0.6rem] font-bold uppercase tracking-widest"
                      style={{ color: D.muted }}>
                      {isUser ? 'Du' : 'KI'}
                    </span>
                  </div>
                  <div className="rounded-xl px-4 py-3 text-sm leading-6"
                    style={isUser
                      ? { background: `${accent}18`, border: `1px solid ${accent}35`, color: D.text }
                      : { background: D.surface, border: `1px solid ${D.border}`, color: D.text }}>
                    {isUser
                      ? <p className="whitespace-pre-wrap">{message.content}</p>
                      : <div className="chat-markdown">
                          <ReactMarkdown remarkPlugins={[remarkGfm]}>{message.content}</ReactMarkdown>
                        </div>
                    }
                  </div>
                </div>
              </div>
            );
          })}

          {/* Generated tasks card */}
          {generatedTasks.length > 0 && (
            <div className="flex justify-start">
              <div className="max-w-[82%] w-full rounded-xl p-4"
                style={{ background: D.surface, border: `1px solid ${accent}40` }}>
                <p className="mb-3 text-[0.65rem] font-bold uppercase tracking-widest"
                  style={{ color: accent }}>⚡ Automatische Tasks erstellt</p>
                <div className="space-y-1.5 mb-4">
                  {generatedTasks.slice(0, 10).map((task) => {
                    const sevColor: Record<string, string> = {
                      critical: 'var(--soc-critical)', high: 'var(--soc-warning)', medium: 'var(--soc-primary)', low: accentCyan,
                    };
                    const c = sevColor[task.severity.toLowerCase()] ?? accentCyan;
                    return (
                      <div key={task.task_id}
                        className="flex items-center gap-2 rounded-lg px-3 py-1.5 text-xs"
                        style={{ background: `${c}12`, border: `1px solid ${c}25` }}>
                        <span className="font-bold flex-shrink-0" style={{ color: c }}>
                          [{task.severity.toUpperCase()}]
                        </span>
                        <span className="truncate" style={{ color: D.text }}>
                          {task.host} – {task.title.slice(0, 50)}
                        </span>
                      </div>
                    );
                  })}
                  {generatedTasks.length > 10 && (
                    <p className="text-[0.65rem] italic pl-1" style={{ color: D.muted }}>
                      +{generatedTasks.length - 10} weitere Tasks…
                    </p>
                  )}
                </div>
                <button type="button" onClick={() => onSwitchTab('tasks')}
                  className="w-full rounded-lg py-2 text-sm font-bold transition hover:opacity-90"
                  style={{ background: accent, color: 'var(--soc-background)' }}>
                  → Alle Tasks anzeigen ({generatedTasks.length} gesamt)
                </button>
              </div>
            </div>
          )}

          {/* Busy / typing indicator */}
          {busy && (
            <div className="flex justify-start">
              <div className="rounded-xl px-4 py-3"
                style={{ background: D.surface, border: `1px solid ${D.border}` }}>
                <div className="mb-1 flex items-center gap-2">
                  <div className="flex h-5 w-5 items-center justify-center rounded-full text-[0.6rem]"
                    style={{ background: `${accent}20`, border: `1px solid ${accent}40` }}>🤖</div>
                  <span className="text-[0.6rem] font-bold uppercase tracking-widest" style={{ color: D.muted }}>KI</span>
                </div>
                <div className="typing-indicator">
                  <span /><span /><span />
                  <span className="ml-2 text-sm" style={{ color: D.muted }}>KI analysiert…</span>
                </div>
              </div>
            </div>
          )}

          <div ref={bottomRef} />
        </div>
      </div>

      {/* ── Input bar ── */}
      <div style={{ background: D.surface, borderTop: `1px solid ${D.border}` }}
        className="flex-shrink-0 px-5 py-4">
        <div className="w-full flex flex-col gap-3">
          {/* Textarea */}
          <div className="relative rounded-xl overflow-hidden"
            style={{ background: D.surface2, border: `1px solid ${D.border}` }}>
            <textarea
              value={input}
              onChange={(e) => setInput(e.target.value)}
              onKeyDown={(e) => {
                if (e.key === 'Enter' && !e.shiftKey) { e.preventDefault(); submit(false); }
              }}
              placeholder="Schreibe direkt an die KI… (Enter zum Senden, Shift+Enter für neue Zeile)"
              rows={3}
              disabled={busy}
              className="w-full resize-none px-4 py-3 text-sm bg-transparent outline-none"
              style={{ color: D.text }}
            />
          </div>
          {/* Actions row */}
          <div className="flex items-center gap-2 flex-wrap">
            <button type="button" onClick={() => submit(true)} disabled={busy}
              className="rounded-lg px-4 py-2 text-sm font-semibold transition hover:opacity-90 disabled:opacity-40"
              style={{ background: D.surface2, color: D.text, border: `1px solid ${D.border}` }}>
              {busy ? 'Läuft…' : `▶ Skript starten (${selectedLookbackHours}h)`}
            </button>
            <button type="button" onClick={() => submit(false)} disabled={busy}
              className="rounded-lg px-5 py-2 text-sm font-bold transition hover:opacity-90 disabled:opacity-40"
              style={{ background: accent, color: 'var(--soc-background)' }}>
              {busy ? 'Warten…' : 'Senden ↑'}
            </button>
            {/* Lookback presets */}
            <div className="flex items-center gap-1">
              {lookbackPresets.map((hours) => {
                const selected = selectedLookbackHours === hours;
                return (
                  <button key={hours} type="button" onClick={() => onSelectLookback(hours)} disabled={busy}
                    className="rounded px-2.5 py-1.5 text-[0.65rem] font-semibold transition"
                    style={{
                      background: selected ? accent : 'transparent',
                      color:      selected ? 'var(--soc-background)' : D.muted,
                      border:     `1px solid ${selected ? accent : D.border}`,
                    }}>
                    {hours === 24 ? '24h' : hours === 168 ? '7d' : '30d'}
                  </button>
                );
              })}
            </div>
            {hasReportFiles && (
              <button type="button"
                onClick={() => { setDrawerOpen(true); setDrawerTab('txt'); }}
                className="rounded px-2.5 py-1.5 text-[0.65rem] font-semibold transition hover:opacity-80"
                style={{ background: `${accent}1a`, color: accent, border: `1px solid ${accent}33` }}>
                Report ↗
              </button>
            )}
            <span className="ml-auto text-xs" style={{ color: D.muted }}>
              {hasContext ? '✓ Kontext' : '○ Kein Kontext'}
            </span>
          </div>
        </div>
      </div>

      {/* ── File drawer ── */}
      {drawerOpen && (
        <div className="fixed inset-0 z-50 flex justify-end">
          <div className="flex-1 bg-black/40" onClick={() => setDrawerOpen(false)} />
          <div className="flex w-[440px] flex-col shadow-2xl"
            style={{ background: D.surface, borderLeft: `1px solid ${D.border}` }}>
            {/* drawer header */}
            <div className="flex items-center justify-between px-4 py-3"
              style={{ borderBottom: `1px solid ${D.border}` }}>
              <div className="flex gap-1">
                {(['txt', 'json'] as const).map((t) => (
                  <button key={t} type="button" onClick={() => setDrawerTab(t)}
                    className="rounded px-3 py-1.5 text-xs font-semibold transition"
                    style={{
                      background: drawerTab === t ? accent : 'transparent',
                      color:      drawerTab === t ? 'var(--soc-background)' : D.muted,
                      border:     `1px solid ${drawerTab === t ? accent : D.border}`,
                    }}>
                    .{t}
                  </button>
                ))}
              </div>
              <button type="button" onClick={() => setDrawerOpen(false)}
                className="text-xs transition hover:opacity-70" style={{ color: D.muted }}>
                ✕ Schließen
              </button>
            </div>
            {/* filename label */}
            <div className="px-4 py-2 text-[0.62rem] font-mono"
              style={{ color: D.muted, borderBottom: `1px solid ${D.border}`, background: D.surface2 }}>
              {drawerTab === 'txt' ? 'ai_wazuh_24h_report.txt' : 'ai_wazuh_24h_report.json'}
            </div>
            {/* content */}
            <div className="flex-1 overflow-auto p-4">
              <pre className="whitespace-pre-wrap break-words rounded-lg p-3 font-mono text-[0.72rem] leading-5"
                style={{ background: D.surface2, border: `1px solid ${D.border}`, color: D.text }}>
                {drawerTab === 'txt' ? (lastReportTxt ?? '(keine Daten)') : formattedReportJson}
              </pre>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
