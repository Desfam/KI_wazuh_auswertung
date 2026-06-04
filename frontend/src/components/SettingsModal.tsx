import { useEffect, useRef, useState } from 'react';
import type { AnalysisProfileConfig, RemoteAccessMode, RemoteAccessModeConfig } from '../types';

type SettingsModalProps = {
  isOpen: boolean;
  onClose: () => void;
  theme: 'light' | 'dark';
  currentVideoSource: string | null;
  onVideoSelect: (file: File) => void;
  onClearVideo: () => void;
  analysisProfile: AnalysisProfileConfig;
  onSaveAnalysisProfile: (profile: AnalysisProfileConfig) => void;
  remoteAccessMode: RemoteAccessModeConfig;
  onSaveRemoteAccessMode: (mode: RemoteAccessMode, changedBy: string, reason: string) => Promise<void>;
};

export function SettingsModal({
  isOpen,
  onClose,
  theme,
  currentVideoSource,
  onVideoSelect,
  onClearVideo,
  analysisProfile,
  onSaveAnalysisProfile,
  remoteAccessMode,
  onSaveRemoteAccessMode,
}: SettingsModalProps) {
  const fileInputRef = useRef<HTMLInputElement>(null);
  const [modeDraft, setModeDraft] = useState<RemoteAccessMode>('admin');
  const [changedByDraft, setChangedByDraft] = useState('');
  const [reasonDraft, setReasonDraft] = useState('');
  const [modeSaving, setModeSaving] = useState(false);
  const [modeFeedback, setModeFeedback] = useState('');

  useEffect(() => {
    if (!isOpen) return;
    setModeDraft(remoteAccessMode.mode);
    setChangedByDraft(remoteAccessMode.changed_by || '');
    setReasonDraft(remoteAccessMode.reason || '');
    setModeFeedback('');
  }, [isOpen, remoteAccessMode]);

  function handleFileSelect(e: React.ChangeEvent<HTMLInputElement>) {
    const file = e.target.files?.[0];
    if (file && file.type.startsWith('video/')) {
      onVideoSelect(file);
    } else {
      alert('Bitte wähle eine Videodatei aus (MP4, WebM, etc.)');
    }
  }

  function handleClearVideo() {
    if (fileInputRef.current) {
      fileInputRef.current.value = '';
    }
    onClearVideo();
  }

  function updateProfile(patch: Partial<AnalysisProfileConfig>) {
    onSaveAnalysisProfile({ ...analysisProfile, ...patch });
  }

  async function handleSaveMode() {
    if (!changedByDraft.trim()) {
      alert('Bitte "Changed by" angeben.');
      return;
    }
    setModeSaving(true);
    setModeFeedback('');
    try {
      await onSaveRemoteAccessMode(modeDraft, changedByDraft.trim(), reasonDraft.trim());
      setModeFeedback('Remote Access Mode gespeichert.');
    } catch (error) {
      const message = error instanceof Error ? error.message : 'Speichern fehlgeschlagen';
      setModeFeedback(`Fehler: ${message}`);
    } finally {
      setModeSaving(false);
    }
  }

  if (!isOpen) return null;

  return (
    <div className={`fixed inset-0 z-50 flex items-center justify-center ${theme === 'dark' ? 'dark-modal-scrim' : 'bg-black/60'}`} onClick={onClose}>
      <div
        className={`rounded-2xl border shadow-2xl backdrop-blur ${theme === 'dark' ? 'dark-panel-strong' : 'border-ink/10 bg-white/95'}`}
        style={{ width: '90%', maxWidth: '500px' }}
        onClick={(e) => e.stopPropagation()}
      >
        {/* Header */}
        <div className={`flex items-center justify-between border-b px-6 py-4 ${theme === 'dark' ? 'dark-divider' : 'border-ink/10'}`}>
          <h2 className={`font-['Space_Grotesk'] text-xl font-semibold ${theme === 'dark' ? 'dark-text-main' : 'text-ink'}`}>
            Einstellungen
          </h2>
          <button
            type="button"
            onClick={onClose}
            className={`text-2xl transition hover:scale-110 ${theme === 'dark' ? 'dark-text-muted hover:text-white' : 'text-slate hover:text-ink'}`}
          >
            ✕
          </button>
        </div>

        {/* Content */}
        <div className="space-y-6 px-6 py-6">
          {/* Video Background Section */}
          <div>
            <h3 className={`mb-3 text-sm font-semibold uppercase tracking-widest ${theme === 'dark' ? 'dark-kicker' : 'text-slate'}`}>
              Video-Hintergrund
            </h3>
            <p className={`mb-4 text-sm ${theme === 'dark' ? 'dark-text-soft' : 'text-slate'}`}>
              Wähle eine MP4-Datei als Hintergrund für den Dark-Mode. Das Video wird in einer Schleife abgespielt.
            </p>

            {/* Video Preview */}
            {currentVideoSource && (
              <div className={`mb-4 rounded-xl border overflow-hidden ${theme === 'dark' ? 'dark-video-preview' : 'border-ink/10'}`}>
                <video
                  src={currentVideoSource}
                  autoPlay
                  loop
                  muted
                  className="w-full h-40 object-cover"
                />
              </div>
            )}

            {/* File Input */}
            <input
              ref={fileInputRef}
              type="file"
              accept="video/mp4,video/webm,video/mpeg"
              onChange={handleFileSelect}
              className="hidden"
            />

            {/* Buttons */}
            <div className="flex gap-3">
              <button
                type="button"
                onClick={() => fileInputRef.current?.click()}
                className={`flex-1 rounded-xl px-4 py-2 text-sm font-medium transition hover:-translate-y-0.5 ${theme === 'dark' ? 'dark-outline-button' : 'border border-ink/15 bg-shell text-ink hover:bg-ink hover:text-shell'}`}
              >
                📁 Video auswählen
              </button>
              {currentVideoSource && (
                <button
                  type="button"
                  onClick={handleClearVideo}
                  className={`rounded-xl px-4 py-2 text-sm font-medium transition hover:-translate-y-0.5 ${theme === 'dark' ? 'border border-rose-400/30 bg-rose-950/60 text-rose-100 hover:bg-rose-900/70' : 'border border-rose-300 bg-rose-50 text-rose-700 hover:bg-rose-100'}`}
                >
                  🗑️ Löschen
                </button>
              )}
            </div>
          </div>

          <div>
            <h3 className={`mb-3 text-sm font-semibold uppercase tracking-widest ${theme === 'dark' ? 'dark-kicker' : 'text-slate'}`}>
              Analyse-Profil (Phase 1)
            </h3>
            <div className="grid gap-3 sm:grid-cols-2">
              <label className={`text-xs ${theme === 'dark' ? 'dark-text-soft' : 'text-slate'}`}>
                Min Rule Level
                <input
                  type="number"
                  min={0}
                  max={20}
                  value={analysisProfile.min_rule_level}
                  onChange={(e) => updateProfile({ min_rule_level: Number(e.target.value) || 0 })}
                  className={`mt-1 w-full rounded-lg border px-3 py-2 text-sm ${theme === 'dark' ? 'dark-input' : 'border-ink/15 bg-white text-ink'}`}
                />
              </label>
              <label className={`text-xs ${theme === 'dark' ? 'dark-text-soft' : 'text-slate'}`}>
                Max Findings
                <input
                  type="number"
                  min={10}
                  max={1000}
                  value={analysisProfile.max_findings}
                  onChange={(e) => updateProfile({ max_findings: Number(e.target.value) || 200 })}
                  className={`mt-1 w-full rounded-lg border px-3 py-2 text-sm ${theme === 'dark' ? 'dark-input' : 'border-ink/15 bg-white text-ink'}`}
                />
              </label>
              <label className={`text-xs sm:col-span-2 ${theme === 'dark' ? 'dark-text-soft' : 'text-slate'}`}>
                Max Events pro Host (0 = unlimitiert)
                <input
                  type="number"
                  min={0}
                  max={20000}
                  value={analysisProfile.max_events_per_host}
                  onChange={(e) => updateProfile({ max_events_per_host: Number(e.target.value) || 0 })}
                  className={`mt-1 w-full rounded-lg border px-3 py-2 text-sm ${theme === 'dark' ? 'dark-input' : 'border-ink/15 bg-white text-ink'}`}
                />
              </label>
              <label className={`text-xs sm:col-span-2 ${theme === 'dark' ? 'dark-text-soft' : 'text-slate'}`}>
                Windows Event IDs (CSV, leer = Script-Default)
                <input
                  type="text"
                  value={analysisProfile.event_ids.join(',')}
                  onChange={(e) => updateProfile({ event_ids: e.target.value.split(',').map((v) => v.trim()).filter(Boolean) })}
                  className={`mt-1 w-full rounded-lg border px-3 py-2 text-sm ${theme === 'dark' ? 'dark-input' : 'border-ink/15 bg-white text-ink'}`}
                  placeholder="4625,4688,7045"
                />
              </label>
            </div>
            <div className="mt-3 grid gap-2 sm:grid-cols-2">
              <label className={`inline-flex items-center gap-2 text-xs ${theme === 'dark' ? 'dark-text-soft' : 'text-slate'}`}>
                <input type="checkbox" checked={analysisProfile.include_agent_info} onChange={(e) => updateProfile({ include_agent_info: e.target.checked })} />
                Include agent info
              </label>
              <label className={`inline-flex items-center gap-2 text-xs ${theme === 'dark' ? 'dark-text-soft' : 'text-slate'}`}>
                <input type="checkbox" checked={analysisProfile.include_commandline} onChange={(e) => updateProfile({ include_commandline: e.target.checked })} />
                Include commandLine
              </label>
              <label className={`inline-flex items-center gap-2 text-xs ${theme === 'dark' ? 'dark-text-soft' : 'text-slate'}`}>
                <input type="checkbox" checked={analysisProfile.include_full_log} onChange={(e) => updateProfile({ include_full_log: e.target.checked })} />
                Include full_log
              </label>
              <label className={`inline-flex items-center gap-2 text-xs ${theme === 'dark' ? 'dark-text-soft' : 'text-slate'}`}>
                <input type="checkbox" checked={analysisProfile.include_mitre_mapping} onChange={(e) => updateProfile({ include_mitre_mapping: e.target.checked })} />
                Include MITRE mapping
              </label>
            </div>
          </div>

          <div>
            <h3 className={`mb-3 text-sm font-semibold uppercase tracking-widest ${theme === 'dark' ? 'dark-kicker' : 'text-slate'}`}>
              Server Operations / Remote Access Mode
            </h3>
            <div className="grid gap-3 sm:grid-cols-2">
              <label className={`text-xs ${theme === 'dark' ? 'dark-text-soft' : 'text-slate'}`}>
                Remote Access Mode
                <select
                  value={modeDraft}
                  onChange={(e) => setModeDraft(e.target.value as RemoteAccessMode)}
                  className={`mt-1 w-full rounded-lg border px-3 py-2 text-sm ${theme === 'dark' ? 'dark-input' : 'border-ink/15 bg-white text-ink'}`}
                >
                  <option value="safe">SAFE</option>
                  <option value="admin">ADMIN</option>
                  <option value="break_glass">BREAK_GLASS</option>
                </select>
              </label>
              <label className={`text-xs ${theme === 'dark' ? 'dark-text-soft' : 'text-slate'}`}>
                Changed by
                <input
                  type="text"
                  value={changedByDraft}
                  onChange={(e) => setChangedByDraft(e.target.value)}
                  className={`mt-1 w-full rounded-lg border px-3 py-2 text-sm ${theme === 'dark' ? 'dark-input' : 'border-ink/15 bg-white text-ink'}`}
                  placeholder="Colin"
                />
              </label>
              <label className={`text-xs sm:col-span-2 ${theme === 'dark' ? 'dark-text-soft' : 'text-slate'}`}>
                Reason (optional)
                <textarea
                  rows={2}
                  value={reasonDraft}
                  onChange={(e) => setReasonDraft(e.target.value)}
                  className={`mt-1 w-full rounded-lg border px-3 py-2 text-sm ${theme === 'dark' ? 'dark-input' : 'border-ink/15 bg-white text-ink'}`}
                  placeholder="incident response maintenance window"
                />
              </label>
            </div>
            <div className="mt-3 flex flex-wrap items-center gap-3">
              <button
                type="button"
                onClick={() => void handleSaveMode()}
                disabled={modeSaving}
                className={`rounded-xl px-4 py-2 text-sm font-medium transition hover:-translate-y-0.5 ${theme === 'dark' ? 'dark-outline-button' : 'border border-ink/15 bg-shell text-ink hover:bg-ink hover:text-shell'}`}
              >
                {modeSaving ? 'Speichern…' : 'Mode speichern'}
              </button>
              <span className={`text-xs ${theme === 'dark' ? 'dark-text-soft' : 'text-slate'}`}>
                Current: {remoteAccessMode.mode.toUpperCase()} · Changed by: {remoteAccessMode.changed_by || 'system'} · Changed at: {remoteAccessMode.changed_at || '—'}
              </span>
            </div>
            {modeFeedback && (
              <div className={`mt-2 text-xs ${modeFeedback.startsWith('Fehler') ? 'text-red-400' : theme === 'dark' ? 'dark-text-soft' : 'text-slate'}`}>
                {modeFeedback}
              </div>
            )}
          </div>

          {/* Info */}
          <div className={`rounded-xl border border-dashed p-3 text-xs ${theme === 'dark' ? 'dark-panel-faint dark-text-soft' : 'border-ink/15 bg-white text-slate'}`}>
            <p><strong>Hinweis:</strong> Das Video wird sofort als Hintergrund gesetzt. Wegen Dateigroesse speichere ich es nicht dauerhaft im Browser, damit die Auswahl in Tauri stabil funktioniert.</p>
          </div>
        </div>

        {/* Footer */}
        <div className={`flex justify-end gap-3 border-t px-6 py-4 ${theme === 'dark' ? 'dark-divider' : 'border-ink/10'}`}>
          <button
            type="button"
            onClick={onClose}
            className={`rounded-xl px-6 py-2 text-sm font-medium transition hover:-translate-y-0.5 ${theme === 'dark' ? 'dark-outline-button' : 'border border-ink/15 bg-white text-ink hover:bg-shell'}`}
          >
            Schließen
          </button>
        </div>
      </div>
    </div>
  );
}
