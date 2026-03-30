import { useEffect, useState } from 'react';

type TasksPageProps = {
  active: boolean;
  theme: 'light' | 'dark';
  onThemeToggle: () => void;
  generatedTasks: Array<{
    task_id: string;
    host: string;
    severity: string;
    title: string;
    details: string;
    recommended_checks: string[];
  }>;
  onSwitchTab: (tab: 'chat' | 'tasks') => void;
};

export function TasksPage({ active, theme, onThemeToggle, generatedTasks, onSwitchTab }: TasksPageProps) {
  const [doneTaskIds, setDoneTaskIds] = useState<string[]>([]);
  const [visibleTasks, setVisibleTasks] = useState<number>(0);

  // Animate in tasks one by one
  useEffect(() => {
    if (!active || generatedTasks.length === 0) {
      setVisibleTasks(0);
      return;
    }

    let index = 0;
    const interval = setInterval(() => {
      index++;
      if (index > generatedTasks.length) {
        clearInterval(interval);
        return;
      }
      setVisibleTasks(index);
    }, 120);

    return () => clearInterval(interval);
  }, [active, generatedTasks.length]);

  function toggleTask(taskId: string) {
    setDoneTaskIds((current) =>
      current.includes(taskId)
        ? current.filter((item) => item !== taskId)
        : [...current, taskId]
    );
  }

  const completedCount = doneTaskIds.length;
  const severityOrder: Record<string, number> = {
    critical: 4,
    high: 3,
    medium: 2,
    low: 1,
  };

  const sortedTasks = [...generatedTasks].sort((a, b) => {
    const aOrder = severityOrder[a.severity.toLowerCase()] || 0;
    const bOrder = severityOrder[b.severity.toLowerCase()] || 0;
    return bOrder - aOrder;
  });

  const getSeverityColor = (severity: string) => {
    const darkColors = {
      critical: 'text-white border-red-400/35 bg-[linear-gradient(180deg,rgba(72,20,28,0.95),rgba(38,12,18,0.95))] shadow-[0_18px_48px_rgba(2,6,18,0.34)]',
      high: 'text-white border-orange-400/30 bg-[linear-gradient(180deg,rgba(70,34,16,0.95),rgba(37,18,9,0.95))] shadow-[0_18px_48px_rgba(2,6,18,0.34)]',
      medium: 'text-white border-amber-300/28 bg-[linear-gradient(180deg,rgba(69,54,17,0.95),rgba(37,28,9,0.95))] shadow-[0_18px_48px_rgba(2,6,18,0.34)]',
      low: 'text-white border-emerald-300/28 bg-[linear-gradient(180deg,rgba(17,58,46,0.95),rgba(10,31,24,0.95))] shadow-[0_18px_48px_rgba(2,6,18,0.34)]',
    };
    const lightColors = {
      critical: 'border-red-300 bg-red-50',
      high: 'border-orange-300 bg-orange-50',
      medium: 'border-yellow-300 bg-yellow-50',
      low: 'border-green-300 bg-green-50',
    };
    const colors = theme === 'dark' ? darkColors : lightColors;
    return colors[severity.toLowerCase() as keyof typeof colors] || (theme === 'dark' ? 'border-slate-700 bg-slate-800/50' : 'border-ink/10 bg-white');
  };

  const getSeverityBadgeColor = (severity: string) => {
    const darkColors = {
      critical: 'bg-red-400/18 text-red-100 border border-red-300/25',
      high: 'bg-orange-400/18 text-orange-100 border border-orange-300/25',
      medium: 'bg-amber-300/18 text-amber-50 border border-amber-200/25',
      low: 'bg-emerald-300/18 text-emerald-50 border border-emerald-200/25',
    };
    const lightColors = {
      critical: 'bg-red-200 text-red-700',
      high: 'bg-orange-200 text-orange-700',
      medium: 'bg-yellow-200 text-yellow-700',
      low: 'bg-green-200 text-green-700',
    };
    const colors = theme === 'dark' ? darkColors : lightColors;
    return colors[severity.toLowerCase() as keyof typeof colors] || (theme === 'dark' ? 'text-white bg-slate-700 border border-slate-400/25' : 'bg-slate-200 text-slate-700');
  };

  return (
    <div className={`flex h-full flex-col ${theme === 'dark' ? 'bg-transparent text-slate-50' : 'bg-shell bg-grid bg-[size:26px_26px] text-ink'} ${!active ? 'hidden' : ''}`}>

      <section className={`grid gap-3 border-b px-6 py-4 md:grid-cols-3 ${theme === 'dark' ? 'dark-panel dark-divider' : 'border-ink/10 bg-white/70'}`}>
        <article className={`rounded-2xl border px-4 py-3 ${theme === 'dark' ? 'dark-panel-soft' : 'border-ink/10 bg-white'}`}>
          <p className={`text-xs uppercase tracking-[0.2em] ${theme === 'dark' ? 'dark-kicker' : 'text-slate'}`}>Gesamt</p>
          <p className={`mt-2 text-2xl font-bold ${theme === 'dark' ? 'text-slate-50' : 'text-ink'}`}>{generatedTasks.length}</p>
        </article>
        <article className={`rounded-2xl border px-4 py-3 ${theme === 'dark' ? 'border-emerald-600/70 bg-emerald-950/72' : 'border-emerald-300 bg-emerald-50'}`}>
          <p className={`text-xs uppercase tracking-[0.2em] ${theme === 'dark' ? 'text-emerald-300' : 'text-emerald-700'}`}>Erledigt</p>
          <p className={`mt-2 text-2xl font-bold ${theme === 'dark' ? 'text-emerald-300' : 'text-emerald-700'}`}>{completedCount}</p>
        </article>
        <article className={`rounded-2xl border px-4 py-3 ${theme === 'dark' ? 'border-amber-600/70 bg-amber-950/72' : 'border-amber-300 bg-amber-50'}`}>
          <p className={`text-xs uppercase tracking-[0.2em] ${theme === 'dark' ? 'text-amber-300' : 'text-amber-700'}`}>Offen</p>
          <p className={`mt-2 text-2xl font-bold ${theme === 'dark' ? 'text-amber-300' : 'text-amber-700'}`}>{Math.max(0, generatedTasks.length - completedCount)}</p>
        </article>
      </section>

      <div className="flex-1 overflow-auto px-6 py-6">
        <div className="mx-auto w-full max-w-5xl space-y-3">
          {sortedTasks.length === 0 ? (
            <div className={`rounded-2xl border border-dashed p-8 text-center text-sm ${theme === 'dark' ? 'dark-panel dark-text-soft' : 'border-ink/15 bg-white text-slate'}`}>
              Keine Tasks vorhanden. Starten Sie das Skript, um Tasks zu generieren.
            </div>
          ) : (
            sortedTasks.map((task, index) => {
              const isVisible = index < visibleTasks;
              const done = doneTaskIds.includes(task.task_id);

              return (
                <div
                  key={task.task_id}
                  className={`task-item-enter border-2 rounded-2xl p-4 transition ${getSeverityColor(task.severity)} ${done ? 'opacity-50' : ''} ${isVisible ? 'opacity-100' : 'opacity-0'}`}
                  style={{
                    transitionDelay: `${index * 50}ms`,
                  }}
                >
                  <div className="flex items-start gap-4">
                    <input
                      type="checkbox"
                      checked={done}
                      onChange={() => toggleTask(task.task_id)}
                      className="mt-1 h-5 w-5 cursor-pointer flex-shrink-0"
                    />
                    <div className="min-w-0 flex-1">
                      <div className="mb-2 flex flex-wrap items-center gap-2">
                        <span className={`text-xs font-bold uppercase px-2.5 py-1 rounded-full ${getSeverityBadgeColor(task.severity)}`}>
                          {task.severity}
                        </span>
                        <span className={`text-xs font-medium ${theme === 'dark' ? 'text-slate-200' : 'text-slate'}`}>{task.host}</span>
                        <span className={`text-[0.65rem] ${theme === 'dark' ? 'text-slate-300' : 'text-slate/60'}`}>{task.task_id}</span>
                      </div>
                      <h3 className={`text-sm font-semibold ${done ? (theme === 'dark' ? 'line-through text-slate-500' : 'line-through text-slate') : (theme === 'dark' ? 'text-slate-50' : 'text-ink')}`}>
                        {task.title}
                      </h3>
                      <p className={`mt-2 text-xs ${theme === 'dark' ? 'text-white' : 'text-slate'}`}>{task.details}</p>

                      {task.recommended_checks && task.recommended_checks.length > 0 && (
                        <div className="mt-3 space-y-1.5">
                          <p className={`text-xs font-medium uppercase tracking-widest ${theme === 'dark' ? 'text-slate-200' : 'text-slate'}`}>Empfohlene Checks:</p>
                          <ul className="space-y-1">
                            {task.recommended_checks.map((check, idx) => (
                              <li key={idx} className={`flex items-start gap-2 text-xs ${theme === 'dark' ? 'text-slate-100' : 'text-slate/80'}`}>
                                <span className={`mt-1 h-1.5 w-1.5 flex-shrink-0 rounded-full ${theme === 'dark' ? 'bg-slate-500' : 'bg-ink/40'}`} />
                                <span>{check}</span>
                              </li>
                            ))}
                          </ul>
                        </div>
                      )}
                    </div>
                  </div>
                </div>
              );
            })
          )}
        </div>
      </div>
    </div>
  );
}
