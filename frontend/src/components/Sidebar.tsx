import { Activity, Bot, FileText, LayoutDashboard, MessageSquare, ServerCog, ShieldAlert, Users } from 'lucide-react';

type SidebarProps = {
  current: string;
  onSelect: (page: string) => void;
};

const items = [
  { id: 'dashboard', label: 'Dashboard', icon: LayoutDashboard },
  { id: 'findings', label: 'Findings', icon: ShieldAlert },
  { id: 'hosts', label: 'Hosts', icon: Users },
  { id: 'reports', label: 'Reports', icon: FileText },
  { id: 'chat', label: 'Chat', icon: MessageSquare },
  { id: 'ai-log', label: 'AI Log', icon: Bot },
  { id: 'settings', label: 'Settings', icon: ServerCog },
  { id: 'jobs', label: 'Jobs', icon: Activity }
];

export function Sidebar({ current, onSelect }: SidebarProps) {
  return (
    <aside className="relative flex min-h-screen w-full max-w-[18rem] flex-col overflow-hidden border-r border-ink/10 bg-ink px-5 py-6 text-shell shadow-panel">
      <div className="absolute inset-0 bg-[radial-gradient(circle_at_top,_rgba(203,92,50,0.28),_transparent_44%),radial-gradient(circle_at_bottom,_rgba(182,138,72,0.18),_transparent_36%)]" />
      <div className="relative">
        <div className="mb-10 border-b border-shell/10 pb-6">
          <p className="text-xs uppercase tracking-[0.35em] text-shell/50">Wazuh + Ollama</p>
          <h1 className="mt-3 font-['Space_Grotesk'] text-2xl font-semibold">Analyzer Console</h1>
          <p className="mt-3 text-sm leading-6 text-shell/70">Dense triage workflow for grouped security findings, host ranking and stored reports.</p>
        </div>

        <nav className="space-y-2">
          {items.map((item) => {
            const Icon = item.icon;
            const selected = current === item.id;

            return (
              <button
                key={item.id}
                type="button"
                onClick={() => onSelect(item.id)}
                className={`flex w-full items-center gap-3 rounded-2xl px-4 py-3 text-left transition ${
                  selected
                    ? 'bg-shell text-ink shadow-[0_10px_30px_rgba(0,0,0,0.12)]'
                    : 'text-shell/70 hover:bg-shell/10 hover:text-shell'
                }`}
              >
                <Icon size={18} />
                <span className="font-medium">{item.label}</span>
              </button>
            );
          })}
        </nav>
      </div>
    </aside>
  );
}
