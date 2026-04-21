import { Search, Bell, Power } from "lucide-react";

export function SocTopbar({ title, sub }: { title: string; sub?: string }) {
  return (
    <header className="h-10 shrink-0 border-b border-border bg-[var(--panel)] flex items-center px-3 gap-3">
      <div className="flex items-baseline gap-2">
        <div className="text-[12.5px] font-semibold tracking-wide">{title}</div>
        {sub && <div className="text-[11px] text-muted-foreground font-mono">{sub}</div>}
      </div>

      <div className="ml-4 flex items-center gap-2 flex-1 max-w-[480px]">
        <div className="flex items-center gap-2 h-7 w-full px-2 rounded-sm bg-input border border-border">
          <Search className="h-3.5 w-3.5 text-muted-foreground" />
          <input
            placeholder="host:, user:, eid:, hash:, ip:…"
            className="bg-transparent flex-1 outline-none text-[12px] font-mono placeholder:text-muted-foreground"
          />
          <kbd className="text-[10px] font-mono px-1 rounded-sm bg-muted border border-border text-muted-foreground">/</kbd>
        </div>
      </div>

      <div className="ml-auto flex items-center gap-2">
        <span className="flex items-center gap-1.5 text-[11px] font-mono text-muted-foreground">
          <span className="h-1.5 w-1.5 rounded-full bg-success animate-pulse" />
          live · 09:42:18
        </span>
        <button className="h-7 px-2 rounded-sm border border-border hover:bg-accent text-[11px] flex items-center gap-1">
          <Bell className="h-3.5 w-3.5" /> 12
        </button>
        <button className="h-7 px-2 rounded-sm border border-border hover:bg-accent text-[11px] flex items-center gap-1">
          <Power className="h-3.5 w-3.5 text-success" /> on-call
        </button>
        <div className="h-6 w-6 rounded-sm bg-primary/20 border border-primary/40 grid place-items-center text-[10px] font-mono">
          AS
        </div>
      </div>
    </header>
  );
}
