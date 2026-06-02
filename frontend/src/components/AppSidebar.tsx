import { useCallback, useState } from 'react';
import type { ElementType } from 'react';
import {
  Activity, AlertTriangle, Brain, CheckSquare, ChevronRight,
  Compass, Cpu, Crosshair, Database, FileSearch, FileText,
  GitBranch, Home, LayoutDashboard, Lock, MessageSquare,
  Network, ScrollText, Search, Server, Settings, Settings2,
  Shield, ShieldCheck, Terminal, Wifi,
} from 'lucide-react';

// ── Types ─────────────────────────────────────────────────────────────────────

export type AppTab =
  | 'chat'
  | 'tasks'
  | 'dashboard'
  | 'hosts'
  | 'host-overview'
  | 'unified-hosts'
  | 'snipen'
  | 'fullscan'
  | 'baseline'
  | 'server'
  | 'scripts'
  | 'trust'
  | 'constellation'
  | 'wazuh-integration';

interface NavItem {
  id?: AppTab;
  label: string;
  icon: ElementType;
  disabled?: boolean;
  badge?: string | null;
}

interface NavGroup {
  id: string;
  label: string;
  icon: ElementType;
  items: NavItem[];
}

export interface AppSidebarProps {
  activeTab: AppTab;
  onNavigate: (tab: AppTab) => void;
  onSettingsOpen: () => void;
  taskBadge?: string | null;
  aiOnline?: boolean;
  clockStr?: string;
}

// ── Breadcrumb mapping (exported for App.tsx header) ─────────────────────────

export const CATEGORY_LABELS: Record<string, string> = {
  dashboard:          'Home',
  chat:               'Administration',
  tasks:              'Security Operations',
  hosts:              'Endpoint Security',
  'host-overview':    'Endpoint Security',
  'unified-hosts':    'Endpoint Security',
  snipen:             'Explore',
  fullscan:           'Explore',
  baseline:           'Explore',
  constellation:      'Explore',
  server:             'Endpoint Security',
  scripts:            'Endpoint Security',
  'wazuh-integration':'Endpoint Security',
  trust:              'Administration',
};

// ── Collapsed state (localStorage) ───────────────────────────────────────────

const STORAGE_KEY = 'sentinel_sidebar_collapsed';

function loadCollapsed(): Record<string, boolean> {
  try {
    return JSON.parse(localStorage.getItem(STORAGE_KEY) ?? '{}') as Record<string, boolean>;
  } catch {
    return {};
  }
}

function persistCollapsed(state: Record<string, boolean>): void {
  try {
    localStorage.setItem(STORAGE_KEY, JSON.stringify(state));
  } catch { /* ignore quota errors */ }
}

// ── Component ─────────────────────────────────────────────────────────────────

export function AppSidebar({
  activeTab,
  onNavigate,
  onSettingsOpen,
  taskBadge,
  aiOnline,
  clockStr,
}: AppSidebarProps) {
  const [collapsed, setCollapsed] = useState<Record<string, boolean>>(loadCollapsed);

  const groups: NavGroup[] = [
    {
      id: 'home',
      label: 'Home',
      icon: Home,
      items: [
        { id: 'dashboard', label: 'Dashboard', icon: LayoutDashboard },
      ],
    },
    {
      id: 'explore',
      label: 'Explore',
      icon: Compass,
      items: [
        { id: 'constellation', label: 'Event Map',     icon: GitBranch },
        { id: 'snipen',        label: 'Investigation', icon: Crosshair },
        { id: 'fullscan',      label: 'Full Scan',     icon: Cpu       },
        { id: 'baseline',      label: 'Baseline',      icon: Database  },
        { disabled: true,      label: 'Timeline',      icon: Activity  },
      ],
    },
    {
      id: 'endpoint',
      label: 'Endpoint Security',
      icon: Shield,
      items: [
        { id: 'hosts',              label: 'Hosts',              icon: Server    },
        { id: 'unified-hosts',      label: 'Unified Hosts',      icon: Network   },
        { id: 'server',             label: 'Server Operations',  icon: Terminal  },
        { id: 'scripts',            label: 'Script Library',     icon: ScrollText},
        { id: 'wazuh-integration',  label: 'Wazuh Integration',  icon: Wifi      },
      ],
    },
    {
      id: 'secops',
      label: 'Security Operations',
      icon: AlertTriangle,
      items: [
        { id: 'tasks',    label: 'Incidents',          icon: CheckSquare, badge: taskBadge },
        { disabled: true, label: 'Findings',           icon: FileSearch },
        { disabled: true, label: 'Controlled Actions', icon: Lock       },
        { disabled: true, label: 'Audit Log',          icon: FileText   },
      ],
    },
    {
      id: 'threatintel',
      label: 'Threat Intelligence',
      icon: Brain,
      items: [
        { disabled: true, label: 'Threat Intel',   icon: Brain         },
        { disabled: true, label: 'MITRE ATT&CK',   icon: Crosshair     },
        { disabled: true, label: 'Vulnerabilities', icon: AlertTriangle },
        { disabled: true, label: 'IOC Lookup',      icon: Search        },
      ],
    },
    {
      id: 'admin',
      label: 'Administration',
      icon: Settings2,
      items: [
        { id: 'trust',    label: 'Trust Center',  icon: ShieldCheck   },
        { id: 'chat',     label: 'Chat',          icon: MessageSquare },
        { disabled: true, label: 'System Health', icon: Activity      },
      ],
    },
  ];

  function isGroupActive(group: NavGroup): boolean {
    return group.items.some(
      item => item.id === activeTab || (item.id === 'hosts' && activeTab === 'host-overview'),
    );
  }

  function isEffectivelyCollapsed(groupId: string, hasActive: boolean): boolean {
    if (hasActive) return false; // active group is always visible
    return collapsed[groupId] ?? false;
  }

  const toggleGroup = useCallback((groupId: string, hasActive: boolean) => {
    if (hasActive) return;
    setCollapsed(prev => {
      const next = { ...prev, [groupId]: !prev[groupId] };
      persistCollapsed(next);
      return next;
    });
  }, []);

  return (
    <aside
      className="w-[220px] shrink-0 border-r flex flex-col h-full"
      style={{ borderColor: 'var(--soc-border)', background: 'var(--soc-sidebar)' }}
    >
      {/* ── Logo ─────────────────────────────────────────────────────────── */}
      <div
        className="h-10 px-3 flex items-center gap-2 border-b shrink-0"
        style={{ borderColor: 'var(--soc-border)' }}
      >
        <div
          className="h-5 w-5 rounded-sm grid place-items-center shrink-0"
          style={{
            background: 'color-mix(in srgb, var(--soc-primary) 20%, transparent)',
            border: '1px solid color-mix(in srgb, var(--soc-primary) 40%, transparent)',
          }}
        >
          <Shield size={12} style={{ color: 'var(--soc-primary)' }} />
        </div>
        <div
          className="text-[12px] font-semibold tracking-wide"
          style={{ color: 'var(--soc-foreground)' }}
        >
          SENTINEL/OPS
        </div>
      </div>

      {/* ── Nav groups ───────────────────────────────────────────────────── */}
      <nav className="flex-1 py-1 overflow-y-auto">
        {groups.map(group => {
          const GroupIcon = group.icon;
          const hasActive = isGroupActive(group);
          const isCollapsed = isEffectivelyCollapsed(group.id, hasActive);

          return (
            <div key={group.id}>
              {/* Group header */}
              <button
                type="button"
                onClick={() => toggleGroup(group.id, hasActive)}
                className="flex items-center gap-2 w-full h-[30px] px-3 select-none"
                style={{
                  color: hasActive
                    ? 'var(--soc-foreground)'
                    : 'color-mix(in srgb, var(--soc-muted-fg) 75%, transparent)',
                  cursor: hasActive ? 'default' : 'pointer',
                }}
                onMouseEnter={e => {
                  if (!hasActive)
                    (e.currentTarget as HTMLElement).style.color = 'var(--soc-foreground)';
                }}
                onMouseLeave={e => {
                  if (!hasActive)
                    (e.currentTarget as HTMLElement).style.color =
                      'color-mix(in srgb, var(--soc-muted-fg) 75%, transparent)';
                }}
              >
                <GroupIcon size={12} className="shrink-0" />
                <span className="flex-1 text-left text-[10px] font-bold tracking-[0.12em] uppercase truncate">
                  {group.label}
                </span>
                <ChevronRight
                  size={11}
                  className="shrink-0 transition-transform duration-150"
                  style={{ transform: isCollapsed ? 'rotate(0deg)' : 'rotate(90deg)' }}
                />
              </button>

              {/* Items */}
              {!isCollapsed && (
                <div className="mb-1">
                  {group.items.map((item, idx) => {
                    const ItemIcon = item.icon;
                    const isActive =
                      item.id === activeTab ||
                      (item.id === 'hosts' && activeTab === 'host-overview');
                    const isDisabled = !!item.disabled;

                    return (
                      <button
                        key={item.id ?? `${group.id}-dis-${idx}`}
                        type="button"
                        disabled={isDisabled}
                        onClick={() => { if (!isDisabled && item.id) onNavigate(item.id); }}
                        className="flex items-center gap-2 w-full h-[27px] text-[11.5px]"
                        style={{
                          paddingLeft: '24px',
                          paddingRight: '8px',
                          color: isDisabled
                            ? 'var(--soc-muted-fg)'
                            : isActive
                              ? 'var(--soc-foreground)'
                              : 'var(--soc-sidebar-fg)',
                          background: isActive ? 'var(--soc-sidebar-accent)' : 'transparent',
                          borderLeft: isActive
                            ? '2px solid var(--soc-primary)'
                            : '2px solid transparent',
                          opacity: isDisabled ? 0.45 : 1,
                          cursor: isDisabled ? 'not-allowed' : 'pointer',
                          transition: 'background 0.1s',
                        }}
                        onMouseEnter={e => {
                          if (!isDisabled && !isActive)
                            (e.currentTarget as HTMLElement).style.background = 'var(--soc-sidebar-accent)';
                        }}
                        onMouseLeave={e => {
                          if (!isDisabled && !isActive)
                            (e.currentTarget as HTMLElement).style.background = 'transparent';
                        }}
                      >
                        <ItemIcon size={13} className="shrink-0" />
                        <span className="flex-1 text-left truncate">{item.label}</span>

                        {/* Count badge */}
                        {item.badge && !isDisabled && (
                          <span
                            className="text-[9px] font-mono px-1 rounded-sm shrink-0"
                            style={{ background: 'var(--soc-critical)', color: 'oklch(0.98 0 0)' }}
                          >
                            {item.badge}
                          </span>
                        )}

                        {/* Coming-soon badge */}
                        {isDisabled && (
                          <span
                            className="text-[9px] font-mono px-1 rounded-sm shrink-0"
                            style={{
                              background: 'color-mix(in srgb, var(--soc-border) 80%, transparent)',
                              color: 'var(--soc-muted-fg)',
                            }}
                          >
                            soon
                          </span>
                        )}
                      </button>
                    );
                  })}
                </div>
              )}

              {/* Inter-group divider */}
              <div
                className="mx-3 border-b"
                style={{ borderColor: 'color-mix(in srgb, var(--soc-border) 50%, transparent)' }}
              />
            </div>
          );
        })}
      </nav>

      {/* ── Bottom status strip ──────────────────────────────────────────── */}
      <div
        className="border-t p-2 text-[10.5px] font-mono space-y-0.5 shrink-0"
        style={{ borderColor: 'var(--soc-border)', color: 'var(--soc-muted-fg)' }}
      >
        <div className="flex justify-between">
          <span>ai status</span>
          <span style={{ color: aiOnline ? 'var(--soc-success)' : 'var(--soc-critical)' }}>
            {aiOnline ? 'online' : 'offline'}
          </span>
        </div>
        {clockStr && (
          <div className="flex justify-between">
            <span>time</span>
            <span>{clockStr}</span>
          </div>
        )}
        <button
          type="button"
          onClick={onSettingsOpen}
          className="w-full flex items-center gap-1.5 mt-1 h-6 px-2 rounded-sm border text-[11px] font-mono"
          style={{ borderColor: 'var(--soc-border)', color: 'var(--soc-muted-fg)' }}
          onMouseEnter={e => (e.currentTarget as HTMLElement).style.background = 'var(--soc-sidebar-accent)'}
          onMouseLeave={e => (e.currentTarget as HTMLElement).style.background = 'transparent'}
        >
          <Settings size={11} />
          <span>Settings</span>
        </button>
      </div>
    </aside>
  );
}
