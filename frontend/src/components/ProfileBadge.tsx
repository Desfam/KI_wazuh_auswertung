
const PROFILE_CONFIG: Record<string, { label: string; bg: string; text: string; border: string }> = {
  datacenter: {
    label: 'RZ',
    bg: 'bg-slate-500/20',
    text: 'text-slate-300',
    border: 'border-slate-500/30',
  },
  customer_service: {
    label: 'KS',
    bg: 'bg-cyan-500/20',
    text: 'text-cyan-300',
    border: 'border-cyan-500/30',
  },
  developer: {
    label: 'DEV',
    bg: 'bg-purple-500/20',
    text: 'text-purple-300',
    border: 'border-purple-500/30',
  },
};

const NO_PROFILE = {
  label: 'Kein Profil',
  bg: 'bg-slate-500/10',
  text: 'text-slate-500',
  border: 'border-slate-600/20',
};

/** Accept any object that has profile_name / profile_display_name (e.g. HostProfileAssignment or inline refs) */
interface ProfileRef {
  profile_name?: string | null;
  profile_display_name?: string | null;
}

interface ProfileBadgeProps {
  assignment?: ProfileRef | null;
  size?: 'sm' | 'md';
  showLabel?: boolean;
}

export function ProfileBadge({ assignment, size = 'sm', showLabel = false }: ProfileBadgeProps) {
  const profileName = assignment?.profile_name ?? null;
  const displayName = assignment?.profile_display_name ?? null;
  const cfg = profileName ? (PROFILE_CONFIG[profileName] ?? NO_PROFILE) : NO_PROFILE;

  const sizeClasses = size === 'sm'
    ? 'px-1.5 py-0.5 text-[0.62rem]'
    : 'px-2 py-1 text-xs';

  return (
    <span
      className={`inline-flex items-center rounded-full border font-semibold ${cfg.bg} ${cfg.text} ${cfg.border} ${sizeClasses}`}
      title={displayName ?? 'Kein Profil zugewiesen'}
    >
      {showLabel ? (displayName ?? 'Kein Profil') : cfg.label}
    </span>
  );
}

export function profileBadgeConfig(profileName: string | null | undefined) {
  return profileName ? (PROFILE_CONFIG[profileName] ?? NO_PROFILE) : NO_PROFILE;
}
