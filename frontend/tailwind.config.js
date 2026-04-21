/** @type {import('tailwindcss').Config} */
export default {
  content: ['./index.html', './src/**/*.{ts,tsx}'],
  darkMode: 'class',
  theme: {
    extend: {
      fontFamily: {
        sans: ['Nunito', 'sans-serif'],
        mono: ['"JetBrains Mono"', 'ui-monospace', 'SFMono-Regular', 'Menlo', 'monospace'],
      },
      colors: {
        // Ubold primary palette (preserved for existing pages)
        primary: 'var(--primary)',
        success: 'var(--success)',
        info: 'var(--info)',
        warning: 'var(--warning)',
        danger: '#fa5c7c',
        // Semantic aliases (keep backward compat)
        ink: '#313a46',
        shell: '#f5f6fa',
        ember: '#727cf5',
        brass: '#ffbc00',
        pine: '#0acf97',
        signal: '#fa5c7c',
        slate: '#6c757d',
        // Ubold surfaces
        sidebar: '#313a46',
        'sidebar-dark': '#37404a',
        'card-dark': '#3d4451',
        'dark-bg': '#343a40',
        // ── SOC Design System tokens (reference CSS custom properties) ──
        background:  'var(--background)',
        foreground:  'var(--foreground)',
        border:      'var(--border)',
        input:       'var(--input)',
        ring:        'var(--soc-ring)',
        panel:       'var(--panel)',
        'row-hover': 'var(--row-hover)',
        critical:    'var(--critical)',
        high:        'var(--high)',
        muted: {
          DEFAULT:    'var(--muted)',
          foreground: 'var(--muted-foreground)',
        },
        accent: {
          DEFAULT:    'var(--accent)',
          foreground: 'var(--foreground)',
        },
        'soc-critical': 'var(--soc-critical)',
        'soc-high':     'var(--soc-high)',
        'soc-warning':  'var(--soc-warning)',
        'soc-success':  'var(--soc-success)',
        'soc-info':     'var(--soc-info)',
        'soc-bg':       'var(--soc-background)',
        'soc-fg':       'var(--soc-foreground)',
        'soc-panel':    'var(--soc-panel)',
        'soc-border':   'var(--soc-border)',
        'soc-muted':    'var(--soc-muted)',
        'soc-muted-fg': 'var(--soc-muted-fg)',
        'soc-accent':   'var(--soc-accent)',
        'soc-row':      'var(--soc-row-hover)',
        'soc-sidebar':  'var(--soc-sidebar)',
        'soc-sidebar-fg':     'var(--soc-sidebar-fg)',
        'soc-sidebar-accent': 'var(--soc-sidebar-accent)',
        'soc-input':    'var(--soc-input)',
        'soc-primary':  'var(--soc-primary)',
      },
      boxShadow: {
        panel: '0 0 35px 0 rgba(154, 161, 171, 0.15)',
        card: '0 0 35px 0 rgba(154, 161, 171, 0.15)',
        'card-dark': '0 0 35px 0 rgba(0, 0, 0, 0.3)',
      },
    }
  },
  plugins: []
};
