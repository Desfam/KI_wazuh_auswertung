import { type CSSProperties, useEffect, useRef } from 'react';
import { animate } from 'animejs';

export type PreflightCheck = {
  key: string;
  label: string;
  detail: string;
  state: 'pending' | 'running' | 'success' | 'warning' | 'error';
  required?: boolean;
};

type AppStartOverlayProps = {
  theme: 'light' | 'dark';
  visible: boolean;
  statusText: string;
  checks: PreflightCheck[];
  canEnter: boolean;
  hasBlockingFailure: boolean;
  onRetry: () => void;
  onContinue: () => void;
  onExited: () => void;
};

// Merge plain CSSProperties with CSS custom properties (--var) without TypeScript errors
function s(base: CSSProperties, vars?: Record<string, string | number>): CSSProperties {
  return { ...base, ...(vars ?? {}) } as CSSProperties;
}

const PARTICLES = [
  { left: '12%', top: '20%', dx: '-30px', dy: '-60px', dur: '5s',   delay: '0s'   },
  { left: '25%', top: '60%', dx: '20px',  dy: '-80px', dur: '7s',   delay: '1s'   },
  { left: '70%', top: '15%', dx: '-20px', dy: '50px',  dur: '6s',   delay: '2s'   },
  { left: '80%', top: '70%', dx: '30px',  dy: '-40px', dur: '5.5s', delay: '0.5s' },
  { left: '50%', top: '80%', dx: '-40px', dy: '-30px', dur: '8s',   delay: '1.5s' },
  { left: '40%', top: '10%', dx: '10px',  dy: '60px',  dur: '6.5s', delay: '3s'   },
];

const CSS_KEYFRAMES = `
  @keyframes sp-rot    { to { transform: rotate(360deg); } }
  @keyframes sp-pulse  { 0%,100%{opacity:.45} 50%{opacity:1} }
  @keyframes sp-scan   {
    0%{top:-2px;opacity:0} 5%{opacity:1} 95%{opacity:1} 100%{top:100%;opacity:0}
  }
  @keyframes sp-blink  { 0%,49%{opacity:1} 50%,100%{opacity:0} }
  @keyframes sp-drift  {
    0%{transform:translate(0,0);opacity:0} 10%{opacity:.8}
    90%{opacity:.4} 100%{transform:translate(var(--pdx),var(--pdy));opacity:0}
  }
  @keyframes sp-orbit  {
    0%  { transform: rotate(var(--os)) translateX(var(--or)); }
    100%{ transform: rotate(calc(var(--os) + 360deg)) translateX(var(--or)); }
  }
  @keyframes sp-shimmer {
    0%{background-position:200% center} 100%{background-position:-200% center}
  }
  @keyframes sp-logIn  {
    from{opacity:0;transform:translateX(-8px)} to{opacity:1;transform:translateX(0)}
  }
  @keyframes sp-fadeUp  { from{opacity:0;transform:translateY(12px)} to{opacity:1;transform:translateY(0)} }
  @keyframes sp-panelL  { from{opacity:0;transform:translateX(-14px)} to{opacity:1;transform:translateX(0)} }
  @keyframes sp-panelR  { from{opacity:0;transform:translateX(14px)}  to{opacity:1;transform:translateX(0)} }
  @keyframes sp-barIn   { from{opacity:0;transform:translateY(8px)}   to{opacity:1;transform:translateY(0)} }
  @keyframes sp-centerIn {
    from{opacity:0;transform:translate(-50%,-50%) scale(.87)}
    to  {opacity:1;transform:translate(-50%,-50%) scale(1)}
  }
`;

function logTag(state: PreflightCheck['state']): string {
  switch (state) {
    case 'success': return '[OK ]';
    case 'warning': return '[WRN]';
    case 'error':   return '[ERR]';
    case 'running': return '[RUN]';
    default:        return '[---]';
  }
}
function logColor(state: PreflightCheck['state']): string {
  switch (state) {
    case 'success': return '#4a90e0';
    case 'warning': return '#7060b0';
    case 'error':   return '#c04060';
    case 'running': return '#4a80d0';
    default:        return '#1e3868';
  }
}
function logBorder(state: PreflightCheck['state']): string {
  switch (state) {
    case 'success': return '#3070d0';
    case 'warning': return '#6040b0';
    case 'error':   return '#a03060';
    case 'running': return '#3070d0';
    default:        return 'rgba(40,80,160,.18)';
  }
}

function MetricRow({ label, value, color = '#4a90e0' }: { label: string; value: string; color?: string }) {
  return (
    <div style={{ display:'flex', justifyContent:'space-between', alignItems:'center', marginTop:4, marginBottom:4 }}>
      <span style={{ fontSize:9, color:'#1e3060' }}>{label}</span>
      <span style={{ fontSize:10.5, color, fontWeight:500 }}>{value}</span>
    </div>
  );
}
function ShimmerBar({ pct, animDelay = '0s', gradient }: { pct: number; animDelay?: string; gradient?: string }) {
  return (
    <div style={{ height:2.5, background:'rgba(30,60,160,.2)', borderRadius:2, marginBottom:8 }}>
      <div style={{
        height:'100%', borderRadius:2,
        width:`${Math.max(0, Math.min(100, pct))}%`,
        transition:'width 0.4s ease',
        background: gradient ?? 'linear-gradient(90deg,#0a2070,#3070e0,#80c0ff)',
        backgroundSize:'200% 100%',
        animation:`sp-shimmer 3s linear infinite ${animDelay}`,
      }} />
    </div>
  );
}
function StatusDot({ color, label, value, valueColor = '#3070c0', dotDelay = '0s' }: {
  color: string; label: string; value: string; valueColor?: string; dotDelay?: string;
}) {
  return (
    <div style={{ fontSize:9, color:'#1e3050', letterSpacing:'.08em', display:'flex', alignItems:'center', gap:5 }}>
      <div style={{ width:5, height:5, borderRadius:'50%', background:color, animation:`sp-pulse 1.6s ease-in-out infinite ${dotDelay}` }} />
      {label}
      <span style={{ color:valueColor, fontSize:9.5, marginLeft:2 }}>{value}</span>
    </div>
  );
}

export function AppStartOverlay({
  visible, statusText, checks,
  canEnter, hasBlockingFailure,
  onRetry, onContinue, onExited,
}: AppStartOverlayProps) {
  const rootRef   = useRef<HTMLDivElement | null>(null);
  const hasExited = useRef(false);

  const totalCount   = checks.length;
  const successCount = checks.filter((c) => c.state === 'success').length;
  const warningCount = checks.filter((c) => c.state === 'warning').length;
  const errorCount   = checks.filter((c) => c.state === 'error').length;
  const settledCount = checks.filter((c) => c.state !== 'pending' && c.state !== 'running').length;
  const progressPct  = totalCount > 0 ? Math.round((settledCount / totalCount) * 100) : 0;

  // Exit fade-out driven by visible → false
  useEffect(() => {
    if (visible || !rootRef.current || hasExited.current) return;
    hasExited.current = true;
    animate(rootRef.current, {
      opacity: [1, 0],
      duration: 500,
      ease: 'inOutQuad',
      onComplete: onExited,
    });
  }, [visible, onExited]);

  return (
    <div
      ref={rootRef}
      style={{
        position:'fixed', inset:0, zIndex:70,
        background:'#03050d',
        fontFamily:"'SF Mono','Fira Code','Courier New',monospace",
        overflow:'hidden',
      }}
    >
      <style>{CSS_KEYFRAMES}</style>

      {/* Dot grid */}
      <div style={{
        position:'absolute', inset:0, pointerEvents:'none',
        backgroundImage:'linear-gradient(rgba(40,80,200,.06) 1px,transparent 1px),linear-gradient(90deg,rgba(40,80,200,.06) 1px,transparent 1px)',
        backgroundSize:'48px 48px',
      }} />

      {/* Ambient glows */}
      <div style={{ position:'absolute', borderRadius:'50%', filter:'blur(60px)', pointerEvents:'none', width:400, height:400, left:-80, top:-120, background:'radial-gradient(circle,rgba(30,60,180,.45) 0%,transparent 70%)' }} />
      <div style={{ position:'absolute', borderRadius:'50%', filter:'blur(60px)', pointerEvents:'none', width:360, height:360, right:-60, bottom:-80, background:'radial-gradient(circle,rgba(80,30,180,.4) 0%,transparent 70%)' }} />
      <div style={{ position:'absolute', borderRadius:'50%', filter:'blur(60px)', pointerEvents:'none', width:260, height:260, left:'50%', top:'50%', transform:'translate(-50%,-50%)', background:'radial-gradient(circle,rgba(20,100,255,.18) 0%,transparent 70%)', animation:'sp-pulse 3s ease-in-out infinite' }} />

      {/* Horizontal scan line */}
      <div style={{ position:'absolute', left:0, right:0, height:1, background:'linear-gradient(90deg,transparent,rgba(80,140,255,.7) 40%,rgba(160,200,255,.9) 50%,rgba(80,140,255,.7) 60%,transparent)', animation:'sp-scan 4s ease-in-out infinite', pointerEvents:'none', zIndex:10 }} />

      {/* Drifting particles */}
      {PARTICLES.map((p, i) => (
        <div
          key={i}
          style={s(
            { position:'absolute', width:2, height:2, borderRadius:'50%', background:'#3060c0', left:p.left, top:p.top, animation:`sp-drift ${p.dur} ease-in-out infinite ${p.delay}` },
            { '--pdx':p.dx, '--pdy':p.dy }
          )}
        />
      ))}

      {/* ── Left panel: event stream / preflight checks ───────────── */}
      <div style={{ position:'absolute', left:22, top:22, width:230, zIndex:5, animation:'sp-panelL 0.55s ease 0.25s both' }}>
        <div style={{ fontSize:8.5, letterSpacing:'.2em', color:'#1e3050', textTransform:'uppercase', marginBottom:7, borderBottom:'1px solid rgba(40,80,160,.2)', paddingBottom:4 }}>
          ▸ event stream
        </div>
        {checks.map((check, i) => (
          <div
            key={check.key}
            style={{
              fontSize:9, color:logColor(check.state), lineHeight:1.75,
              paddingLeft:8, borderLeft:`1.5px solid ${logBorder(check.state)}`,
              marginBottom:3,
              animation:`sp-logIn 0.35s ease ${0.45 + i * 0.11}s both`,
              transition:'color 0.35s, border-color 0.35s',
            }}
          >
            <span style={{ color:'#1e3050' }}>{logTag(check.state)}</span>{' '}{check.label}
            {check.state === 'running' && (
              <span style={{ animation:'sp-blink 1s step-end infinite', color:'#5090ff' }}>█</span>
            )}
          </div>
        ))}
      </div>

      {/* ── Right panel: metrics ──────────────────────────────────── */}
      <div style={{ position:'absolute', right:22, top:22, width:168, zIndex:5, animation:'sp-panelR 0.55s ease 0.35s both' }}>
        <div style={{ fontSize:8.5, letterSpacing:'.2em', color:'#1e3050', textTransform:'uppercase', marginBottom:7, borderBottom:'1px solid rgba(40,80,160,.2)', paddingBottom:4 }}>
          ▸ metrics
        </div>
        <MetricRow label="Checks"  value={`${settledCount}/${totalCount}`} />
        <ShimmerBar pct={progressPct} animDelay="0s" />
        <MetricRow label="Passed"  value={String(successCount)} />
        <ShimmerBar pct={totalCount > 0 ? Math.round((successCount / totalCount) * 100) : 0} animDelay="0.4s" />
        {warningCount > 0 && (
          <>
            <MetricRow label="Warnings" value={String(warningCount)} color="#7060b0" />
            <ShimmerBar pct={Math.round((warningCount / totalCount) * 100)} animDelay="0.8s" gradient="linear-gradient(90deg,#1a0a50,#6040c0,#b080ff)" />
          </>
        )}
        {errorCount > 0 && (
          <>
            <MetricRow label="Failed" value={String(errorCount)} color="#c04060" />
            <ShimmerBar pct={Math.round((errorCount / totalCount) * 100)} animDelay="1.2s" gradient="linear-gradient(90deg,#400a20,#a03060,#ff80a0)" />
          </>
        )}
      </div>

      {/* ── Center: orbit rings + shield ─────────────────────────── */}
      <div style={{
        position:'absolute', left:'50%', top:'44%',
        transform:'translate(-50%,-50%)',
        textAlign:'center', zIndex:5,
        animation:'sp-centerIn 0.7s cubic-bezier(.16,1,.3,1) 0.1s both',
      }}>
        <div style={{ position:'relative', width:160, height:160, margin:'0 auto 18px' }}>
          {/* Rings */}
          <div style={{ position:'absolute', inset:0,  borderRadius:'50%', border:'1px solid rgba(60,120,255,.2)', animation:'sp-rot 8s linear infinite' }} />
          <div style={{ position:'absolute', inset:18, borderRadius:'50%', border:'1px solid rgba(100,80,255,.15)', animation:'sp-rot 12s linear infinite reverse' }} />
          <div style={{ position:'absolute', inset:36, borderRadius:'50%', border:'1px dashed rgba(60,120,255,.1)', animation:'sp-rot 20s linear infinite' }} />
          {/* Orbit dots */}
          <div style={s({ position:'absolute', width:6, height:6, borderRadius:'50%', background:'#5090ff', top:'50%', left:'50%', marginTop:-3, marginLeft:-3, animation:'sp-orbit 8s linear infinite'  }, { '--os':'0deg',   '--or':'80px' })} />
          <div style={s({ position:'absolute', width:6, height:6, borderRadius:'50%', background:'#8060ff', top:'50%', left:'50%', marginTop:-3, marginLeft:-3, animation:'sp-orbit 12s linear infinite' }, { '--os':'120deg', '--or':'62px' })} />
          <div style={s({ position:'absolute', width:4, height:4, borderRadius:'50%', background:'#a0c0ff', top:'50%', left:'50%', marginTop:-2, marginLeft:-2, animation:'sp-orbit 20s linear infinite' }, { '--os':'240deg', '--or':'42px' })} />
          {/* Shield */}
          <div style={{ position:'absolute', left:'50%', top:'50%', transform:'translate(-50%,-50%)' }}>
            <svg width="72" height="80" viewBox="0 0 72 80">
              <defs>
                <radialGradient id="sp-sg" cx="50%" cy="40%" r="60%">
                  <stop offset="0%"   stopColor="#2050c0" stopOpacity=".3" />
                  <stop offset="100%" stopColor="#0a0f30" stopOpacity=".05" />
                </radialGradient>
              </defs>
              <path d="M36 5 L64 16 L64 40 Q64 63 36 75 Q8 63 8 40 L8 16 Z" fill="url(#sp-sg)" stroke="#3060c0" strokeWidth="1.2" strokeLinejoin="round" />
              <path d="M36 14 L56 22 L56 40 Q56 58 36 68 Q16 58 16 40 L16 22 Z" fill="none" stroke="rgba(80,130,255,.25)" strokeWidth=".8" />
              <circle cx="36" cy="40" r="14" fill="none" stroke="rgba(60,110,240,.3)" strokeWidth=".8" strokeDasharray="3 2" />
              <text x="36" y="45" textAnchor="middle" dominantBaseline="central" fontFamily="SF Mono,Fira Code,monospace" fontSize="15" fontWeight="500" fill="#6090e0" letterSpacing=".04em">KI</text>
            </svg>
          </div>
        </div>

        <div style={{ fontSize:21, fontWeight:500, letterSpacing:'.14em', color:'#c8d8ff', textTransform:'uppercase', animation:'sp-fadeUp .6s ease .2s both' }}>
          Wazuh Analyzer<span style={{ animation:'sp-blink 1s step-end infinite', color:'#5090ff' }}>_</span>
        </div>
        <div style={{ fontSize:10, letterSpacing:'.28em', color:'#3a5080', marginTop:6, textTransform:'uppercase', animation:'sp-fadeUp .6s ease .5s both' }}>
          AI-powered Security Intelligence
        </div>
        <div style={{ fontSize:11, color:'#2a4060', letterSpacing:'.1em', marginTop:14, animation:'sp-fadeUp .6s ease .8s both' }}>
          Wazuh · <span style={{ color:'#4a80c0' }}>SIEM</span> · Threat Detection · <span style={{ color:'#4a80c0' }}>ML Analysis</span>
        </div>
      </div>

      {/* ── Status bar ─────────────────────────────────────────────── */}
      <div style={{
        position:'absolute', bottom:0, left:0, right:0,
        minHeight:38,
        background:'rgba(2,6,20,.9)',
        borderTop:'1px solid rgba(30,60,150,.2)',
        display:'flex', alignItems:'center', flexWrap:'wrap',
        gap:18, padding:'6px 16px',
        animation:'sp-barIn 0.5s ease 0.6s both',
      }}>
        <StatusDot color="#3070d0" label="Wazuh"  value={statusText}                     dotDelay="0s"   />
        <StatusDot color="#6040b0" label="checks" value={`${settledCount}/${totalCount}`} dotDelay="0.5s" />
        {errorCount > 0 && (
          <StatusDot color="#b03060" label="errors" value={String(errorCount)} valueColor="#b04060" dotDelay="0.9s" />
        )}
        <div style={{ marginLeft:'auto', display:'flex', gap:8, alignItems:'center' }}>
          {(hasBlockingFailure || canEnter) && (
            <button
              type="button"
              onClick={onRetry}
              style={{
                fontSize:9, letterSpacing:'.1em', color:'#3060b0',
                background:'rgba(20,40,100,.4)',
                border:'1px solid rgba(40,80,160,.35)',
                borderRadius:4, padding:'3px 10px', cursor:'pointer',
                textTransform:'uppercase', fontFamily:'inherit',
              }}
            >
              Retry
            </button>
          )}
          {canEnter && (
            <button
              type="button"
              onClick={onContinue}
              style={{
                fontSize:9, letterSpacing:'.1em', color:'#80c0ff',
                background:'rgba(20,60,160,.4)',
                border:'1px solid rgba(40,100,220,.4)',
                borderRadius:4, padding:'3px 10px', cursor:'pointer',
                textTransform:'uppercase', fontFamily:'inherit',
              }}
            >
              Enter App ›
            </button>
          )}
          <span style={{ fontSize:9, color:'#151e30' }}>v1.0.0 · 2026</span>
        </div>
      </div>
    </div>
  );
}
