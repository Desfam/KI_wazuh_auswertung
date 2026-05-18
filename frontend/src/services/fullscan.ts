// Full Scan API integration

const isDesktopShell =
  window.location.protocol === 'tauri:' ||
  window.location.hostname === 'tauri.localhost' ||
  navigator.userAgent.includes('Tauri');

const API_BASE = isDesktopShell ? 'http://127.0.0.1:8000/fullscan' : '/api/fullscan';

async function parseJsonOrThrow(res: Response): Promise<any> {
  const text = await res.text();
  if (!res.ok) {
    throw new Error(text || `Request failed with status ${res.status}`);
  }
  try {
    return JSON.parse(text);
  } catch {
    throw new Error(`Invalid JSON response from Full Scan API: ${text.slice(0, 180)}`);
  }
}

export async function startFullScan(host: string, params: any): Promise<{ job_id: string }> {
  const res = await fetch(`${API_BASE}/start`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ host, params })
  });
  return parseJsonOrThrow(res);
}

export async function getFullScanStatus(job_id: string): Promise<any> {
  const res = await fetch(`${API_BASE}/status/${job_id}`);
  return parseJsonOrThrow(res);
}

export async function getFullScanResult(job_id: string): Promise<any> {
  const res = await fetch(`${API_BASE}/result/${job_id}`);
  return parseJsonOrThrow(res);
}

// ─── Fleet Scan ───────────────────────────────────────────────────
const FLEET_BASE = isDesktopShell ? 'http://127.0.0.1:8000/fleet-scan' : '/api/fleet-scan';

export async function startFleetScan(hosts: string[], params: any): Promise<{ job_id: string; total_hosts: number }> {
  const res = await fetch(`${FLEET_BASE}/start`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ hosts, params }),
  });
  return parseJsonOrThrow(res);
}

export async function getFleetScanStatus(job_id: string): Promise<any> {
  const res = await fetch(`${FLEET_BASE}/status/${job_id}`);
  return parseJsonOrThrow(res);
}

export async function getFleetScanResult(job_id: string): Promise<any> {
  const res = await fetch(`${FLEET_BASE}/result/${job_id}`);
  return parseJsonOrThrow(res);
}

export async function cancelFleetScan(job_id: string): Promise<void> {
  await fetch(`${FLEET_BASE}/cancel/${job_id}`, { method: 'POST' });
}
