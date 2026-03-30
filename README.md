# Wazuh AI Analyzer

Desktop-oriented analyst app for pulling Wazuh alerts from the Indexer, filtering relevant Windows and Linux security events, grouping similar patterns, applying local risk scoring, and enriching the result with a locally reachable Ollama model.

The app now also supports triggering an analysis script on the Wazuh VM itself over SSH, with preset checkboxes saved in the app and a selectable run mode per analysis.
## The App
- to start the App run 
```
cmd /c desktop\tauri\run_tauri.cmd
```
## Ai
- to start the Ai run 
```
$env:OLLAMA_HOST="0.0.0.0:11434"
ollama serve
```
- and to run a test use 
```
Invoke-RestMethod -Uri "http://localhost:11434/api/generate" `
-Method Post `
-Body '{
  "model": "llama3",
  "prompt": "test",
  "stream": false
}' `
-ContentType "application/json"
```
## Architecture

```text
Wazuh Indexer API (9200)
        -> FastAPI backend
        -> local filtering and grouping
  -> optional SSH trigger to Python script on the Wazuh VM
        -> Ollama API (172.21.5.111:11434)
        -> SQLite job, finding, and report storage
        -> React analyst UI
        -> Tauri desktop wrapper
```

## What is included

- FastAPI backend with:
  - `GET /health`, `GET /health/indexer`, `GET /health/ollama`
  - `POST /connections`, `PUT /connections/{id}`, `POST /connections/test`
  - `POST /analysis/run`, `GET /analysis/jobs`, `GET /analysis/jobs/{id}/findings`
  - `GET /hosts/ranking`, `GET /hosts/{host}/findings`
  - `GET /reports/latest`, `GET /reports/{id}`
- SSH-based VM script triggering with remote TXT/JSON report ingestion
- SQLite persistence for connections, analysis jobs, grouped findings and reports
- Local scoring for the initial Windows and Linux event families from your requirements
- Ollama JSON prompting for structured triage output
- React + Vite + Tailwind desktop-style UI with pages for Dashboard, Findings, Hosts, Reports, Settings and Jobs
- Minimal Tauri shell scaffold for later packaging

## Relevant event coverage in the MVP

### Windows

- 4625 Failed Logon
- 4688 Process Creation
- 7045 Service Installation
- 4720 User Created
- 4728 User added to privileged group
- 4732 Member added to local group
- 1102 Audit Log Cleared

### Linux

- sshd
- authentication_failed
- invalid_login
- sudo
- pam
- useradd
- usermod
- groupadd
- cron

## Project layout

```text
backend/
  main.py
  api/
  db/
  schemas/
  services/

frontend/
  src/
    components/
    hooks/
    pages/
    services/

desktop/
  tauri/
```

## Backend start

```bash
cd backend
pip install -r requirements.txt
uvicorn main:app --reload
```

Backend default URL: `http://127.0.0.1:8000`

## Frontend start

```bash
cd frontend
npm install
npm run dev
```

Frontend default URL: `http://127.0.0.1:5173`

The Vite dev server proxies `/api/*` to the FastAPI backend.

## Desktop start

The desktop entry point is [desktop/tauri/src/main.rs](desktop/tauri/src/main.rs).

Current desktop behavior:

- starts the Tauri window
- starts the local FastAPI backend automatically from `.venv` if `127.0.0.1:8000` is not already running
- loads the React frontend inside the desktop shell

Run it from [desktop/tauri](desktop/tauri):

```bash
cargo run
```

For Tauri dev mode:

```bash
cargo tauri dev
```

## One-click desktop start on Windows

Use [start-desktop.cmd](start-desktop.cmd) from the project root.

It initializes the Visual Studio Build Tools environment and starts the desktop app with `cargo run`:

```bat
start-desktop.cmd
```

## Current workflow

1. Open the Settings page and enter Indexer and Ollama credentials.
2. If you want VM execution, enable the Remote VM Script section and enter SSH access plus script paths.
3. Save the active connection.
4. Run a connectivity test.
5. Choose the run profile checkboxes and mode in the Analysis Control panel.
6. Start an analysis job.
7. Review grouped findings, host ranking and the stored Markdown report.

## Current limitations

- Analysis runs synchronously inside the API request. That is fine for the MVP, but a background worker is the next step.
- VM execution currently uses password-based SSH through the backend. For production packaging, switch that to key-based auth or OS-backed secret storage.
- The Tauri wrapper is only scaffolded, not yet wired to spawn the backend as a sidecar.
- Secrets are stored in SQLite right now. For production packaging, replace this with OS-backed secure storage.
- The dashboard uses current-job state, not historical trend deltas yet.

## Deploy the VM script

The app-ready script is stored in [backend/scripts/ai_wazuh_24h_v2.py](backend/scripts/ai_wazuh_24h_v2.py).

Copy it to the Wazuh VM and point the Settings page to that path:

```bash
scp backend/scripts/ai_wazuh_24h_v2.py user@wazuh-vm:/home/user/ai_wazuh_24h_v2.py
chmod +x /home/user/ai_wazuh_24h_v2.py
```

The app then runs it like this conceptually:

```bash
python3 /home/user/ai_wazuh_24h_v2.py \
  --indexer-url https://localhost:9200 \
  --indexer-user admin \
  --indexer-pass '***' \
  --ollama-url http://172.21.5.111:11434/api/generate \
  --lookback-hours 24 \
  --size 1000 \
  --output-txt /tmp/ai_wazuh_24h_report.txt \
  --output-json /tmp/ai_wazuh_24h_report.json
```

## Recommended next implementation steps

1. Add async job execution and progress tracking.
2. Add host detail drilldowns with raw grouped event previews.
3. Add trend comparisons versus the previous day.
4. Move secrets into a secure local store before packaging.
5. Wire the Tauri app to bundle the frontend and control the backend process.
