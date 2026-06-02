# SSH_Manager — Idea Import Plan

**Source**: [GitHub SSH_Manager repo](https://github.com/lxe/ssh_manager) (analysiert: 2025)  
**Ziel**: Welche Konzepte/Techniken aus SSH_Manager lassen sich in die bestehende
Server-Operations-Infrastruktur übernehmen? Was ist abgelehnt oder später geplant?

---

## 1. Feature-Inventar (SSH_Manager → unsere Plattform)

| # | Feature | Quelle | Technik | Phase 1 | Phase 2 | Status |
|---|---------|--------|---------|---------|---------|--------|
| F01 | JSON-Konfigurationsimport | `~/.ssh_manager.json` | nested dict `{"ssh":{name:{...}}}` | ✅ | — | **implementiert** |
| F02 | CSV-Import | interner Export | Spalten: name,hostname,ip,port,... | ✅ | — | **implementiert** |
| F03 | SSH-Verbindungstest | `ssh_manager.py test` | paramiko TCP-Handshake | ✅ | — | **implementiert** |
| F04 | SSH Read-Only Befehle | `ssh_readonly_commands` | feste Allowlist → paramiko exec_command | ✅ | — | **implementiert** |
| F05 | SSH Host-Info (uname, df, …) | `get_host_info()` | Allowlist-Aufruf | ✅ | — | **implementiert** |
| F06 | Passwort nie importieren | `legacy_importer.py` | `_WARNED_FIELDS` Blacklist | ✅ | — | **implementiert** |
| F07 | RDP öffnen (mstsc.exe) | `rdp_service.py` | subprocess, kein Passwort-Inject | ✅ | — | **implementiert** |
| F08 | Wake-on-LAN (Magic Packet) | `host_tools_service.py` | UDP Broadcast, MAC-Validierung | ✅ | — | **implementiert** |
| F09 | Ping / DNS / Reverse DNS | `host_tools_service.py` | subprocess / socket | ✅ | — | **implementiert** |
| F10 | Port-Check / Traceroute | `host_tools_service.py` | socket / subprocess | ✅ | — | **implementiert** |
| F11 | SFTP Datei-Liste | `ssh_service.py` | paramiko SFTP, Pfadsanitierung | ✅ | — | **implementiert** |
| F12 | SFTP Datei-Download | `ssh_service.py` | paramiko SFTP | ✅ | — | **implementiert** |
| F13 | SSH-Config-Export | `ssh_service.py` | `~/.ssh/config` Eintragsformat | ✅ | — | **implementiert** |
| F14 | Aktivitätsprotokoll | `server_activity_log` | SQLite | ✅ | — | **implementiert** |
| F15 | Tag-System / Favoriten | `ServerConnection.tags/favorite` | SQLite JSON-Feld | ✅ | — | **implementiert** |
| F16 | Link zu Unified Hosts | `legacy_importer._link_unified` | hostname/IP-Match | ✅ | — | **implementiert** |
| F17 | Interaktives Web-SSH-Terminal | Flask-SocketIO + xterm.js | WebSocket + PTY-Kanal | ❌ | ✅ | **Phase 2 (deaktiviert)** |
| F18 | SSH-Key-Deployment | `ssh-copy-id` äquivalent | paramiko `authorized_keys` | ❌ | ✅ | **deaktiviert** |
| F19 | Datei-Upload via SFTP | `sftp.put()` | paramiko SFTP write | ❌ | ✅ | **deaktiviert** |
| F20 | Port-Forwarding | `ssh -L/-R` | paramiko Transport | ❌ | ✅ | **deaktiviert** |
| F21 | Agenten-Deployment | psutil HTTP-Server Port 9876 | Python subprocess (unsicher, no auth!) | ❌ | ❌ | **abgelehnt** |
| F22 | PowerShell-Remoting (WinRM) | `powershell.exe -Command` | subprocess | ❌ | ⚠️ | **Phase 2 mit Policy** |
| F23 | Reboot / Shutdown remote | `ssh reboot`, `shutdown now` | paramiko exec_command | ❌ | ❌ | **abgelehnt (kritisch)** |
| F24 | Prozess killen remote | `kill -9 <pid>` | paramiko exec_command | ❌ | ❌ | **abgelehnt** |
| F25 | Firewall-Änderungen remote | `iptables`, `firewall-cmd` | paramiko exec_command | ❌ | ❌ | **abgelehnt** |
| F26 | Benutzerverwaltung remote | `useradd`, `passwd` | paramiko exec_command | ❌ | ❌ | **abgelehnt** |
| F27 | mini_top Monitor | `top -b -n1 \| head -20` | Allowlist-Erweiterung | ✅ | — | **implementiert (Erweiterung)** |
| F28 | dmesg Tail | `dmesg \| tail -20` | Allowlist-Erweiterung | ✅ | — | **implementiert (Erweiterung)** |
| F29 | ip addr show | `ip addr show` | Allowlist-Erweiterung | ✅ | — | **implementiert (Erweiterung)** |
| F30 | /etc/os-release | `cat /etc/os-release` | Allowlist-Erweiterung | ✅ | — | **implementiert (Erweiterung)** |
| F31 | Windows systeminfo | `systeminfo` | Allowlist-Erweiterung | ✅ | — | **implementiert (Erweiterung)** |
| F32 | Windows Dienste-Status | `sc query ...` | Allowlist-Erweiterung | ✅ | — | **implementiert (Erweiterung)** |

---

## 2. Phase-Klassifizierung

### Phase 1 — Erlaubt (implementiert oder geplant)
Operationen, die **kein aktives Eingreifen** am Remote-System darstellen:
- Verbindungsverwaltung (CRUD, Import, Export)
- Netzwerk-Diagnose (Ping, DNS, Port-Check, Traceroute, ARP, WoL)
- SSH Read-Only Befehle (feste Allowlist)
- SSH Host-Info, SFTP Datei-Liste + Download (kein Upload)
- RDP starten (kein Passwort-Inject)
- Health-Check (Verbindungstest)
- Aktivitäts-/Session-Log lesen

### Phase 2 — Geplant (derzeit blockiert)
Operationen, die Schreibzugriff darstellen, aber mit Audit/Approval-Workflow realisierbar wären:
- Interaktives Web-SSH-Terminal (`ssh_interactive_shell`)
- SSH-Key-Deployment (`ssh_key_deploy`)
- SFTP Datei-Upload (`ssh_upload`)
- Port-Forwarding (`ssh_port_forward`)
- PowerShell-Remoting / WinRM (`winrm_execute`)

### Dauerhaft deaktiviert
Zu hohe Angriffsfläche oder keine sichere Implementierung möglich:
- Agenten-Deployment (psutil HTTP, kein Auth → CVE-Muster)
- Remote-Reboot / Shutdown
- Remote-Prozesskill
- Firewall-Konfiguration via SSH
- Benutzerverwaltung via SSH

---

## 3. Mapping zu Backend-Dateien

| Feature | Backend-Datei |
|---------|--------------|
| Verbindungs-CRUD | `backend/api/routes_server.py` |
| SSH-Ausführung | `backend/services/remote_access/ssh_service.py` |
| SSH-Allowlist | `backend/services/remote_access/models.py` → `SSH_READONLY_COMMANDS` |
| Policy-Enforcement | `backend/services/remote_access/remote_policy.py` |
| Legacy-Import | `backend/services/remote_access/legacy_importer.py` |
| Netzwerk-Tools | `backend/services/remote_access/host_tools_service.py` |
| RDP | `backend/services/remote_access/rdp_service.py` |
| Feature-Katalog | `backend/services/remote_access/legacy_feature_catalog.py` |
| DB-Schema | `backend/db/database.py` → Tabelle `server_connections` |
| Trust Center Tests | `backend/api/routes_validation.py` → `_run_server_operations_tests()` |

---

## 4. Sicherheitsinvarianten

Folgende Invarianten dürfen **nie** gelockert werden:

1. **Kein Passwort-Import**: `_WARNED_FIELDS` in `legacy_importer.py` blockt `password`, `passwd`, `pass`, `secret`
2. **Keine beliebigen Befehle**: `SSH_READONLY_COMMANDS` ist eine statische dict-Konstante; Roheingaben vom Client werden **nie** ausgeführt
3. **Policy zuerst**: Jede Server-Aktion ruft `check_policy()` auf, bevor sie ausgeführt wird
4. **Pfadsanitierung**: SFTP-Pfade werden via `posixpath.normpath("/" + path.lstrip("/"))` kanonisch gemacht (kein Path-Traversal)
5. **Kein PTY-Kanal**: `ssh_interactive_shell` ist in `_PHASE1_BLOCKED_ACTIONS` und bleibt es bis Phase 2 mit vollständigem Audit-Trail
6. **Kein Passwort-Inject in RDP**: `rdp_service.py` verwendet keine `/p:password` Argumente in mstsc.exe
7. **Agent-Deployment abgelehnt**: psutil-HTTP-Port-9876-Pattern aus SSH_Manager ist ohne Authentifizierung — **nicht portiert**

---

## 5. Trust Center Test-Plan

Die folgenden Tests werden in `routes_validation.py` unter Kategorie `server_operations` hinzugefügt:

| Test-ID | Name | Ziel |
|---------|------|------|
| T01 | DB table server_connections | Tabelle existiert |
| T02 | DB table server_activity_log | Tabelle existiert |
| T03 | DB table remote_sessions | Tabelle existiert |
| T04 | Legacy importer importierbar | Modul lädt ohne Fehler |
| T05 | Legacy importer: SSH/RDP-Format | Nested-JSON korrekt geparsed |
| T06 | Legacy importer: kein Passwort | Passwort-Feld wird übersprungen |
| T07 | SSH_READONLY_COMMANDS vorhanden | ≥ 10 Einträge in der Allowlist |
| T08 | Pflicht-Befehle in Allowlist | `uname`, `df`, `ps_cpu`, `systemctl_fail`, `mini_top` |
| T09 | Phase-1-Block: arbitrary command | `ssh_arbitrary_command` → `blocked` |
| T10 | Phase-1-Block: interactive shell | `ssh_interactive_shell` → `blocked` |
| T11 | Phase-1-Block: file upload | `ssh_upload` → `blocked` |
| T12 | Phase-1-Block: key deploy | `ssh_key_deploy` → `blocked` |
| T13 | Phase-1-Block: port forward | `ssh_port_forward` → `blocked` |
| T14 | Policy: create_connection (kein ctx) | `create_connection` ohne Connection → `ok` |
| T15 | Feature-Katalog importierbar | `legacy_feature_catalog` lädt ohne Fehler |
| T16 | Agent-Deployment deaktiviert | `agent_deployment` Feature hat `status = disabled` |

---

## 6. SSH_Manager Abhängigkeiten (nicht übertragen)

SSH_Manager-`requirements.txt` enthielt:
- `colorama` — CLI-Farben → nicht benötigt (Web-UI)
- `keyring` — OS-Keychain → wir nutzen `credential_ref` (keine Klartext-Passwörter)
- `flask`, `flask-socketio`, `flask-login` → ersetzt durch FastAPI + React
- `paramiko` → ✅ schon eingebunden (optional mit `_PARAMIKO_AVAILABLE`)
- `psutil` → nur für Agent-Deployment verwendet → **abgelehnt**
- `werkzeug` → im Flask-Kontext → nicht benötigt

---

## 7. Nächste Schritte (Backlog)

- [ ] Phase-2-Ticket: Web-SSH-Terminal (xterm.js + WebSocket + PTY) mit Approval-Workflow
- [ ] Phase-2-Ticket: SFTP-Upload mit Dateigröße-Limit + Audit-Log-Pflicht
- [ ] Phase-2-Ticket: SSH-Key-Deployment mit expliziter Benutzerbestätigung
- [ ] Frontend: SSH-Befehls-Dropdown in `SnipenPage` oder `ServerPage` zeigen
- [ ] Frontend: Legacy-Import-Fortschrittsanzeige (Conflicts/Skipped)
- [ ] DB: Index auf `server_connections.hostname` und `.ip` für schnelle Host-Verknüpfung
