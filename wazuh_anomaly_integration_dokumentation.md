# Wazuh + OpenSearch Anomaly Detection Integration

## Zweck dieser Dokumentation

Diese Dokumentation beschreibt, wie die neue beziehungsweise vorhandene Anomaly-Detection-Funktionalität im Wazuh-Umfeld verstanden und sinnvoll in die eigene **KI Wazuh Auswertung / SOC-Copilot-App** integriert werden kann.

Ziel ist nicht, die eigene App durch Wazuh zu ersetzen, sondern vorhandene Wazuh- und OpenSearch-Funktionen als zusätzliche Signalquelle zu nutzen.

Die Grundidee lautet:

```text
Wazuh erkennt und sammelt Sicherheitsereignisse.
OpenSearch Anomaly Detection erkennt statistische Abweichungen.
Die eigene App bewertet, erklärt, korreliert und priorisiert diese Signale.
```

---

## Ausgangssituation

Nach dem Update auf Wazuh 4.14.x ist aufgefallen, dass im Dashboard beziehungsweise in den Komponenten Hinweise auf Anomaly Detection auftauchen können. Auf den ersten Blick wirkt es so, als hätte Wazuh nun selbst einen neuen vollständigen Anomaly Detector eingebaut.

Bei genauerer Betrachtung ist der entscheidende Punkt:

- Wazuh nutzt als Indexer OpenSearch.
- OpenSearch bringt eigene Plugins mit.
- Dazu gehört unter anderem das **OpenSearch Anomaly Detection Plugin**.
- Dieses Plugin kann auf Wazuh-Daten angewendet werden.

Das bedeutet: Die Anomaly Detection kommt sehr wahrscheinlich nicht als eigenständige Wazuh-Core-Detection-Engine, sondern aus dem OpenSearch-Ökosystem.

---

## Warum das wichtig ist

Die eigene App hat bereits folgende Funktionen oder Konzepte:

- Wazuh Event-Auswertung
- Event-Erklärungen mit KI
- Host-Profile
- Baseline / Known-Good-Ansatz
- Full-Scan-Reports
- Risikobewertung
- Event-Kontextanalyse
- geplante Integration von Tactical RMM, Checkmk und SSH/RDP Manager

Ein OpenSearch-Anomaly-Detector ersetzt diese Funktionen nicht.

Er ergänzt sie um ein sehr wichtiges Signal:

```text
„Dieses Verhalten ist statistisch ungewöhnlich.“
```

Aber er beantwortet nicht automatisch:

```text
„Ist das gefährlich?“
„Warum ist es gefährlich?“
„Was spricht dagegen?“
„Was soll ich jetzt tun?“
„Ist das für diesen Host normal?“
```

Genau diese Bewertung ist die Aufgabe der eigenen App.

---

## Grundarchitektur

```text
+------------------+
| Wazuh Agents     |
+--------+---------+
         |
         v
+------------------+
| Wazuh Manager    |
+--------+---------+
         |
         v
+---------------------------+
| Wazuh Indexer / OpenSearch|
+-------------+-------------+
              |
              v
+-------------------------------+
| OpenSearch Anomaly Detection  |
+-------------+-----------------+
              |
              v
+-------------------------------+
| REST API / Detector Results   |
+-------------+-----------------+
              |
              v
+-------------------------------+
| Eigene SOC-Copilot-App        |
| - Baseline                    |
| - Host Profile                |
| - AI Explanation              |
| - Risk Scoring                |
| - UI / Full Scan / Dashboard  |
+-------------------------------+
```

---

## Rollenverteilung

### Wazuh

Wazuh ist die zentrale Datenquelle.

Es liefert:

- Windows Security Events
- Linux Syscheck/FIM Events
- Service Events
- Authentication Events
- File Integrity Monitoring
- Inventory-Daten
- Vulnerability-Daten
- Agent-Status
- Regel-Level
- MITRE-Mappings

Wazuh beantwortet hauptsächlich:

```text
Was wurde erkannt?
Welche Regel hat ausgelöst?
Welcher Host war betroffen?
Welches Event wurde erzeugt?
```

---

### OpenSearch Anomaly Detection

OpenSearch Anomaly Detection erkennt statistische Abweichungen.

Es beantwortet hauptsächlich:

```text
Ist ein Messwert oder Muster ungewöhnlich im Vergleich zur Vergangenheit?
```

Beispiele:

- ungewöhnlich viele 4625 Login Failures
- ungewöhnlich viele neue Prozesse
- ungewöhnlich hohes Event-Volumen
- ungewöhnliches Verhalten eines bestimmten Hosts
- ungewöhnliche Häufung von Service-Änderungen
- ungewöhnliche Netzwerk-/Port-Aktivität

Wichtig:

```text
Anomaly Detection erkennt Abweichung, nicht automatisch Angriff.
```

---

### Eigene App

Die eigene App sollte die Entscheidungsebene sein.

Sie beantwortet:

```text
Ist diese Abweichung sicherheitsrelevant?
Passt sie zum Host-Profil?
Ist sie in der Baseline bekannt?
Gibt es zusätzliche verdächtige Signale?
Welche Maßnahmen sind sinnvoll?
Wie erkläre ich das verständlich?
```

Damit wird die eigene App nicht überflüssig, sondern wichtiger.

---

## Warum die eigene App weiterhin notwendig ist

Ein Anomaly Detector kann False Positives erzeugen.

Beispiel:

```text
Ein Sysadmin-Laptop erzeugt viele PowerShell-Events.
```

Für einen normalen Office-Client wäre das ungewöhnlich.
Für eine Sysadmin-Workstation kann es normal sein.

Ein reines Anomaly-System könnte sagen:

```text
„Ungewöhnlich.“
```

Die eigene App sollte sagen:

```text
„Für diesen Host-Typ normal, solange keine suspicious command line, kein EncodedCommand, kein DownloadString und kein Credential-Dumping vorkommt.“
```

Das ist der Unterschied zwischen einer Detection Engine und einem SOC-Copilot.

---

## Beispiel: Event 4625

### Reine Wazuh-Sicht

```text
Event ID: 4625
Beschreibung: Logon Failure
Regel-Level: 5
MITRE: T1531
```

### Reine Anomaly-Sicht

```text
Viele 4625 Events innerhalb kurzer Zeit.
Anomalie erkannt.
```

### Eigene App-Sicht

```text
4625 mit Gast-Konto, Logon Type 3, explorer.exe, Konto deaktiviert.
Das spricht eher für einen SMB-/Netzlaufwerk-Zugriff oder Windows-Fallback.
LOW, solange keine hohe Frequenz, keine externe Quelle, keine verschiedenen Zielkonten und kein erfolgreicher 4624 danach auftreten.
```

---

## Beispiel: Event 7045

### Reine Wazuh-Sicht

```text
Event ID: 7045
Neuer Windows-Dienst wurde installiert.
MITRE: T1543.003 Windows Service
```

### Reine Anomaly-Sicht

```text
Neue Dienstinstallation ist ungewöhnlich.
```

### Eigene App-Sicht

```text
Dienstname: Intel Graphics Software
Pfad: C:\Program Files\WindowsApps\...
Vendor: Intel
Kontext: wahrscheinlich AppX-/Treiber-/Store-Update
Bewertung: eher LOW/MEDIUM statt HIGH, sofern Signatur passt und keine suspicious command line vorhanden ist.
```

---

## Zielbild der Integration

Die eigene App sollte Anomaly Detection als zusätzliches Signal nutzen.

```text
Event Risk =
  Wazuh Rule Risk
+ Baseline Deviation Risk
+ Behavior Risk
+ Threat Intel Risk
+ Anomaly Detection Signal
+ Host Profile Context
```

Dabei darf Anomaly Detection nicht allein das Risiko bestimmen.

### Schlechte Logik

```text
Anomaly detected = HIGH
```

### Gute Logik

```text
Anomaly detected + Known Good = LOW/MEDIUM
Anomaly detected + New Service = MEDIUM
Anomaly detected + Suspicious Command Line = HIGH
Anomaly detected + TI Match = HIGH/CRITICAL
```

---

## Praktische Prüfung im Docker-Wazuh-Setup

Da Wazuh bei dir als Docker Single-Node-Stack läuft, werden die Prüfungen im LXC über Docker ausgeführt.

### Container prüfen

```bash
docker ps
```

Erwartete Container:

```text
single-node-wazuh.indexer-1
single-node-wazuh.manager-1
single-node-wazuh.dashboard-1
```

---

## Plugin-Verfügbarkeit prüfen

### Variante 1: Im Indexer-Container

```bash
docker exec -it single-node-wazuh.indexer-1 \
/usr/share/wazuh-indexer/bin/opensearch-plugin list
```

Gesucht werden Einträge wie:

```text
opensearch-anomaly-detection
opensearch-job-scheduler
opensearch-alerting
```

### Variante 2: Per OpenSearch API

```bash
curl -k -u admin https://localhost:9200/_cat/plugins?v
```

Falls das Passwort nicht bekannt ist, steht es meistens in:

```text
wazuh-docker/single-node/docker-compose.yml
.env
config/wazuh_indexer/internal_users.yml
```

---

## Prüfen, ob bereits Detector existieren

```bash
curl -k -u admin https://localhost:9200/_plugins/_anomaly_detection/detectors/_search \
-H 'Content-Type: application/json' -d'
{
  "query": { "match_all": {} },
  "size": 20
}'
```

### Mögliche Ergebnisse

#### Fall 1: Keine Detector

Dann ist das Plugin vorhanden, aber noch nicht eingerichtet.

#### Fall 2: Detector vorhanden

Dann können die Ergebnisse direkt abgefragt und in die eigene App integriert werden.

---

## Anomaly-Ergebnisse abfragen

```bash
curl -k -u admin https://localhost:9200/_plugins/_anomaly_detection/detectors/results/_search \
-H 'Content-Type: application/json' -d'
{
  "size": 20,
  "query": {
    "range": {
      "anomaly_grade": {
        "gt": 0
      }
    }
  },
  "sort": [
    { "data_start_time": { "order": "desc" } }
  ]
}'
```

---

## Wichtige Felder aus Anomaly Results

| Feld | Bedeutung |
|---|---|
| detector_id | ID des Detectors |
| anomaly_grade | Stärke der Anomalie von 0.0 bis 1.0 |
| confidence | Vertrauen in die Anomalie-Erkennung |
| anomaly_score | interner Score |
| entity | betroffene Entität, z. B. Host/User/Service |
| data_start_time | Startzeit des betrachteten Zeitfensters |
| data_end_time | Endzeit des betrachteten Zeitfensters |
| feature_data | Werte der überwachten Features |

---

## Bewertung von anomaly_grade

Eine einfache Normalisierung für die eigene App:

| anomaly_grade | Bedeutung | Vorschlag App-Severity |
|---:|---|---|
| 0.0 | keine Anomalie | info |
| 0.1 - 0.3 | leichte Abweichung | low |
| 0.3 - 0.6 | deutliche Abweichung | medium |
| 0.6 - 0.8 | starke Abweichung | high |
| 0.8 - 1.0 | extreme Abweichung | critical |

Wichtig: Diese Severity darf nicht direkt final verwendet werden. Sie ist nur ein Signal.

---

## Empfohlene interne Datenstruktur

Die eigene App sollte Anomalien in ein eigenes Format mappen.

```python
@dataclass
class WazuhAnomaly:
    detector_id: str
    detector_name: str | None
    host: str | None
    entity: str | None
    anomaly_grade: float
    confidence: float
    anomaly_score: float | None
    data_start_time: str
    data_end_time: str
    feature_data: dict
    raw: dict
```

Oder als JSON:

```json
{
  "source": "opensearch_anomaly_detection",
  "detector_id": "abc123",
  "detector_name": "failed_logon_spike_detector",
  "host": "SWE-13",
  "entity": "SWE-13",
  "anomaly_grade": 0.72,
  "confidence": 0.91,
  "normalized_score": 7.2,
  "severity_hint": "high",
  "data_start_time": "2026-04-30T08:00:00Z",
  "data_end_time": "2026-04-30T08:05:00Z"
}
```

---

## Backend-Integration in der eigenen App

### Neue Datei

```text
backend/services/wazuh_anomaly_service.py
```

### Aufgabe

Diese Datei soll:

1. OpenSearch kontaktieren
2. Detector suchen
3. Anomaly Results abrufen
4. Ergebnisse normalisieren
5. optional nach Host filtern
6. Ergebnisse an Full Scan, Baseline und Host Overview liefern

---

## Beispiel: Service-Funktion

```python
from __future__ import annotations

from typing import Any
import requests


def normalize_anomaly_grade(grade: float) -> tuple[float, str]:
    score = round(max(0.0, min(1.0, grade)) * 10, 1)

    if score >= 8:
        sev = "critical"
    elif score >= 6:
        sev = "high"
    elif score >= 3:
        sev = "medium"
    elif score > 0:
        sev = "low"
    else:
        sev = "info"

    return score, sev


def get_recent_anomalies(
    base_url: str,
    username: str,
    password: str,
    host: str | None = None,
    hours: int = 24,
    limit: int = 50,
) -> list[dict[str, Any]]:
    query = {
        "size": limit,
        "query": {
            "bool": {
                "must": [
                    {"range": {"anomaly_grade": {"gt": 0}}}
                ]
            }
        },
        "sort": [{"data_start_time": {"order": "desc"}}]
    }

    url = f"{base_url.rstrip('/')}/_plugins/_anomaly_detection/detectors/results/_search"

    response = requests.post(
        url,
        auth=(username, password),
        json=query,
        verify=False,
        timeout=20,
    )
    response.raise_for_status()

    hits = response.json().get("hits", {}).get("hits", [])
    results: list[dict[str, Any]] = []

    for hit in hits:
        src = hit.get("_source", {})
        grade = float(src.get("anomaly_grade") or 0)
        score, sev = normalize_anomaly_grade(grade)

        entity = src.get("entity")
        entity_text = str(entity or "")

        if host and host.lower() not in entity_text.lower():
            continue

        results.append({
            "source": "opensearch_anomaly_detection",
            "detector_id": src.get("detector_id"),
            "entity": entity,
            "host": host,
            "anomaly_grade": grade,
            "confidence": src.get("confidence"),
            "anomaly_score": src.get("anomaly_score"),
            "normalized_score": score,
            "severity_hint": sev,
            "data_start_time": src.get("data_start_time"),
            "data_end_time": src.get("data_end_time"),
            "feature_data": src.get("feature_data", {}),
            "raw": src,
        })

    return results
```

---

## Integration in Full Scan

Der Full Scan sollte Anomaly-Daten als eigenes Modul bekommen.

### Aktueller Full Scan

```text
Events
Findings
Threat Intel
Baseline
Profile
AI Summary
```

### Ziel

```text
Events
Findings
Threat Intel
Baseline
Profile
Wazuh Anomalies
AI Summary
```

---

## Full Scan Score-Erweiterung

### Beispiel-Scoring

```python
def calculate_anomaly_score(anomalies: list[dict]) -> float:
    if not anomalies:
        return 0.0

    max_grade = max(float(a.get("anomaly_grade") or 0) for a in anomalies)
    max_conf = max(float(a.get("confidence") or 0) for a in anomalies)

    return round(max_grade * max_conf * 10, 1)
```

### Risk Breakdown erweitern

```json
{
  "rule_score": 3.0,
  "behavior_score": 0.0,
  "baseline_score": 1.5,
  "threat_intel_score": 0.0,
  "anomaly_score": 4.2,
  "final_score": 5.1
}
```

---

## Wichtige Scoring-Regel

Anomaly Detection darf nie allein kritisch eskalieren.

### Empfehlung

```python
if anomaly_score >= 7 and baseline_deviation_score >= 5:
    risk += 2

if anomaly_score >= 7 and suspicious_behavior_score >= 5:
    risk += 3

if anomaly_score >= 7 and threat_intel_match:
    risk += 4

if anomaly_score >= 7 and no_other_signal:
    risk += 1
```

---

## Integration in Baseline

Die Baseline sollte Anomaly Detection nicht ersetzen, sondern ergänzen.

### Baseline erkennt

```text
Was ist für diesen Host bekannt?
```

### Anomaly Detection erkennt

```text
Was weicht statistisch ab?
```

### Kombiniert

```text
Ist eine bekannte Aktivität plötzlich ungewöhnlich stark?
```

Beispiel:

```text
4625 ist für Host bekannt.
Normal: 5 pro Stunde.
Aktuell: 120 pro Stunde.
Anomaly Grade: 0.84.
Bewertung: MEDIUM/HIGH abhängig von Zielkonten und Erfolg nach Fehlversuchen.
```

---

## Known Good vs Known But Suspicious

Ein wichtiger Punkt für deine App:

```text
Known Good bedeutet nicht automatisch ungefährlich.
```

Beispiel:

```text
powershell.exe ist bekannt.
```

Aber:

```text
powershell.exe -EncodedCommand ...
```

ist weiterhin verdächtig.

Das gleiche gilt für Anomalies:

```text
Bekannter Dienst + ungewöhnliche Häufung von Neustarts = prüfungswürdig.
```

---

## UI-Integration

### Dashboard

Auf dem Dashboard sollte ein neuer Bereich erscheinen:

```text
Anomaly Signals
```

Mögliche Karten:

| Karte | Inhalt |
|---|---|
| Active Anomalies | Anzahl aktiver Anomalien |
| Highest Grade | höchste anomaly_grade |
| Affected Hosts | betroffene Hosts |
| Confidence | durchschnittliche Confidence |

---

## Full Scan Report UI

Im Full Scan Report sollte Anomaly Detection als eigene Sektion erscheinen.

### Beispiel

```text
Anomaly Signals
- 3 anomalies detected in the last 24h
- Highest anomaly grade: 0.72
- Main entity: SWE-13
- Confidence: 0.91
```

### Bewertungstext

```text
Die erkannte Anomalie ist ein Zusatzsignal. Da keine verdächtigen Command-Line-Muster, keine Threat-Intel-Treffer und keine neuen kritischen Baseline-Abweichungen vorliegen, wird das Risiko nicht automatisch erhöht.
```

---

## Host Overview Integration

Im Host-Tab sollte pro Host sichtbar sein:

```text
Host: SWE-13
Baseline: Stable
Anomalies: 2
Highest anomaly: 0.41
Last anomaly: 08:15
```

So erkennt man schnell:

- welcher Host gerade abweicht
- ob die Abweichung neu ist
- ob sie mit anderen Findings zusammenhängt

---

## Timeline Integration

Eine sehr starke Funktion wäre eine kombinierte Timeline:

```text
08:00 baseline normal
08:10 anomaly detected: login failures spike
08:12 4625 burst
08:15 4624 success
08:17 new service installed
08:20 suspicious PowerShell
```

Das macht aus Einzel-Events eine Story.

---

## Empfohlene Detector-Ideen

### 1. Failed Logon Spike Detector

Ziel:

```text
Erkennt ungewöhnlich viele fehlgeschlagene Logins.
```

Metrik:

```text
count(EventID 4625) pro Host pro 5 Minuten
```

Entity:

```text
agent.name oder data.win.system.computer
```

Nutzen:

- Brute Force
- Password Spray
- Fehlkonfiguration
- defekte Services

---

### 2. Service Change Detector

Ziel:

```text
Erkennt ungewöhnliche Häufung von Dienstinstallationen oder Service-Änderungen.
```

Metriken:

```text
count(EventID 7045)
count(EventID 7040)
```

Nutzen:

- Persistence
- Software Rollout
- Update-Wellen

---

### 3. Process Creation Spike Detector

Ziel:

```text
Erkennt ungewöhnlich viele Prozessstarts.
```

Metrik:

```text
count(EventID 4688)
```

Nutzen:

- Script-Ausführung
- Build-Prozesse
- Malware-Aktivität

Wichtig:

Für Sysadmin- oder Developer-Workstations muss das Host-Profil berücksichtigt werden.

---

### 4. File Integrity Spike Detector

Ziel:

```text
Erkennt ungewöhnlich viele FIM-Änderungen.
```

Metrik:

```text
count(syscheck events)
```

Nutzen:

- Updates
- Konfigurationsänderungen
- Manipulation
- Ransomware-Vorzeichen

---

### 5. Network Port Change Detector

Ziel:

```text
Erkennt ungewöhnliche Port-Änderungen.
```

Metrik:

```text
count(netstat listening ports changed)
```

Nutzen:

- neue Services
- unerwartete Listener
- NFS/RPC/Service-Restarts

---

## Umsetzungsvorschlag in Phasen

### Phase 1: Lesen statt Erzeugen

Zuerst nur prüfen, ob vorhandene Detectors und Results existieren.

Aufgaben:

- Plugin prüfen
- Detectors suchen
- Results abrufen
- Backend-Service bauen
- UI nur lesend integrieren

Vorteil:

```text
Kein Risiko für Wazuh-Konfiguration.
```

---

### Phase 2: Eigene App-Integration

Aufgaben:

- Anomaly Results im Full Scan anzeigen
- Risk Breakdown um anomaly_score erweitern
- Host Overview um Anomaly Count erweitern
- AI-Prompt um Anomaly-Kontext erweitern

---

### Phase 3: Eigene Detector erstellen

Erst danach eigene Detectors automatisch oder halbautomatisch erstellen.

Aufgaben:

- Detector für 4625-Spikes
- Detector für 7045/7040 Service Changes
- Detector für Event-Volumen pro Host
- Detector für FIM-Spikes

---

### Phase 4: Correlation Engine

Aufgaben:

- Anomalies mit Events verbinden
- Anomalies mit Baseline-Deviations verbinden
- Anomalies mit Threat Intel verbinden
- Angriffsketten erkennen

---

## Beispiel: Correlation Rules

### Rule 1: Login Spike ohne Erfolg

```text
IF anomaly failed_logon_spike
AND no successful 4624 after burst
AND same target user
THEN medium
```

### Rule 2: Login Spike mit Erfolg

```text
IF anomaly failed_logon_spike
AND successful 4624 after burst
THEN high
```

### Rule 3: Service Install + Suspicious Path

```text
IF anomaly service_change_spike
AND event_id 7045
AND path contains AppData or Temp
THEN high
```

### Rule 4: Service Install + Trusted Vendor

```text
IF anomaly service_change_spike
AND event_id 7045
AND vendor is trusted
AND path is Program Files or WindowsApps
THEN low/medium
```

### Rule 5: FIM Spike + Package Update

```text
IF anomaly fim_spike
AND apt/dpkg/windows update activity nearby
THEN low
```

### Rule 6: FIM Spike + Sensitive Path

```text
IF anomaly fim_spike
AND path in /etc/ssh or /etc/sudoers.d or C:\Windows\System32
THEN medium/high
```

---

## AI-Prompt-Erweiterung

Wenn Anomaly-Daten vorhanden sind, sollte die KI folgenden Kontext bekommen:

```text
Anomaly Context:
- Detector: failed_logon_spike
- anomaly_grade: 0.72
- confidence: 0.91
- affected_entity: SWE-13
- time_window: 08:00-08:05
- related_events: 4625 x 120

Important:
This anomaly means statistical deviation, not confirmed compromise.
Only increase severity if supported by additional evidence.
```

---

## Beispiel-Ausgabe der App

```text
Risk Level: MEDIUM
Risk Score: 5.4 / 10

Eine statistische Anomalie wurde erkannt: fehlgeschlagene Logins auf SWE-13 liegen deutlich über dem normalen Verhalten. Die Anomalie allein beweist keinen Angriff, erhöht aber die Priorität der Prüfung.

Warum relevant:
- 4625-Events liegen deutlich über Baseline
- anomaly_grade 0.72 bei confidence 0.91
- mehrere Zielkonten betroffen

Spricht dagegen:
- keine externe Quelle erkannt
- kein erfolgreicher 4624 nach dem Burst
- keine Threat-Intel-Treffer

Nächste Checks:
- 4624 nach den 4625-Events prüfen
- Zielkonten und Quellhosts gruppieren
- prüfen, ob ein Dienst falsche Credentials verwendet
```

---

## Sicherheitsaspekte

### OpenSearch API absichern

Die OpenSearch API sollte intern bleiben.

Empfehlungen:

- kein öffentlicher Zugriff auf Port 9200
- kein öffentlicher Zugriff auf Port 55000
- Zugriff nur aus Admin-Netz
- starke Passwörter
- API-Zugriffe loggen

---

## Docker-spezifische Hinweise

Da Wazuh bei dir in Docker läuft:

- keine apt/yum-Upgrades im Container ausführen
- Images über docker compose aktualisieren
- Volumes behalten die Daten
- Zertifikate nur neu generieren, wenn notwendig

Update-Beispiel:

```bash
cd /root/wazuh-docker/single-node
nano docker-compose.yml
# Images auf 4.14.5 setzen

docker compose down
docker compose pull
docker compose up -d
```

---

## Health Checks nach Update

```bash
docker ps
```

```bash
curl -k -u admin https://localhost:9200/_cluster/health?pretty
```

```bash
curl -k -u admin https://localhost:9200/_cat/nodes?v
```

```bash
curl -k -u admin https://localhost:9200/_cat/plugins?v
```

---

## Mögliche UI-Komponenten

### Dashboard Card

```text
Anomaly Detection
Active: 4
Highest Grade: 0.72
Affected Hosts: 3
Confidence Avg: 0.86
```

### Host Detail

```text
Host Anomaly Summary
- Last anomaly: 08:12
- Detector: failed_logon_spike
- Grade: 0.72
- Confidence: 0.91
```

### Full Scan Report

```text
Anomaly Signals
- 2 anomalies in last 24h
- Highest grade: 0.72
- No TI match
- No suspicious command line
- Risk impact: +1.2
```

### Baseline Tab

```text
Known State
- Normal 4625/h: 3
- Current 4625/h: 85
- Anomaly: yes
```

---

## Warum das Enterprise-Level ist

Ein einfaches SIEM zeigt:

```text
Event X ist passiert.
```

Ein besseres SIEM zeigt:

```text
Event X ist ungewöhnlich.
```

Deine App soll zeigen:

```text
Event X ist ungewöhnlich, aber für diesen Host wahrscheinlich harmlos.
Oder:
Event X ist ungewöhnlich und zusammen mit Y und Z wahrscheinlich kritisch.
```

Das ist der eigentliche Mehrwert.

---

## Zusammenfassung

Die OpenSearch Anomaly Detection ist keine Konkurrenz zur eigenen App.

Sie ist eine zusätzliche Signalquelle.

Die eigene App sollte sie nutzen, um:

- Full Scans besser zu bewerten
- Baseline-Abweichungen zu priorisieren
- Host-Risiken verständlicher zu machen
- Angriffsketten sichtbarer zu machen
- False Positives zu reduzieren

Die beste Architektur ist:

```text
Wazuh = Sensorik
OpenSearch AD = statistische Auffälligkeiten
Eigene App = Entscheidung, Erklärung, Priorisierung
```

---

## Empfohlene nächste Schritte

1. Plugin-Liste prüfen
2. Detectors suchen
3. Anomaly Results testen
4. Backend-Service `wazuh_anomaly_service.py` bauen
5. Full Scan Risk Breakdown erweitern
6. Host Overview um Anomaly-Signale erweitern
7. Baseline mit Anomaly-Kontext verbinden
8. Danach eigene Detectors erstellen

---

## Kurzfassung für Copilot / Codex

```text
We want to integrate OpenSearch Anomaly Detection results from the Wazuh Indexer into our Wazuh AI Analyzer app.

Do not replace our baseline/scoring system.
Use anomaly results as an additional signal.

Implement backend service:
backend/services/wazuh_anomaly_service.py

Functions:
- list_anomaly_detectors()
- get_recent_anomalies(host=None, hours=24)
- normalize_anomaly_result(raw)

Integrate into:
- Full Scan risk breakdown as anomaly_score
- Host overview as anomaly_count/highest_grade
- Baseline page as statistical deviation context
- AI prompt as Anomaly Context

Important scoring rule:
Anomaly alone must not become HIGH.
Only increase risk strongly when combined with suspicious behavior, baseline deviation, threat intel, or attack-chain evidence.
```

