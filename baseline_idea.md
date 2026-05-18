🧠 Wazuh + Anomaly Detection Integration (Konzept & Umsetzung)
📌 Überblick

Mit dem Update auf Wazuh 4.14.x entsteht der Eindruck, dass ein Anomaly Detector integriert wurde.
Tatsächlich basiert diese Funktion jedoch nicht auf Wazuh selbst, sondern auf dem darunterliegenden OpenSearch Anomaly Detection Plugin.

Das bedeutet:

👉 Wazuh liefert die Daten
👉 OpenSearch erkennt Anomalien
👉 Deine App kann daraus intelligente Entscheidungen ableiten

🧩 Architektur (vereinfacht)
[ Wazuh Agents ]
        ↓
[ Wazuh Manager ]
        ↓
[ Wazuh Indexer (OpenSearch) ]
        ↓
[ Anomaly Detection Plugin ]
        ↓
[ REST API (Results) ]
        ↓
[ Deine App / Analyzer ]
❗ Wichtige Erkenntnis

Der Anomaly Detector ist:

❌ kein eigenständiges Wazuh Feature
✅ ein OpenSearch Plugin (opensearch-anomaly-detection)
✅ bereits in vielen Setups vorhanden (aber oft ungenutzt)
🔍 Warum das für dich extrem wertvoll ist

Du musst:

❌ keine eigene ML/AI Detection bauen
❌ keine Zeit in mathematische Modelle investieren

Stattdessen:

✅ nutzt du bestehende Detection-Logik
✅ kombinierst sie mit deiner eigenen Analyse-Engine
⚙️ Schritt 1: Plugin prüfen
docker exec -it single-node-wazuh.indexer-1 \
/usr/share/wazuh-indexer/bin/opensearch-plugin list

Oder:

curl -k -u admin https://localhost:9200/_cat/plugins?v

Gesucht:

opensearch-anomaly-detection
opensearch-job-scheduler
⚙️ Schritt 2: Detector prüfen
curl -k -u admin https://localhost:9200/_plugins/_anomaly_detection/detectors/_search \
-H 'Content-Type: application/json' -d'
{
  "query": { "match_all": {} }
}'

Wenn leer → es existiert noch kein Detector.

⚙️ Schritt 3: Anomalien abrufen
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
📊 Wichtige Felder
Feld	Bedeutung
anomaly_grade	0–1 (wie stark die Anomalie ist)
confidence	Vertrauen in die Erkennung
anomaly_score	interner Score
entity	Host / User / Prozess
data_start_time	Zeitpunkt
🧠 Interpretation (sehr wichtig)

Der Detector sagt nur:

“Das ist ungewöhnlich”

NICHT:

“Das ist ein Angriff”

🔥 Genau hier kommt deine App ins Spiel

Deine App macht:

Anomaly + Kontext = echte Bewertung
🧪 Beispiel Logik
Case 1:
Anomaly (CPU Spike)
→ LOW

Case 2:
Anomaly + neuer Prozess
→ MEDIUM

Case 3:
Anomaly + Login Failures
→ HIGH

Case 4:
Anomaly + bekannte Malware IP
→ CRITICAL
🧩 Integration in deine App
Neue Service-Komponente
backend/services/wazuh_anomaly_service.py
Funktion
def get_recent_anomalies(host=None, hours=24):
    # 1. Query OpenSearch API
    # 2. Filter anomaly_grade > 0
    # 3. Map to internal structure
    # 4. Return normalized results
📊 Normalisierung (wichtig für UI)
anomaly_grade → severity

0.0 - 0.2 → LOW
0.2 - 0.5 → MEDIUM
0.5 - 0.8 → HIGH
0.8 - 1.0 → CRITICAL
🧠 Erweiterte Ideen
1. Baseline + Anomaly kombinieren
Deine Baseline erkennt:
→ "normal ist 10 login fails / Stunde"

Anomaly erkennt:
→ "jetzt sind es 200"

= sehr starke Detection
2. Host Risk Score
Score =

Anomaly * Gewicht
+ Failed Logins
+ Suspicious Processes
+ TI Treffer
3. Timeline View
08:00 → normal
09:00 → anomaly detected
09:05 → suspicious process
09:10 → outbound traffic spike

= perfekte Angriffskette

4. Auto Alerts
IF anomaly_grade > 0.7 AND confidence > 0.8
→ Alert triggern
⚡ Alternative Wege (falls du mehr Kontrolle willst)
Option A: Nur OpenSearch nutzen (empfohlen)
einfach
stabil
schnell
Option B: Eigene ML bauen
extrem aufwendig
selten nötig
Option C: Hybrid (beste Lösung)
OpenSearch → erkennt Muster
Deine App → bewertet Risiko
🧠 Fazit

Du hast gerade einen massiven Vorteil:

Du baust kein Tool gegen Wazuh
Du baust ein Tool AUF Wazuh
🚀 Nächste sinnvolle Schritte
Plugin prüfen
Detector erstellen (falls keiner existiert)
API testen
Service in deine App bauen
UI Integration (Dashboard / Alerts)