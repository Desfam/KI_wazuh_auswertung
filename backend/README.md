# Backend

FastAPI backend for pulling Wazuh alerts from the Indexer, grouping them, applying local scoring, optionally calling Ollama, and storing reports in SQLite.

It also supports triggering a Python script on the Wazuh VM over SSH, then ingesting the generated TXT and JSON reports back into the app.

## Run

```bash
pip install -r requirements.txt
uvicorn main:app --reload --app-dir backend
```

## Remote VM script

The app can trigger a script on the Wazuh VM over SSH. The script version prepared for app control is in [backend/scripts/ai_wazuh_24h_v2.py](d:/PYTHON/KI_wazuh_auswertung/backend/scripts/ai_wazuh_24h_v2.py).

Example deployment on the VM:

```bash
scp backend/scripts/ai_wazuh_24h_v2.py user@wazuh-vm:/home/user/ai_wazuh_24h_v2.py
chmod +x /home/user/ai_wazuh_24h_v2.py
python3 /home/user/ai_wazuh_24h_v2.py --help
```
