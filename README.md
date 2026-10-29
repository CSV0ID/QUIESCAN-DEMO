# Quiescan Local

Upload a file in the browser, get a verdict. Runs only on your machine. The file is read, never run.

## Run it (Kali / Debian / Ubuntu)

```bash
cd quiescan-local
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
cp .env.example .env
nano .env                      # paste your Gemini key after GEMINI_API_KEY=
uvicorn app:app --port 8000
```

Open http://localhost:8000, choose a file, click **Scan file**.

If `pip install` fails on `yara-python`:
```bash
sudo apt install -y build-essential python3-dev libssl-dev
pip install -r requirements.txt
```

## The .env file

Only one value. Everything else in the original project (Firebase, Firestore, Upstash, Railway, Vercel) is NOT needed here.

| Name | Needed | Where to get it |
|------|--------|-----------------|
| `GEMINI_API_KEY` | Recommended | aistudio.google.com, Get API key, Create API key. Free tier is enough. |
| `GEMINI_MODEL` | No | Default `gemini-3.1-flash-lite` |
| `GEMINI_FALLBACK_MODEL` | No | Default `gemini-2.5-flash` |

Without a key the app still runs, but the AI step is skipped. Then only hash and YARA matches can flag a file, and a script like `control.py` comes back CLEAN.

The bottom of the page shows what loaded: hash count, YARA rules, Gemini key.

## Optional: known-malware hash list

```bash
python3 sync_hashes.py          # last 48 hours, small
python3 sync_hashes.py --full   # everything, large and slow
```
This writes `hashes.txt`. Restart the server after it finishes. A SHA-256 match then shows KNOWN MALWARE with the family name.

## Files

- `app.py` server and verdict logic
- `index.html` the page
- `extractor.py` hashes, entropy, strings, URLs, PE info
- `yara_scan.py` YARA matching (rules in `yara_rules/`, from Yara-Rules/rules, GPL-2.0)
- `llm.py` Gemini summary and risk score
- `sync_hashes.py` optional hash download
