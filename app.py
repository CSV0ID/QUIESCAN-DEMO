import os
import tempfile
from pathlib import Path

from dotenv import load_dotenv

load_dotenv()

from fastapi import FastAPI, File, HTTPException, UploadFile
from fastapi.responses import FileResponse

import extractor
import llm
import yara_scan

HERE = Path(__file__).parent
MAX_MB = 50
app = FastAPI(title="Quiescan Local")


def load_hashes() -> dict:
    """hashes.txt: one line per file, '<sha256> <family>'. Made by sync_hashes.py (optional)."""
    db, f = {}, HERE / "hashes.txt"
    if f.exists():
        with open(f, errors="ignore") as fh:
            for line in fh:
                h, _, fam = line.strip().partition(" ")
                if len(h) == 64:
                    db[h.lower()] = fam or "unknown"
    return db


HASHES = load_hashes()


def verdict(risk, family, hits):
    if family:
        return f"KNOWN MALWARE: {family['family']}"
    if hits and not any("error" in h for h in hits):
        return f"SUSPICIOUS: {len(hits)} YARA rule(s) matched"
    return {"low": "CLEAN", "medium": "SUSPICIOUS", "high": "LIKELY MALICIOUS", "critical": "MALICIOUS"}.get(risk, "UNKNOWN")


@app.get("/")
def home():
    return FileResponse(HERE / "index.html")


@app.get("/status")
def status():
    return {"hashes": len(HASHES), "yara": yara_scan._get_rules() is not None, "gemini": bool(os.environ.get("GEMINI_API_KEY"))}


@app.post("/analyze")
def analyze(file: UploadFile = File(...)):
    tmp = tempfile.NamedTemporaryFile(delete=False)
    path, size = tmp.name, 0
    try:
        with tmp:
            while chunk := file.file.read(65536):
                size += len(chunk)
                if size > MAX_MB << 20:
                    raise HTTPException(413, f"File too large (max {MAX_MB} MB)")
                tmp.write(chunk)
        if size == 0:
            raise HTTPException(400, "Empty file")
        features = extractor.extract(file.filename, path, size)
        hits = yara_scan.scan(path)
        fam = HASHES.get(features["sha256"])
        family = {"family": fam} if fam else None
        analysis = llm.analyze({**features, "yara_hits": hits, "known_family": family})
        return {**features, **analysis, "yara_hits": hits, "family_match": family,
                "verdict": verdict(analysis["risk_score"], family, hits)}
    finally:
        os.unlink(path)  # the file is only read, never run
