"""Optional. Downloads known-malware hashes from MalwareBazaar into hashes.txt.
  python3 sync_hashes.py          last 48h (small, fast)
  python3 sync_hashes.py --full   everything (big, slow, ~1-2 GB RAM briefly)"""
import csv, io, sys, zipfile
import httpx

url = "https://bazaar.abuse.ch/export/csv/" + ("full/" if "--full" in sys.argv else "recent/")
print("Downloading", url)
r = httpx.get(url, timeout=300, follow_redirects=True)
r.raise_for_status()
z = zipfile.ZipFile(io.BytesIO(r.content))
raw = z.read(z.namelist()[0]).decode("utf-8", "ignore").splitlines()
head = next((l.lstrip("# ") for l in raw if l.startswith("#") and "sha256_hash" in l), None)
data = [l for l in raw if l.strip() and not l.startswith("#")]
lines = ([head] + data) if head else data   # header is a "# ..." comment line in the export
n = 0
with open("hashes.txt", "w") as out:
    for row in csv.DictReader(lines, skipinitialspace=True):
        h = (row.get("sha256_hash") or "").strip('" ').lower()
        if len(h) == 64:
            fam = (row.get("signature") or "unknown").strip('" ').replace(" ", "_") or "unknown"
            out.write(f"{h} {fam}\n"); n += 1
print("Saved", n, "hashes to hashes.txt")
