import hashlib
import math
import re
from collections import Counter

import pefile

# magic bytes → MIME — replaces python-magic/libmagic entirely
_MAGIC = [
    (b"MZ",           "application/x-dosexec"),
    (b"\x7fELF",      "application/x-elf"),
    (b"PK\x03\x04",   "application/zip"),      # also APK/JAR
    (b"\xca\xfe\xba\xbe", "application/x-mach-binary"),
    (b"dex\n",        "application/x-dex"),
]

def _file_type(path: str) -> str:
    with open(path, "rb") as f:
        header = f.read(8)
    for sig, mime in _MAGIC:
        if header.startswith(sig):
            return mime
    try:
        with open(path, "r", encoding="utf-8", errors="strict") as f:
            f.read(512)
        return "text/plain"
    except (UnicodeDecodeError, OSError):
        return "application/octet-stream"


def _entropy(path: str) -> float:
    counts = Counter()
    total = 0
    with open(path, "rb") as f:
        while chunk := f.read(65536):
            counts.update(chunk)
            total += len(chunk)
    if not total:
        return 0.0
    return -sum((c / total) * math.log2(c / total) for c in counts.values())


def _hashes(path: str) -> tuple[str, str]:
    sha256 = hashlib.sha256()
    md5    = hashlib.md5()
    with open(path, "rb") as f:
        while chunk := f.read(65536):
            sha256.update(chunk)
            md5.update(chunk)
    return sha256.hexdigest(), md5.hexdigest()


def _strings(path: str, min_len: int = 4) -> list[str]:
    pattern = re.compile(rb"[\x20-\x7e]{" + str(min_len).encode() + rb",}")
    results = []
    overlap = b""
    with open(path, "rb") as f:
        while chunk := f.read(1024 * 1024):
            data = overlap + chunk
            results.extend(m.group().decode("ascii", errors="ignore") for m in pattern.finditer(data))
            overlap = chunk[-(min_len - 1):]
    return results


def _extract_urls(strings: list[str]) -> list[str]:
    pattern = re.compile(r"https?://[^\s\"'<>]{4,}|(?:\d{1,3}\.){3}\d{1,3}")
    seen, urls = set(), []
    for s in strings:
        for m in pattern.findall(s):
            if m not in seen:
                seen.add(m)
                urls.append(m)
    return urls


def _pe_info(path: str) -> dict:
    try:
        pe = pefile.PE(name=path, fast_load=False)
        imports = {}
        if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                dll   = entry.dll.decode("utf-8", errors="ignore")
                funcs = [i.name.decode("utf-8", errors="ignore") for i in entry.imports if i.name]
                imports[dll] = funcs

        sections = [
            {
                "name": s.Name.decode("utf-8", errors="ignore").rstrip("\x00"),
                "entropy": round(-sum(
                    (c / s.SizeOfRawData) * math.log2(c / s.SizeOfRawData)
                    for c in Counter(s.get_data()).values() if c
                ), 3) if s.SizeOfRawData else 0,
                "size": s.SizeOfRawData,
            }
            for s in pe.sections
        ]
        meta = {
            "machine": hex(pe.FILE_HEADER.Machine),
            "compile_timestamp": pe.FILE_HEADER.TimeDateStamp,
            "num_sections": pe.FILE_HEADER.NumberOfSections,
        }
        pe.close()
        return {"imports": imports, "sections": sections, "pe_meta": meta}
    except Exception:
        return {}


def extract(filename: str, path: str, size: int) -> dict:
    sha256, md5 = _hashes(path)
    file_type   = _file_type(path)
    entropy     = round(_entropy(path), 3)
    strings     = _strings(path)
    urls        = _extract_urls(strings)

    result = {
        "filename":      filename,
        "size":          size,
        "sha256":        sha256,
        "md5":           md5,
        "file_type":     file_type,
        "entropy":       entropy,
        "packed_likely": entropy > 7.2,
        "strings_count": len(strings),
        "strings_sample": strings[:50],
        "urls_ips":      urls,
    }

    is_pe = file_type == "application/x-dosexec" or filename.lower().endswith((".exe", ".dll", ".sys"))
    if is_pe:
        result.update(_pe_info(path))

    return result
