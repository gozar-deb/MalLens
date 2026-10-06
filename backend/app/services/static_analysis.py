"""
Static analysis engine.

Everything in this module is read-only inspection of file bytes: hashing,
entropy, string extraction, PE/ELF parsing, and YARA matching. Nothing here
ever executes, interprets, or runs the sample. This is what makes "static"
analysis safe to do outside of a sandbox.
"""
from __future__ import annotations

import hashlib
import math
import re
from collections import Counter
from pathlib import Path
from typing import Any

MIN_STRING_LEN = 5
MAX_STRINGS_RETURNED = 500

_PRINTABLE_RE = re.compile(rb"[\x20-\x7e]{%d,}" % MIN_STRING_LEN)
_PRINTABLE_UTF16_RE = re.compile(rb"(?:[\x20-\x7e]\x00){%d,}" % MIN_STRING_LEN)

# A small, illustrative set of API-name substrings commonly associated with
# suspicious behavior when found in imports/strings. This is a heuristic
# aid for triage, not a verdict.
SUSPICIOUS_API_HINTS = [
    "VirtualAlloc", "VirtualProtect", "WriteProcessMemory", "CreateRemoteThread",
    "SetWindowsHookEx", "GetAsyncKeyState", "URLDownloadToFile", "WinExec",
    "ShellExecute", "InternetOpen", "CryptEncrypt", "RegSetValue", "IsDebuggerPresent",
    "AdjustTokenPrivileges", "NtUnmapViewOfSection", "LoadLibrary", "GetProcAddress",
]


def hash_file(data: bytes) -> dict[str, str]:
    return {
        "md5": hashlib.md5(data).hexdigest(),
        "sha1": hashlib.sha1(data).hexdigest(),
        "sha256": hashlib.sha256(data).hexdigest(),
    }


def shannon_entropy(data: bytes) -> float:
    """Byte-level Shannon entropy, 0.0 (uniform) to 8.0 (random/packed)."""
    if not data:
        return 0.0
    counts = Counter(data)
    length = len(data)
    entropy = 0.0
    for count in counts.values():
        p = count / length
        entropy -= p * math.log2(p)
    return round(entropy, 3)


def extract_strings(data: bytes, limit: int = MAX_STRINGS_RETURNED) -> list[str]:
    found: list[str] = []
    for m in _PRINTABLE_RE.finditer(data):
        found.append(m.group().decode("ascii", errors="ignore"))
        if len(found) >= limit:
            return found
    for m in _PRINTABLE_UTF16_RE.finditer(data):
        try:
            found.append(m.group().decode("utf-16le", errors="ignore"))
        except UnicodeDecodeError:
            continue
        if len(found) >= limit:
            break
    return found


def detect_file_type(data: bytes, filename: str) -> str:
    if data.startswith(b"MZ"):
        return "PE (Windows executable)"
    if data.startswith(b"\x7fELF"):
        return "ELF (Linux executable)"
    if data.startswith((b"\xfe\xed\xfa\xce", b"\xfe\xed\xfa\xcf", b"\xcf\xfa\xed\xfe")):
        return "Mach-O (macOS executable)"
    if data.startswith(b"%PDF"):
        return "PDF document"
    if data.startswith(b"PK\x03\x04"):
        lower = filename.lower()
        if lower.endswith(".docx"):
            return "Office Open XML (Word)"
        if lower.endswith(".xlsx"):
            return "Office Open XML (Excel)"
        if lower.endswith(".pptx"):
            return "Office Open XML (PowerPoint)"
        return "ZIP archive"
    if data.startswith(b"\xd0\xcf\x11\xe0"):
        return "Legacy MS Office (OLE2)"
    if data.startswith(b"Rar!\x1a\x07"):
        return "RAR archive"
    if data.startswith(b"7z\xbc\xaf\x27\x1c"):
        return "7-Zip archive"
    return "Unknown / raw binary"


def parse_pe(data: bytes) -> dict[str, Any] | None:
    """Parse a Windows PE file with `pefile`. Returns None for non-PE input
    or if the file is malformed (never raises on malformed input by design,
    since malware often ships intentionally-corrupt headers)."""
    try:
        import pefile
    except ImportError:
        return {"error": "pefile not installed"}

    try:
        pe = pefile.PE(data=data, fast_load=True)
        pe.parse_data_directories(
            directories=[
                pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_IMPORT"],
                pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_EXPORT"],
            ]
        )
    except Exception as exc:  # noqa: BLE001 - malformed PE is expected input
        return {"error": f"unparseable PE: {exc}"}

    imports: dict[str, list[str]] = {}
    if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            dll = entry.dll.decode(errors="ignore") if entry.dll else "unknown"
            funcs = [
                imp.name.decode(errors="ignore")
                for imp in entry.imports
                if imp.name
            ]
            imports[dll] = funcs

    sections = [
        {
            "name": s.Name.decode(errors="ignore").rstrip("\x00"),
            "virtual_size": s.Misc_VirtualSize,
            "raw_size": s.SizeOfRawData,
            "entropy": round(s.get_entropy(), 3),
        }
        for s in pe.sections
    ]

    result = {
        "machine": hex(pe.FILE_HEADER.Machine),
        "is_dll": pe.is_dll(),
        "is_exe": pe.is_exe(),
        "timestamp": pe.FILE_HEADER.TimeDateStamp,
        "entry_point": hex(pe.OPTIONAL_HEADER.AddressOfEntryPoint),
        "imports": imports,
        "sections": sections,
    }
    pe.close()
    return result


def yara_scan(data: bytes, rules_dir: str) -> list[dict[str, Any]]:
    """Compile and run every .yar/.yara rule file in rules_dir against the
    sample. Returns [] if yara-python isn't installed or no rules matched --
    never raises, since a missing/broken ruleset shouldn't fail the job."""
    try:
        import yara
    except ImportError:
        return []

    rule_files = {}
    p = Path(rules_dir)
    if p.is_dir():
        for f in list(p.glob("*.yar")) + list(p.glob("*.yara")):
            rule_files[f.stem] = str(f)

    if not rule_files:
        return []

    try:
        compiled = yara.compile(filepaths=rule_files)
        matches = compiled.match(data=data)
    except Exception:  # noqa: BLE001
        return []

    return [
        {
            "rule": m.rule,
            "tags": list(m.tags),
            "meta": dict(m.meta),
        }
        for m in matches
    ]


def find_suspicious_indicators(strings: list[str], imports: dict[str, list[str]] | None) -> list[str]:
    hits: set[str] = set()
    haystack = " ".join(strings)
    for api in SUSPICIOUS_API_HINTS:
        if api in haystack:
            hits.add(api)
    if imports:
        for funcs in imports.values():
            for f in funcs:
                if f in SUSPICIOUS_API_HINTS:
                    hits.add(f)
    return sorted(hits)


def analyze(data: bytes, filename: str, yara_rules_dir: str) -> dict[str, Any]:
    """Run the full static-analysis pipeline over raw file bytes and return
    a dict shaped for the StaticResult model."""
    hashes = hash_file(data)
    file_type = detect_file_type(data, filename)
    entropy = shannon_entropy(data)
    strings = extract_strings(data)

    imports = None
    sections = None
    if file_type.startswith("PE"):
        pe_info = parse_pe(data)
        if pe_info and "error" not in pe_info:
            imports = pe_info["imports"]
            sections = {"list": pe_info["sections"], "entry_point": pe_info["entry_point"]}

    yara_matches = yara_scan(data, yara_rules_dir)
    suspicious = find_suspicious_indicators(strings, imports)

    return {
        "hash_md5": hashes["md5"],
        "hash_sha1": hashes["sha1"],
        "hash_sha256": hashes["sha256"],
        "file_type": file_type,
        "file_size": len(data),
        "entropy": entropy,
        "imports": imports,
        "sections": sections,
        "strings": strings[:200],  # cap what's persisted; full list stays in `strings`
        "yara_matches": yara_matches,
        "suspicious_indicators": suspicious,
    }
