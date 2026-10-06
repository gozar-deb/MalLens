"""File-type allow-listing and basic safety checks for uploads.

This module never executes or interprets file content -- it only inspects
magic bytes / extensions to decide whether a sample is an allowed carrier
type, per the "Allowed File Types" section of README.md.
"""
from dataclasses import dataclass

ALLOWED_EXTENSIONS = {
    ".exe", ".dll", ".sys",
    ".elf", ".so",
    ".macho", ".dylib",
    ".js", ".vbs", ".ps1", ".bat", ".cmd",
    ".pdf",
    ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx",
    ".zip", ".rar", ".7z",
    ".bin",
}

MAGIC_SIGNATURES = {
    b"MZ": "pe",
    b"\x7fELF": "elf",
    b"\xfe\xed\xfa\xce": "macho",
    b"\xfe\xed\xfa\xcf": "macho",
    b"\xcf\xfa\xed\xfe": "macho",
    b"%PDF": "pdf",
    b"PK\x03\x04": "zip_or_office",
    b"\xd0\xcf\x11\xe0": "ole",
    b"Rar!\x1a\x07": "rar",
    b"7z\xbc\xaf\x27\x1c": "7z",
}

BLOCKED_EXTENSIONS = {
    ".png", ".jpg", ".jpeg", ".gif", ".bmp", ".webp",
    ".mp4", ".mov", ".avi", ".mp3", ".wav",
}


@dataclass
class ValidationResult:
    allowed: bool
    reason: str
    detected_kind: str | None = None


def sniff_kind(header: bytes) -> str | None:
    for sig, kind in MAGIC_SIGNATURES.items():
        if header.startswith(sig):
            return kind
    return None


def validate_upload(filename: str, header: bytes, size_bytes: int, max_mb: int) -> ValidationResult:
    lower = filename.lower()
    ext = "." + lower.rsplit(".", 1)[-1] if "." in lower else ""

    if size_bytes > max_mb * 1024 * 1024:
        return ValidationResult(False, f"File exceeds the {max_mb}MB size limit.")

    if ext in BLOCKED_EXTENSIONS:
        return ValidationResult(False, f"'{ext}' is not a supported malware-carrier type.")

    kind = sniff_kind(header)

    if ext not in ALLOWED_EXTENSIONS and kind is None:
        return ValidationResult(
            False, "File type could not be identified as a supported sample type."
        )

    return ValidationResult(True, "ok", detected_kind=kind or ext.lstrip("."))
