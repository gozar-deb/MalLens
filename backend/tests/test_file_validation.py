from app.utils.file_validation import validate_upload


def test_rejects_oversized_file():
    result = validate_upload("big.exe", b"MZ", 200 * 1024 * 1024, max_mb=100)
    assert not result.allowed


def test_rejects_media_extension():
    result = validate_upload("cat.png", b"\x89PNG\r\n\x1a\n", 1000, max_mb=100)
    assert not result.allowed


def test_accepts_pe_by_magic_bytes():
    result = validate_upload("sample.exe", b"MZ\x90\x00", 1000, max_mb=100)
    assert result.allowed
    assert result.detected_kind == "pe"


def test_accepts_pdf_by_magic_bytes():
    result = validate_upload("doc.pdf", b"%PDF-1.4", 1000, max_mb=100)
    assert result.allowed
