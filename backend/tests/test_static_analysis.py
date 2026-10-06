"""Unit tests for the pure, offline parts of static_analysis.py.
No network, no execution of any sample."""
import math

from app.services.static_analysis import (
    detect_file_type,
    extract_strings,
    hash_file,
    shannon_entropy,
)


def test_hash_file_known_vectors():
    data = b"hello world"
    hashes = hash_file(data)
    assert hashes["md5"] == "5eb63bbbe01eeed093cb22bb8f5acdc3"
    assert len(hashes["sha1"]) == 40
    assert len(hashes["sha256"]) == 64


def test_entropy_of_uniform_bytes_is_zero():
    data = b"A" * 1000
    assert shannon_entropy(data) == 0.0


def test_entropy_of_random_bytes_is_high():
    import os

    data = os.urandom(4096)
    entropy = shannon_entropy(data)
    assert entropy > 7.5


def test_entropy_empty_is_zero():
    assert shannon_entropy(b"") == 0.0


def test_extract_strings_finds_ascii():
    data = b"\x00\x00hello_world_string\x00\x00hi\x00"
    strings = extract_strings(data)
    assert "hello_world_string" in strings
    assert "hi" not in strings  # below MIN_STRING_LEN (5)


def test_detect_file_type_pe():
    data = b"MZ" + b"\x00" * 100
    assert "PE" in detect_file_type(data, "sample.exe")


def test_detect_file_type_elf():
    data = b"\x7fELF" + b"\x00" * 100
    assert "ELF" in detect_file_type(data, "sample")


def test_detect_file_type_pdf():
    data = b"%PDF-1.4\n"
    assert "PDF" in detect_file_type(data, "sample.pdf")


def test_detect_file_type_unknown():
    data = b"not a known header"
    assert detect_file_type(data, "sample.bin") == "Unknown / raw binary"
