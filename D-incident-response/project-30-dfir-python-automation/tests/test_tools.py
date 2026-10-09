#!/usr/bin/env python3
"""Minimal tests for the DFIR tools. Run:  python3 -m pytest -q   (or python3 tests/test_tools.py)"""
import os, sys, tempfile
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "scripts"))

import hashit, iocextract


def test_hash_file_known_value():
    with tempfile.NamedTemporaryFile("wb", delete=False) as f:
        f.write(b"abc"); p = f.name
    md5, sha, size = hashit.hash_file(p)
    os.unlink(p)
    assert md5 == "900150983cd24fb0d6963f7d28e17f72"
    assert sha == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    assert size == 3


def test_ioc_refang_and_extract():
    text = "c2 at hxxp://bad[.]example from 203.0.113.70 and 10.0.0.5 internal"
    iocs = iocextract.extract(text)
    assert "203.0.113.70" in iocs["ipv4"]
    assert "10.0.0.5" not in iocs.get("ipv4", [])      # RFC1918 dropped
    assert "bad.example" in iocs["domain"]              # refanged
    assert any(u.startswith("http://bad.example") for u in iocs["url"])


def test_ioc_hashes():
    sha = "a" * 64
    iocs = iocextract.extract(f"hash {sha}")
    assert sha in iocs["sha256"]


if __name__ == "__main__":
    fails = 0
    for name, fn in list(globals().items()):
        if name.startswith("test_") and callable(fn):
            try:
                fn(); print(f"PASS {name}")
            except AssertionError as e:
                fails += 1; print(f"FAIL {name}: {e}")
    sys.exit(1 if fails else 0)
