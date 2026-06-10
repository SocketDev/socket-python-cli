"""Tests for brotli compression of the reachability facts file on upload.

The Socket full-scan endpoint transparently decompresses a multipart part named exactly
`.socket.facts.json.br`, so the CLI compresses the facts file before uploading it. These
tests cover the helpers in `Core` that do that rewriting.
"""
import json
import os

import pytest

try:
    import brotli
except ImportError:  # pragma: no cover - PyPy / non-CPython fallback
    import brotlicffi as brotli

from socketsecurity.core import (
    SOCKET_FACTS_BROTLI_FILENAME,
    SOCKET_FACTS_FILENAME,
    Core,
)


def _write(path, data: bytes):
    with open(path, "wb") as f:
        f.write(data)
    return path


def test_compress_facts_file_roundtrips(tmp_path):
    """The compressed sibling decompresses back to the exact original bytes."""
    source = tmp_path / SOCKET_FACTS_FILENAME
    payload = json.dumps({"components": [{"id": str(i)} for i in range(1000)]}).encode()
    _write(str(source), payload)

    compressed_path = Core._compress_facts_file(str(source))

    # Compressed file is a sibling named exactly `.socket.facts.json.br`.
    assert compressed_path == str(tmp_path / SOCKET_FACTS_BROTLI_FILENAME)
    assert os.path.basename(compressed_path) == SOCKET_FACTS_BROTLI_FILENAME
    # The original is untouched (other code paths still read it locally).
    assert source.read_bytes() == payload
    # Roundtrip matches.
    with open(compressed_path, "rb") as f:
        assert brotli.decompress(f.read()) == payload


def test_compress_for_upload_rewrites_facts_entry(tmp_path):
    """A `.socket.facts.json` entry is replaced by its `.br` sibling; others pass through."""
    core = Core.__new__(Core)
    facts = _write(str(tmp_path / SOCKET_FACTS_FILENAME), b'{"a": 1}')
    manifest = _write(str(tmp_path / "package.json"), b"{}")

    upload_files, temp_paths = core._compress_facts_files_for_upload([facts, manifest])

    expected_br = str(tmp_path / SOCKET_FACTS_BROTLI_FILENAME)
    assert upload_files == [expected_br, manifest]
    assert temp_paths == [expected_br]
    assert os.path.isfile(expected_br)
    # Non-facts files are never compressed.
    assert manifest in upload_files


def test_compress_facts_file_removes_partial_output_on_failure(tmp_path, monkeypatch):
    """If compression fails mid-stream, the half-written .br is removed (not orphaned)."""
    source = _write(str(tmp_path / SOCKET_FACTS_FILENAME), b'{"a": 1}' * 1000)

    class ExplodingCompressor:
        def __init__(self, *args, **kwargs):
            pass

        def process(self, _data):
            raise RuntimeError("disk full")

        def finish(self):  # pragma: no cover - never reached
            return b""

    # Patch the module the helper imports (brotli on CPython, brotlicffi elsewhere).
    monkeypatch.setattr(brotli, "Compressor", ExplodingCompressor)

    with pytest.raises(RuntimeError, match="disk full"):
        Core._compress_facts_file(source)

    # No orphaned .br left behind in the target directory.
    assert not (tmp_path / SOCKET_FACTS_BROTLI_FILENAME).exists()


def test_compress_for_upload_preserves_directory_prefix(tmp_path):
    """The `.br` sibling keeps the facts file's directory so the relative key is preserved."""
    core = Core.__new__(Core)
    subdir = tmp_path / "nested"
    subdir.mkdir()
    facts = _write(str(subdir / SOCKET_FACTS_FILENAME), b'{"a": 1}')

    upload_files, temp_paths = core._compress_facts_files_for_upload([facts])

    assert upload_files == [str(subdir / SOCKET_FACTS_BROTLI_FILENAME)]
    assert temp_paths == [str(subdir / SOCKET_FACTS_BROTLI_FILENAME)]


def test_empty_facts_file_is_not_compressed(tmp_path):
    """Empty placeholder facts files (e.g. baseline scans) are uploaded as-is."""
    core = Core.__new__(Core)
    empty_facts = _write(str(tmp_path / SOCKET_FACTS_FILENAME), b"")

    upload_files, temp_paths = core._compress_facts_files_for_upload([empty_facts])

    assert upload_files == [empty_facts]
    assert temp_paths == []
    assert not (tmp_path / SOCKET_FACTS_BROTLI_FILENAME).exists()


def test_custom_named_facts_file_is_not_compressed(tmp_path):
    """A custom --reach-output-file name is not compressed (server only matches the exact name)."""
    core = Core.__new__(Core)
    custom = _write(str(tmp_path / "custom.facts.json"), b'{"a": 1}')

    upload_files, temp_paths = core._compress_facts_files_for_upload([custom])

    assert upload_files == [custom]
    assert temp_paths == []


def test_compression_failure_falls_back_to_plain_file(tmp_path, monkeypatch):
    """If compression raises, the original plain file is uploaded instead of failing."""
    core = Core.__new__(Core)
    facts = _write(str(tmp_path / SOCKET_FACTS_FILENAME), b'{"a": 1}')

    def boom(_source_path):
        raise RuntimeError("brotli unavailable")

    monkeypatch.setattr(Core, "_compress_facts_file", staticmethod(boom))

    upload_files, temp_paths = core._compress_facts_files_for_upload([facts])

    assert upload_files == [facts]
    assert temp_paths == []
