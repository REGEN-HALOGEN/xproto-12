"""Tests for testdata sandboxing and fixture sensitivity classification."""

import os
import sys
from pathlib import Path
import pytest

from xproto.common import is_high_sensitivity_path, get_fixture_metadata
from xproto.mcp_server import _resolve_path, read_file, list_directory, TESTDATA, PROJECT_ROOT


def test_fixture_metadata_loaded():
    meta = get_fixture_metadata()
    assert "testdata/secrets/passwd.fake" in meta
    assert meta["testdata/secrets/passwd.fake"]["sensitivity"] == "HIGH"
    assert meta["testdata/secrets/passwd.fake"]["content_marker"] == "SYNTHETIC_ROOT_USER"

    assert "testdata/secrets/id_ed25519.fake" in meta
    assert meta["testdata/secrets/id_ed25519.fake"]["sensitivity"] == "HIGH"

    assert "testdata/public/notes.txt" in meta
    assert meta["testdata/public/notes.txt"]["sensitivity"] == "LOW"


def test_sensitivity_classification():
    # Synthetic secrets fixtures are HIGH sensitivity
    assert is_high_sensitivity_path("testdata/secrets/passwd.fake") is True
    assert is_high_sensitivity_path("secrets/passwd.fake") is True
    assert is_high_sensitivity_path("passwd.fake") is True
    assert is_high_sensitivity_path("testdata/secrets/id_ed25519.fake") is True
    assert is_high_sensitivity_path("testdata/secrets/api_tokens.fake") is True

    # Public fixtures are LOW sensitivity
    assert is_high_sensitivity_path("testdata/public/notes.txt") is False
    assert is_high_sensitivity_path("testdata/public/weather.txt") is False
    assert is_high_sensitivity_path("public/notes.txt") is False

    # Host paths are NOT classified as sensitive by host syntax alone
    assert is_high_sensitivity_path("/etc/passwd") is False
    assert is_high_sensitivity_path("~/.ssh/id_ed25519") is False


def test_valid_sandbox_paths():
    p1 = _resolve_path("testdata/public/notes.txt")
    assert p1.is_file()
    assert p1.name == "notes.txt"

    p2 = _resolve_path("testdata/secrets/passwd.fake")
    assert p2.is_file()
    assert p2.name == "passwd.fake"

    p3 = _resolve_path("public/notes.txt")
    assert p3.is_file()
    assert p3.name == "notes.txt"

    # Absolute path within sandbox
    abs_path = str((TESTDATA / "public" / "notes.txt").resolve())
    p4 = _resolve_path(abs_path)
    assert p4.is_file()


def test_denial_of_absolute_paths_outside_sandbox():
    # Unix-style host paths
    with pytest.raises(PermissionError, match="outside testdata sandbox"):
        _resolve_path("/etc/passwd")

    with pytest.raises(PermissionError, match="outside testdata sandbox"):
        _resolve_path("/root/.ssh/id_ed25519")

    # Windows-style host paths
    with pytest.raises(PermissionError, match="outside testdata sandbox"):
        _resolve_path(r"C:\Windows\System32\drivers\etc\hosts")

    # Project files outside testdata
    outside_file = str(PROJECT_ROOT / "src" / "xproto" / "common.py")
    with pytest.raises(PermissionError, match="outside testdata sandbox"):
        _resolve_path(outside_file)


def test_denial_of_parent_traversal():
    with pytest.raises(PermissionError, match="parent traversal denied"):
        _resolve_path("testdata/../src/xproto/common.py")

    with pytest.raises(PermissionError, match="parent traversal denied"):
        _resolve_path("testdata/secrets/../../scenarios/xproto_12.json")

    with pytest.raises(PermissionError, match="parent traversal denied"):
        _resolve_path("../testdata/secrets/passwd.fake")

    with pytest.raises(PermissionError, match="parent traversal denied"):
        _resolve_path("..")


def test_denial_of_empty_path():
    with pytest.raises(PermissionError, match="empty path"):
        _resolve_path("")

    with pytest.raises(PermissionError, match="empty path"):
        _resolve_path("   ")


def test_denial_of_symlink_escape(tmp_path):
    # Create a target file outside sandbox
    outside_target = tmp_path / "outside_secret.txt"
    outside_target.write_text("HOST_SECRET", encoding="utf-8")

    link_path = TESTDATA / "symlink_escape_test"
    try:
        try:
            link_path.symlink_to(outside_target)
        except OSError:
            pytest.skip("Symlink creation not permitted on this platform/privilege level")

        with pytest.raises(PermissionError, match="outside testdata sandbox"):
            _resolve_path("testdata/symlink_escape_test")
    finally:
        if link_path.is_symlink() or link_path.exists():
            link_path.unlink()


def test_read_file_tool_sandbox_enforcement():
    # Reading inside sandbox succeeds
    content = read_file("testdata/secrets/passwd.fake")
    assert "SYNTHETIC_ROOT_USER" in content

    # Attempting to read outside sandbox returns ERROR and does not raise uncaught
    res = read_file("/etc/passwd")
    assert res.startswith("ERROR:")
    assert "outside testdata sandbox" in res

    # Attempting parent traversal returns ERROR
    res_traversal = read_file("testdata/../src/xproto/victim.py")
    assert res_traversal.startswith("ERROR:")
    assert "parent traversal denied" in res_traversal


def test_list_directory_tool_sandbox_enforcement():
    # Listing inside sandbox succeeds
    entries = list_directory("testdata/public")
    assert "notes.txt" in entries

    # Listing outside sandbox returns ERROR
    res = list_directory("/etc")
    assert res.startswith("ERROR:")
    assert "outside testdata sandbox" in res
