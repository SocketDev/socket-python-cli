from socketsecurity.socketcli import _normalize_workspace


def test_normalize_workspace_none():
    assert _normalize_workspace(None) is None


def test_normalize_workspace_empty_string():
    assert _normalize_workspace("") is None


def test_normalize_workspace_whitespace_string():
    assert _normalize_workspace("   ") is None


def test_normalize_workspace_valid_string():
    assert _normalize_workspace("my-workspace") == "my-workspace"

