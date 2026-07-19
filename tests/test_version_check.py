"""``check_for_update`` is a pure-ish core over a cache file + one HTTP call: it must
never raise (a broken update check must not surface as a broken scan), must use a
fresh cache instead of re-hitting PyPI, and must only report a genuinely newer version.
"""

from __future__ import annotations

import json
import time
from unittest.mock import Mock, patch

import pytest

from webscanner.net import version_check as vc


@pytest.mark.parametrize(
    "a, b, expected",
    [
        ("2.10.0", "2.9.9", True),   # numeric, not lexicographic, segment compare
        ("2.1.5", "2.1.5", False),
        ("2.1.6", "2.1.5", True),
        ("2.1.5", "2.1.6", False),
    ],
)
def test_parse_ordering(a: str, b: str, expected: bool) -> None:
    assert (vc._parse(a) > vc._parse(b)) is expected


def test_check_for_update_newer_available(tmp_path) -> None:
    cache = tmp_path / "version_check.json"
    resp = Mock()
    resp.json.return_value = {"info": {"version": "2.3.0"}}
    with patch.object(vc, "_cache_file", return_value=cache), \
         patch("webscanner.net.version_check.requests.get", return_value=resp) as get:
        assert vc.check_for_update("2.1.5") == "2.3.0"
        assert get.call_count == 1
    assert json.loads(cache.read_text())["latest"] == "2.3.0"


def test_check_for_update_already_current(tmp_path) -> None:
    cache = tmp_path / "version_check.json"
    resp = Mock()
    resp.json.return_value = {"info": {"version": "2.1.5"}}
    with patch.object(vc, "_cache_file", return_value=cache), \
         patch("webscanner.net.version_check.requests.get", return_value=resp):
        assert vc.check_for_update("2.1.5") is None


def test_check_for_update_uses_fresh_cache_without_a_request(tmp_path) -> None:
    cache = tmp_path / "version_check.json"
    cache.parent.mkdir(parents=True, exist_ok=True)
    cache.write_text(json.dumps({"latest": "2.3.0", "checked_at": time.time()}))
    with patch.object(vc, "_cache_file", return_value=cache), \
         patch("webscanner.net.version_check.requests.get") as get:
        assert vc.check_for_update("2.1.5") == "2.3.0"
        get.assert_not_called()


def test_check_for_update_refetches_stale_cache(tmp_path) -> None:
    cache = tmp_path / "version_check.json"
    cache.parent.mkdir(parents=True, exist_ok=True)
    stale = time.time() - vc._TTL_SECONDS - 1
    cache.write_text(json.dumps({"latest": "2.2.0", "checked_at": stale}))
    resp = Mock()
    resp.json.return_value = {"info": {"version": "2.4.0"}}
    with patch.object(vc, "_cache_file", return_value=cache), \
         patch("webscanner.net.version_check.requests.get", return_value=resp) as get:
        assert vc.check_for_update("2.1.5") == "2.4.0"
        assert get.call_count == 1


def test_check_for_update_silent_on_network_failure(tmp_path) -> None:
    cache = tmp_path / "version_check.json"
    with patch.object(vc, "_cache_file", return_value=cache), \
         patch("webscanner.net.version_check.requests.get", side_effect=OSError("boom")):
        assert vc.check_for_update("2.1.5") is None


def test_check_for_update_silent_on_bad_json(tmp_path) -> None:
    cache = tmp_path / "version_check.json"
    resp = Mock()
    resp.json.side_effect = ValueError("bad json")
    with patch.object(vc, "_cache_file", return_value=cache), \
         patch("webscanner.net.version_check.requests.get", return_value=resp):
        assert vc.check_for_update("2.1.5") is None
