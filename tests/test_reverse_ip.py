"""``reverse_ip_lookup`` is one HTTP call over hackertarget.com whose body is plain
text — a hostname list on success, a space-bearing sentinel on every failure mode
(bad input, no records, spent quota). It must return the hostnames on a real result
and ``None`` on everything else, so the Server panel shows ``(Shared · N)`` only when
genuinely verified and never guesses from an error string.
"""

from __future__ import annotations

from unittest.mock import Mock, patch

import pytest

from webscanner.net import http


def _resp(text: str, status: int = 200) -> Mock:
    r = Mock()
    r.status_code = status
    r.text = text
    return r


def _call(resp: Mock) -> list[str] | None:
    with patch("webscanner.net.http.requests.get", return_value=resp):
        return http.reverse_ip_lookup("1.2.3.4")


def test_hostname_list_returned() -> None:
    assert _call(_resp("a.com\nwww.a.com\nb.org\n")) == ["a.com", "www.a.com", "b.org"]


def test_single_hostname_is_a_result_not_an_error() -> None:
    # One space-free domain is a legitimate (unshared) result, not a sentinel.
    assert _call(_resp("solo.example\n")) == ["solo.example"]


@pytest.mark.parametrize(
    "body",
    [
        "error check your search parameter",          # invalid input
        "No DNS A records found",                      # no hostnames on the IP
        "API count exceeded - Increase Quota with Membership",  # 50/day quota spent
        "",                                            # empty body
        "   \n  ",                                     # whitespace only
    ],
)
def test_sentinels_return_none(body: str) -> None:
    assert _call(_resp(body)) is None


def test_non_200_returns_none() -> None:
    assert _call(_resp("a.com\nb.com", status=429)) is None


def test_network_error_returns_none() -> None:
    with patch(
        "webscanner.net.http.requests.get",
        side_effect=http.requests.exceptions.ConnectionError(),
    ):
        assert http.reverse_ip_lookup("1.2.3.4") is None
