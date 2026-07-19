"""The email-spoofing verdict is a pure function over DNS records.

DMARC enforcement — not SPF — is what stops visible (From-header) spoofing, so the
verdict keys off DMARC policy and only falls back to SPF when DMARC is absent. These
cover every row of that table plus the record-parsing edge cases (missing SPF, pct<100,
mixed-case ``V=SPF1``, DMARC with only ``p=none``).
"""

from __future__ import annotations

import pytest

from webscanner.modules.dns import _dmarc_policy, _spf_qualifier, assess_spoofing

DMARC_REJECT = ["v=DMARC1; p=reject; rua=mailto:x@example.com"]
DMARC_QUARANTINE = ["v=DMARC1; p=quarantine"]
DMARC_NONE = ["v=DMARC1; p=none"]
SPF_HARD = ["v=spf1 include:_spf.google.com -all"]
SPF_SOFT = ["v=spf1 include:_spf.google.com ~all"]


# ---- _spf_qualifier -------------------------------------------------------


@pytest.mark.parametrize(
    "records, expected",
    [
        (SPF_HARD, "-all"),
        (SPF_SOFT, "~all"),
        (["v=spf1 ?all"], "?all"),
        (["v=spf1 +all"], "+all"),
        (["V=SPF1 include:foo -ALL"], "-all"),  # case-insensitive
        (["v=spf1 include:foo"], None),  # SPF but no `all`
        (["some other txt record"], None),  # no SPF at all
        ([], None),
    ],
)
def test_spf_qualifier(records, expected):
    assert _spf_qualifier(records) == expected


def test_spf_qualifier_ignores_non_spf_txt():
    txt = ["google-site-verification=abc", "v=spf1 mx -all"]
    assert _spf_qualifier(txt) == "-all"


# ---- _dmarc_policy --------------------------------------------------------


def test_dmarc_policy_defaults_pct_to_100():
    assert _dmarc_policy(DMARC_REJECT) == ("reject", 100)


def test_dmarc_policy_reads_pct():
    assert _dmarc_policy(["v=DMARC1; p=reject; pct=50"]) == ("reject", 50)


def test_dmarc_policy_none_when_absent():
    assert _dmarc_policy([]) == (None, 100)


def test_dmarc_policy_bad_pct_falls_back_to_100():
    assert _dmarc_policy(["v=DMARC1; p=quarantine; pct=abc"]) == ("quarantine", 100)


# ---- assess_spoofing (the verdict table) ----------------------------------


def test_reject_is_protected():
    verdict, _ = assess_spoofing(SPF_HARD, DMARC_REJECT, True)
    assert verdict == "Protected"


def test_quarantine_is_protected():
    verdict, _ = assess_spoofing(SPF_HARD, DMARC_QUARANTINE, True)
    assert verdict == "Protected (quarantine)"


def test_enforcing_policy_with_partial_pct_is_weak():
    verdict, reason = assess_spoofing(SPF_HARD, ["v=DMARC1; p=reject; pct=25"], True)
    assert verdict == "Weak"
    assert "pct=25" in reason


def test_p_none_is_weak_even_with_hard_spf():
    verdict, reason = assess_spoofing(SPF_HARD, DMARC_NONE, True)
    assert verdict == "Weak"
    assert "p=none" in reason


def test_hard_spf_no_dmarc_is_weak():
    verdict, reason = assess_spoofing(SPF_HARD, [], True)
    assert verdict == "Weak"
    assert "SPF -all" in reason


def test_soft_spf_no_dmarc_is_vulnerable():
    verdict, _ = assess_spoofing(SPF_SOFT, [], False)
    assert verdict == "Vulnerable"


def test_no_spf_no_dmarc_is_vulnerable():
    verdict, reason = assess_spoofing([], [], False)
    assert verdict == "Vulnerable"
    assert "no SPF" in reason
