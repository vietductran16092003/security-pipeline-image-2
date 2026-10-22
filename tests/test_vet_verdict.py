import itertools

import pytest

from scanner.vet.signals import ScanResult, Signal
from scanner.vet.verdict import Verdict, decide


def sig(level):
    return Signal("x", level, "f", 1, "why")


def res(levels=(), incomplete=()):
    return ScanResult([sig(l) for l in levels], list(incomplete))


def test_values():
    assert Verdict.NOT_SAFE == "Không nên mở"
    assert Verdict.SUSPICIOUS == "Đáng ngờ"
    assert Verdict.SAFER == "An toàn hơn"


@pytest.mark.parametrize("result,kw,expected", [
    (res(["high"]), {}, Verdict.NOT_SAFE),
    (res(["high"]), {"truncated": True}, Verdict.NOT_SAFE),
    (res(["high"], ["x"]), {"tool_errors": ["e"]}, Verdict.NOT_SAFE),
    (res(["high"]), {"fetch_error": "boom"}, Verdict.NOT_SAFE),
    (res(["medium"]), {}, Verdict.SUSPICIOUS),
    (res(["low"]), {}, Verdict.SUSPICIOUS),
    (res(), {"truncated": True}, Verdict.SUSPICIOUS),
    (res(incomplete=["big file"]), {}, Verdict.SUSPICIOUS),
    (res(), {"tool_errors": ["trivy timeout"]}, Verdict.SUSPICIOUS),
    (res(), {"fetch_error": "partial"}, Verdict.SUSPICIOUS),
    (res(), {}, Verdict.SAFER),
    (res(["info", "info"]), {}, Verdict.SAFER),
    (res(["info"], ["x"]), {}, Verdict.SUSPICIOUS),
    (None, {"fetch_error": "404"}, None),
    (None, {}, None),
    (None, {"truncated": True}, None),
])
def test_table(result, kw, expected):
    assert decide(result, **kw) == expected


def test_never_safer_property():
    levels = [(), ("info",), ("low",), ("medium",), ("high",), ("info", "low")]
    for lv, inc, trunc, te, fe in itertools.product(
        levels, [(), ("i",)], [False, True], [None, [], ["e"]], [None, "err"]
    ):
        v = decide(res(lv, inc), fetch_error=fe, truncated=trunc, tool_errors=te)
        non_info = any(l != "info" for l in lv)
        degraded = bool(inc or trunc or te or fe)
        assert v is not None and v in Verdict
        if (not ('high' in lv)) and (non_info or degraded):
            assert v == Verdict.SUSPICIOUS
        if v == Verdict.SAFER:
            assert not non_info and not degraded
        if "high" in lv:
            assert v == Verdict.NOT_SAFE
        if not non_info and not degraded:
            assert v == Verdict.SAFER


@pytest.mark.parametrize("level", ["critical", None, "", "bogus"])
def test_odd_levels_never_safer(level):
    assert decide(res([level])) == Verdict.SUSPICIOUS


@pytest.mark.parametrize("level", ["HIGH", "High", " high "])
def test_high_case_insensitive(level):
    assert decide(res([level])) == Verdict.NOT_SAFE


def test_empty_string_tool_error_counts():
    assert decide(res(), tool_errors=[""]) == Verdict.SUSPICIOUS


def test_empty_fetch_error_string_means_no_error():
    # fetch_error="" is falsy: treated as no error
    assert decide(res(), fetch_error="") == Verdict.SAFER
