from scanner.diff import diff_reports
from scanner.models import SECTION_IDS, Section
from conftest import make_report, vuln


def _with_deps_status(findings, status):
    secs = [Section(sid, "clean") for sid in SECTION_IDS]
    secs[SECTION_IDS.index("deps")] = Section("deps", status, findings=list(findings))
    return make_report(findings, sections=secs)


def test_first_scan():
    d = diff_reports(make_report([vuln("A")]), None)
    assert d.first_scan and d.new == [] and d.fixed == [] and d.deltas == {} and d.not_compared == []


def test_new_and_fixed():
    prev = make_report([vuln("A"), vuln("B")])
    cur = make_report([vuln("B"), vuln("C")])
    d = diff_reports(cur, prev)
    assert not d.first_scan
    assert [f.rule_id for f in d.new] == ["C"]
    assert [f.rule_id for f in d.fixed] == ["A"]


def test_errored_section_excluded():
    prev = _with_deps_status([], "error")
    cur = make_report([vuln(f"C{i}") for i in range(50)])
    d = diff_reports(cur, prev)
    assert d.new == [] and d.fixed == []
    assert "deps" in d.not_compared
    assert d.deltas["total"] == 0


def test_skipped_section_excluded():
    prev = make_report([vuln("A")])
    cur = _with_deps_status([], "skipped")
    d = diff_reports(cur, prev)
    assert d.fixed == [] and "deps" in d.not_compared


def test_skipped_in_both_not_reported():
    prev = _with_deps_status([], "skipped")
    cur = _with_deps_status([], "skipped")
    assert diff_reports(cur, prev).not_compared == []


def test_deltas():
    prev = make_report([vuln("A", "P1"), vuln("B", "P2")])
    cur = make_report([vuln("A", "P1"), vuln("C", "P1"), vuln("D", "P1")])
    d = diff_reports(cur, prev)
    assert d.deltas == {"P1": 2, "P2": -1, "Backlog": 0, "total": 1}
