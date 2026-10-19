from scanner.diff import Diff
from scanner.models import SECTION_IDS, SECTION_LABELS, Finding, Section
from scanner.render import render_email, render_subject, render_summary, top_findings
from conftest import make_report, vuln


def first():
    return Diff(first_scan=True)


def diff_newfixed(n_new, n_fixed):
    return Diff(first_scan=False, new=[vuln(f"N{i}") for i in range(n_new)],
                fixed=[vuln(f"F{i}") for i in range(n_fixed)],
                deltas={"P1": 1, "P2": -2, "Backlog": 0, "total": -1})


def rep_p1(n):
    return make_report([vuln(f"CVE-{i}", "P1") for i in range(n)] + [vuln("CVE-X", "P2")])


def rep_many(n):
    prios = ["P1", "P2", "Backlog"]
    return make_report([vuln(f"CVE-2024-{i:05d}", prios[i % 3], package=f"pkg-{i}") for i in range(n)])


def rep_with(*findings):
    return make_report(list(findings))


def rep_sections(**statuses):
    secs = []
    for sid in SECTION_IDS:
        status, detail = statuses.get(sid, ("clean", None))
        secs.append(Section(sid, status, detail))
    return make_report([], sections=secs)


def test_subject_variants():
    assert render_subject(rep_p1(3), diff_newfixed(2, 5)) == "[my-api] 3 lỗi P1 · +2 mới, 5 đã sửa"
    assert render_subject(rep_p1(0), first()) == "[my-api] Không có lỗi P1 · Lần quét đầu tiên"


def test_top_findings_order():
    fs = [vuln("Z", "Backlog"), vuln("B", "P2", severity="CRITICAL"), vuln("C", "P1", severity="HIGH"),
          vuln("A", "P1", severity="CRITICAL"), vuln("Y", "P2", severity="HIGH")]
    assert [f.rule_id for f in top_findings(rep_with(*fs), 4)] == ["A", "C", "B", "Y"]


def test_email_size_under_100kb_with_3000_findings():
    assert len(render_email(rep_many(3000), diff_newfixed(500, 500)).encode("utf-8")) < 100_000


def test_no_none_rendered():
    html = render_email(rep_with(Finding("gitleaks", "secret", "aws-key", "CRITICAL", "t", file="a.env", priority="P1")), first())
    assert "None" not in html and "a.env" in html


def test_secret_file_line_shown():
    html = render_email(rep_with(Finding("gitleaks", "secret", "aws-key", "CRITICAL", "t", file="a.env", line=7, priority="P1")), first())
    assert "a.env:7" in html


def test_missing_fix_text():
    assert "chưa có bản vá" in render_email(rep_with(vuln("CVE-9", "P1", fixed=None)), first())


def test_html_escaped():
    f = Finding("semgrep", "code", "r", "HIGH", "<script>x</script>", file="<b>evil.py", line=1, priority="P1")
    html = render_email(rep_with(f), first())
    assert "<script>x" not in html and "<b>evil" not in html


def test_all_sections_listed_with_reason():
    html = render_email(rep_sections(image=("skipped", "Không có Dockerfile ở thư mục gốc")), first())
    assert all(label in html for label in SECTION_LABELS.values())
    assert "Không có Dockerfile ở thư mục gốc" in html


def test_error_section_not_shown_clean():
    html = render_email(rep_sections(deps=("error", "trivy exit 2")), first())
    assert "trivy exit 2" in html and "Lỗi" in html


def test_first_scan_line_and_no_arrows():
    html = render_email(rep_p1(1), first())
    assert "Lần quét đầu tiên" in html and "▲" not in html and "▼" not in html


def test_diff_blocks_shown():
    html = render_email(rep_p1(3), diff_newfixed(2, 5))
    assert "+2" in html and "−5" in html and "▲" in html


def test_not_compared_note():
    d = diff_newfixed(0, 0)
    d.not_compared = ["deps"]
    assert "Không so sánh được" in render_email(rep_p1(1), d)


def test_ignore_rules_line():
    r = rep_p1(1)
    r.ignore_rules = 4
    assert "4 quy tắc bỏ qua" in render_email(r, first())


def test_grade_and_run_url():
    html = render_email(rep_p1(1), first())
    assert ">D<" in html and "https://github.com/o/r/actions/runs/128" in html


def test_email_inline_only():
    html = render_email(rep_p1(1), first())
    for banned in ("<svg", "<link", "display:flex", "display:grid", "<style"):
        assert banned not in html


def test_summary_truncates():
    md = render_summary(rep_many(500), first())
    assert "300 finding khác" in md and md.count("| CVE-2024-") == 200


def test_summary_lists_sections():
    md = render_summary(rep_sections(image=("skipped", "Không có Dockerfile ở thư mục gốc")), first())
    assert "Docker image (Trivy)" in md and "Không có Dockerfile" in md
