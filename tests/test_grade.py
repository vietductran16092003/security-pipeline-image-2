import pytest

from scanner.grade import GRADE_COLORS, compute_grade
from scanner.models import Finding
from conftest import make_report, vuln


def _report(p1, p2, secrets=0):
    fs = [vuln(f"A{i}", "P1") for i in range(p1)] + [vuln(f"B{i}", "P2") for i in range(p2)]
    fs += [Finding("gitleaks", "secret", f"k{i}", "CRITICAL", "t", file="a", priority="P1") for i in range(secrets)]
    return make_report(fs)


@pytest.mark.parametrize("p1,p2,secrets,grade", [
    (0, 0, 0, "A"), (0, 1, 0, "B"), (0, 5, 0, "B"), (0, 6, 0, "C"),
    (1, 0, 0, "D"), (3, 9, 0, "D"), (4, 0, 0, "F"), (0, 0, 1, "F"),
])
def test_grade_table(p1, p2, secrets, grade):
    assert compute_grade(_report(p1, p2, secrets)) == grade


def test_colors_cover_all_grades():
    assert set(GRADE_COLORS) == set("ABCDF")
    assert GRADE_COLORS["A"] == GRADE_COLORS["B"] == "#16a34a"
    assert GRADE_COLORS["C"] == "#ca8a04"
    assert GRADE_COLORS["D"] == GRADE_COLORS["F"] == "#ef4444"
