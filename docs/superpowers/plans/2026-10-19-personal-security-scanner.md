# Bộ quét bảo mật cá nhân: Kế hoạch triển khai

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Xây một repo mới, public, chứa reusable GitHub workflow. Workflow này tự nhận biết dự án gọi nó, chạy Gitleaks/Semgrep/Trivy/Conftest, xếp ưu tiên mọi finding bằng Rule Engine, so sánh với lần quét trước, rồi gửi email HTML "Hướng 1".

**Architecture:** Package Python `scanner/` làm hết phần logic: nhận biết dự án, chạy công cụ qua subprocess, parse, áp rule, chấm điểm, so sánh, render, gửi mail. Nhờ vậy toàn bộ logic test được bằng pytest. `scan.yml` chỉ làm vỏ mỏng: checkout dự án và bộ quét, cài công cụ, gọi `python -m scanner`, upload artifact, ghi Job Summary.

**Tech Stack:** Python 3.11, PyYAML, Jinja2, pytest; GitHub Actions; Trivy (binary), Gitleaks, Semgrep và Conftest (Docker image); Gmail SMTP qua `smtplib`.

**Spec:** `docs/superpowers/specs/2026-10-19-personal-security-scanner-design.md` (cùng mockup `2026-10-19-email-mockup.html`, cột "Hướng 1").

## Global Constraints

- Mọi job chạy trên `ubuntu-latest`. Không self-hosted runner, không registry nội bộ, không công cụ quét thương mại/DefectDojo, không gọi LLM.
- Repo mới, sạch, **public**. Repo cũ `security-pipeline-image` không được sửa (kể cả không commit file kế hoạch này vào đó).
- Không file nào trong repo mới được chứa tên hạ tầng nội bộ cũ hay tên người hướng dẫn (danh sách để ngoài repo) (không phân biệt hoa thường). Kiểm tra bằng grep trước mỗi lần push.
- Tìm thấy lỗi **không** được làm workflow đỏ. Chỉ khi không tạo được `report.json` thì mới đỏ.
- Mọi finding phải có `priority` thuộc `{"P1","P2","Backlog"}`.
- 4 trạng thái phần quét: `clean`, `findings`, `skipped` (kèm lý do), `error` (kèm thông báo). 6 phần quét, ID cố định: `secrets`, `code`, `deps`, `image`, `dockerfile_policy`, `iac`.
- Email: rộng tối đa 600px, layout bằng `<table>`, CSS inline, không SVG, không font ngoài. Mọi màu báo mức độ có chữ đi kèm.
- Pin version chính xác cho mọi action (`@vX.Y.Z` hoặc SHA) và Docker image công cụ. Không dùng `:latest`.
- Artifact báo cáo tên `security-report`, giữ 90 ngày.
- Secret của workflow: `SMTP_USERNAME`, `SMTP_PASSWORD`, `REPORT_EMAIL_TO`, đều không bắt buộc.
- Tiếng Việt cho mọi chữ người dùng nhìn thấy (email, summary, README).

## Review Focus

1. **Dự án có hàng nghìn finding** (repo cũ có 2718): Gmail cắt email lớn hơn 102KB. Email phải nằm dưới 100KB bất kể số finding. Test ở Task 7.
2. **Finding thiếu trường** (không có bản vá, không có package, secret chỉ có file/dòng): email hiện "chưa có bản vá" hoặc file:dòng, không được hiện `None`. Test ở Task 7.
3. **Nội dung finding chứa HTML** (message của Semgrep có `<script>`): phải được escape. Test ở Task 7.
4. **Báo cáo trước hỏng hoặc khác `schema_version`**: coi như lần quét đầu, không crash. Test ở Task 6 và Task 9.
5. **Công cụ trả exit 0 nhưng không ghi file output, hoặc file JSON hỏng**: phần đó là `error`, không phải `clean`. Test ở Task 8.

---

## Cấu trúc file (repo mới)

```
.github/workflows/scan.yml        # reusable workflow (workflow_call) - Task 10
.github/workflows/self-scan.yml   # repo tự quét chính nó - Task 10
scanner/__init__.py
scanner/__main__.py               # CLI: run | send - Task 9
scanner/models.py                 # Finding, Section, Report - Task 1
scanner/parsers.py                # parse_trivy/semgrep/gitleaks/conftest - Task 2
scanner/detect.py                 # nhận biết dự án - Task 3
scanner/rules.py                  # Rule Engine - Task 4
scanner/grade.py                  # điểm A–F - Task 5
scanner/diff.py                   # so sánh với lần trước - Task 6
scanner/render.py                 # email HTML + summary markdown - Task 7
scanner/templates/email.html.j2   # Task 7
scanner/runner.py                 # chạy công cụ, trạng thái phần quét - Task 8
scanner/previous.py               # lấy báo cáo lần trước - Task 9
scanner/mailer.py                 # gửi Gmail SMTP - Task 9
rules.yaml                        # Task 4
schema.json                       # Task 11
policy/docker.rego                # Task 10
agents/*.md                       # Task 11
tests/fixtures/*.json
tests/test_*.py
requirements.txt                  # PyYAML, Jinja2
requirements-dev.txt              # pytest
README.md                         # Task 11
docs/superpowers/specs/, docs/superpowers/plans/   # chép từ repo cũ - Task 1
```

---

### Task 1: Khởi tạo repo mới và mô hình dữ liệu

**Files:**
- Create: `scanner/__init__.py`, `scanner/models.py`, `tests/test_models.py`, `requirements.txt`, `requirements-dev.txt`, `.gitignore`
- Copy: `docs/superpowers/specs/2026-10-19-personal-security-scanner-design.md`, `docs/superpowers/specs/2026-10-19-email-mockup.html`, file kế hoạch này

**Interfaces:**
- Produces (`scanner/models.py`):
  - `SECTION_IDS: tuple[str, ...] = ("secrets", "code", "deps", "image", "dockerfile_policy", "iac")`
  - `SECTION_LABELS: dict[str, str]`, nhãn tiếng Việt: `secrets`→"Secret (Gitleaks)", `code`→"Code (Semgrep)", `deps`→"Thư viện (Trivy)", `image`→"Docker image (Trivy)", `dockerfile_policy`→"Dockerfile policy (Conftest)", `iac`→"Cấu hình IaC (Trivy)"
  - `@dataclass Finding`: `tool: str`, `kind: str` (`vuln|secret|code|policy|config`), `rule_id: str`, `severity: str` (`CRITICAL|HIGH|MEDIUM|LOW|UNKNOWN`), `title: str`, `package: str|None=None`, `installed_version: str|None=None`, `fixed_version: str|None=None`, `file: str|None=None`, `line: int|None=None`, `base_os_eol: bool=False`, `priority: str|None=None`, `reason: str|None=None`, `recommendation: str|None=None`; method `key() -> str` = `f"{tool}:{rule_id}:{package or file or ''}"`
  - `@dataclass Section`: `id: str`, `status: str`, `detail: str|None=None`, `findings: list[Finding]=field(default_factory=list)`
  - `@dataclass Report`: `project, branch, commit, run_id, run_url, scanned_at: str` (ISO 8601), `sections: list[Section]`, `ignore_rules: int=0`, `schema_version: int=1`; methods `all_findings() -> list[Finding]`, `counts() -> dict[str,int]` (khoá `P1`, `P2`, `Backlog`, `total`), `section(id) -> Section|None`, `to_json() -> str`, `@classmethod from_json(text: str) -> Report` (raise `ValueError` khi JSON hỏng hoặc `schema_version != 1`)

- [ ] **Step 1: Hỏi chủ repo tên repo mới** và tạo thư mục cục bộ cạnh repo cũ (ví dụ `D:\Project\<tên>`), `git init`, nhánh `main`. Chưa tạo repo trên GitHub ở bước này.
- [ ] **Step 2: Chép spec, mockup và kế hoạch** vào `docs/superpowers/` của repo mới. Tạo `requirements.txt` (`PyYAML>=6.0`, `Jinja2>=3.1`), `requirements-dev.txt` (`-r requirements.txt`, `pytest>=8`), và `.gitignore` (`__pycache__/`, `.venv/`, `scan-out/`, `.superpowers/`).
- [ ] **Step 3: Viết test fail** `tests/test_models.py`:

```python
def test_key_uses_package_then_file():
    assert Finding("trivy","vuln","CVE-1","HIGH","t",package="openssl").key() == "trivy:CVE-1:openssl"
    assert Finding("gitleaks","secret","aws-key","CRITICAL","t",file="a.env").key() == "gitleaks:aws-key:a.env"

def test_counts():
    r = make_report([Finding(..., priority="P1"), Finding(..., priority="P2"), Finding(..., priority="Backlog"), Finding(..., priority="P1")])
    assert r.counts() == {"P1": 2, "P2": 1, "Backlog": 1, "total": 4}

def test_json_roundtrip():
    r = make_report([...])
    assert Report.from_json(r.to_json()) == r

def test_from_json_rejects_bad_input():
    for bad in ["not json", '{"schema_version": 2}', "{}"]:
        with pytest.raises(ValueError):
            Report.from_json(bad)
```
(`make_report` là helper trong `tests/conftest.py`, tạo một `Report` với một Section `deps` chứa danh sách finding.)

- [ ] **Step 4: Chạy** `pytest tests/test_models.py -v`. Mong đợi: FAIL (ImportError).
- [ ] **Step 5: Hiện thực `scanner/models.py`** theo Interfaces. `from_json` gói mọi `KeyError`/`TypeError`/`JSONDecodeError` thành `ValueError`.
- [ ] **Step 6: Chạy** `pytest -v`. Mong đợi: PASS.
- [ ] **Step 7: Commit** `git add -A; git commit -m "chore: khởi tạo repo, mô hình dữ liệu Finding/Section/Report"`

---

### Task 2: Parser cho 4 công cụ

**Files:**
- Create: `scanner/parsers.py`, `tests/test_parsers.py`, `tests/fixtures/trivy-fs.json`, `trivy-image.json`, `trivy-config.json`, `semgrep.json`, `gitleaks.json`, `conftest.json`

**Interfaces:**
- Consumes: `Finding` (Task 1)
- Produces:
  - `parse_trivy(raw: dict) -> list[Finding]`: đọc `Results[].Vulnerabilities[]` (kind `vuln`, `rule_id`=VulnerabilityID, `package`=PkgName, `installed_version`, `fixed_version`=FixedVersion hoặc None, `file`=PkgPath hoặc Target, `title`=Title hoặc ID) và `Results[].Misconfigurations[]` (kind `config`, `rule_id`=ID, `file`=Target, `line`=CauseMetadata.StartLine, `title`). `base_os_eol` = `raw["Metadata"]["OS"]["EOSL"]` nếu có. Tool luôn là `"trivy"`.
  - `parse_semgrep(raw: dict) -> list[Finding]`: `results[]`, kind `code`, `rule_id`=check_id, `file`=path, `line`=start.line, `title`=extra.message; severity map `ERROR→HIGH`, `WARNING→MEDIUM`, `INFO→LOW`, khác→`UNKNOWN`.
  - `parse_gitleaks(raw: list) -> list[Finding]`: kind `secret`, severity `CRITICAL`, `rule_id`=RuleID, `file`=File, `line`=StartLine, `title`=Description. **Không** đưa giá trị `Secret`/`Match` vào bất kỳ trường nào.
  - `parse_conftest(raw: list) -> list[Finding]`: mỗi `failures[]` → kind `policy`, severity `HIGH`, `rule_id`=`"deny:" + msg[:60]`; mỗi `warnings[]` → severity `LOW`, `rule_id`=`"warn:" + msg[:60]`; `file`=filename, `title`=msg.

- [ ] **Step 1: Tạo fixture** bằng cách chạy thật mỗi công cụ (định dạng JSON) trên một dự án mẫu nhỏ có lỗ hổng, cắt gọn còn 2–3 phần tử mỗi file. Fixture gitleaks phải có trường `Secret` để test việc lọc bỏ.
- [ ] **Step 2: Viết test fail** `tests/test_parsers.py`:

```python
def test_trivy_vuln_fields(): f = parse_trivy(load("trivy-image.json"))[0]; assert (f.kind, f.tool) == ("vuln","trivy") and f.rule_id.startswith("CVE-") and f.package
def test_trivy_missing_fix_is_none(): assert any(f.fixed_version is None for f in parse_trivy(load("trivy-fs.json")))
def test_trivy_eosl_flag(): assert all(f.base_os_eol for f in parse_trivy(load("trivy-image.json")))  # fixture có EOSL: true
def test_trivy_misconfig(): f = parse_trivy(load("trivy-config.json"))[0]; assert f.kind == "config" and f.line is not None
def test_trivy_empty_results(): assert parse_trivy({"Results": None}) == [] and parse_trivy({}) == []
def test_semgrep_severity_map(): assert {f.severity for f in parse_semgrep(load("semgrep.json"))} <= {"HIGH","MEDIUM","LOW","UNKNOWN"}
def test_gitleaks_never_stores_secret():
    raw = load("gitleaks.json"); secret = raw[0]["Secret"]
    assert secret not in json.dumps([asdict(f) for f in parse_gitleaks(raw)])
def test_conftest_deny_and_warn(): sev = sorted(f.severity for f in parse_conftest(load("conftest.json"))); assert "HIGH" in sev and "LOW" in sev
```

- [ ] **Step 3: Chạy** `pytest tests/test_parsers.py -v`. Mong đợi: FAIL.
- [ ] **Step 4: Hiện thực** 4 hàm. Dùng `or []`/`.get()` ở mọi tầng để chịu được `null`.
- [ ] **Step 5: Chạy** `pytest -v`. Mong đợi: PASS.
- [ ] **Step 6: Commit** `"feat: parser cho Trivy, Semgrep, Gitleaks, Conftest"`

---

### Task 3: Nhận biết dự án

**Files:**
- Create: `scanner/detect.py`, `tests/test_detect.py`

**Interfaces:**
- Produces:
  - `@dataclass Profile`: `deps_files: list[str]`, `dockerfile: str|None`, `iac_files: list[str]`
  - `detect_project(root: Path) -> Profile`. Manifest: `package.json`, `package-lock.json`, `yarn.lock`, `pnpm-lock.yaml`, `requirements.txt`, `Pipfile.lock`, `poetry.lock`, `pyproject.toml`, `go.mod`, `pom.xml`, `build.gradle`, `*.csproj`, `packages.lock.json`, `Gemfile.lock`, `Cargo.lock`, `composer.lock`. Dockerfile: chỉ `root/Dockerfile`. IaC: `*.tf`, `Chart.yaml`, và file `*.yaml`/`*.yml` chứa cả `apiVersion:` lẫn `kind:`. Bỏ qua các thư mục `.git`, `node_modules`, `.venv`, `vendor`, `.scanner`.
  - `plan_sections(p: Profile) -> dict[str, str|None]`: khoá là mọi `SECTION_IDS`; `None` = chạy; chuỗi = lý do bỏ qua: `deps`→"Không tìm thấy file khai báo thư viện", `image` và `dockerfile_policy`→"Không có Dockerfile ở thư mục gốc", `iac`→"Không có file Terraform/Kubernetes/Helm". `secrets` và `code` luôn là `None`.

- [ ] **Step 1: Viết test fail** dùng `tmp_path`:

```python
def test_empty_project(tmp_path):
    plan = plan_sections(detect_project(tmp_path))
    assert plan["secrets"] is None and plan["code"] is None
    assert plan["deps"] and plan["image"] and plan["dockerfile_policy"] and plan["iac"]
def test_node_with_dockerfile(tmp_path): (tmp_path/"package.json").write_text("{}"); (tmp_path/"Dockerfile").write_text("FROM alpine"); plan = plan_sections(detect_project(tmp_path)); assert plan["deps"] is None and plan["image"] is None
def test_k8s_yaml_detected(tmp_path): (tmp_path/"k8s").mkdir(); (tmp_path/"k8s/d.yaml").write_text("apiVersion: v1\nkind: Pod\n"); assert detect_project(tmp_path).iac_files
def test_plain_yaml_not_iac(tmp_path): (tmp_path/"c.yml").write_text("a: 1\n"); assert not detect_project(tmp_path).iac_files
def test_node_modules_ignored(tmp_path): (tmp_path/"node_modules/x").mkdir(parents=True); (tmp_path/"node_modules/x/main.tf").write_text(""); assert not detect_project(tmp_path).iac_files
```

- [ ] **Step 2: Chạy** `pytest tests/test_detect.py -v`. Mong đợi: FAIL.
- [ ] **Step 3: Hiện thực** bằng `os.walk`, cắt bớt các thư mục bị bỏ qua. Chỉ đọc 4KB đầu của mỗi file YAML.
- [ ] **Step 4: Chạy** `pytest -v`. Mong đợi: PASS.
- [ ] **Step 5: Commit** `"feat: tự nhận biết dự án và lập kế hoạch phần quét"`

---

### Task 4: Rule Engine

**Files:**
- Create: `scanner/rules.py`, `rules.yaml`, `tests/test_rules.py`
- Tham khảo: `ai_triage/main.py` (`apply_rules`) và `ai_triage/rules.yaml` ở repo cũ

**Interfaces:**
- Consumes: `Finding`
- Produces: `load_rules(path: Path) -> list[dict]`; `apply_rules(findings: list[Finding], rules: list[dict]) -> None` (ghi `priority`, `reason`, `recommendation` vào từng finding; raise `ValueError` nếu có finding không khớp rule nào, hoặc rule có `priority` ngoài `P1|P2|Backlog`).

Cách đánh giá: giữ `eval(rule["when"], {"__builtins__": {}}, asdict(finding))` như repo cũ. Rule khớp đầu tiên thắng; lỗi khi eval thì coi như không khớp.

`rules.yaml` theo đúng thứ tự (mỗi rule có `name`, `when`, `priority`, `reason`, `recommendation` tiếng Việt):

| name | when | priority |
|---|---|---|
| secret_leak | `kind == 'secret'` | P1 |
| critical | `severity == 'CRITICAL'` | P1 |
| eol_medium_backlog | `base_os_eol and severity == 'MEDIUM'` | Backlog |
| high_fixable | `severity == 'HIGH' and kind in ('vuln','config','code') and (kind != 'vuln' or fixed_version)` | P1 |
| high_nofix | `severity == 'HIGH' and kind == 'vuln'` | P2 |
| policy_deny | `kind == 'policy' and rule_id.startswith('deny:')` | P2 |
| medium | `severity == 'MEDIUM'` | P2 |
| default_backlog | `True` | Backlog |

- [ ] **Step 1: Viết test fail**:

```python
@pytest.mark.parametrize("f,expected", [
    (Finding("gitleaks","secret","k","CRITICAL","t"), "P1"),
    (Finding("trivy","vuln","C","HIGH","t",fixed_version="1.2"), "P1"),
    (Finding("trivy","vuln","C","HIGH","t",fixed_version=None), "P2"),
    (Finding("trivy","vuln","C","MEDIUM","t",base_os_eol=True), "Backlog"),
    (Finding("trivy","vuln","C","MEDIUM","t"), "P2"),
    (Finding("conftest","policy","deny:x","HIGH","t"), "P2"),
    (Finding("conftest","policy","warn:x","LOW","t"), "Backlog"),
    (Finding("semgrep","code","r","UNKNOWN","t"), "Backlog"),
])
def test_real_rules(f, expected): apply_rules([f], load_rules(Path("rules.yaml"))); assert f.priority == expected and f.reason and f.recommendation
def test_unmatched_raises(): with pytest.raises(ValueError): apply_rules([Finding("t","vuln","C","LOW","t")], [{"name":"x","when":"False","priority":"P1","reason":"r","recommendation":"r"}])
def test_bad_priority_raises(): ...  # priority "P9" -> ValueError
def test_empty_list_ok(): apply_rules([], load_rules(Path("rules.yaml")))
```
(Policy không thuộc nhóm `kind` của `high_fixable`, nên deny rơi xuống `policy_deny` và thành P2, đúng spec mục 5.3.)

- [ ] **Step 2: Chạy** `pytest tests/test_rules.py -v`. Mong đợi: FAIL.
- [ ] **Step 3: Hiện thực** `scanner/rules.py` và `rules.yaml`.
- [ ] **Step 4: Chạy** `pytest -v`. Mong đợi: PASS.
- [ ] **Step 5: Commit** `"feat: Rule Engine xếp mọi finding vào P1/P2/Backlog"`

---

### Task 5: Điểm A–F

**Files:**
- Create: `scanner/grade.py`, `tests/test_grade.py`

**Interfaces:**
- Consumes: `Report`
- Produces: `compute_grade(report: Report) -> str` trả về `"A"|"B"|"C"|"D"|"F"`; `GRADE_COLORS: dict[str, str]` gồm `A`/`B`→`#16a34a`, `C`→`#ca8a04`, `D`/`F`→`#ef4444`.

Quy tắc (spec mục 6): F nếu P1 > 3 hoặc có bất kỳ finding `kind == "secret"`; D nếu P1 từ 1 đến 3; C nếu P1 = 0 và P2 > 5; B nếu P1 = 0 và P2 từ 1 đến 5; A nếu P1 = 0 và P2 = 0.

- [ ] **Step 1: Viết test fail** với bảng tham số: `(0,0,no secret)→A`, `(0,1)→B`, `(0,5)→B`, `(0,6)→C`, `(1,0)→D`, `(3,0)→D`, `(4,0)→F`, `(0,0,1 secret)→F`.
- [ ] **Step 2: Chạy**, mong đợi FAIL. **Step 3: Hiện thực.** **Step 4: Chạy** `pytest -v`, mong đợi PASS.
- [ ] **Step 5: Commit** `"feat: chấm điểm A–F"`

---

### Task 6: So sánh với lần quét trước

**Files:**
- Create: `scanner/diff.py`, `tests/test_diff.py`

**Interfaces:**
- Consumes: `Report`, `Finding.key()`
- Produces: `@dataclass Diff`: `first_scan: bool`, `new: list[Finding]`, `fixed: list[Finding]`, `deltas: dict[str,int]` (khoá `P1`, `P2`, `Backlog`, `total`; rỗng nếu `first_scan`), `not_compared: list[str]` (ID phần quét bị loại khỏi so sánh); `diff_reports(current: Report, previous: Report|None) -> Diff`.

Thuật toán: nếu `previous is None` thì `first_scan=True` và các trường khác rỗng. Ngược lại, tập phần quét so sánh được là những phần có status thuộc `{"clean","findings"}` ở **cả hai** báo cáo; các phần còn lại vào `not_compared`. `new` = finding của phần so sánh được có `key()` không có trong previous; `fixed` = ngược lại. `deltas` = `counts()` hiện tại trừ `counts()` trước, chỉ tính trên các phần so sánh được.

- [ ] **Step 1: Viết test fail**: `test_first_scan`; `test_new_and_fixed` (prev có A và B, cur có B và C → new=[C], fixed=[A]); `test_errored_section_excluded` (`deps` ở prev là `error`, cur là `findings` với 50 finding → `new == []`, `"deps" in not_compared`); `test_skipped_section_excluded`; `test_deltas` (prev P1=1, cur P1=3 → `deltas["P1"] == 2`).
- [ ] **Step 2: Chạy**, mong đợi FAIL. **Step 3: Hiện thực.** **Step 4: Chạy** `pytest -v`, mong đợi PASS.
- [ ] **Step 5: Commit** `"feat: so sánh với lần quét trước"`

---

### Task 7: Render email HTML và Job Summary

**Files:**
- Create: `scanner/render.py`, `scanner/templates/email.html.j2`, `tests/test_render.py`

**Interfaces:**
- Consumes: `Report`, `Diff`, `compute_grade`, `GRADE_COLORS`, `SECTION_LABELS`
- Produces:
  - `render_subject(report, diff) -> str`: `"[{project}] {n} lỗi P1"` hoặc `"[{project}] Không có lỗi P1"`, nối thêm `" · +{x} mới, {y} đã sửa"` khi không phải lần đầu, hoặc `" · Lần quét đầu tiên"`.
  - `render_email(report: Report, diff: Diff) -> str`: HTML.
  - `render_summary(report: Report, diff: Diff) -> str`: markdown cho `$GITHUB_STEP_SUMMARY`. Gồm bảng phần quét, bảng số liệu, và **tối đa 200** finding sắp theo P1 → P2 → Backlog, sau đó ghi "… và N finding khác, xem `report.json` trong artifact".
  - `top_findings(report, n=5) -> list[Finding]`: sắp theo priority (P1 < P2 < Backlog), rồi severity (CRITICAL trước), rồi `rule_id`.

Template theo mockup Hướng 1, viết lại bằng `<table>` và `style=""` inline. Thứ tự khối đúng như spec mục 6, gồm 9 mục: đầu email tối (`background:#0b1220` cùng `background-image:linear-gradient(135deg,#0b1220,#1e1b4b 55%,#4c0519)`), ô điểm, 4 ô số liệu kèm ▲/▼/"không đổi" (ẩn khi `first_scan`), dải tỉ lệ, khung cảnh báo, ô Lỗi mới/Đã sửa (thay bằng dòng "Lần quét đầu tiên" khi `first_scan`), "Cần xử lý trước" (top 5), nút "Xem đủ {total} lỗi" dẫn tới `run_url`, danh sách đủ 6 phần quét kèm trạng thái và lý do, dòng "Đang áp dụng {ignore_rules} quy tắc bỏ qua từ file ignore của dự án" khi `ignore_rules > 0`, dòng "Không so sánh được: …" khi `not_compared` khác rỗng, và footer. Jinja `Environment(autoescape=True)`.

Hiển thị theo loại finding: `vuln` → `package · installed_version`, bản vá là `fixed_version` hoặc "chưa có bản vá"; loại khác → `file:line` (bỏ `:line` khi `line` là None), không có cột bản vá.

> Ghi chú so với spec: Job Summary dùng markdown (`render_summary`) chứ không dán nguyên HTML email, vì GitHub không hiển thị CSS inline trong summary. Bản HTML đầy đủ nằm trong artifact (Task 10).
>
> Ghi chú thứ hai: các công cụ không báo số finding đã bị ignore, nên email hiện **số quy tắc bỏ qua** (đếm từ các file ignore, Task 8) thay cho "đã bỏ qua N finding".

- [ ] **Step 1: Viết test fail**:

```python
def test_subject_variants(): assert render_subject(rep_p1(3), diff_newfixed(2,5)) == "[my-api] 3 lỗi P1 · +2 mới, 5 đã sửa"; assert render_subject(rep_p1(0), first()) == "[my-api] Không có lỗi P1 · Lần quét đầu tiên"
def test_email_size_under_100kb_with_3000_findings(): assert len(render_email(rep_many(3000), first()).encode()) < 100_000
def test_no_none_rendered(): html = render_email(rep_with(Finding("gitleaks","secret","k","CRITICAL","t",file="a.env",priority="P1")), first()); assert "None" not in html and "a.env" in html
def test_missing_fix_text(): assert "chưa có bản vá" in render_email(rep_with(vuln_nofix_p1()), first())
def test_html_escaped(): html = render_email(rep_with(code_finding(title="<script>x</script>", priority="P1")), first()); assert "<script>x" not in html
def test_all_sections_listed(): html = render_email(rep_skipped_image(), first()); assert all(lbl in html for lbl in SECTION_LABELS.values()) and "Không có Dockerfile" in html
def test_error_section_not_shown_clean(): html = render_email(rep_error("deps","trivy exit 2"), first()); assert "trivy exit 2" in html
def test_email_inline_only(): html = render_email(rep_p1(1), first()); assert "<svg" not in html and "<link" not in html and "display:flex" not in html and "display:grid" not in html
def test_summary_truncates(): assert "finding khác" in render_summary(rep_many(500), first())
```
(Các helper `rep_*`, `first()`, `diff_newfixed()` đặt trong `tests/conftest.py`.)

- [ ] **Step 2: Chạy** `pytest tests/test_render.py -v`. Mong đợi: FAIL.
- [ ] **Step 3: Hiện thực** `render.py` và template.
- [ ] **Step 4: Chạy** `pytest -v`. Mong đợi: PASS.
- [ ] **Step 5: Xem bằng mắt:** ghi `render_email(...)` của dữ liệu mẫu (3 P1, có so sánh) ra `scan-out/preview.html`, mở trong trình duyệt ở độ rộng 600px và 375px, đối chiếu với mockup Hướng 1. Chủ repo xác nhận.
- [ ] **Step 6: Commit** `"feat: email HTML Hướng 1 và Job Summary"`

---

### Task 8: Chạy công cụ và xác định trạng thái phần quét

**Files:**
- Create: `scanner/runner.py`, `tests/test_runner.py`

**Interfaces:**
- Consumes: `detect_project`, `plan_sections`, các parser, `Section`
- Produces:
  - `Executor = Callable[[list[str], Path], int]` (lệnh, thư mục làm việc → exit code); `default_executor` chạy `subprocess.run`, timeout 600 giây, ghi stderr vào log.
  - `TOOL_IMAGES: dict[str,str]`: image Docker đã pin version cho `gitleaks`, `semgrep`, `conftest`. Trivy dùng binary có sẵn trên PATH (được cài ở Task 10).
  - `build_commands(section_id: str, root: Path, out: Path, scanner_dir: Path) -> list[list[str]]`:
    - `secrets`: `docker run --rm -v root:/repo gitleaks detect --source /repo --report-format json --report-path /repo/.scan-out/gitleaks.json --exit-code 0`
    - `code`: `docker run --rm -v root:/src semgrep semgrep scan --config auto --json --output /src/.scan-out/semgrep.json --metrics=off`
    - `deps`: `trivy fs --scanners vuln --format json --output out/trivy-fs.json root`
    - `image`: `docker build -t scan-target:local root`, sau đó `trivy image --format json --output out/trivy-image.json scan-target:local`
    - `dockerfile_policy`: `docker run --rm -v root:/project -v scanner_dir/policy:/policy conftest test /project/Dockerfile --policy /policy --parser dockerfile --all-namespaces --output json`. Exit 1 do có deny là bình thường; stdout ghi ra `out/conftest.json`.
    - `iac`: `trivy config --format json --output out/trivy-config.json root`
    - (Thư mục output thật là `root/.scan-out` để container ghi được; chép sang `out` sau mỗi bước.)
  - `run_scan(root: Path, out: Path, scanner_dir: Path, executor: Executor = default_executor) -> list[Section]`: trả về đúng 6 Section theo thứ tự `SECTION_IDS`. Phần bị bỏ qua → `skipped` kèm lý do của `plan_sections`. Phần chạy được: exit code không được chấp nhận (`dockerfile_policy` chấp nhận 0 và 1, các phần khác chỉ 0), thiếu file output, hoặc parse lỗi → `error` kèm detail ngắn (ví dụ `"docker build thất bại (exit 1)"`, `"không có file output"`, `"JSON không hợp lệ"`). Có finding → `findings`, không có → `clean`.
  - `count_ignore_rules(root: Path) -> int`: số dòng không rỗng, không bắt đầu bằng `#` trong `.gitleaksignore` và `.trivyignore`, cộng số lần xuất hiện `nosemgrep` trong các file text (bỏ qua các thư mục giống Task 3).

- [ ] **Step 1: Viết test fail** dùng `FakeExecutor` (ghi lại lệnh, trả exit code theo kịch bản và chép fixture của Task 2 vào thư mục output):

```python
def test_six_sections_in_order(tmp_path): assert [s.id for s in run_scan(tmp_path, out, sd, fake_ok())] == list(SECTION_IDS)
def test_skipped_has_reason(tmp_path): s = section(run_scan(tmp_path, out, sd, fake_ok()), "image"); assert s.status == "skipped" and "Dockerfile" in s.detail
def test_exit0_but_no_output_is_error(tmp_path): s = section(run_scan(proj_with_deps(tmp_path), out, sd, fake_no_output()), "deps"); assert s.status == "error"
def test_corrupt_json_is_error(tmp_path): ... fake_writes("trivy-fs.json", "{bad") -> status "error"
def test_docker_build_fail_is_error_others_continue(tmp_path): secs = run_scan(proj_with_dockerfile(tmp_path), out, sd, fake_fail_on("docker build")); assert section(secs,"image").status == "error" and section(secs,"secrets").status in ("clean","findings")
def test_conftest_exit1_ok(tmp_path): assert section(run_scan(proj_with_dockerfile(tmp_path), out, sd, fake_exit_for("conftest",1)), "dockerfile_policy").status == "findings"
def test_count_ignore_rules(tmp_path): (tmp_path/".trivyignore").write_text("# c\nCVE-1\n\nCVE-2\n"); (tmp_path/"a.py").write_text("x=1  # nosemgrep\n"); assert count_ignore_rules(tmp_path) == 3
```

- [ ] **Step 2: Chạy** `pytest tests/test_runner.py -v`. Mong đợi: FAIL.
- [ ] **Step 3: Hiện thực** `runner.py`. Pin `TOOL_IMAGES` theo bản ổn định mới nhất tại thời điểm làm, ghi đúng tag cụ thể.
- [ ] **Step 4: Chạy** `pytest -v`. Mong đợi: PASS.
- [ ] **Step 5: Thử thật** (máy có Docker): `python -c` gọi `run_scan` trên chính repo mới và trên một dự án mẫu có Dockerfile. Mong đợi: 6 Section, không phần nào `error` ngoài lý do chính đáng.
- [ ] **Step 6: Commit** `"feat: chạy công cụ quét và xác định trạng thái từng phần"`

---

### Task 9: Lấy báo cáo trước, gửi mail và CLI

**Files:**
- Create: `scanner/previous.py`, `scanner/mailer.py`, `scanner/__main__.py`, `tests/test_previous.py`, `tests/test_mailer.py`, `tests/test_cli.py`

**Interfaces:**
- Consumes: mọi thứ ở trên
- Produces:
  - `select_previous_artifact(artifacts: list[dict], branch: str, current_run_id: str, name: str = "security-report") -> int|None`: lọc theo `name`, `expired == False`, `workflow_run.head_branch == branch`, `workflow_run.id != current_run_id`; lấy `id` của artifact có `created_at` mới nhất.
  - `fetch_previous_report(repo: str, branch: str, run_id: str, token: str) -> Report|None`: gọi `GET /repos/{repo}/actions/artifacts?name=security-report&per_page=100`, chọn bằng hàm trên, tải `/actions/artifacts/{id}/zip`, đọc `report.json`, rồi `Report.from_json`. **Mọi** lỗi (mạng, 403, zip hỏng, `ValueError`) → trả `None` và in cảnh báo. Dùng `urllib.request`, không thêm thư viện.
  - `send_email(subject: str, html: str, user: str, password: str, to: str, smtp_factory=smtplib.SMTP_SSL) -> None`: tới `smtp.gmail.com:465`, MIME `multipart/alternative` gồm phần text ngắn và phần HTML, header `Subject` mã hoá UTF-8.
  - CLI `python -m scanner run --root PATH --out DIR --scanner-dir PATH`: đọc env `GITHUB_REPOSITORY`, `GITHUB_REF_NAME`, `GITHUB_SHA`, `GITHUB_RUN_ID`, `GITHUB_SERVER_URL`, `GITHUB_TOKEN` (thiếu thì dùng giá trị mặc định cục bộ: project = tên thư mục, branch `local`, previous = None). Thực hiện `run_scan` → `apply_rules` → tạo `Report` → `fetch_previous_report` → `diff_reports` → ghi `DIR/report.json`, `DIR/email.html`, `DIR/subject.txt`, `DIR/summary.md`. Exit 0 kể cả khi có finding; chỉ exit khác 0 khi không ghi được `report.json`. Project là phần sau dấu `/` của `GITHUB_REPOSITORY`.
  - CLI `python -m scanner send --out DIR`: nếu thiếu `SMTP_USERNAME`, `SMTP_PASSWORD` hoặc `REPORT_EMAIL_TO` thì in "Bỏ qua gửi email: thiếu secret SMTP" và exit 0. Lỗi SMTP → in lỗi và exit 0 (không làm workflow đỏ).

- [ ] **Step 1: Viết test fail**:

```python
def test_select_newest_same_branch(): arts = [a(1,"main","2026-10-01"), a(2,"main","2026-10-03"), a(3,"dev","2026-10-04"), a(4,"main","2026-10-05",expired=True)]; assert select_previous_artifact(arts, "main", "999") == 2
def test_select_excludes_current_run(): assert select_previous_artifact([a(5,"main","2026-10-06",run_id="999")], "main", "999") is None
def test_fetch_returns_none_on_http_error(monkeypatch): monkeypatch.setattr(urllib.request, "urlopen", raise_http(403)); assert fetch_previous_report("o/r","main","1","t") is None
def test_fetch_returns_none_on_old_schema(monkeypatch): ... zip with report.json schema_version 0 -> None
def test_send_email_uses_ssl_465(): fake = FakeSMTP(); send_email("s","<b>x</b>","u","p","to@x", smtp_factory=fake); assert fake.host == ("smtp.gmail.com",465) and fake.sent_to == ["to@x"]
def test_cli_run_writes_four_files(tmp_path, monkeypatch): # FakeExecutor không finding, không env GitHub
    main(["run","--root",str(proj),"--out",str(tmp_path),"--scanner-dir","."], executor=fake_ok()); assert {p.name for p in tmp_path.iterdir()} >= {"report.json","email.html","subject.txt","summary.md"}
def test_cli_send_without_secrets_exits_0(tmp_path, monkeypatch, capsys): assert main(["send","--out",str(tmp_path)]) == 0 and "Bỏ qua gửi email" in capsys.readouterr().out
```
(`main(argv, executor=default_executor) -> int` nằm trong `scanner/__main__.py`; `if __name__ == "__main__": sys.exit(main(sys.argv[1:]))`.)

- [ ] **Step 2: Chạy** `pytest tests/test_previous.py tests/test_mailer.py tests/test_cli.py -v`. Mong đợi: FAIL.
- [ ] **Step 3: Hiện thực** 3 module.
- [ ] **Step 4: Chạy** `pytest -v`. Mong đợi: PASS.
- [ ] **Step 5: Commit** `"feat: CLI run/send, lấy báo cáo trước qua artifact, gửi Gmail"`

---

### Task 10: Workflow GitHub và policy

**Files:**
- Create: `.github/workflows/scan.yml`, `.github/workflows/self-scan.yml`, `policy/docker.rego`, `tests/policy/` (dùng cho `conftest verify`)
- Tham khảo: `.github/workflows/ci.yml` và `policy/docker.rego` ở repo cũ

**Interfaces:**
- Consumes: CLI ở Task 9
- Produces (giao diện công khai, ghi vào README):

```yaml
on:
  workflow_call:
    inputs:
      scanner-ref: { type: string, default: "v1" }
    secrets:
      SMTP_USERNAME: { required: false }
      SMTP_PASSWORD: { required: false }
      REPORT_EMAIL_TO: { required: false }
```

Job `scan` (`runs-on: ubuntu-latest`, `permissions: { contents: read, actions: read }`, `timeout-minutes: 20`), các bước:
1. `actions/checkout` dự án gọi, `fetch-depth: 0`.
2. `actions/checkout` repo bộ quét, `repository: vietductran16092003/<repo-mới>`, `ref: ${{ inputs.scanner-ref }}`, `path: .scanner`.
3. `actions/setup-python` 3.11, rồi `pip install -r .scanner/requirements.txt`.
4. `aquasecurity/setup-trivy` (pin version) để có `trivy` trên PATH.
5. `PYTHONPATH=.scanner python -m scanner run --root . --out scan-out --scanner-dir .scanner`, với `GITHUB_TOKEN: ${{ github.token }}`.
6. `cat scan-out/summary.md >> $GITHUB_STEP_SUMMARY` (`if: always()`).
7. `actions/upload-artifact`, `name: security-report`, `path: scan-out/report.json` và `scan-out/email.html`, `retention-days: 90` (`if: always()`). Nhờ vậy khi không gửi được mail vẫn tải được bản HTML (spec mục 5.5).
8. `python -m scanner send --out scan-out`, truyền 3 secret qua `env` (`if: always()`).

`self-scan.yml`: `on: push`, gọi `uses: ./.github/workflows/scan.yml` với `scanner-ref: ${{ github.sha }}`, `secrets: inherit`.

`policy/docker.rego`: giữ Rule 1 (USER cuối không phải root, `deny`) và Rule 3 (thiếu HEALTHCHECK, `warn`). Rule 2 (`:latest`) chuyển thành `warn` áp dụng cho **mọi** stage và bỏ hẳn `is_aliased_source`. Thông báo bằng tiếng Việt, không nhắc tên image nội bộ nào.

- [ ] **Step 1: Viết test policy** trong `tests/policy/docker_test.rego`: Dockerfile với `USER root` cuối → có deny; `USER app` → không deny; `FROM node:latest AS build` → có warn; có `HEALTHCHECK` → không có warn healthcheck.
- [ ] **Step 2: Chạy** `docker run --rm -v ${PWD}:/p -w /p <conftest-image> verify --policy policy --data tests/policy`. Mong đợi: FAIL với policy chưa sửa.
- [ ] **Step 3: Viết** `policy/docker.rego` mới. Chạy lại lệnh trên, mong đợi PASS.
- [ ] **Step 4: Viết** `scan.yml` và `self-scan.yml`. Kiểm tra cú pháp bằng `actionlint` (Docker image `rhysd/actionlint`, pin version). Mong đợi: không lỗi.
- [ ] **Step 5: Commit** `"feat: reusable workflow scan.yml, self-scan và Dockerfile policy chung"`

---

### Task 11: Schema, agents, README và quét sạch thông tin nội bộ

**Files:**
- Create: `schema.json`, `agents/README.md`, `agents/context_agent.md`, `agents/exploit_agent.md`, `agents/severity_agent.md`, `agents/recommendation_agent.md`, `README.md`, `tests/test_schema.py`
- Tham khảo: `ai_triage/agents/*.md` ở repo cũ

**Interfaces:**
- Consumes: `Report.to_json()`

- [ ] **Step 1: Viết test fail** `tests/test_schema.py`: `jsonschema` (thêm vào `requirements-dev.txt`) validate `make_report([...]).to_json()` theo `schema.json` → hợp lệ; một report thiếu `priority` trong finding → không hợp lệ.
- [ ] **Step 2: Viết** `schema.json` (JSON Schema draft 2020-12, mô tả `Report`/`Section`/`Finding` đúng như Task 1, `priority` là enum). Chạy `pytest -v`, mong đợi PASS.
- [ ] **Step 3: Chép và sửa 4 agent `.md`** cho khớp schema mới: bỏ `environment` và `business_criticality` khỏi đầu vào bắt buộc; ghi rõ agent sửa `priority` trên **một bản sao** `report.json` tải từ artifact, kết quả không ảnh hưởng lần quét sau (spec mục 5.3). `agents/README.md` mô tả thứ tự chạy tay, bỏ bước Rule Engine cục bộ (vì `report.json` đã có `priority`).
- [ ] **Step 4: Viết** `README.md` tiếng Việt: bộ quét làm gì; đoạn YAML 10 dòng để gắn vào dự án (lấy đúng từ interface ở Task 10); cách tạo Gmail App Password và thêm 3 secret; bảng 6 phần quét và điều kiện chạy; bảng điểm A–F; ý nghĩa P1/P2/Backlog; cách dùng `.gitleaksignore`, `.trivyignore`, `# nosemgrep` (nhấn mạnh trường hợp secret cũ đã thu hồi); cách chạy tay 4 agent; lưu ý là chỉ hỗ trợ `Dockerfile` ở thư mục gốc; cách thêm lịch cố định sau này (thêm `schedule: - cron: ...` vào `on:` của file workflow trong dự án, không phải sửa bộ quét).
- [ ] **Step 5: Quét thông tin nội bộ**: `git grep -n -i -f <file danh sách tên nội bộ, để ngoài repo>` ở repo mới (kể cả `docs/`). Mong đợi: chỉ khớp trong spec/kế hoạch ở đoạn mô tả lý do tách repo. Đoạn đó phải được viết lại cho chung chung ("hạ tầng nội bộ của nơi thực tập") để kết quả grep **rỗng**. Không có tên người hướng dẫn.
- [ ] **Step 6: Commit** `"docs: schema, agents chạy tay, README"`

---

### Task 12: Đưa lên GitHub và nghiệm thu thật

Task này có thao tác ra bên ngoài (tạo repo public, push, tạo tag, gửi mail thật). **Mỗi thao tác phải được chủ repo đồng ý ngay trước khi làm.**

- [ ] **Step 1: Chạy** `pytest -v` toàn bộ và lặp lại grep của Task 11 Step 5. Mong đợi: PASS và grep rỗng.
- [ ] **Step 2: Xin chủ repo đồng ý**, rồi tạo repo public `vietductran16092003/<repo-mới>` (`gh repo create --public --source . --push`). Thay `<repo-mới>` trong `scan.yml` và README bằng tên thật, commit trước khi push.
- [ ] **Step 3: Chủ repo tự thêm 3 secret** SMTP vào repo mới (không nhập hộ). Xin đồng ý rồi tạo và push tag `v1`.
- [ ] **Step 4: Nghiệm thu repo mới**: push một commit. Mong đợi: `self-scan` xanh, Job Summary có báo cáo, nhận được email. Push commit thứ hai: email có mũi tên và ô "Lỗi mới / Đã sửa".
- [ ] **Step 5: Nghiệm thu 2 repo thử nghiệm** (chủ repo tạo hoặc chỉ định): (a) có `Dockerfile` và `package.json` hoặc `requirements.txt` → đủ 6 phần chạy hoặc bỏ qua đúng; (b) chỉ có code → `image` và `dockerfile_policy` hiện "không quét" kèm lý do.
- [ ] **Step 6: Nghiệm thu các tình huống lỗi**: xoá tạm secret SMTP → workflow vẫn xanh, Job Summary vẫn có; thêm Dockerfile hỏng (`FROM khong-ton-tai:1`) → phần `image` là "lỗi", email vẫn gửi, workflow xanh.
- [ ] **Step 7: Mở email trên Gmail web và Gmail điện thoại**. Chủ repo xác nhận đúng mẫu Hướng 1 và không bị cắt ("[Message clipped]").
- [ ] **Step 8: Đo thời gian** chạy `scan` trên repo thử nghiệm (a). Mong đợi: dưới khoảng 10 phút. Nếu vượt, ghi lại phần chậm nhất để xử lý sau.
