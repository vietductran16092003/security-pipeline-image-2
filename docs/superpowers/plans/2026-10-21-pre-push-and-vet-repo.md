# Kiểm tra trước khi push và kiểm tra repo lạ — Kế hoạch triển khai

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Thêm (A) quét trên máy + hook `pre-push` chặn lỗi nặng, và (B) kiểm tra repo GitHub/GitLab lạ trong sandbox Docker cách ly, cho ra một trong ba mức rủi ro.

**Architecture:** Mở rộng package `scanner` hiện có (Python 3.11+, tool chạy qua Docker). Phần A thêm `--mode local`, kho lịch sử `scanner/store.py`, lệnh `check` và `prepush`. Phần B thêm package `scanner/vet/`: phân tích tĩnh bằng Python thuần chạy trong container `--network none`, tải repo ở container riêng có mạng, hai container chia sẻ một volume Docker có tên. Mọi giao diện người dùng là file `.cmd` nhấp đúp gọi PowerShell/Python.

**Tech Stack:** Python 3.11, pytest, Jinja2 (đã có), Docker Desktop, PowerShell + WinForms (hộp thoại), `alpine/git` và `python:3.12-slim` (pin digest/tag cụ thể).

**Spec:** `docs/superpowers/specs/2026-10-21-pre-push-and-vet-repo-design.md` (mục 8b là quyết định bổ sung). Giai đoạn 2 (`2026-10-20-...`) **không** nằm trong kế hoạch này.

## Global Constraints

- Chữ người dùng nhìn thấy bằng tiếng Việt; báo cáo HTML mở trong trình duyệt mặc định; không cần Gmail, không cần quyền admin.
- Không đổi hành vi chế độ CI mặc định (`--mode ci`), `scan.yml`, Rule Engine, điểm A–F; 127+ test hiện có phải vẫn qua.
- Pin version cho image/công cụ mới như `TOOL_IMAGES` hiện tại; không dịch vụ trả phí.
- Ba mức (mục 8b.2): `Không nên mở` / `Đáng ngờ` / `An toàn hơn`; không kiểm tra được gì thì **không có mức nào**. Kiểm tra không đầy đủ tối đa `Đáng ngờ`. CVE thường không đổi mức.
- Repo lạ: không bao giờ nằm trong hệ thống file Windows, không chạy code của nó, bước phân tích `--network none`, mount `:ro`, không theo symlink. Tải repo với hook/filter/submodule/LFS tắt. Giới hạn mặc định 500 MB và 5 phút phân tích.
- Chỉ hỗ trợ repo công khai; GitLab chấp nhận nhóm con và host https truy cập được, từ chối IP/host nội bộ.
- Hook pre-push: chỉ chặn secret (trong các commit sắp push) và P1; cho bỏ qua; Docker không chạy thì tự mở, vẫn không được thì **cho push kèm cảnh báo**; không ghi đè hook sẵn có (nối chuỗi, gỡ được, cài lặp không nhân đôi); `core.hooksPath` báo "không hỗ trợ".
- Nội dung secret không bao giờ in nguyên văn (giữ `--redact`).
- README thêm mục "Kiểm tra trước khi push" và "Kiểm tra repo lạ trước khi tải".

## Review Focus

- Push nhánh mới (remote sha toàn số 0) và xoá nhánh (local sha toàn số 0): hook phải quét đúng phạm vi / bỏ qua, không crash.
- URL mánh khoé: `https://github.com@evil.example/x`, `http://` , `file://`, `ssh://`, host là `localhost`/`127.0.0.1`/`10.x`/`192.168.x`/`169.254.x`, dấu `..`, khoảng trắng, ký tự điều khiển: đều bị từ chối trước khi chạm Docker.
- Repo lạ chứa symlink trỏ ra ngoài (`/etc/passwd`, `../..`) và file nhị phân/không decode được/rất lớn: phân tích không crash, không đọc ngoài `/repo`, ghi vào "kiểm tra không đầy đủ" khi bỏ sót.
- Công cụ lỗi/timeout/tải lỗi giữa chừng: không bao giờ ra `An toàn hơn`.
- Đường dẫn có dấu cách/tiếng Việt (`D:\Dự án mới\avatar`) cho slug, `.cmd` và hook; hook có sẵn không có dòng cuối hoặc CRLF.

---

### Task 1: Chế độ `--mode local` và `--previous` cho lệnh `run`

**Files:**
- Modify: `scanner/runner.py` (`build_commands`, `_run_section`, `run_scan`), `scanner/__main__.py` (`run` parser, `_scan`)
- Test: `tests/test_runner.py`, `tests/test_cli.py`

**Interfaces:**
- Produces: `build_commands(section_id, root, out, scanner_dir, mode: str = "ci")`; `run_scan(..., mode: str = "ci")`; CLI `run --mode {ci,local}` (mặc định `ci`) và `run --previous PATH`.

- [ ] **Step 1: Viết test thất bại**
  - `test_build_commands_ci_secrets_unchanged`: `build_commands("secrets", ..., mode="ci")` bằng đúng kết quả hiện tại (1 lệnh, không có `--no-git`).
  - `test_local_secrets_scans_working_tree`: `mode="local"` thì có lệnh chứa `--no-git` ghi `/out/gitleaks.json`.
  - `test_local_secrets_adds_git_history_when_git_repo`: thư mục có `.git` → thêm lệnh thứ hai (không `--no-git`) ghi `/out/gitleaks-git.json`; không có `.git` → chỉ 1 lệnh.
  - `test_local_merges_both_gitleaks_outputs_without_duplicates`: executor giả ghi hai file có một finding trùng (cùng rule, file, dòng) → Section chỉ có 1 finding đó.
  - `test_run_previous_flag_skips_github_api`: `main(["run", ..., "--previous", path])` đọc `report.json` ở `path`, không gọi `fetch_previous_report` (patch nó để nổ nếu bị gọi), và email/summary có phần so sánh; `--previous` trỏ file không tồn tại hoặc hỏng → coi như không có lần trước, không crash.
- [ ] **Step 2: Chạy test, thấy thất bại:** `.venv\Scripts\python -m pytest tests/test_runner.py tests/test_cli.py -q` → FAIL.
- [ ] **Step 3: Cài đặt.** Chế độ `local` chỉ khác ở phần `secrets` như trên; các phần khác dùng chung. `_run_section` đọc thêm file phụ trong `OUTPUTS` (khoá mới `extra_outputs`) rồi gộp, khử trùng theo `Finding.key()` cộng dòng. `_scan` đặt `branch="local"` khi `--mode local`; `--previous` dùng `Report.from_json`, lỗi → `None`.
- [ ] **Step 4: Chạy lại toàn bộ:** `.venv\Scripts\python -m pytest -q` → tất cả qua (≥ 127 + test mới).
- [ ] **Step 5: Commit** `feat: chế độ quét local và --previous`

### Task 2: Kho lịch sử quét trên máy `scanner/store.py`

**Files:**
- Create: `scanner/store.py`
- Test: `tests/test_store.py`

**Interfaces:**
- Produces:
  - `slug_for(path: Path) -> str` — từ đường dẫn tuyệt đối đã chuẩn hoá: chữ thường, chỉ `a-z0-9-`, thêm 8 ký tự băm ngắn của đường dẫn gốc (hai thư mục khác nhau không bao giờ trùng slug).
  - `store_root() -> Path` — `%LOCALAPPDATA%\security-scan` (biến môi trường `SCAN_STORE` ghi đè, dùng cho test).
  - `new_run_dir(slug: str, now: datetime | None = None) -> Path` — tạo `<store>/<slug>/<YYYYmmdd-HHMMSS>/`.
  - `latest_report(slug: str) -> Path | None` — `report.json` mới nhất; bỏ qua thư mục không có file.
  - `prune(slug: str, keep: int = 20) -> None`.

- [ ] **Step 1: Viết test:** `test_slug_is_stable_and_distinct_for_paths_differing_in_case_or_separators_only_when_really_different`; `test_slug_handles_spaces_and_vietnamese` (`D:\Dự án mới\avatar` → chỉ ký tự hợp lệ, không rỗng); `test_latest_report_none_when_empty`; `test_latest_report_returns_newest`; `test_prune_keeps_20_newest`; `test_run_dirs_created_under_scan_store_env`.
- [ ] **Step 2:** chạy `pytest tests/test_store.py -q` → FAIL. **Step 3:** cài đặt (dùng `os.environ`/`Path`, không mkdir ngoài `store_root()`). **Step 4:** PASS. **Step 5:** commit `feat: kho lịch sử quét theo dự án`.

### Task 3: Lệnh `check` (quét trên máy, lưu, so sánh, mở báo cáo)

**Files:**
- Create: `scanner/local.py`
- Modify: `scanner/__main__.py` (subcommand `check`)
- Test: `tests/test_local.py`

**Interfaces:**
- Consumes: Task 1 (`run_scan(..., mode="local")`), Task 2 (`slug_for`, `new_run_dir`, `latest_report`, `prune`), `DockerDesktop`.
- Produces: `check_project(root: Path, scanner_dir: Path, executor, docker, open_report: Callable[[Path], None] = webbrowser.open) -> int` (0 = quét xong, bất kể có lỗi; 2 = không quét được); CLI `python -m scanner check --root PATH` (`--scanner-dir` mặc định thư mục repo bộ quét).

- [ ] **Step 1: Test:** `test_check_writes_report_files_in_store_and_opens_email_html` (executor giả; `open_report` ghi nhận đúng đường dẫn `email.html`); `test_check_second_run_compares_with_previous` (lần hai có "đã sửa/mới" trong summary); `test_check_does_not_touch_other_projects_history`; `test_check_docker_unavailable_returns_2_and_message_in_vietnamese`; `test_check_nonexistent_root_returns_2`; `test_check_folder_not_git_repo_still_scans`.
- [ ] **Step 2:** FAIL. **Step 3:** cài đặt: đảm bảo Docker (đóng lại nếu mình mở), quét `mode="local"`, `Report.project = root.name`, ghi 4 file như `_scan`, gọi `prune`, mở `email.html`, in tổng kết (điểm, số P1). Tách phần dựng+ghi báo cáo từ `_scan` thành hàm dùng chung thay vì sao chép. **Step 4:** PASS toàn bộ. **Step 5:** commit.

### Task 4: File nhấp đúp quét dự án

**Files:**
- Create: `Quet-du-an.cmd`, `scripts/bootstrap.cmd`, `scripts/pick-folder.ps1`

**Interfaces:**
- Consumes: `python -m scanner check --root <đường dẫn>`.
- Produces: `bootstrap.cmd` — tìm `py -3`/`python` ≥ 3.11, tạo `.venv` và `pip install -r requirements.txt` lần đầu, in "Đang chuẩn bị lần đầu…"; không có Python → thông báo tiếng Việt kèm mở trang tải. `pick-folder.ps1` — hộp thoại chọn thư mục WinForms, in đường dẫn ra stdout (rỗng nếu huỷ).

- [ ] **Step 1: Test** `tests/test_scripts.py`: `test_cmd_files_exist_and_reference_scanner_check`, `test_pick_folder_script_parses` (chạy `powershell -NoProfile -Command "[scriptblock]::Create((Get-Content -Raw scripts/pick-folder.ps1)) | Out-Null"` → exit 0), `test_cmd_files_use_crlf_and_utf8_codepage` (có `chcp 65001`, đường dẫn bọc dấu nháy kép).
- [ ] **Step 2:** FAIL. **Step 3:** viết file; `Quet-du-an.cmd` gọi bootstrap → pick-folder → `check`, cuối cùng `pause`. Dùng `%~dp0` và bọc mọi đường dẫn trong dấu nháy kép. **Step 4:** PASS. **Step 5 (kiểm tra tay):** nhấp đúp, chọn thư mục `D:\Dự án mới\...` có dấu cách; báo cáo mở trong trình duyệt. **Step 6:** commit.

### Task 5: Hook scan `prepush` (rút gọn)

**Files:**
- Create: `scanner/prepush.py`
- Modify: `scanner/__main__.py` (subcommand `prepush`)
- Test: `tests/test_prepush.py`

**Interfaces:**
- Produces:
  - `parse_ref_lines(text: str) -> list[RefUpdate]` — đọc stdin chuẩn của hook (`<local ref> <local sha> <remote ref> <remote sha>`); `RefUpdate` là dataclass `local_sha`, `remote_sha`.
  - `commit_range(u: RefUpdate) -> str | None` — `None` khi xoá nhánh (local sha toàn `0`); `"<remote>..<local>"`; nhánh mới (remote sha toàn `0`) → `"<local>"` kèm `--not --remotes` (người xây dựng chọn cách biểu diễn, miễn chỉ gồm commit chưa có trên remote).
  - `prepush(root: Path, stdin_text: str, scanner_dir: Path, executor, docker) -> int` — 0 cho push đi, 1 chặn. Chạy Gitleaks (`--log-opts` theo range) và Trivy `deps`; chặn khi có secret hoặc P1; biến môi trường `SCAN_SKIP=1` bỏ qua (in ra một dòng xác nhận).
  - CLI `python -m scanner prepush --root .` đọc stdin.

- [ ] **Step 1: Test:** `test_blocks_on_secret_in_pushed_commits` (executor giả trả finding secret → return 1, thông báo có tên file/dòng và cách bỏ qua `git push --no-verify` / `SCAN_SKIP=1`, **không** có nội dung secret); `test_blocks_on_p1_dependency`; `test_allows_when_only_p2_or_backlog`; `test_delete_branch_is_not_scanned`; `test_new_branch_range_covers_only_unpushed_commits`; `test_docker_unavailable_allows_push_with_warning` (DockerUnavailable → return 0, cảnh báo tiếng Việt rõ ràng); `test_scan_skip_env_bypasses`; `test_scanner_crash_allows_push_with_warning` (không để lỗi của chính bộ quét khoá push).
- [ ] **Step 2:** FAIL. **Step 3:** cài đặt dùng lại `build_commands`/parser; chỉ gồm hai phần `secrets` (giới hạn bằng range) và `deps`; áp `apply_rules` để có `priority`. **Step 4:** PASS. **Step 5:** commit.

### Task 6: Cài/gỡ hook `scanner/hooks.py` và `Cai-hook.cmd`

**Files:**
- Create: `scanner/hooks.py`, `Cai-hook.cmd`
- Modify: `scanner/__main__.py` (subcommand `hook install|uninstall --root PATH`)
- Test: `tests/test_hooks.py`

**Interfaces:**
- Produces: `install_hook(repo: Path, scanner_cmd: str) -> str` và `uninstall_hook(repo: Path) -> str` (trả thông báo tiếng Việt). Hook của ta nằm giữa hai dòng đánh dấu `# >>> security-scan >>>` / `# <<< security-scan <<<`; nếu đã có hook, giữ nguyên nội dung và thêm khối của ta (hook cũ chạy trước, hook cũ lỗi thì dừng); cài lặp lại không nhân đôi; gỡ chỉ cắt khối của ta, và xoá file nếu chỉ còn dòng shebang.

- [ ] **Step 1: Test:** `test_install_creates_executable_hook_in_git_hooks` (dùng `git init` tạm); `test_install_twice_is_idempotent`; `test_install_preserves_existing_hook_and_runs_it_first`; `test_existing_hook_without_trailing_newline_and_with_crlf`; `test_uninstall_restores_original_bytes_of_existing_hook`; `test_uninstall_removes_file_when_ours_only`; `test_not_a_git_repo_returns_message_not_exception`; `test_core_hookspath_returns_not_supported_message`.
- [ ] **Step 2:** FAIL. **Step 3:** cài đặt; hook là script `sh` (Git for Windows chạy được) gọi `.venv\Scripts\python -m scanner prepush --root "$(git rev-parse --show-toplevel)"` với đường dẫn tuyệt đối của bộ quét ghi lúc cài. `Cai-hook.cmd` dùng `pick-folder.ps1`, hỏi Cài/Gỡ bằng hộp thoại (`MessageBox` Yes/No). **Step 4:** PASS. **Step 5 (tay):** trong dự án mẫu có secret giả, `git push` bị chặn và thông báo đúng; `git push --no-verify` đi qua. **Step 6:** commit.

### Task 7: Kiểm tra nguồn repo `scanner/vet/source.py`

**Files:**
- Create: `scanner/vet/__init__.py`, `scanner/vet/source.py`
- Test: `tests/test_vet_source.py`

**Interfaces:**
- Produces: `@dataclass(frozen=True) class Source: host: str; path: str; branch: str | None; clone_url: str; display: str`; `parse_source(text: str) -> Source`; `class InvalidSource(ValueError)` (thông báo tiếng Việt). Chấp nhận `owner/repo`, `owner/repo@nhanh` (GitHub), `https://github.com/owner/repo[.git]`, `https://<host>/<nhóm>/<nhóm con>/<dự án>[@nhanh]`; `clone_url` luôn là `https://host/path.git` đã chuẩn hoá, không chứa user/password.

- [ ] **Step 1: Test** theo Review Focus: mỗi dòng (userinfo `@`, `http`, `file`, `ssh`, `localhost`, `127.0.0.1`, `10.0.0.5`, `192.168.1.1`, `169.254.169.254`, `[::1]`, `..`, khoảng trắng, ký tự điều khiển, tên nhánh có `;` hoặc `$(`, rỗng) → `InvalidSource`; hợp lệ: `torvalds/linux`, `gitlab.com/a/b/c/d`, `my/repo@feature/x`, `https://gitlab.com/g/s/p.git`. Thêm `test_hostname_resolving_to_private_ip_rejected` (hàm phân giải DNS được tiêm vào, mặc định `socket.getaddrinfo`).
- [ ] **Step 2:** FAIL. **Step 3:** cài đặt bằng `urllib.parse` + `ipaddress`, regex cho tên repo/nhánh; không bao giờ ghép chuỗi vào shell. **Step 4:** PASS. **Step 5:** commit.

### Task 8: Bộ phát hiện dấu hiệu `scanner/vet/signals.py`

**Files:**
- Create: `scanner/vet/signals.py`, `scanner/vet/__main__.py` (chạy được trong container: `python -m scanner.vet /repo --osv /work/osv.json --out /out/vet.json`)
- Create (fixtures, **chuỗi vô hại**, chỉ khớp mẫu): `tests/fixtures/vet/evil_npm/`, `evil_py/`, `evil_ps/`, `clean_small/`, `symlink_escape/` (tạo symlink trong test bằng `os.symlink`, bỏ qua test nếu hệ thống không cho)
- Test: `tests/test_vet_signals.py`

**Interfaces:**
- Produces: `@dataclass class Signal: id: str; level: str  # "high"|"medium"|"low"; file: str; line: int | None; why: str`; `@dataclass class ScanResult: signals: list[Signal]; incomplete: list[str]  # lý do không đầy đủ`; `analyze_tree(root: Path, osv: dict | None = None, max_file_bytes: int = 2_000_000, deadline: float = 300, clock=time.monotonic) -> ScanResult`. Quy tắc id tối thiểu: `autorun-install-script` (npm `pre/post/install` có `curl|wget|node -e|powershell|http`), `autorun-editor-task` (`.vscode/tasks.json` với `runOn: folderOpen`), `autorun-devcontainer` (`postCreateCommand` có tải mạng), `pipe-to-shell`, `obfuscated-exec` (base64/hex rồi `eval|exec|Function`, `powershell -enc`), `credential-access` (đọc `.ssh`, `.aws`, `.env`, `Login Data`, `wallet`) kèm `exfil-network` trong cùng file → `high`, riêng một mình → `medium`, `exfil-webhook` (discord/telegram webhook), `executable-binary` (`.exe .dll .scr .jar .bat` hoặc header MZ/ELF trong repo mã nguồn), `typosquat-dependency` (khoảng cách sửa ≤ 1 với danh sách ~50 gói phổ biến, nhúng sẵn trong code), `direct-url-dependency`, `osv-malware` (khớp `osv`, mức `high`).

- [ ] **Step 1: Test:** mỗi id ở trên có một test dùng fixture tương ứng, kiểm `id`, `level`, `file` và `line`; `test_clean_small_repo_has_no_signals_and_not_incomplete`; `test_symlink_escape_not_followed` (không đọc nội dung ngoài `root`, thêm một mục `incomplete`); `test_binary_and_undecodable_files_do_not_crash`; `test_file_over_max_bytes_goes_to_incomplete`; `test_deadline_exceeded_sets_incomplete`; `test_empty_repo_is_not_incomplete`.
- [ ] **Step 2:** FAIL. **Step 3:** cài đặt thuần Python; đọc file ở chế độ bytes, `errors="ignore"`; `os.walk(followlinks=False)`; bỏ `.git` khi đọc nội dung nhưng **có** xét `.git/hooks` (hook không có đuôi `.sample` → `autorun-git-hook`, `medium`). Không bao giờ in nội dung secret/chuỗi độc dài; `why` chỉ nêu mẫu khớp. **Step 4:** PASS. **Step 5:** commit.

### Task 9: Quy tắc ba mức `scanner/vet/verdict.py`

**Files:**
- Create: `scanner/vet/verdict.py`
- Test: `tests/test_vet_verdict.py`

**Interfaces:**
- Consumes: `Signal`, `ScanResult`.
- Produces: `class Verdict(str, Enum): NOT_SAFE = "Không nên mở"; SUSPICIOUS = "Đáng ngờ"; SAFER = "An toàn hơn"`; `decide(result: ScanResult | None, fetch_error: str | None = None, truncated: bool = False, tool_errors: list[str] | None = None) -> Verdict | None` (trả `None` khi không kiểm tra được gì).

- [ ] **Step 1: Test:** bảng tham số đủ các nhánh mục 8b.2: có `high` → `NOT_SAFE` (kể cả `truncated=True`); chỉ `medium`/`low` → `SUSPICIOUS`; không tín hiệu nhưng `incomplete` không rỗng / `truncated` / `tool_errors` → `SUSPICIOUS`; sạch và đủ → `SAFER`; `fetch_error` và `result is None` → `None`; **không bao giờ `SAFER`** khi `truncated`, `incomplete` hoặc `tool_errors` khác rỗng (test thuộc tính duyệt qua tổ hợp).
- [ ] **Step 2–5:** FAIL → cài đặt → PASS → commit.

### Task 10: Sandbox Docker `scanner/vet/sandbox.py`

**Files:**
- Create: `scanner/vet/sandbox.py`, `scanner/vet/Dockerfile` (từ `python:3.12-slim` pin tag + copy package `scanner`, không cài thêm gì, chạy user không phải root), `scanner/vet/osv.py`
- Test: `tests/test_vet_sandbox.py`, `tests/test_vet_osv.py`

**Interfaces:**
- Consumes: `Source`, `Executor`, `DockerDesktop`.
- Produces:
  - `build_fetch_command(src: Source, volume: str, max_bytes: int = 500_000_000) -> list[str]` — `alpine/git` pin; `--network` mặc định; `-v <volume>:/work` (volume có tên, **không** bind-mount thư mục máy); git với `-c core.hooksPath=/dev/null -c protocol.file.allow=never -c filter.lfs.smudge= -c filter.lfs.process= --depth 1 --no-recurse-submodules`, `--branch` khi có nhánh, giới hạn dung lượng.
  - `build_analyze_command(volume: str, out_volume: str, ...) -> list[str]` — `--network none --read-only --cap-drop ALL --security-opt no-new-privileges --memory --pids-limit`, repo mount `:ro`, chạy `python -m scanner.vet /work/repo ...`.
  - `lookup_osv(packages: list[tuple[str, str, str]], http: Callable) -> dict` (ecosystem, tên, phiên bản → kết quả `osv.json`; chỉ giữ mục có tiền tố id `MAL-`); chạy ở bước tải; lỗi mạng → trả `{"error": "..."}` (đưa vào `tool_errors`, không phải im lặng).
  - `vet_repo(src: Source, executor, docker, now=None) -> VetOutcome` với `VetOutcome(verdict, result, fetch_error, truncated, tool_errors, source)`. Luôn xoá volume trong `finally`. Đọc `vet.json` qua một container thứ ba (`docker run --rm -v vol:/in:ro ... cat`) hoặc `docker cp`; **không** có thư mục repo trên host.

- [ ] **Step 1: Test (executor giả, không Docker thật):** `test_fetch_command_has_no_host_bind_mount_and_disables_hooks`; `test_analyze_command_is_offline_readonly_and_dropped_caps`; `test_volume_removed_even_when_analysis_raises`; `test_clone_failure_gives_none_verdict_and_fetch_error`; `test_oversize_marks_truncated`; `test_analysis_timeout_marks_incomplete_and_never_safer`; `test_osv_malware_hit_included_and_non_mal_ids_dropped`; `test_osv_network_error_recorded_as_tool_error`.
- [ ] **Step 2:** FAIL. **Step 3:** cài đặt; thêm hàm tạo tên volume ngẫu nhiên `scanvet-<hex>`. **Step 4:** PASS. **Step 5 (tay, Docker thật):** `vet_repo` trên một repo công khai nhỏ → `An toàn hơn` hoặc `Đáng ngờ` có lý do; sau khi chạy `docker volume ls` không còn volume `scanvet-*`; `Get-ChildItem` thư mục dự án và `%TEMP%` không có thư mục repo. **Step 6:** commit.

### Task 11: Báo cáo HTML, lệnh `vet` và file nhấp đúp

**Files:**
- Create: `scanner/vet/render.py`, `Kiem-tra-repo-la.cmd`, `scripts/ask-repo.ps1` (hộp thoại nhập link)
- Modify: `scanner/__main__.py` (subcommand `vet --source TEXT`)
- Test: `tests/test_vet_render.py`, `tests/test_cli.py`

**Interfaces:**
- Consumes: `parse_source`, `vet_repo`, `VetOutcome`.
- Produces: `render_vet_html(outcome: VetOutcome) -> str` (tự chứa, escape toàn bộ nội dung từ repo — repo lạ có thể chứa HTML/JS); `main(["vet", "--source", ...])` → 0 khi ra mức hoặc "không kiểm tra được" (kèm thông báo), 2 khi link sai. Lưu `vet.html` vào `%LOCALAPPDATA%\security-scan\vet\<slug>\<thời gian>\` rồi mở trình duyệt.

- [ ] **Step 1: Test:** `test_html_escapes_repo_supplied_text` (file tên `<script>x</script>` không xuất hiện thô); `test_html_shows_level_reason_file_line_and_limit_note`; `test_no_level_html_says_could_not_check_and_never_safe_wording`; `test_cli_vet_invalid_link_returns_2_without_touching_docker`; `test_cli_vet_prints_level_and_opens_report`.
- [ ] **Step 2–4:** FAIL → cài đặt → PASS. **Step 5 (tay):** nhấp đúp `Kiem-tra-repo-la.cmd`, dán link repo mẫu độc hại (xem Task 12) → `Không nên mở` kèm file/dòng. **Step 6:** commit.

### Task 12: Repo mẫu độc hại, kiểm tra đầu-cuối, tài liệu

**Files:**
- Create: `tests/fixtures/vet/README.md` (nêu rõ: chuỗi vô hại, chỉ để test), `tests/test_vet_e2e.py` (đánh dấu `@pytest.mark.docker`, bỏ qua mặc định)
- Modify: `README.md` (hai mục theo Global Constraints), `HANDOFF.md`, `pytest.ini`/`conftest.py` nếu cần đăng ký marker `docker`

- [ ] **Step 1:** test e2e (cần Docker, chạy tay): dựng git repo tạm từ fixture `evil_npm` + `evil_py`, `vet_repo` qua file-based fake `Source` (cho phép `file://` **chỉ trong test** qua tham số tiêm, không mở trong `parse_source`) → `Không nên mở` và liệt kê đúng file/dòng; fixture `clean_small` → `SAFER` có ghi chú giới hạn.
- [ ] **Step 2:** chạy bộ test đầy đủ `.venv\Scripts\python -m pytest -q` → qua hết; chạy e2e `-m docker` → qua.
- [ ] **Step 3:** kiểm tra tay theo mục 9 của spec (hook chặn/cho qua; thư mục không phải git; repo lạ không để lại thư mục/volume; đo thời gian hook trên dự án nhỏ và ghi vào `HANDOFF.md`).
- [ ] **Step 4:** viết README và cập nhật `HANDOFF.md`; commit `docs: hướng dẫn kiểm tra trước push và repo lạ`.

---

## Tự kiểm tra với spec

- Mục 2A: 1 → T5+T6; 2 → T3+T4; 3 → T1; 4 → T6; 5 → T2+T3. Mục 2B: 1 → T7+T11; 2 → T10; 3 → T9+T11; 4 → T7; 5 → T4/T11.
- Mục 3 (tín hiệu) → T8; 8b.1–9 → T1, T5–T10; mục 9 (kiểm tra hoàn thành) → các bước kiểm tra tay ở T4, T6, T10, T12 và test e2e T12.
- Chỗ lệch có chủ ý: file `.cmd` kiểm tra tay vì không thể test tự động hộp thoại WinForms.
