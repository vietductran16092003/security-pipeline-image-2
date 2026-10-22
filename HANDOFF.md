# Bàn giao (22/10/2026)

Repo: `D:\Project\security-scan-action`. Đã push lên GitHub `vietductran16092003/security-pipeline-image-2` (public), tag `v1`, CI `Self scan` xanh.
Repo cũ `D:\Project\security-pipeline-image\security-pipeline-image` giữ làm lưu trữ.
Nhật ký quyết định: `.superpowers/sdd/*/progress.md` (không commit).

## Trạng thái hiện tại

- Nhánh `main`: quét CI, `Quet-du-an.cmd` (Cách 1), `scan.yml` (Cách 3), email, gợi ý sửa. Xong từ trước.
- Nhánh **`feat/prepush-and-vet`** (chưa merge, chưa push): đã cài đặt và đã review xong hai tính năng:
  - **A. Chốt kiểm tra trước khi push** (`Cai-hook.cmd`, `python -m scanner hook|prepush`): chặn secret và P1, cho bỏ qua, Docker không chạy thì cho push kèm cảnh báo, nối chuỗi với hook sẵn có.
  - **B. Kiểm tra repo lạ** (`Kiem-tra-repo-la.cmd`, `python -m scanner vet --source TEXT | --source-file PATH`, `scanner/vet/`): sandbox Docker, 3 mức `Không nên mở` / `Đáng ngờ` / `An toàn hơn`.
  - README đã có Cách 4. Spec: `docs/superpowers/specs/2026-10-21-pre-push-and-vet-repo-design.md`.
- `pytest`: 544 passed, 1 skipped, 3 deselected (test Docker). Test đầu-cuối có Docker thật: `tests/test_vet_e2e.py`, chưa ai chạy.

## Việc người dùng cần làm tay (cần Docker Desktop và giao diện)

Ghi kết quả và thời gian vào cuối mục này.

1. Test Docker thật: `.venv\Scripts\python -m pytest -m docker -q` (lần đầu dựng image vài phút). Phải qua 3 test và không còn volume `scanvet-*`: `docker volume ls --filter name=scanvet-` trống.
2. Hook chặn/cho qua: tạo một repo git nhỏ có remote (có thể là repo rỗng trên GitHub), commit một file chứa secret giả, chạy `Cai-hook.cmd` chọn repo đó, `git push` → bị chặn, nêu file và dòng, không in nội dung secret. Xoá secret, commit, push lại → qua. `git push --no-verify` và `SCAN_SKIP=1` đều bỏ qua được. Thử thêm: push nhánh mới, xoá nhánh, và tắt Docker (phải push được kèm cảnh báo "KHÔNG ĐƯỢC KIỂM TRA").
3. Thư mục không có git: tạo thư mục có file chưa commit chứa secret giả, nhấp đúp `Quet-du-an.cmd`, chọn thư mục → báo cáo phải nêu secret.
4. Repo độc hại: nhấp đúp `Kiem-tra-repo-la.cmd`, dán link một repo công khai bạn tự dựng theo mẫu `tests/fixtures/vet/evil_npm` (postinstall tải script, `eval(base64)`, đọc `.ssh`) → `Không nên mở`, liệt kê đúng file và dòng.
5. Repo sạch nhỏ: dán một repo công khai bình thường → `An toàn hơn` kèm dòng ghi giới hạn.
6. Link sai (`http://...`, thiếu `repo`), repo private, repo không tồn tại → "Không kiểm tra được", tuyệt đối không có mức nào, không hiện "An toàn hơn".
7. Dọn dẹp: sau các lần chạy B, không có thư mục repo lạ nào trên đĩa; `docker volume ls --filter name=scanvet-` và `docker ps -a --filter label=scanvet=1` đều trống. Báo cáo nằm ở `%LOCALAPPDATA%\security-scan\vet\...`.
8. Đo thời gian hook pre-push trên một dự án nhỏ (`Measure-Command { git push }`, một lần nguội sau khi Docker tắt và một lần nóng) và ghi số vào đây: chưa đo.
9. Thư mục có dấu cách và tiếng Việt (ví dụ `D:\Dự án mới\avatar`) với `Cai-hook.cmd` và `Quet-du-an.cmd`.

Sau khi đạt: merge `feat/prepush-and-vet` vào `main`, push, nâng tag `v1` nếu muốn người dùng workflow nhận bản mới.

## Việc nhỏ đã hoãn (Minor), điểm quan trọng

- Hook: cài đè lên hook cũ bị đổi + hook lạ mới thì có thể ghi đè bản `orig` (`hooks.py` ~dòng 132) → nên từ chối hoặc sao lưu có giờ. Thiếu test chuyển `$@`, đường dẫn tương đối, `orig` không có quyền chạy.
- Hook: khi `rules.yaml` hỏng thì chỉ chặn secret/CRITICAL (bỏ lỡ HIGH→P1, có cảnh báo); dòng kết luận hơi nói quá trong trường hợp đó.
- Hộp chọn thư mục có thể nằm sau cửa sổ console; dấu `.deps-ok` không tự mất hiệu lực khi `requirements` đổi; `webbrowser.open` trả về False thì im lặng.
- Phân tích repo lạ: dòng dài bị cắt ở `MAX_LINE` (có thể bị lách bằng cách độn chữ, `setup.py`/workflow); `eval` và `atob` ở xa nhau trong nhiều cửa sổ không được nối; `setup.py` chỉ dùng subprocess có thể báo nhầm mức medium; hết giờ quét cây thì tra OSV/gói chưa được ghi riêng.
- Sandbox: `valid_packages` âm thầm bỏ mục hỏng (có thể ra `An toàn hơn` mà không có cảnh báo); kết quả OSV quá 20 nghìn ký tự bị cắt (có ghi `tool_error`); `docker build` chạy lại mỗi lần; chưa ghim digest cho image; tham số `now` chưa dùng.
- Kiểu dáng: thiếu dòng trống PEP8 ở vài file; BOM đầu `tests/test_vet_verdict.py`; tên file tạm của `.cmd` dùng `%RANDOM%`.
- Từ trước: tải DB của Trivy chỉ một nguồn (#15); khoá so sánh không có số dòng (#13, cố ý); đếm `nosemgrep` ra 11 do chuỗi mẫu trong test; chỉ đọc `Dockerfile` ở thư mục gốc.

## Giai đoạn 2 (chưa làm): quét nhiều repo cũ

- Spec: `docs/superpowers/specs/2026-10-20-on-demand-multi-project-design.md` (chưa duyệt, chưa commit).
- Hướng đã chốt: nút Run workflow nhập danh sách repo GitHub/link GitLab; kết quả quét dự án private nằm ở repo **private** riêng `security-scan-runs` (repo bộ quét là public nên không để kết quả ở đó); dự án trên máy quét bằng nhấp đúp.
- Còn chờ người dùng: GitLab ở gitlab.com hay nội bộ cần VPN? (nội bộ thì GitHub không vào được, phải quét tại máy).
- Email thật: cần Gmail App Password do người dùng tự nhập. Đã có mật khẩu bị dán vào trò chuyện trước đây → nên đổi mật khẩu tài khoản Google đó. Gửi thử: đặt `$env:SMTP_USERNAME`, `$env:SMTP_PASSWORD` rồi chạy `scan-out\send_test_emails.ps1`. Cho CI: secret `SMTP_USERNAME`, `SMTP_PASSWORD`, `REPORT_EMAIL_TO`.

## Dọn dẹp

- Repo cũ còn 2 thư mục chưa commit do trợ lý tạo: `.superpowers/` và `docs/superpowers/`. Hỏi người dùng có xoá không.
- `scan-out/` trong repo mới (đã gitignore) chứa kết quả test 5 kịch bản và ảnh chụp.
