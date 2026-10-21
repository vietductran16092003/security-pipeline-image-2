# Bàn giao: việc còn dang dở (20/10/2026)

Repo: `D:\Project\security-scan-action` (nhánh `main`, ~25 commit, **chưa push**).
Repo cũ `D:\Project\security-pipeline-image\security-pipeline-image` giữ nguyên làm lưu trữ.
Nhật ký chi tiết mọi quyết định: `.superpowers/sdd/2026-10-19-personal-security-scanner/progress.md` (không commit).

## 1–2. Đã xong (21/10/2026)
- Repo trên GitHub: **`vietductran16092003/security-pipeline-image-2`** (public). Thư mục trên máy vẫn tên `security-scan-action`.
- CI `Self scan` xanh từ lần #3. SHA upload-artifact cũ sai → đã nâng checkout/setup-python/upload-artifact lên v7 (Node 24).
- Lần #4: Job Summary điểm A, "So với lần trước: +0 mới, 0 đã sửa" → tải báo cáo lần trước chạy đúng; gitleaks/semgrep/trivy fs ghi file được.
- Chưa thử trên CI: `docker build` + Conftest (repo không có Dockerfile; trên máy đã chạy đúng).
- Tag `v1` đã push, trỏ `a252662`.
- Đọc Job Summary/log cần đăng nhập GitHub: đã đăng nhập trong khung trình duyệt của app. API ẩn danh giới hạn 60 lượt/giờ.
- Cũng đã làm: gợi ý sửa theo loại lỗi, "finding" → "lỗi", tự mở/tắt Docker Desktop khi quét trên máy (Windows), README viết lại cho nhiều kiểu người đọc.

## 3. Email thật chưa gửi được
- Cần **Gmail App Password** (không phải mật khẩu thường). Người dùng phải tự nhập; trợ lý không được nhập mật khẩu.
- ⚠️ Người dùng đã dán một mật khẩu vào cuộc trò chuyện → nên **đổi mật khẩu tài khoản Google đó**.
- Gửi thử tại máy: đặt `$env:SMTP_USERNAME`, `$env:SMTP_PASSWORD` trong terminal rồi chạy `scan-out\send_test_emails.ps1` (gửi 5 email test tới vietductran390@gmail.com). Chưa chạy.
- Cách không cần mật khẩu: tạo thư nháp qua Gmail connector để xem hiển thị (đã đề xuất, chưa làm).
- Cho CI: thêm secret `SMTP_USERNAME`, `SMTP_PASSWORD`, `REPORT_EMAIL_TO` vào repo GitHub.

## 4. Tính năng mới đang thiết kế: quét theo yêu cầu cho nhiều dự án
- Tài liệu: `docs/superpowers/specs/2026-10-20-on-demand-multi-project-design.md` (**chưa duyệt, chưa commit**).
- Đã chốt với người dùng: nút Run workflow nhập danh sách repo GitHub/link GitLab; dự án trên máy quét bằng **nhấp đúp file** `Quet-du-an.cmd`; chưa có Gmail thì chỉ mở báo cáo trong trình duyệt; không làm app/web.
- **2 câu còn chờ người dùng trả lời** (reviewer nêu):
  1. Kết quả quét dự án private nằm ở đâu? Repo bộ quét là public → đề xuất tạo repo **private** riêng `security-scan-runs` chứa nút Run workflow và lịch sử.
  2. GitLab ở **gitlab.com** hay **nội bộ cần VPN**? Nội bộ thì GitHub không vào được → phải quét bằng nhấp đúp trên máy.
- Sau khi trả lời: cập nhật tài liệu → người dùng duyệt → lập kế hoạch (superpowers:writing-plans) → triển khai.

## 5. Việc nhỏ đã hoãn (Minor)
- #15: tải DB của Trivy chỉ từ một nguồn (có thể thêm cache `actions/cache` hoặc mirror).
- #13: khoá so sánh không có số dòng (cố ý, để sửa code không bị báo nhầm).
- Đếm `nosemgrep` của chính repo này ra 11 vì chuỗi mẫu trong test giống chú thích.
- Chỉ hỗ trợ `Dockerfile` ở thư mục gốc.

## 6. Dọn dẹp
- Repo cũ còn 2 thư mục chưa commit do trợ lý tạo: `.superpowers/` và `docs/superpowers/` (mockup + bản thiết kế gốc; bản chính đã ở repo mới). Hỏi người dùng có xoá không.
- `scan-out/` trong repo mới (đã gitignore) chứa kết quả test 5 kịch bản, ảnh chụp, trang `scenarios/index.html`.

## Trạng thái kiểm tra hiện tại
- `pytest`: 127 passed · `conftest verify`: 9/9 · actionlint: sạch.
- Quét thật bằng Docker trên 5 kịch bản (A đầy đủ, B chỉ code, C sạch, D Dockerfile hỏng, E lần push thứ hai): đều đúng; Playwright kiểm tra email ở 600px và 375px đạt.
