# Thiết kế: Quét theo yêu cầu cho nhiều dự án (GitHub, GitLab, trên máy)

Ngày: 20/10/2026 (cập nhật 21/10/2026) · Trạng thái: chờ duyệt · Nối tiếp: `2026-10-19-personal-security-scanner-design.md`

## 1. Ý định và lý do

Bộ quét hiện chạy khi dự án **gắn file workflow và push code** (reusable workflow `scan.yml`). Chủ repo muốn thêm cách thứ hai: **quét khi nào mình cần**, cho **nhiều dự án một lúc**, mà **không phải sửa gì trong các dự án đó**. Dự án có thể nằm ở **GitHub**, **GitLab**, hoặc **chỉ trên máy tính**.

Chủ repo đã cân nhắc và **không muốn làm ứng dụng hay web riêng** ở giai đoạn này (một trang web nhỏ chạy trên máy để xem lịch sử có thể làm sau).

## 2. Mục tiêu

1. **Dự án online (GitHub, GitLab):** trong repo `security-scan-action` trên GitHub, bấm **Run workflow**, dán danh sách dự án (tên repo GitHub hoặc link GitLab), bộ quét tải từng dự án về, quét, và gửi **mỗi dự án một email** theo mẫu Hướng 1 hiện có.
2. **Dự án trên máy:** **nhấp đúp một file** trong repo, chọn một hoặc nhiều thư mục bằng hộp thoại của Windows, bộ quét chạy trên máy và **tự mở báo cáo trong trình duyệt**; nếu máy đã cấu hình Gmail thì gửi thêm email.
3. **So sánh với lần trước** vẫn hoạt động cho cả hai cách: so với lần quét trước **của chính dự án đó**.
4. Cách cũ (gắn `scan.yml` vào dự án, quét mỗi lần push) **giữ nguyên, không đổi hành vi**.

## 3. Không làm

- Chạy trực tiếp trên GitLab CI (file `.gitlab-ci.yml`). Chủ repo chỉ cần quét theo yêu cầu.
- Ứng dụng desktop, web có đăng nhập, dashboard lịch sử.
- Quét theo lịch cho danh sách dự án (có thể thêm sau, xem mục 9).
- Nguồn khác ngoài GitHub, GitLab và thư mục trên máy (Bitbucket, Azure DevOps...).
- Chạy trên macOS/Linux cho phần nhấp đúp (chủ repo dùng Windows). Lệnh CLI bên dưới vẫn chạy được ở mọi nơi có Python và Docker.

## 4. Anti-goals (chạy được nhưng vẫn coi là hỏng)

- **Token bị lộ:** token GitHub/GitLab hay mật khẩu Gmail xuất hiện trong log, email, Job Summary, artifact, hoặc file trên đĩa.
- **Một dự án hỏng kéo theo cả lượt:** dự án A không tải được (sai tên, hết quyền) mà các dự án khác không được quét hoặc không có email.
- **Im lặng khi hỏng:** dự án không tải được thì phải có thông báo rõ (email hoặc Job Summary) ghi tên dự án và lý do, không được biến mất.
- **Phần nhấp đúp đòi hỏi kỹ thuật:** người dùng phải mở terminal, sửa file cấu hình, hoặc chạy với quyền admin thì coi như không đạt.
- Báo cáo của dự án này **trộn** vào lịch sử so sánh của dự án khác.

## 4b. Quyết định đã chốt với chủ repo (21/10/2026)

- **Nơi chạy và lưu kết quả:** repo **private** riêng `security-scan-runs` (cùng tài khoản). Repo này chứa nút Run workflow, artifact và lịch sử so sánh. Lý do: repo bộ quét là public, nên log/artifact của dự án private không được nằm ở đó. Repo `security-scan-runs` gọi lõi quét từ repo bộ quét (gắn tag `v1`) và chứa 3 secret SMTP, `SCAN_GITHUB_TOKEN`, `SCAN_GITLAB_TOKEN`.
- **GitLab dùng cả hai loại:**
  - **gitlab.com** (hoặc host GitLab truy cập được từ internet): quét bằng nút Run workflow (mục 5).
  - **GitLab nội bộ cần VPN:** runner của GitHub không vào được, nên **chỉ quét bằng nhấp đúp trên máy** (mục 6). Phần trên máy phải nhận được **link GitLab** (ngoài thư mục), tự `git clone` bằng thông tin đăng nhập git sẵn có trên máy (hoặc token trong Credential Manager) vào thư mục tạm, quét, rồi xoá thư mục tạm.
  - Nếu người dùng dán link GitLab nội bộ vào Run workflow, workflow báo "không tải được" kèm gợi ý: "dự án này cần quét bằng Quet-du-an.cmd trên máy có VPN".

## 5. Phần online: workflow `scan-on-demand.yml`

### 5.1 Cách dùng
- File mới `.github/workflows/scan-on-demand.yml` nằm trong repo **private `security-scan-runs`** (không phải repo bộ quét), kích hoạt bằng `workflow_dispatch`. Lõi quét lấy từ `vietductran16092003/security-pipeline-image-2@v1`.
- Input `projects` (chuỗi nhiều dòng hoặc cách nhau bằng dấu phẩy). Mỗi mục là một trong:
  - `ten-repo`: repo GitHub của **chính chủ repo** (owner = owner của repo `security-scan-action`).
  - `owner/ten-repo`: repo GitHub bất kỳ.
  - Link GitLab dạng `https://<host>/<nhom>/.../<du-an>`, hỗ trợ cả gitlab.com lẫn GitLab tự dựng (host bất kỳ chạy https).
  - Có thể thêm `@nhanh` ở cuối để quét một nhánh cụ thể (ví dụ `my-api@develop`); không có thì dùng nhánh mặc định.
- Giới hạn **tối đa 10 dự án** mỗi lần bấm; vượt quá thì workflow báo lỗi ngay ở bước đầu, không quét gì.

### 5.2 Luồng chạy
1. **Job chuẩn bị:** đọc input, kiểm tra từng mục bằng regex chặt (chỉ cho phép ký tự hợp lệ của tên repo, URL https, tên nhánh); mục sai định dạng được ghi vào Job Summary là "bỏ qua: sai định dạng" và không làm hỏng các mục khác. Sinh ra danh sách cho bước sau.
2. **Job quét (matrix, mỗi dự án một job, `fail-fast: false`, chạy song song tối đa 3):**
   - Tải dự án bằng `git clone` **đầy đủ lịch sử** (Gitleaks cần) vào thư mục `project/`.
   - Repo private dùng token (mục 5.3). Token chỉ được truyền qua biến môi trường hoặc git credential helper, **không** nằm trong URL được in ra log.
   - Không tải được: ghi Job Summary "không tải được `<dự án>`: `<lý do ngắn>`" và **gửi email báo lỗi** cho dự án đó (tiêu đề `[<dự án>] Không tải được dự án`), rồi kết thúc job đó ở trạng thái xanh.
   - Tải được: chạy đúng lõi quét hiện có (`python -P -m scanner run ...`), ghi Job Summary, upload artifact, gửi email, giống `scan.yml`.
3. Tên dự án trong email/báo cáo: tên repo (GitHub) hoặc phần cuối đường dẫn (GitLab). Nếu hai dự án trùng tên ngắn thì dùng tên đầy đủ (`owner/repo` hoặc `nhom/du-an`).

### 5.3 Token
- `SCAN_GITHUB_TOKEN` (không bắt buộc): fine-grained PAT, quyền **Contents: read** trên các repo private cần quét. Không có thì chỉ quét được repo public.
- `SCAN_GITLAB_TOKEN` (không bắt buộc): GitLab personal access token quyền `read_repository`. Dùng cho mọi host GitLab trong danh sách (giai đoạn này một token chung là đủ).
- Thêm vào cùng chỗ với 3 secret SMTP hiện có của repo `security-scan-action`.

### 5.4 So sánh với lần trước
- Artifact của mỗi dự án đặt tên riêng, ổn định: `security-report-<slug>` với `<slug>` sinh từ host + đường dẫn dự án + nhánh (chỉ chữ thường, số, dấu gạch). Ví dụ `security-report-github-com-vietductran-my-api-main`.
- `scanner/previous.py` phải nhận **tên artifact** làm tham số thay vì cố định `security-report`, và khi dùng cho on-demand thì **không lọc theo nhánh của repo bộ quét** (vì các lượt on-demand luôn chạy trên nhánh của `security-scan-action`); slug đã chứa nhánh của dự án được quét.
- `scan.yml` (cách cũ) vẫn dùng tên `security-report` và lọc theo nhánh như hiện tại.

## 6. Phần trên máy: file nhấp đúp

### 6.1 Trải nghiệm
1. Người dùng nhấp đúp `Quet-du-an.cmd` ở thư mục gốc repo.
2. **Lần đầu:** tự tạo môi trường Python (`.venv`) và cài thư viện; hiện thông báo "Đang chuẩn bị lần đầu…". Không có Python thì báo rõ cần cài Python 3.11+ và mở trang tải về.
3. Kiểm tra Docker: chưa chạy thì hiện hộp thoại "Hãy mở Docker Desktop rồi bấm OK" (thử lại / huỷ), không hiện lỗi kỹ thuật.
4. Hộp thoại chọn thư mục của Windows. Sau mỗi lần chọn hỏi "Thêm dự án khác?" (Có / Không) để chọn nhiều thư mục.
5. Một cửa sổ console hiện tiến độ: tên dự án, từng phần quét đang chạy, kết quả từng phần.
6. Xong mỗi dự án: **mở báo cáo HTML trong trình duyệt mặc định**; nếu Gmail đã cấu hình thì gửi email; cuối cùng hiện tổng kết (dự án, điểm, số P1) và "Nhấn phím bất kỳ để đóng".
7. Không cần quyền admin.

### 6.2 Cấu hình Gmail một lần (không bắt buộc)
- File thứ hai `Cau-hinh-Gmail.cmd`: hỏi địa chỉ Gmail gửi, App Password, email nhận (hộp thoại nhập của Windows, ô mật khẩu được che). Lưu vào **Windows Credential Manager**, không ghi ra file.
- Có lựa chọn xoá cấu hình.
- Chưa cấu hình: chỉ mở báo cáo trong trình duyệt, coi là thành công (chủ repo đã chấp nhận).

### 6.3 Lưu trữ và so sánh
- Kết quả lưu ở `%LOCALAPPDATA%\security-scan\<slug>\<thời gian>\` (report.json, email.html, summary.md, subject.txt). `<slug>` sinh từ **đường dẫn tuyệt đối** của thư mục dự án.
- So sánh với `report.json` mới nhất trong thư mục `<slug>` đó.
- CLI cần thêm tùy chọn `--previous <đường dẫn report.json>` (hoặc tương đương) để phần trên máy truyền báo cáo cũ vào; khi có tùy chọn này thì không gọi GitHub API.
- Giữ tối đa 20 lần quét gần nhất mỗi dự án, xoá cũ hơn.

### 6.4 Quét secret ở chế độ trên máy
- Dự án trên máy có thể **không phải git repo**, hoặc có secret trong file **chưa commit**. Vì vậy ở chế độ trên máy, phần Secret quét **cả thư mục làm việc** (Gitleaks `--no-git`), và nếu thư mục là git repo thì quét thêm lịch sử git như hiện tại.
- Đây là ngoại lệ được phép với ràng buộc "không đổi lõi quét" ở mục 7: thêm một tùy chọn chế độ (ví dụ `--mode local`) vào `runner.py`; chế độ mặc định (CI) giữ nguyên hành vi.

## 7. Ràng buộc chung

- Không thay đổi lõi quét, Rule Engine, mẫu email hay điểm A–F, ngoài những chỗ mục 5.4 và 6.3 yêu cầu.
- Mọi thứ chạy trên `ubuntu-latest` cho phần online. Phần trên máy dùng Docker Desktop đã có.
- Pin version cho action và image như hiện tại. Không thêm dịch vụ trả phí.
- Chữ người dùng nhìn thấy bằng tiếng Việt.
- Tài liệu README có thêm 2 mục: "Quét theo yêu cầu (GitHub/GitLab)" và "Quét dự án trên máy".

## 8. Kiểm tra hoàn thành

- Run workflow với 3 mục: một repo GitHub public, một link GitLab public, một tên repo không tồn tại → 2 email báo cáo, 1 email "Không tải được", workflow xanh.
- Chạy lại lần hai cùng danh sách → email có phần "Lỗi mới / Đã sửa".
- Repo private không có token → báo "không tải được" rõ ràng; có token → quét được.
- Tìm token trong log, Job Summary, artifact → không thấy.
- Nhấp đúp `Quet-du-an.cmd` khi Docker tắt → hộp thoại hướng dẫn; khi bật → chọn 2 thư mục, mở 2 báo cáo trong trình duyệt.
- Chạy lại cho cùng thư mục → báo cáo có so sánh với lần trước.
- Có cấu hình Gmail → có email; không có → chỉ mở trình duyệt, không lỗi.

## 9. Để lại cho người xây dựng

- Cách chia job (matrix hay vòng lặp trong một job), miễn đáp ứng mục 4 và 5.2.
- Định dạng chính xác của slug.
- Công nghệ hộp thoại trên Windows (PowerShell + WinForms hay cách khác), miễn không cần cài thêm phần mềm ngoài Python và Docker.
- Thư viện đọc Windows Credential Manager (ví dụ `keyring`, chỉ cài cho phần trên máy).
- Có thêm `schedule:` cho danh sách dự án cố định hay không (nếu làm thì danh sách lấy từ biến repo `SCAN_PROJECTS`).

## 10. Quyết định do người thiết kế tự đặt (chủ repo nên xem lại)

1. Tối đa 10 dự án mỗi lần bấm, chạy song song 3.
2. Dự án không tải được vẫn nhận một email báo lỗi riêng.
3. Một token GitLab chung cho mọi host GitLab.
4. Lịch sử trên máy giữ 20 lần quét mỗi dự án, lưu ở `%LOCALAPPDATA%`.
5. Cú pháp `@nhanh` để chọn nhánh.
6. Thông tin Gmail trên máy lưu trong Windows Credential Manager.
7. Chế độ trên máy quét secret cả thư mục làm việc (kể cả file chưa commit, thư mục không phải git) — mục 6.4.
8. Lịch sử so sánh online: artifact giữ tối đa thời gian GitHub cho phép (repo private: 400 ngày). Hết hạn thì coi như lần quét đầu và email ghi rõ "chưa có dữ liệu lần trước (quá hạn lưu)".
