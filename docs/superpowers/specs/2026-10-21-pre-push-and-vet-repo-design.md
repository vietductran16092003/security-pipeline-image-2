# Thiết kế: Kiểm tra trước khi push và kiểm tra repo lạ trước khi tải

Ngày: 21/10/2026 · Trạng thái: chờ duyệt · Làm trước hướng của `2026-10-20-on-demand-multi-project-design.md`; tài liệu 20/10 là **giai đoạn 2** (xem mục 4), chưa triển khai.

## 1. Ý định và lý do

Chủ repo (một người, dùng Windows, code trên máy) cần hai việc, đúng như lời người này nói:

1. **Kiểm tra lỗi trước khi đẩy code lên git.** Tình huống gần nhất: đang code dự án "avatar", cần xem có lỗi gì để sửa trước khi gửi đi.
2. **Kiểm tra an toàn trước khi đẩy hoặc tải một repo trên GitHub/GitLab về máy.** Nỗi sợ cụ thể: repo bị **gài mã độc** hoặc **cài thông tin xấu**.

Bộ quét hiện tại (Gitleaks, Semgrep, Trivy, Conftest) tìm lộ khoá, lỗi code, thư viện có lỗ hổng, cấu hình sai. Nó **không** được làm ra để phát hiện mã độc, nên việc 2 cần một lớp kiểm tra mới. Việc 1 phần lớn dùng lại bộ quét sẵn có.

Bản thiết kế 20/10 (quét danh sách nhiều dự án qua repo private `security-scan-runs`, token, GitLab nội bộ) được chủ repo xem lại và **không còn là nhu cầu chính**; không làm trong giai đoạn này.

## 2. Mục tiêu

**A. Kiểm tra trước khi push (code của mình, trên máy)**
1. Chạy **tự động khi gõ `git push`** (git `pre-push` hook), và chặn push nếu có lỗi mức nặng; cho phép bỏ qua có chủ ý (ví dụ `git push --no-verify`, hoặc một biến môi trường) và nói rõ cách bỏ qua trong thông báo chặn.
2. Chạy được **bất cứ lúc nào** bằng nhấp đúp một file `.cmd`, chọn thư mục dự án, mở báo cáo HTML trong trình duyệt (dùng lại phần quét trên máy của bản 20/10, mục 6 và 6.4 của tài liệu đó, không cần Gmail).
3. Quét cả **file chưa commit** và thư mục **không phải git repo** (chế độ `--mode local`, Gitleaks `--no-git` cộng lịch sử git nếu có).
4. Cài hook cho một dự án bằng **một thao tác** (nhấp đúp `Cai-hook.cmd` rồi chọn thư mục), không phải sửa file bằng tay.
5. So sánh với lần quét trước của chính dự án đó (đã có, lưu ở `%LOCALAPPDATA%\security-scan\<slug>\`).

**B. Kiểm tra repo lạ trước khi tải về (GitHub, GitLab)**
1. Người dùng dán **link repo** (hoặc `owner/repo` của GitHub) vào một file nhấp đúp `Kiem-tra-repo-la.cmd` (hộp thoại nhập). Có thể thêm `@nhánh`.
2. Repo được tải vào **chỗ cách ly**: container Docker dùng xong xoá, **không** có mạng khi phân tích, **không** chạy bất kỳ code nào của repo, mount chỉ đọc. Máy người dùng chỉ nhận **báo cáo**, không nhận repo.
3. Kết quả là **một trong ba mức** kèm lý do cụ thể (file, dòng, vì sao đáng ngờ): `An toàn hơn` / `Đáng ngờ` / `Không nên mở`. Không có lời cam đoan "sạch tuyệt đối"; báo cáo ghi rõ giới hạn này.
4. Chạy được cho cả repo GitHub/GitLab công khai (gitlab.com và host GitLab truy cập được). Repo private hoặc GitLab nội bộ: **không hỗ trợ trong giai đoạn này** (ghi rõ trong thông báo khi tải không được).
5. Không cần quyền admin, không cần cài gì ngoài Python và Docker Desktop (đã có).

## 3. Những thứ lớp kiểm tra B phải soi (đề xuất của người thiết kế, chưa phải yêu cầu cứng)

- **Script tự chạy khi cài hoặc mở:** `postinstall`/`preinstall` trong `package.json`, `setup.py`/`pyproject` build hook, `Makefile` mục mặc định, GitHub Actions workflow, `.vscode/tasks.json` (tự chạy khi mở thư mục), `.devcontainer`, git hook đi kèm, `.cmd/.ps1/.sh` ở thư mục gốc.
- **Mã bị che giấu:** base64/hex rồi `eval`/`exec`, `curl|sh`, `iwr|iex`, `powershell -enc`, chuỗi rất dài vô nghĩa, minify bất thường ở file nguồn.
- **Hành vi đánh cắp:** đọc khoá SSH, `.env`, trình duyệt (cookie/mật khẩu), ví tiền mã hoá, biến môi trường rồi gửi ra ngoài (HTTP, webhook Discord/Telegram, paste site).
- **Thư viện đáng ngờ:** tên gần giống thư viện nổi tiếng (typosquatting), phiên bản bị báo là mã độc trong cơ sở dữ liệu công khai (ví dụ OSV có mục malware), nguồn cài từ URL/git trực tiếp.
- **File lạ:** file thực thi `.exe/.dll/.scr/.jar/.bat`, file nén có mật khẩu, file nhị phân không giải thích được trong repo mã nguồn.
- Công cụ cụ thể (ví dụ Semgrep rule bộ riêng, một công cụ phát hiện gói độc như GuardDog, quét OSV) **để người xây dựng chọn** (mục 7).

## 4. Không làm

- Chạy thử repo lạ trong sandbox để quan sát hành vi (dynamic analysis).
- Cam đoan repo không có mã độc; thay bằng mức rủi ro và giới hạn.
- **Giai đoạn 2 (làm sau, chủ repo muốn giữ):** quét danh sách nhiều repo cũ của mình theo yêu cầu, qua repo private `security-scan-runs`, token GitHub/GitLab, GitLab nội bộ cần VPN (quét bằng nhấp đúp trên máy có VPN). Thiết kế đầy đủ nằm ở `2026-10-20-on-demand-multi-project-design.md` (mục 4b và 5–6) và vẫn hợp lệ. Giai đoạn 2 phải dùng chung lớp kiểm tra mã độc của việc B, để "kiểm tra repo cũ" gồm cả lỗ hổng lẫn dấu hiệu bị gài mã. Không làm trong giai đoạn 1.
- Ứng dụng desktop/web, bảng điều khiển lịch sử.
- macOS/Linux cho phần nhấp đúp (CLI vẫn chạy được ở mọi nơi có Python và Docker).
- Đổi cách `scan.yml` (quét khi push trên CI) đang hoạt động.

## 5. Anti-goals (chạy được nhưng vẫn coi là hỏng)

- **Repo lạ chạm vào máy người dùng theo cách có thể chạy code:** ví dụ clone ra thư mục máy rồi mở bằng editor, chạy `npm install`, cho container có mạng, mount ghi được, hoặc để git chạy hook/filter/submodule của repo đó. Đây là lỗi nghiêm trọng nhất.
- **Báo "An toàn hơn" khi thực ra không kiểm tra được** (tải lỗi, bị cắt vì repo quá lớn, công cụ lỗi): phải báo rõ "không kiểm tra đầy đủ" và không được cho mức an toàn.
- **Pre-push làm người dùng bỏ luôn hook:** chậm quá (quá vài chục giây cho dự án nhỏ), hoặc chặn vì lỗi nhỏ, hoặc không cho bỏ qua. Hook phải nhanh, chỉ chặn lỗi nặng, và luôn nói cách bỏ qua.
- **Lộ bí mật:** nội dung secret tìm thấy xuất hiện nguyên văn trong báo cáo, log, hoặc email (che bớt như bộ quét hiện tại).
- **Phần nhấp đúp đòi kỹ thuật:** phải mở terminal, sửa file cấu hình, hoặc chạy admin.
- Báo cáo của dự án này trộn vào lịch sử so sánh của dự án khác.

## 6. Ràng buộc

- Không đổi lõi quét hiện có, Rule Engine, điểm A–F ngoài những chỗ thật cần (thêm `--mode local`, `--previous`, mục mức rủi ro cho chế độ B).
- Chữ người dùng nhìn thấy bằng tiếng Việt. Báo cáo HTML mở trong trình duyệt mặc định.
- Pin version cho image/công cụ như hiện tại. Không thêm dịch vụ trả phí. Dùng được khi không có Gmail.
- README thêm hai mục: "Kiểm tra trước khi push" và "Kiểm tra repo lạ trước khi tải".
- Có test tự động cho phần logic (phân loại mức rủi ro, phát hiện mẫu đáng ngờ) với repo mẫu cố tình độc hại do chính dự án tạo (an toàn, không chứa mã độc thật).

## 7. Để lại cho người xây dựng

- Chọn công cụ và rule cho mục 3; cách ghép điểm thành ba mức.
- Cách tải repo vào container an toàn (ví dụ `git clone` trong container không có mạng sau khi tải, tắt hook/filter/submodule tự chạy, giới hạn dung lượng và thời gian).
- Giới hạn kích thước repo và thời gian chạy; báo gì khi vượt.
- Công nghệ hộp thoại trên Windows (PowerShell + WinForms hoặc cách khác).
- Ngưỡng "lỗi nặng" mặc định cho pre-push (đề xuất: chỉ P1 và secret).
- Cách cài hook không ghi đè hook sẵn có của dự án.

## 8. Quyết định người thiết kế tự đặt (chủ repo nên xem lại)

1. Ba mức kết quả cho việc B; không có "sạch tuyệt đối".
2. Chỉ hỗ trợ repo công khai trong giai đoạn này; repo private và GitLab nội bộ làm sau nếu cần.
3. Hook pre-push chỉ chặn lỗi nặng, và có cách bỏ qua.
4. Chủ repo chưa nói sau khi tải repo lạ về sẽ chỉ đọc hay cài và chạy thử; thiết kế giả định **cả hai**, nên cảnh báo rõ các điểm tự chạy (mục 3) vì chúng nguy hiểm kể cả khi chỉ mở thư mục.
5. Không dùng email cho hai tính năng này (chỉ báo cáo mở trong trình duyệt); email vẫn có ở `scan.yml`.

## 8b. Quyết định bổ sung sau vòng kiểm tra (người thiết kế tự đặt, chủ repo xem lại)

1. **Phần quét trên máy phải xây mới** (hiện chưa có: không có `--mode local`, `--previous`, kho lưu theo slug, mở HTML trong trình duyệt). Dùng lại nguyên mô tả mục 6 và 6.4 của tài liệu 20/10 **chỉ cho các phần đó**, bỏ phần Gmail/Credential Manager/chọn nhiều thư mục. Dùng lại image và entrypoint quét hiện có; gọi Docker từ Python trên máy.
2. **Quy tắc ba mức (việc B):**
   - `Không nên mở`: có ít nhất một dấu hiệu mã độc mức cao (mục 3: script tự chạy tải/chạy mã từ mạng, mã che giấu + thực thi, đọc khoá/cookie rồi gửi ra ngoài, gói bị báo là độc).
   - `Đáng ngờ`: có dấu hiệu mức trung/thấp, hoặc **kiểm tra không đầy đủ** (tải lỗi một phần, repo vượt giới hạn, công cụ lỗi). Báo cáo ghi rõ lý do không đầy đủ.
   - `An toàn hơn`: kiểm tra chạy đủ, không có dấu hiệu nào. Lỗ hổng CVE thường và lỗi code của bộ quét hiện có **không** đổi mức này; chúng vẫn được liệt kê ở phần riêng.
   - Nếu không kiểm tra được gì (link sai, tải thất bại hoàn toàn): thông báo "không kiểm tra được", không có mức nào.
   - Repo bị cắt vì quá lớn vẫn báo các dấu hiệu tìm thấy (có thể ra `Không nên mở`), nhưng không bao giờ ra `An toàn hơn`.
3. **Cách ly:** hai bước trong Docker. Bước 1 (có mạng): tải repo bằng `git clone` với hook/filter/submodule/LFS tắt (hoặc tarball của GitHub/GitLab nếu đơn giản hơn), vào **volume Docker có tên hoặc tmpfs**, không mount thư mục máy. Bước 2 (`--network none`, mount chỉ đọc): phân tích. Xong xoá volume. Volume nằm trong ổ ảo của Docker được coi là "không chạm máy" cho bài kiểm tra mục 9; điều cấm là có thư mục repo trong hệ thống file Windows.
4. **Image được phép thêm công cụ** (rule Semgrep riêng, công cụ phát hiện gói độc). Tra cứu cần mạng (ví dụ OSV) làm ở **bước 1**, kết quả đưa vào bước 2; hoặc nhúng bản chụp dữ liệu vào image, ghi rõ ngày chụp. Người xây dựng chọn một.
5. **Giới hạn mặc định:** repo tối đa khoảng 500 MB, tối đa 5 phút phân tích; vượt thì cắt và áp quy tắc "không đầy đủ" ở trên.
6. **Hook pre-push dùng bản rút gọn:** secret (Gitleaks) trên các commit sắp push cộng thư viện có lỗ hổng nặng; **chỉ chặn secret và P1**. Quét đầy đủ chỉ khi nhấp đúp. "Secret" ở ngưỡng chặn nghĩa là phát hiện trong phạm vi các commit sắp push.
7. **Docker chưa chạy khi push:** hook tự mở Docker Desktop (đã có sẵn trong `docker_desktop.py`) và đợi; nếu vẫn không được thì **cho push đi kèm cảnh báo rõ ràng** (không chặn), vì chặn mọi lần push sẽ khiến người dùng gỡ hook.
8. **Cài hook không ghi đè:** nếu đã có hook `pre-push`, chuỗi gọi hook cũ trước rồi tới hook mới; có lệnh gỡ trả về như cũ; cài lặp lại không nhân đôi. `core.hooksPath` (ví dụ husky) ngoài phạm vi, chỉ báo "không hỗ trợ".
9. **GitLab:** chấp nhận đường dẫn có nhóm con, host https bất kỳ truy cập được từ internet; từ chối địa chỉ nội bộ/IP riêng (chống truy cập mạng nội bộ). Python hệ thống 3.11+, tự tạo `.venv` lần đầu.

## 9. Kiểm tra hoàn thành

- Dự án mẫu có secret + thư viện lỗi: `git push` bị chặn, thông báo nêu lỗi và cách bỏ qua; sửa xong push qua. `--no-verify` bỏ qua được.
- Thư mục không phải git, có secret trong file chưa commit: nhấp đúp quét ra secret.
- Repo mẫu độc hại (do dự án tạo) với `postinstall` tải script, `eval(base64)`, đọc `.ssh`: ra `Không nên mở`, liệt kê đúng file và dòng.
- Repo bình thường nhỏ: ra `An toàn hơn` kèm dòng ghi giới hạn.
- Link sai hoặc repo private: báo "không kiểm tra được", không bao giờ ra mức an toàn.
- Kiểm tra bằng cách quan sát: trong lúc chạy B, không có thư mục repo lạ nào xuất hiện trên đĩa máy; container không có mạng khi phân tích.
- Dự án nhỏ: hook pre-push xong trong thời gian chấp nhận được (người xây dựng đo và báo).
