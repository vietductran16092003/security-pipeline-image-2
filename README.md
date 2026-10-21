# security-scan-action

Công cụ này tìm chỗ yếu về bảo mật trong dự án phần mềm của bạn, rồi báo bằng tiếng Việt: lỗi nào cần sửa trước, sửa thế nào.

Nó tìm được những thứ như:

- Mật khẩu hoặc khoá bí mật lỡ để lộ trong code.
- Chỗ viết code dễ bị tấn công.
- Thư viện đang dùng có lỗ hổng đã được công bố.
- Dockerfile và file cấu hình hạ tầng viết chưa an toàn.

## Bạn muốn dùng theo cách nào?

| Bạn muốn | Cách dùng | Cần biết code không? |
|---|---|---|
| Xem dự án trên máy mình có lỗi gì, bất cứ lúc nào | [Cách 1: Quét bằng cách nhấp đúp](#cách-1-quét-dự-án-trên-máy-bằng-nhấp-đúp) | Không |
| Bị chặn lại nếu sắp đẩy code có mật khẩu bị lộ hoặc lỗi nặng | [Cách 2: Chặn lỗi trước khi push](#cách-2-chặn-lỗi-nặng-trước-khi-push) | Biết dùng `git push` |
| Mỗi lần đẩy code lên GitHub thì tự quét và nhận email báo cáo | [Cách 3: Tự quét trên GitHub](#cách-3-tự-quét-trên-github-và-nhận-email) | Biết tạo một file trong dự án |

Chưa rõ nên chọn gì thì bắt đầu với Cách 1. Cách này dễ nhất và không thay đổi gì trong dự án của bạn.

Nếu gặp từ lạ, xem [Giải thích từ ngữ](#giải-thích-từ-ngữ) ở cuối trang.

## Chuẩn bị (làm một lần)

Cách 1 và Cách 2 chạy trên máy Windows của bạn, nên cần cài 3 thứ sau. Cách 3 chạy trên GitHub nên không cần cài gì.

1. **Python, bản 3.11 trở lên.** Tải ở https://www.python.org/downloads/. Khi cài, tick ô **Add Python to PATH**.
2. **Docker Desktop.** Tải ở https://www.docker.com/products/docker-desktop/. Cài xong, mở nó một lần để chấp nhận điều khoản. Từ lần sau, công cụ tự mở Docker khi cần.
3. **Git.** Tải ở https://git-scm.com/download/win. Cách 2 cần nó. Nếu bạn chỉ dùng Cách 1 thì bỏ qua.

Sau đó tải công cụ này về máy:

1. Mở trang https://github.com/vietductran16092003/security-pipeline-image-2.
2. Bấm nút xanh **Code**, chọn **Download ZIP**.
3. Giải nén vào một thư mục cố định, ví dụ `D:\Cong-cu-quet`. Đừng di chuyển hoặc xoá thư mục này sau khi bắt đầu dùng. Cách 2 nhớ đường dẫn của nó.

## Cách 1: Quét dự án trên máy bằng nhấp đúp

Cách này chỉ đọc dự án của bạn, không sửa file nào trong đó.

1. Mở thư mục công cụ (ví dụ `D:\Cong-cu-quet`).
2. Nhấp đúp vào file **`Quet-du-an.cmd`**.
3. **Lần đầu tiên**, cửa sổ đen hiện dòng "Đang chuẩn bị lần đầu". Hãy chờ vài phút, nó đang tự cài những thứ cần thiết. Những lần sau không phải chờ.
4. Một hộp thoại hiện ra. Chọn thư mục dự án cần quét, rồi bấm **OK**. Bấm **Cancel** nếu muốn thôi.
5. Chờ quét xong. Lần đầu có thể lâu vì Docker phải tải các công cụ quét về.
6. Báo cáo tự mở trong trình duyệt. Cách đọc nằm ở phần [Đọc báo cáo](#đọc-báo-cáo).
7. Nhấn phím bất kỳ để đóng cửa sổ đen.

**Quét lại sau khi sửa:** làm lại từ bước 2 và chọn đúng thư mục cũ. Báo cáo mới sẽ cho bạn biết có bao nhiêu lỗi mới và bao nhiêu lỗi đã sửa so với lần trước.

**Báo cáo được lưu ở đâu:** trong `%LOCALAPPDATA%\security-scan` (dán đường dẫn này vào thanh địa chỉ của File Explorer). Mỗi dự án có một thư mục riêng, mỗi lần quét một thư mục con theo ngày giờ. Công cụ giữ 20 lần quét gần nhất cho mỗi dự án. File `email.html` mở được lại bằng trình duyệt.

Cách này không gửi email.

## Cách 2: Chặn lỗi nặng trước khi push

Cách này gắn một "chốt kiểm tra" vào dự án. Mỗi lần bạn gõ `git push`, công cụ xem những thay đổi sắp đẩy lên. Nếu thấy mật khẩu bị lộ hoặc lỗi nặng (mức P1), nó dừng lại và cho bạn biết, nên code chưa rời khỏi máy.

**Cài chốt kiểm tra**

1. Nhấp đúp file **`Cai-hook.cmd`** trong thư mục công cụ.
2. Chờ dòng "Đang chuẩn bị lần đầu" nếu bạn chưa dùng Cách 1.
3. Chọn thư mục dự án (phải là dự án đã dùng git), rồi bấm **OK**.
4. Một hộp hỏi hiện ra. Bấm **Có** (Yes) để **cài**.
5. Cửa sổ đen báo "Đã cài hook...". Xong.

**Dùng hằng ngày:** bạn vẫn gõ `git push` như bình thường.

- Không có lỗi nặng: push đi bình thường.
- Có lỗi nặng: push bị chặn. Công cụ in ra file và dòng có vấn đề (không in nội dung mật khẩu). Bạn sửa rồi push lại.

**Khi bạn muốn đẩy code dù có lỗi** (ví dụ lỗi này bạn đã biết và chấp nhận), có hai cách:

- Gõ `git push --no-verify`.
- Hoặc đặt biến `SCAN_SKIP=1` rồi push.

**Khi Docker không chạy được:** công cụ thử tự mở Docker. Nếu vẫn không được, push vẫn đi nhưng có dòng cảnh báo **KHÔNG ĐƯỢC KIỂM TRA**. Công cụ cố ý làm vậy để một lỗi của chính nó không chặn công việc của bạn. Bạn nên đọc dòng cảnh báo này.

**Dự án của bạn đã có chốt kiểm tra khác (ví dụ husky):** hook cũ được giữ nguyên và vẫn chạy trước. Công cụ không ghi đè nó. Riêng dự án có đặt `core.hooksPath` thì công cụ chưa hỗ trợ và sẽ báo như vậy.

**Gỡ chốt kiểm tra**

1. Nhấp đúp `Cai-hook.cmd`, chọn lại thư mục dự án.
2. Ở hộp hỏi, bấm **Không** (No) để **gỡ**. Hook cũ của dự án (nếu có) được trả lại nguyên vẹn.

Nếu bấm **Hủy** (Cancel) hoặc đóng hộp bằng dấu X, công cụ không làm gì.

## Cách 3: Tự quét trên GitHub và nhận email

Mỗi lần bạn đẩy code lên GitHub, GitHub tự chạy công cụ quét trên máy của nó, miễn phí. Bạn không cần bật máy nào. Kết quả nằm ở tab **Actions** của dự án, và nếu đã cài email thì cả trong hộp thư.

**Bước 1. Tạo file cấu hình trong dự án**

1. Trong dự án cần quét, tạo thư mục `.github/workflows` nếu chưa có.
2. Trong đó tạo file `security-scan.yml` với nội dung sau (chép nguyên văn):

```yaml
name: Security scan
on: [push]
jobs:
  scan:
    permissions:
      contents: read
      actions: read
    uses: vietductran16092003/security-pipeline-image-2/.github/workflows/scan.yml@v1
    secrets:
      SMTP_USERNAME: ${{ secrets.SMTP_USERNAME }}
      SMTP_PASSWORD: ${{ secrets.SMTP_PASSWORD }}
      REPORT_EMAIL_TO: ${{ secrets.REPORT_EMAIL_TO }}
```

**Bước 2. Cài email (bỏ qua nếu chưa cần)**

Không làm bước này thì dự án vẫn được quét. Chỉ là bạn không nhận email, mà phải xem kết quả ở tab **Actions**.

Công cụ gửi email qua Gmail. Nó cần một **mật khẩu ứng dụng** của Google. Đây là mật khẩu riêng gồm 16 ký tự, chỉ dùng để gửi thư. Nó không phải mật khẩu Gmail bạn dùng để đăng nhập, nên nếu lộ thì bạn xoá nó đi mà không ảnh hưởng tài khoản.

1. Bật **xác minh 2 bước** cho tài khoản Google (vào https://myaccount.google.com/security).
2. Mở https://myaccount.google.com/apppasswords và tạo một mật khẩu ứng dụng. Chép 16 ký tự đó ra.
3. Mở dự án trên GitHub, vào **Settings → Secrets and variables → Actions**.
4. Bấm **New repository secret**, tạo lần lượt 3 mục:

| Tên (gõ đúng) | Điền gì |
|---|---|
| `SMTP_USERNAME` | Địa chỉ Gmail dùng để gửi |
| `SMTP_PASSWORD` | Mật khẩu ứng dụng 16 ký tự vừa tạo |
| `REPORT_EMAIL_TO` | Email nhận báo cáo. Nhiều người nhận thì cách nhau bằng dấu phẩy |

GitHub giữ kín 3 mục này. Người khác xem dự án cũng không đọc được.

**Bước 3. Đẩy code lên GitHub**

1. Đẩy code lên bằng `git push` như bình thường.
2. Mở dự án trên GitHub, bấm tab **Actions**. Lần chạy mới nhất hiện ở đầu danh sách.
3. Chờ vài phút. Chạy xong, bạn nhận email (nếu đã làm Bước 2).

**Muốn xem kết quả mà không có email:** ở tab **Actions**, mở lần chạy, xem phần tóm tắt (tên tiếng Anh là Job Summary). Hoặc kéo xuống cuối, tải file đính kèm `security-report`, giải nén rồi mở `email.html`.

## Đọc báo cáo

### Báo cáo cho biết điều gì

Mỗi báo cáo có 6 phần. Mỗi phần ở một trong 4 trạng thái:

| Trạng thái | Nghĩa là |
|---|---|
| **Sạch** | Không thấy lỗi |
| **Có lỗi** | Kèm số lỗi tìm được |
| **Không quét** | Dự án không có thứ cần kiểm tra ở phần này. Báo cáo ghi lý do |
| **Lỗi** | Công cụ kiểm tra bị hỏng khi chạy nên chưa có kết quả. Đừng hiểu là "sạch" |

| Phần | Kiểm tra khi nào | Công cụ dùng |
|---|---|---|
| Mật khẩu, khoá bí mật bị lộ | Luôn kiểm tra, kể cả các lần sửa code cũ | Gitleaks |
| Lỗi bảo mật trong code | Luôn kiểm tra | Semgrep |
| Thư viện có lỗ hổng đã biết | Khi dự án có danh sách thư viện (`package.json`, `requirements.txt`, `go.mod`, `pom.xml`...) | Trivy |
| Docker image | Khi có `Dockerfile` ở thư mục gốc | Docker build, rồi Trivy |
| Dockerfile có đúng quy định không | Khi có `Dockerfile` ở thư mục gốc | Conftest |
| File cấu hình hạ tầng | Khi có Terraform, Kubernetes, Helm | Trivy |

Hiện tại công cụ chỉ đọc `Dockerfile` nằm ở thư mục gốc của dự án.

### Lỗi nào sửa trước

Mỗi lỗi được xếp vào một trong 3 mức:

| Mức | Nghĩa là | Ví dụ |
|---|---|---|
| **P1** | Sửa ngay | Lộ mật khẩu hoặc khoá bí mật. Lỗ hổng mức CRITICAL. Lỗ hổng mức HIGH đã có bản sửa |
| **P2** | Lên kế hoạch sửa | Lỗ hổng mức HIGH chưa có bản sửa. Mức MEDIUM. Dockerfile sai quy định |
| **Backlog** | Rảnh thì sửa | Mức LOW. Các gợi ý nhỏ |

Báo cáo có gợi ý cách sửa theo từng loại lỗi: nâng phiên bản thư viện, sửa đoạn code, hoặc sửa file cấu hình.

### Điểm từ A đến F

| Điểm | Khi nào |
|---|---|
| A | Không có lỗi P1, không có lỗi P2 |
| B | Không có P1, có 1 đến 5 lỗi P2 |
| C | Không có P1, có hơn 5 lỗi P2 |
| D | Có 1 đến 3 lỗi P1 |
| F | Có hơn 3 lỗi P1, hoặc có mật khẩu, khoá bí mật bị lộ |

Nếu có phần bị "Lỗi", báo cáo ghi **ĐIỂM TẠM**, vì chưa kiểm tra đủ.

### So với lần trước

Từ lần quét thứ hai, báo cáo cho biết có bao nhiêu **lỗi mới** và bao nhiêu **lỗi đã sửa**. Phần nào bị "Lỗi" hoặc "Không quét" ở một trong hai lần thì không đưa vào so sánh.

- Cách 1: so với lần quét trước của chính thư mục đó.
- Cách 3: so với lần quét gần nhất trên cùng nhánh. GitHub giữ kết quả mỗi lần quét 90 ngày.

### Có lỗi thì dự án có bị hỏng không?

Không. Tìm thấy lỗi không chặn bạn gộp code (merge) và không làm dự án ngừng chạy. Ở Cách 3, lần chạy chỉ báo thất bại khi chính công cụ không tạo ra được báo cáo. Ở Cách 2, chỉ lỗi nặng mới chặn `git push`, và bạn luôn bỏ qua được.

## Gặp sự cố

| Bạn thấy | Làm thế này |
|---|---|
| Cửa sổ đen báo cần Python | Cài Python 3.11 trở lên (xem [Chuẩn bị](#chuẩn-bị-làm-một-lần)), nhớ tick **Add Python to PATH**, rồi nhấp đúp lại |
| Báo "Docker chưa sẵn sàng" | Mở Docker Desktop bằng tay, chờ biểu tượng cá voi ở góc phải dưới ngừng chuyển động, rồi chạy lại |
| Lần đầu quét rất lâu | Bình thường. Docker đang tải các công cụ quét về. Những lần sau nhanh hơn |
| Hộp chọn thư mục không thấy đâu | Nó có thể nằm sau cửa sổ khác. Bấm vào thanh tác vụ để tìm |
| Cách 2: push không bị chặn dù có lỗi | Xem dòng cảnh báo **KHÔNG ĐƯỢC KIỂM TRA**. Có thể Docker không chạy được. Hoặc bạn đã dùng `--no-verify` |
| Cách 2: sau khi di chuyển thư mục công cụ thì push báo lỗi | Hook nhớ đường dẫn cũ. Nhấp đúp `Cai-hook.cmd` ở vị trí mới, chọn lại dự án và cài lại |
| Cách 3: không có email | Kiểm tra 3 mục `SMTP_USERNAME`, `SMTP_PASSWORD`, `REPORT_EMAIL_TO` đã tạo đúng tên chưa. Thiếu một mục là không có email, dù quét vẫn chạy bình thường |
| Cách 3: email báo "Lỗi" ở một phần | Phần đó chưa kiểm tra được. Mở lần chạy ở tab **Actions** để xem nguyên nhân |

## Tuỳ chỉnh

### Quét thêm theo lịch (Cách 3)

Lỗ hổng mới được công bố hằng ngày, kể cả khi code của bạn không đổi. Muốn quét thêm mỗi đêm, sửa dòng `on:` trong file `security-scan.yml`:

```yaml
on:
  push:
  schedule:
    - cron: "0 19 * * *"   # 2 giờ sáng giờ Việt Nam
```

### Bỏ qua lỗi bạn đã chấp nhận

Có những lỗi bạn đã xem xét và quyết định để đó. Mỗi công cụ có một file riêng để ghi các lỗi này:

- **Mật khẩu, khoá bí mật:** thêm mã nhận dạng của lỗi (gọi là fingerprint, có trong nhật ký của Gitleaks) vào file `.gitleaksignore`. Hoặc khai báo danh sách được phép trong `.gitleaks.toml`. Lưu ý: một khoá cũ dù đã đổi nhưng vẫn nằm trong lịch sử code thì vẫn bị báo. Nếu không ghi nó vào đây, dự án sẽ bị điểm F mãi.
- **Lỗ hổng thư viện, lỗi cấu hình:** thêm mã lỗi (ví dụ `CVE-2023-1234`) vào file `.trivyignore`, mỗi dòng một mã.
- **Lỗi trong code:** thêm chú thích `# nosemgrep` (hoặc `// nosemgrep`) ở cuối dòng đó. Nên ghi kèm lý do.

Báo cáo có một dòng cho biết dự án đang bỏ qua bao nhiêu lỗi theo cách này.

### Chọn phiên bản công cụ (Cách 3)

Đuôi `@v1` trong dòng `uses: ...scan.yml@v1` là phiên bản công cụ bạn dùng. Muốn thử bản mới nhất, đổi thành `@main` và thêm `with: scanner-ref: main` bên dưới, để hai phần dùng cùng một phiên bản.

### Phân tích kỹ bằng AI (không bắt buộc)

Công cụ không tự gọi AI. Khi cần xem kỹ một báo cáo, đọc [agents/README.md](agents/README.md). Ở đó có cách chạy 4 trợ lý AI (Context, Exploit, Severity, Recommendation) bằng Claude Code trên báo cáo đã tải về.

## Đang làm, chưa dùng được

**Kiểm tra repo lạ trước khi tải về máy.** Bạn dán link một dự án trên GitHub hoặc GitLab, công cụ mở nó trong một hộp cách ly (không chạm vào máy bạn) và cho biết có dấu hiệu bị gài mã độc hay không. Phần này chưa xong, nên chưa có file nào để bạn bấm. Khi xong, README này sẽ có thêm hướng dẫn.

Tính năng này chỉ giảm rủi ro, không đảm bảo "sạch tuyệt đối".

## Dành cho người phát triển công cụ

Cài đặt và chạy test:

```bash
python -m venv .venv
.venv/bin/pip install -r requirements-dev.txt
.venv/bin/python -m pytest -q
```

Trên Windows dùng `.venv\Scripts\...` thay cho `.venv/bin/...`.

Quét thử một dự án ngay trên máy (cần Docker):

```bash
python -m scanner run --root ../du-an-cua-ban --out scan-out --scanner-dir .
```

Kết quả nằm trong thư mục `scan-out/`: `report.json`, `email.html`, `subject.txt`, `summary.md`.

Các lệnh khác:

| Lệnh | Việc |
|---|---|
| `python -m scanner check --root PATH` | Quét trên máy, lưu lịch sử, mở báo cáo (là việc `Quet-du-an.cmd` gọi) |
| `python -m scanner hook install --root PATH` | Cài chốt kiểm tra trước khi push (hoặc `uninstall` để gỡ) |
| `python -m scanner prepush --root PATH` | Phần kiểm tra mà chốt trên gọi; đọc dữ liệu push của git từ đầu vào chuẩn |
| `python -m scanner run --mode local ...` | Như `run` nhưng quét cả file chưa commit và thư mục không có git |

Trên Windows bạn không cần tự mở Docker Desktop. Nếu Docker chưa chạy, công cụ tự mở (chờ tối đa 3 phút) và tắt lại sau khi quét xong. Nếu bạn đã mở từ trước, công cụ để nguyên.

Cách xếp mức P1, P2, Backlog nằm trong file `rules.yaml`.

## Giải thích từ ngữ

| Từ | Nghĩa |
|---|---|
| Push (đẩy code) | Gửi những thay đổi trên máy bạn lên GitHub |
| Hook | Một đoạn lệnh nhỏ git tự chạy ở một thời điểm nhất định. Ở đây là ngay trước khi push |
| Workflow | File hướng dẫn GitHub tự làm một việc. Ở đây là chạy công cụ quét |
| Secret | Thông tin bí mật (mật khẩu, khoá) lưu kín trong cài đặt dự án |
| Lỗ hổng | Chỗ yếu có thể bị kẻ xấu lợi dụng |
| CVE | Mã số của một lỗ hổng đã được công bố, ví dụ `CVE-2023-1234` |
| Docker image | Gói chứa ứng dụng cùng mọi thứ nó cần để chạy, tạo từ `Dockerfile` |
| Nhánh (branch) | Một dòng phát triển riêng của code, ví dụ `main` |
| Merge (gộp code) | Đưa thay đổi từ nhánh này vào nhánh khác |
| Artifact | File GitHub lưu lại sau mỗi lần chạy, tải về được ở tab Actions |
| Job Summary | Trang tóm tắt kết quả, hiện khi bạn mở một lần chạy trong tab Actions |
