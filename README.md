# security-scan-action

Công cụ tự kiểm tra lỗ hổng bảo mật cho dự án trên GitHub. Mỗi lần bạn đẩy code lên, nó xem dự án có những gì, chạy các công cụ kiểm tra phù hợp, sắp xếp lỗi theo mức cần sửa gấp, rồi **gửi một email báo cáo** cho bạn.

Mọi việc chạy trên máy miễn phí của GitHub. Bạn không cần thuê máy chủ, không cần VPN, không cần để máy nào bật sẵn.

## Bạn nên đọc phần nào

| Bạn là | Đọc |
|---|---|
| Người muốn gắn công cụ vào dự án của mình | [Gắn vào dự án trong 3 bước](#gắn-vào-dự-án-trong-3-bước) và [Nhận báo cáo qua email](#nhận-báo-cáo-qua-email) |
| Người nhận email và cần biết sửa gì trước | [Đọc báo cáo](#đọc-báo-cáo) |
| Người phụ trách dự án, cần tinh chỉnh | [Tuỳ chỉnh](#tuỳ-chỉnh) |
| Người sửa chính công cụ này | [Dành cho người phát triển công cụ](#dành-cho-người-phát-triển-công-cụ) |

Nếu gặp từ lạ, xem [Giải thích từ ngữ](#giải-thích-từ-ngữ) ở cuối trang.

## Gắn vào dự án trong 3 bước

**Bước 1.** Trong dự án cần kiểm tra, tạo file `.github/workflows/security-scan.yml` với nội dung sau (chép nguyên văn):

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

**Bước 2.** Khai báo thông tin gửi email trong **Settings → Secrets and variables → Actions** của dự án. Cách làm ở phần [Nhận báo cáo qua email](#nhận-báo-cáo-qua-email). Bỏ qua bước này thì vẫn quét được, chỉ là không có email.

**Bước 3.** Đẩy code lên GitHub (push). Khi chạy xong, kết quả hiện ở tab **Actions** của dự án và trong hộp thư của bạn.

## Nhận báo cáo qua email

Công cụ gửi email qua Gmail. Bạn cần một "mật khẩu ứng dụng" của Google. Đây là mật khẩu riêng 16 ký tự, chỉ dùng để gửi mail, không phải mật khẩu Gmail bạn vẫn đăng nhập.

1. Bật xác minh 2 bước cho tài khoản Google.
2. Vào https://myaccount.google.com/apppasswords và tạo một mật khẩu ứng dụng.
3. Trong dự án trên GitHub, vào **Settings → Secrets and variables → Actions**, thêm 3 mục sau:

| Tên | Điền gì |
|---|---|
| `SMTP_USERNAME` | Địa chỉ Gmail dùng để gửi |
| `SMTP_PASSWORD` | Mật khẩu ứng dụng vừa tạo (không phải mật khẩu Gmail) |
| `REPORT_EMAIL_TO` | Email nhận báo cáo. Nhiều người nhận thì cách nhau bằng dấu phẩy |

GitHub giữ kín 3 mục này, người khác xem dự án cũng không đọc được.

Thiếu một trong 3 mục thì công cụ vẫn quét và vẫn báo thành công, chỉ không gửi mail. Khi đó bạn xem báo cáo ở tab **Actions**: mở lần chạy, xem phần tóm tắt (Job Summary), hoặc tải file đính kèm `security-report` về rồi mở `email.html`.

## Đọc báo cáo

### Công cụ kiểm tra những gì

| Phần | Khi nào kiểm tra | Dùng công cụ |
|---|---|---|
| Mật khẩu, khoá bí mật bị lộ trong code | Luôn kiểm tra, cả lịch sử các lần sửa | Gitleaks |
| Lỗi bảo mật trong code | Luôn kiểm tra | Semgrep (`p/default`) |
| Thư viện dùng trong dự án có lỗ hổng đã biết | Khi có `package.json`, `requirements.txt`, `go.mod`, `*.csproj`, `pom.xml`... | Trivy `fs` |
| Docker image | Khi có `Dockerfile` ở thư mục gốc | `docker build` rồi Trivy `image` |
| Dockerfile có viết đúng quy định không | Khi có `Dockerfile` ở thư mục gốc | Conftest (`policy/docker.rego`) |
| File cấu hình hạ tầng | Khi có Terraform, Kubernetes YAML, Helm | Trivy `config` |

Email luôn liệt kê đủ 6 phần, mỗi phần ở một trong 4 trạng thái:

- **Sạch**: không thấy lỗi.
- **Có lỗi**: kèm số lỗi tìm được.
- **Không quét**: dự án không có thứ cần kiểm tra ở phần này, email ghi rõ lý do.
- **Lỗi**: công cụ kiểm tra bị hỏng khi chạy, nên phần này chưa có kết quả. Đừng hiểu nhầm là "sạch".

Hiện tại chỉ đọc được `Dockerfile` nằm ở thư mục gốc của dự án.

### Lỗi nào cần sửa trước

Mỗi lỗi được xếp vào một trong 3 mức:

| Mức | Nghĩa là | Ví dụ |
|---|---|---|
| **P1** | Sửa ngay | Lộ mật khẩu hoặc khoá bí mật; lỗ hổng mức CRITICAL; lỗ hổng mức HIGH đã có bản sửa |
| **P2** | Lên kế hoạch sửa | Lỗ hổng mức HIGH chưa có bản sửa; mức MEDIUM; Dockerfile sai quy định |
| **Backlog** | Rảnh thì sửa | Mức LOW; mức MEDIUM nằm trong hệ điều hành gốc đã hết hỗ trợ; các gợi ý |

Báo cáo có gợi ý cách sửa theo loại lỗi: nâng phiên bản thư viện, sửa đoạn code, hoặc sửa file cấu hình. Email đưa gợi ý cho lỗi nghiêm trọng nhất; danh sách đầy đủ kèm gợi ý nằm trong Job Summary.

### Điểm A đến F

| Điểm | Khi nào |
|---|---|
| A | Không có lỗi P1, không có lỗi P2 |
| B | Không có P1, có 1 đến 5 lỗi P2 |
| C | Không có P1, có hơn 5 lỗi P2 |
| D | Có 1 đến 3 lỗi P1 |
| F | Có hơn 3 lỗi P1, hoặc có mật khẩu, khoá bí mật bị lộ |

Nếu có phần bị "Lỗi", email ghi **ĐIỂM TẠM**, vì chưa kiểm tra đủ.

### So với lần trước

Từ lần quét thứ hai, email cho biết có bao nhiêu **lỗi mới** và bao nhiêu **lỗi đã sửa** so với lần quét gần nhất trên cùng nhánh. Kết quả mỗi lần quét được GitHub giữ 90 ngày. Phần nào bị "Lỗi" hoặc "Không quét" ở một trong hai lần thì không đưa vào so sánh.

### Báo lỗi có làm hỏng dự án không

Không. Tìm thấy lỗi không chặn bạn gộp code (merge). Lần chạy chỉ báo thất bại khi chính công cụ không tạo ra được báo cáo.

## Tuỳ chỉnh

### Quét thêm theo lịch

Lỗ hổng mới được công bố hằng ngày, kể cả khi code của bạn không đổi. Muốn quét thêm mỗi đêm, chỉ cần sửa dòng `on:` trong file ở Bước 1:

```yaml
on:
  push:
  schedule:
    - cron: "0 19 * * *"   # 2 giờ sáng giờ Việt Nam
```

### Bỏ qua lỗi bạn đã chấp nhận

Có những lỗi bạn đã xem xét và quyết định để đó. Mỗi công cụ có file riêng để ghi những lỗi này, không cần cấu hình gì thêm:

- **Mật khẩu, khoá bí mật:** thêm mã nhận dạng của lỗi (fingerprint, có trong nhật ký của Gitleaks) vào file `.gitleaksignore`, hoặc khai báo danh sách được phép trong `.gitleaks.toml`. Lưu ý: một khoá cũ dù đã đổi nhưng vẫn nằm trong lịch sử các lần sửa thì vẫn bị báo. Nếu không ghi nó vào đây, dự án sẽ bị điểm F mãi.
- **Lỗ hổng thư viện, lỗi cấu hình:** thêm mã lỗi (ví dụ `CVE-2023-1234`) vào file `.trivyignore`, mỗi dòng một mã.
- **Lỗi trong code:** thêm chú thích `# nosemgrep` (hoặc `// nosemgrep`) ở cuối dòng đó. Nên ghi kèm lý do.

Email có một dòng cho biết dự án đang bỏ qua bao nhiêu lỗi theo cách này.

### Chọn phiên bản công cụ

Đuôi `@v1` trong dòng `uses: ...scan.yml@v1` là phiên bản công cụ bạn dùng. Workflow này tự tải mã công cụ theo tham số `scanner-ref`, mặc định cũng là `v1`. Nếu bạn đổi sang phiên bản khác (ví dụ `@main` để thử bản mới nhất), hãy thêm `with: scanner-ref: main` để hai phần dùng cùng một phiên bản.

### Phân tích sâu bằng AI (tuỳ chọn)

Công cụ không tự gọi AI. Khi cần phân tích kỹ một báo cáo, xem [agents/README.md](agents/README.md): ở đó hướng dẫn chạy 4 trợ lý AI (Context, Exploit, Severity, Recommendation) bằng Claude Code trên báo cáo đã tải về.

## Dành cho người phát triển công cụ

Cài đặt và chạy test:

```bash
python -m venv .venv
.venv/bin/pip install -r requirements-dev.txt
.venv/bin/python -m pytest -q
```

Quét thử một dự án ngay trên máy (cần Docker):

```bash
python -m scanner run --root ../du-an-cua-ban --out scan-out --scanner-dir .
```

Kết quả nằm trong thư mục `scan-out/`: `report.json`, `email.html`, `subject.txt`, `summary.md`.

Trên Windows bạn không cần tự mở Docker Desktop. Nếu Docker chưa chạy, công cụ tự mở (chờ tối đa 3 phút) và tắt lại sau khi quét xong. Nếu bạn đã mở Docker Desktop từ trước, công cụ để nguyên.

Cách xếp mức P1, P2, Backlog nằm trong file `rules.yaml`.

## Giải thích từ ngữ

| Từ | Nghĩa |
|---|---|
| Push (đẩy code) | Gửi những thay đổi trên máy bạn lên GitHub |
| Workflow | File hướng dẫn GitHub tự làm một việc, ở đây là chạy công cụ quét |
| Secret | Thông tin bí mật (mật khẩu, khoá) lưu kín trong cài đặt dự án |
| CVE | Mã số của một lỗ hổng đã được công bố, ví dụ `CVE-2023-1234` |
| Docker image | Gói chứa ứng dụng cùng mọi thứ nó cần để chạy, build từ `Dockerfile` |
| Nhánh (branch) | Một dòng phát triển riêng của code, ví dụ `main` |
| Artifact | File GitHub lưu lại sau mỗi lần chạy, tải về được ở tab Actions |
| Job Summary | Trang tóm tắt kết quả, hiện khi bạn mở một lần chạy trong tab Actions |
