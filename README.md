# security-scan-action

Bộ quét bảo mật dùng chung cho mọi dự án trên GitHub. Gắn vào dự án bằng một file workflow ngắn: mỗi lần push, bộ quét tự nhận biết dự án có gì, chạy các công cụ phù hợp, xếp ưu tiên lỗi, rồi **gửi email báo cáo HTML** cho bạn.

Mọi thứ chạy trên runner miễn phí `ubuntu-latest` của GitHub. Không cần server, VPN hay máy chạy sẵn.

## Gắn vào một dự án

1. Trong dự án cần quét, tạo file `.github/workflows/security-scan.yml`:

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

2. Thêm 3 secret trong **Settings → Secrets and variables → Actions** của dự án (xem phần bên dưới).
3. Push code. Kết quả xuất hiện ở tab **Actions** (Job Summary) và trong hộp thư của bạn.

Muốn quét thêm theo lịch (ví dụ mỗi đêm, để bắt CVE mới công bố dù code không đổi), chỉ cần sửa dòng `on:` trong file trên, không phải sửa bộ quét:

```yaml
on:
  push:
  schedule:
    - cron: "0 19 * * *"   # 2 giờ sáng giờ Việt Nam
```

## Cấu hình gửi email (Gmail)

1. Bật xác minh 2 bước cho tài khoản Google.
2. Vào https://myaccount.google.com/apppasswords, tạo một **App Password** (16 ký tự).
3. Thêm secret cho dự án:

| Secret | Giá trị |
|---|---|
| `SMTP_USERNAME` | Địa chỉ Gmail dùng để gửi |
| `SMTP_PASSWORD` | App Password vừa tạo (không phải mật khẩu Gmail) |
| `REPORT_EMAIL_TO` | Email nhận báo cáo, nhiều địa chỉ thì cách nhau bằng dấu phẩy |

Thiếu secret thì bộ quét vẫn chạy và workflow vẫn xanh. Báo cáo vẫn có trong Job Summary và trong artifact `security-report` (file `email.html`).

## Bộ quét làm gì

| Phần quét | Khi nào chạy | Công cụ |
|---|---|---|
| Secret bị lộ | Luôn chạy (quét cả lịch sử git) | Gitleaks |
| Lỗi bảo mật trong code | Luôn chạy | Semgrep (`p/default`) |
| Thư viện có CVE | Có `package.json`, `requirements.txt`, `go.mod`, `*.csproj`, `pom.xml`... | Trivy `fs` |
| Docker image | Có `Dockerfile` ở thư mục gốc | `docker build` rồi Trivy `image` |
| Dockerfile policy | Có `Dockerfile` ở thư mục gốc | Conftest (`policy/docker.rego`) |
| Cấu hình IaC | Có Terraform, Kubernetes YAML, Helm | Trivy `config` |

Mỗi phần có một trong 4 trạng thái: **Sạch**, **có finding**, **Không quét** (kèm lý do) hoặc **Lỗi** (công cụ chạy hỏng). Email luôn liệt kê đủ 6 phần.

Tìm thấy lỗi **không** làm workflow đỏ, nên không chặn merge. Workflow chỉ đỏ khi chính bộ quét không tạo ra được báo cáo.

Hiện chỉ hỗ trợ `Dockerfile` ở thư mục gốc của dự án.

## Phiên bản

Dòng `uses: ...scan.yml@v1` chọn phiên bản workflow. Workflow này tải mã bộ quét theo input `scanner-ref`, mặc định cũng là `v1`. Nếu bạn gọi một phiên bản khác (ví dụ `@main` để thử), hãy truyền thêm `with: scanner-ref: main` để workflow và mã bộ quét cùng một phiên bản.

## Mức ưu tiên

Mỗi finding được Rule Engine (`rules.yaml`) xếp vào một mức:

| Mức | Ý nghĩa | Ví dụ |
|---|---|---|
| **P1** | Xử lý ngay | Secret bị lộ, CVE mức CRITICAL, CVE mức HIGH đã có bản vá |
| **P2** | Lên kế hoạch xử lý | CVE mức HIGH chưa có bản vá, mức MEDIUM, vi phạm Dockerfile policy |
| **Backlog** | Khi có thời gian | Mức LOW, MEDIUM trên base OS đã hết hỗ trợ, các khuyến nghị |

## Điểm A–F

| Điểm | Điều kiện |
|---|---|
| A | Không có P1, không có P2 |
| B | Không có P1, có 1–5 lỗi P2 |
| C | Không có P1, có hơn 5 lỗi P2 |
| D | Có 1–3 lỗi P1 |
| F | Có hơn 3 lỗi P1, hoặc có secret bị lộ |

## So sánh với lần trước

Mỗi lần quét lưu `report.json` vào artifact `security-report` (giữ 90 ngày). Lần sau, bộ quét lấy artifact của lần chạy gần nhất trên cùng nhánh để tính **lỗi mới** và **lỗi đã sửa**. Phần nào bị lỗi hoặc không quét ở một trong hai lần thì không được đưa vào so sánh.

## Bỏ qua lỗi đã chấp nhận

Bộ quét dùng các file ignore chuẩn của từng công cụ, không cần cấu hình riêng:

- **Secret:** thêm fingerprint vào `.gitleaksignore` (fingerprint có trong log của Gitleaks), hoặc khai báo allowlist trong `.gitleaks.toml`. Với **secret cũ đã thu hồi** mà vẫn còn trong lịch sử git, bạn phải ignore nó, nếu không dự án sẽ bị điểm F mãi.
- **CVE / cấu hình:** thêm mã lỗi (ví dụ `CVE-2023-1234`) vào `.trivyignore`, mỗi dòng một mã.
- **Code:** thêm chú thích `# nosemgrep` (hoặc `// nosemgrep`) ở cuối dòng, nên ghi kèm lý do.

Email có một dòng cho biết dự án đang áp dụng bao nhiêu quy tắc bỏ qua.

## AI agent chạy tay

Pipeline không gọi AI. Khi cần phân tích sâu, xem [agents/README.md](agents/README.md) để chạy 4 agent (Context, Exploit, Severity, Recommendation) bằng Claude Code trên báo cáo đã tải về.

## Phát triển

```bash
python -m venv .venv
.venv/bin/pip install -r requirements-dev.txt
.venv/bin/python -m pytest -q
```

Chạy thử trên một dự án ở máy (cần Docker):

```bash
python -m scanner run --root ../du-an-cua-ban --out scan-out --scanner-dir .
```

Kết quả nằm trong `scan-out/`: `report.json`, `email.html`, `subject.txt`, `summary.md`.
