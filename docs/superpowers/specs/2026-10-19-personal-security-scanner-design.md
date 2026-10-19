# Thiết kế: Bộ quét bảo mật cá nhân dùng lại cho mọi dự án

Ngày: 19/10/2026 · Trạng thái: chờ duyệt

## 1. Ý định và lý do

Repo này đang là pipeline quét bảo mật cho một Docker image công cụ quét thương mại thuộc hạ tầng nội bộ nơi thực tập. Mỗi lần chạy phải xin VPN để truy cập registry nội bộ, base image phải load tay từ file nén, và các job build/deploy/rollback chạy trên một máy ảo VMware self-hosted. Máy ảo tắt thì pipeline dừng. Các secret công cụ quét thương mại/DefectDojo chưa bao giờ được điền nên những job đó chưa từng chạy thật.

Chủ repo muốn biến nó thành **dự án cá nhân**: một bộ quét bảo mật **gắn được vào bất kỳ dự án nào sau này**, chạy hoàn toàn trên hạ tầng miễn phí của GitHub, không phụ thuộc VPN, registry nội bộ hay máy nào phải bật sẵn. Sau mỗi lần quét, chủ repo **nhận một email HTML** đọc được ngay trong Gmail.

## 2. Mục tiêu

1. **Không phụ thuộc hạ tầng nội bộ cũ:** mọi job chạy trên `ubuntu-latest` của GitHub. Không còn self-hosted runner, registry nội bộ, công cụ quét thương mại hay DefectDojo.
2. **Dùng lại được:** một dự án bất kỳ chỉ cần thêm **một file workflow ngắn** (khoảng 10 dòng) gọi tới repo này, và khai báo vài secret để gửi email.
3. **Tự nhận biết dự án:** bộ quét tự phát hiện dự án có gì và quét phần đó (xem mục 5.2). Người dùng không phải cấu hình từng công cụ.
4. **Xếp ưu tiên tự động:** gom kết quả mọi công cụ về một định dạng chung. Rule Engine xếp **mọi** finding vào P1, P2 hoặc Backlog, không để finding nào "chưa phân loại".
5. **Email HTML sau mỗi lần quét**, kể cả khi không có lỗi, theo mẫu "Hướng 1" (mục 6).
6. **So sánh với lần quét trước**: email cho biết lỗi mới xuất hiện, lỗi đã sửa, và mức tăng/giảm của từng con số.

## 3. Không làm (non-goals)

- **AI agent không chạy tự động trong pipeline.** 4 agent (Context, Exploit, Severity, Recommendation) vẫn chạy tay bằng Claude Code khi cần. Pipeline không gọi LLM và không cần API key.
- Không dựng server nào: không DefectDojo, không database, không dịch vụ web riêng.
- Chưa chạy theo lịch. Giai đoạn này chỉ chạy khi **push code**. Lịch cố định (ví dụ mỗi đêm) sẽ thêm sau khi công cụ hoàn thiện, nên thiết kế phải cho phép thêm `schedule` mà không phải sửa logic.
- Không giữ các tính năng gắn với hạ tầng nội bộ cũ: Dockerfile `image quét cũ`, `pipeline_entrypoint.sh`, job `rollback`, `deploy-vmware`, `job quét cũ`, `defectdojo_agent.py`, tài liệu build image thủ công.

## 4. Anti-goals (chạy được nhưng vẫn coi là thất bại)

Chủ repo chốt mà không trả lời câu này. Các điểm dưới đây là **quyết định của người thiết kế**, chủ repo có thể sửa:

- **Không chặn merge hay push.** Bộ quét chỉ báo cáo; tìm thấy lỗi không được làm workflow của dự án gọi nó bị đỏ. Chỉ khi chính bộ quét hỏng (không chạy được) thì mới báo lỗi.
- **Không im lặng khi hỏng.** Nếu một công cụ quét bị lỗi (khác với "không có finding"), email phải nói rõ công cụ đó lỗi chứ không được hiện như "sạch".
- **Không quá chậm.** Mục tiêu cả lượt quét dưới khoảng 10 phút với dự án cỡ nhỏ và vừa.
- Email phải đọc được trên Gmail web và Gmail điện thoại. Nếu bố cục vỡ trên Gmail thì coi như hỏng.

## 5. Cách hoạt động

### 5.1 Cách gắn vào một dự án

Dự án cần quét thêm file `.github/workflows/security-scan.yml`, đại ý:

```yaml
on: [push]
jobs:
  scan:
    uses: vietductran16092003/<repo-mới>/.github/workflows/scan.yml@v1
    secrets:
      SMTP_USERNAME: ${{ secrets.SMTP_USERNAME }}
      SMTP_PASSWORD: ${{ secrets.SMTP_PASSWORD }}
      REPORT_EMAIL_TO: ${{ secrets.REPORT_EMAIL_TO }}
```

- Đây là một **reusable workflow** (`workflow_call`) trong repo này. Tên file `scan.yml`, tên input và secret do người xây dựng chọn, miễn là file trong dự án gọi vẫn ngắn như trên.
- Bộ quét nằm ở một **repo mới, public**, để repo khác gọi được (xem mục 7).
- Phát hành theo tag (`v1`) để dự án gọi không bị ảnh hưởng khi repo bộ quét thay đổi.

### 5.2 Tự nhận biết và quét

| Phần quét | Điều kiện chạy | Công cụ | Ghi chú |
|---|---|---|---|
| Secret bị lộ | Luôn chạy | Gitleaks | Quét toàn bộ lịch sử git (`fetch-depth: 0`) |
| Lỗi bảo mật trong code | Luôn chạy | Semgrep | Bộ rule tự chọn theo ngôn ngữ, ví dụ `p/default` hoặc `auto` |
| Thư viện có CVE | Có file manifest/lockfile (`package.json`, `requirements.txt`, `*.csproj`, `go.mod`, `pom.xml`…) | Trivy `fs` | |
| Docker image | Có `Dockerfile` | `docker build` rồi Trivy `image` | Build trên runner GitHub, không push đi đâu |
| Dockerfile policy | Có `Dockerfile` | Conftest với `policy/docker.rego` | Rego phải bỏ phần ngoại lệ riêng cho image cũ (`AS source`) và áp dụng chung |
| Cấu hình IaC | Có Terraform, Kubernetes YAML, Helm… | Trivy `config` | |

- Phần nào **không áp dụng** vẫn được ghi vào kết quả với trạng thái "không quét", kèm lý do (ví dụ "không có Dockerfile").
- Mỗi phần có một trong 4 trạng thái: **sạch**, **có finding**, **không quét** (kèm lý do), **lỗi** (công cụ chạy hỏng, kèm thông báo ngắn).
- Dự án có nhiều Dockerfile hoặc Dockerfile không nằm ở thư mục gốc: người xây dựng tự quyết. Tối thiểu phải hỗ trợ `Dockerfile` ở thư mục gốc.
- **Một công cụ bị lỗi không làm workflow đỏ.** Ví dụ `docker build` hỏng vì Dockerfile của dự án: phần đó nhận trạng thái "lỗi", các phần khác vẫn chạy, email vẫn gửi. Workflow chỉ đỏ khi chính bộ quét không tạo ra được báo cáo.

### 5.2b Bỏ qua lỗi chấp nhận được (false positive, secret cũ đã thu hồi)

- Tôn trọng các file ignore **chuẩn của từng công cụ** nếu dự án có sẵn: `.gitleaksignore`, `.trivyignore`, chú thích `# nosemgrep`. Không thêm file cấu hình riêng nào khác, đúng tinh thần "không phải cấu hình".
- Finding bị bỏ qua không tính vào P1/P2/Backlog, không ảnh hưởng điểm A–F. Email có một dòng nhỏ "Đã bỏ qua N finding theo file ignore của dự án" để không bị giấu hoàn toàn.
- README hướng dẫn cách dùng các file ignore này, đặc biệt với secret cũ đã thu hồi (nếu không ignore thì dự án sẽ bị điểm F mãi).

### 5.3 Chuẩn hoá và xếp ưu tiên (Rule Engine)

- Mở rộng `ai_triage/main.py` để đọc output của **mọi** công cụ ở bảng trên (Trivy fs/image/config, Semgrep, Gitleaks, Conftest), không chỉ Trivy image như hiện tại.
- Mở rộng `schema.json` cho phù hợp. Tối thiểu cần thêm: công cụ nguồn (`tool`), loại finding (CVE, secret, lỗi code, policy, cấu hình), và phiên bản đã có bản vá (`fixed_version`, nếu có). Trường nào không áp dụng cho loại finding đó thì để `null`.
- **Mọi finding phải có `priority`.** Bổ sung `rules.yaml` để bao phủ hết; quy tắc cuối cùng là quy tắc mặc định. Gợi ý ban đầu (người xây dựng tinh chỉnh):
  - Secret bị lộ → P1
  - CRITICAL → P1
  - HIGH có bản vá → P1; HIGH chưa có bản vá → P2
  - MEDIUM → P2
  - LOW, UNKNOWN → Backlog
  - Policy `deny` → P2; policy `warn` → Backlog
- Bỏ các giá trị hardcode gắn với image cũ (`KNOWN_EOL_IMAGES`, `DEFAULT_ENVIRONMENT = "production"`). Nếu cần biết base OS đã EOL thì lấy từ output của Trivy, vì Trivy có báo trạng thái EOL của OS.
- Sửa lỗi chia cho 0 khi không có finding nào (`main.py`, hàm `write_report`).
- 4 agent `.md` trong `ai_triage/agents/` giữ nguyên vai trò chạy tay, chỉ cập nhật cho khớp schema mới. Khi chạy tay, agent ghi đè `priority` **trên bản báo cáo đang được phân tích**, phục vụ việc xem xét lúc đó. Kết quả này **không được lưu lại** cho lần quét sau và không ảnh hưởng tới email. Lần quét kế tiếp vẫn dùng Rule Engine. Nếu muốn một lỗi không bị báo nữa thì dùng file ignore (mục 5.2b).
- Bỏ `environment` và `business_criticality` (cùng file `ai_triage/business_criticality.yaml`). Chúng không có nguồn dữ liệu trong pipeline tự động. Context Agent chạy tay có thể tự thêm lại khi cần.
- Giữ cách đánh giá rule bằng `eval` với namespace hạn chế như hiện tại, hoặc thay bằng cách an toàn hơn; người xây dựng quyết. `rules.yaml` nằm trong repo này nên không phải input từ dự án bị quét.

### 5.4 So sánh với lần quét trước

- Mỗi lần quét lưu báo cáo đã chuẩn hoá thành **artifact** của workflow run, với tên cố định.
- Lần quét sau tìm artifact đó từ **lần chạy thành công gần nhất trên cùng nhánh** của cùng dự án (qua GitHub API hoặc `actions/download-artifact` với `run-id`), rồi so sánh.
- Định danh một finding để so sánh: kết hợp công cụ, mã lỗi (CVE, rule id…), package hoặc file. Người xây dựng chọn khoá cụ thể.
- Lần trước để so sánh là **lần chạy gần nhất trên cùng nhánh có artifact báo cáo**, bất kể trạng thái job. Artifact phải ghi trạng thái từng phần quét.
- Phần nào bị "lỗi" hoặc "không quét" ở lần này **hoặc** lần trước thì **không tính** vào "Lỗi mới / Đã sửa" và mũi tên. Nếu không, mọi finding của phần đó sẽ bị tính nhầm là mới hoặc đã sửa. Email ghi chú "không so sánh được phần X".
- Lần quét đầu tiên (chưa có dữ liệu cũ): email bỏ phần mũi tên và phần "Lỗi mới / Đã sửa", thay bằng dòng "Lần quét đầu tiên".
- Artifact giữ tối thiểu 30 ngày; người xây dựng chọn con số cụ thể. Nếu artifact cũ đã hết hạn thì xử lý như lần quét đầu tiên.
- Cách này không dùng GitHub Pages, nên chạy được cả với repo private trên gói miễn phí.

### 5.5 Gửi email

- Gửi từ chính GitHub Actions qua **SMTP của Gmail với App Password** (quyết định của người thiết kế, vì chủ repo dùng Gmail). Ba secret: `SMTP_USERNAME`, `SMTP_PASSWORD`, `REPORT_EMAIL_TO`. Người xây dựng có thể dùng action có sẵn (ví dụ `dawidd6/action-send-mail`) hoặc gửi bằng Python.
- Gửi **mỗi lần quét**, kể cả khi sạch.
- Nếu thiếu secret SMTP thì không gửi mail nhưng vẫn ghi báo cáo vào Job Summary của GitHub Actions và upload file HTML làm artifact. Workflow vẫn xanh.
- Bản HTML của email cũng được ghi vào **Job Summary** của run, để xem lại được trên GitHub.

## 6. Email báo cáo (mẫu "Hướng 1")

Mockup tham chiếu: [2026-10-19-email-mockup.html](2026-10-19-email-mockup.html). Chủ repo đã chọn **cột bên trái, "Hướng 1"**. Cột "Hướng 2" chỉ để tham khảo, không làm.

**Tiêu đề email:** `[<tên dự án>] <tình trạng> · <thay đổi>`, ví dụ `[my-api] 3 lỗi P1 · +2 mới, 5 đã sửa` hoặc `[my-api] Không có lỗi P1 · 3 đã sửa`.

**Bố cục từ trên xuống:**

1. **Đầu email nền tối** (gradient từ xanh đen sang đỏ đậm, kèm màu nền đặc dự phòng cho ứng dụng mail không hỗ trợ gradient). Gồm: chữ "SECURITY PIPELINE", nhãn `tên-dự-án · nhánh`, ô **điểm A–F** lớn (đỏ khi D/F, xanh khi A/B, vàng khi C), tiêu đề tình trạng, mô tả ngắn có mã commit và thời gian.
2. **4 ô số liệu**: P1, P2, Backlog, Tổng, mỗi ô có mũi tên ▲/▼ hoặc "không đổi" so với lần trước.
3. **Dải màu tỉ lệ** P1 / P2 / Backlog.
4. **Khung cảnh báo**: lỗi mới nghiêm trọng nhất kèm bản vá. Nếu không có lỗi mới mức P1/P2 thì đổi sang khung xanh, nội dung tích cực.
5. **Hai ô "Lỗi mới" (tím) và "Đã sửa" (xanh)**, nền màu đặc.
6. **"Cần xử lý trước"**: tối đa 5 finding nghiêm trọng nhất, mỗi dòng có ô mức độ, mã lỗi, nhãn MỚI nếu có, package và phiên bản, bản vá. Với secret hoặc lỗi code thì hiện file và dòng thay cho package.
7. **Nút lớn** "Xem đủ N lỗi" dẫn tới trang workflow run trên GitHub (Job Summary). Không có dashboard riêng.
8. **Danh sách đủ mọi phần quét**, mỗi phần có một trong 4 trạng thái ở mục 5.2. Đây là yêu cầu của chủ repo: phần sạch hay không áp dụng vẫn phải hiện.
9. **Footer**: "Gửi tự động sau mỗi lần quét", số run, link log.

**Điểm A–F** (quy tắc do người thiết kế đặt, chủ repo có thể sửa):

| Điểm | Điều kiện |
|---|---|
| A | Không có P1, không có P2 |
| B | Không có P1, có 1–5 P2 |
| C | Không có P1, có hơn 5 P2 |
| D | Có 1–3 P1 |
| F | Có hơn 3 P1, hoặc có secret bị lộ |

**Ràng buộc kỹ thuật để hiển thị đúng trên Gmail:**
- Rộng tối đa 600px, bố cục bằng bảng (`<table>`), CSS **inline**. Gmail bỏ phần lớn `<style>` và CSS grid/flex, nên mockup (dùng flex/grid) chỉ là tham chiếu về giao diện, không dùng nguyên văn.
- Không dùng SVG, không dùng font tải từ ngoài, không dùng ảnh bắt buộc phải tải mới hiểu được nội dung.
- Mọi màu báo mức độ phải có chữ đi kèm (P1, P2, MỚI, ĐÃ SỬA…).
- Trên điện thoại vẫn phải đọc được. 4 ô số liệu được phép xuống thành 2×2.
- Người xây dựng tự chọn cách render, ví dụ Jinja2 cộng một thư viện inline CSS.

## 7. Repo mới và repo cũ

Lịch sử git và tài liệu của repo hiện tại có thông tin nội bộ nơi thực tập (địa chỉ registry nội bộ, image công cụ quét, câu hỏi gửi người hướng dẫn, baseline CVE). Chủ repo đã quyết:

- **Tạo một repo mới, sạch, public**, không mang lịch sử git cũ. Repo `security-pipeline-image` **giữ nguyên làm lưu trữ**, không sửa và không xoá gì.
- **Tên repo mới** do chủ repo đặt. Trong tài liệu này ghi là `<repo-mới>`.
- **Chỉ mang sang** (và chỉnh lại theo thiết kế này): `ai_triage/main.py`, `ai_triage/rules.yaml`, `ai_triage/schema.json`, `ai_triage/requirements.txt`, `ai_triage/agents/*.md`, `policy/docker.rego`. Workflow `scan.yml` viết mới, có thể tham khảo `ci.yml` cũ.
- **Không mang sang:** `Dockerfile`, `pipeline_entrypoint.sh`, `defectdojo_agent.py`, `business_criticality.yaml`, dashboard, toàn bộ `docs/` cũ, `benchmark-results.md`, `.gitleaksignore` cũ. Trước khi commit đầu tiên, kiểm tra các file mang sang không còn nhắc tới tên hạ tầng nội bộ cũ hay tên người hướng dẫn.
- `README.md` mới: giới thiệu bộ quét, cách gắn vào dự án, cách tạo Gmail App Password, cách dùng file ignore, giải thích điểm A–F và các mức P1/P2/Backlog.
- Repo mới **tự quét chính nó** bằng `scan.yml`, theo đúng cách một dự án bên ngoài sẽ gọi. Đây cũng là bài kiểm tra chính.
- Pin version cho các action và Docker image công cụ (Semgrep, Conftest, Trivy) thay vì dùng `:latest`.
- Tài liệu thiết kế này và file mockup được chép sang repo mới, trong `docs/superpowers/specs/`.

## 8. Kiểm tra hoàn thành

- Repo mới và ít nhất một repo thử nghiệm khác gọi workflow thành công trên `ubuntu-latest`, không cần VPN hay self-hosted runner.
- Repo thử nghiệm có Dockerfile và manifest thư viện: đủ các phần chạy, nhận được email đúng mẫu.
- Repo thử nghiệm chỉ có code (không Dockerfile): phần image và policy hiện "không quét" kèm lý do.
- Lần push thứ hai hiện đúng mũi tên và phần "Lỗi mới / Đã sửa".
- Thiếu secret SMTP: workflow vẫn xanh và Job Summary vẫn có báo cáo.
- Một công cụ bị lỗi (giả lập): email hiện trạng thái "lỗi" cho phần đó, không hiện "sạch".
- Email hiển thị đúng trên Gmail web và Gmail điện thoại.

## 9. Để lại cho người xây dựng

- Tên file workflow, tên input và secret, cấu trúc thư mục mới.
- Bộ rule Semgrep cụ thể, cách phát hiện manifest và IaC.
- Khoá định danh finding khi so sánh, thời gian giữ artifact.
- Cách render email (thư viện template và inline CSS), action gửi mail.
- Giữ `eval` hay thay cách đánh giá rule.
- Hỗ trợ nhiều Dockerfile hay không.

## 10. Quyết định do người thiết kế tự đặt (chủ repo nên xem lại)

1. Bỏ hẳn công cụ quét thương mại, DefectDojo, registry nội bộ và VMware.
2. Anti-goals ở mục 4: không chặn merge, không im lặng khi hỏng, dưới khoảng 10 phút.
3. Quy tắc điểm A–F.
4. Gửi qua Gmail SMTP với App Password.
5. Bỏ dashboard GitHub Pages; nút trong email dẫn tới Job Summary của run.
6. So sánh với lần trước qua artifact, không qua GitHub Pages.
7. Bộ quy tắc ưu tiên gợi ý ở mục 5.3.
8. Dùng các file ignore chuẩn của từng công cụ để bỏ qua false positive (mục 5.2b).
9. Kết quả chạy tay của AI agent không được lưu cho lần quét sau (mục 5.3).
10. Một công cụ lỗi không làm workflow đỏ; phần lỗi không được đưa vào so sánh (mục 5.2, 5.4).
11. Bỏ `environment` và `business_criticality` khỏi pipeline tự động.
