# AI agent chạy tay

Pipeline tự động **không** gọi AI. Mọi finding trong `report.json` đã có `priority`, `reason` và `recommendation` do Rule Engine (`rules.yaml`) gán. Khi muốn phân tích kỹ hơn một lần quét, bạn chạy tay 4 agent dưới đây bằng Claude Code.

**Quan trọng:** agent chỉ sửa trên **bản sao** báo cáo bạn tải về. Kết quả không được lưu lại cho lần quét sau và không làm thay đổi email. Nếu muốn một finding không bị báo nữa, hãy dùng file ignore của dự án (`.gitleaksignore`, `.trivyignore`, `# nosemgrep`).

## Chuẩn bị

1. Mở run trên GitHub Actions, tải artifact `security-report` rồi giải nén ra `report.json`.
2. Chép thành bản làm việc, ví dụ `review.json`.

## Thứ tự chạy

1. **Context Agent** (`context_agent.md`): gắn `environment` và `business_criticality`.
2. **Exploit Agent** (`exploit_agent.md`): gắn `exploitable`.
3. **Severity Agent** (`severity_agent.md`): xem lại `priority` dựa trên dữ liệu ở bước 1–2.
4. **Recommendation Agent** (`recommendation_agent.md`): viết lại `recommendation`, chạy cuối cùng.

```bash
claude "Đọc agents/context_agent.md làm hướng dẫn vai trò. Áp dụng lên review.json. Nhánh: main. Dự án: my-api là service production phục vụ khách hàng."
claude "Đọc agents/exploit_agent.md làm hướng dẫn vai trò. Áp dụng lên review.json."
claude "Đọc agents/severity_agent.md làm hướng dẫn vai trò. Áp dụng lên review.json."
claude "Đọc agents/recommendation_agent.md làm hướng dẫn vai trò. Áp dụng lên review.json."
```

## Cấu trúc file

`review.json` có dạng như `schema.json`: một báo cáo gồm 6 `sections`, mỗi section có danh sách `findings`. Agent duyệt mọi finding trong mọi section. Schema cho phép finding có thêm các trường do agent ghi (`environment`, `business_criticality`, `exploitable`, `assessed_by`).

Với báo cáo lớn (hàng nghìn finding), hãy chạy từng section hoặc chỉ những finding P1/P2 để không vượt giới hạn ngữ cảnh.
