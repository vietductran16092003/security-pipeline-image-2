# Repo mẫu cho kiểm tra repo lạ

Các thư mục ở đây là repo giả, **chỉ dùng để test** bộ phân tích `scanner.vet`.
Mọi chuỗi trong đó đều vô hại: địa chỉ ví dụ (`example.invalid`), không có mã độc thật, không có khoá thật.
Đừng chạy, cài hay `npm install` các thư mục này.

| Thư mục | Mô phỏng | Kết quả mong đợi |
|---|---|---|
| `evil_npm` | `postinstall` tải script, devcontainer/workflow/tác vụ editor tự chạy, thư viện giả tên | Không nên mở |
| `evil_py` | `eval(base64)`, đọc `.ssh`/`.aws`, gửi dữ liệu ra webhook, `setup.py` tự chạy lệnh | Không nên mở |
| `evil_ps` | script PowerShell/sh tải và chạy | Đáng ngờ hoặc Không nên mở |
| `clean_small` | dự án nhỏ bình thường | An toàn hơn |

Test đầu-cuối cần Docker nằm ở `tests/test_vet_e2e.py` (chạy tay: `python -m pytest -m docker -q`).
