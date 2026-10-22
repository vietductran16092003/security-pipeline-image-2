# Image phân tích repo lạ (bước 2, chạy --network none, rootfs chỉ đọc).
# Pin tag cụ thể; digest chưa ghim vì lúc viết không tra được (offline) — ghim digest khi có mạng.
# Chỉ copy package scanner.vet cần thiết (context build là thư mục tạm do ensure_vet_image tạo).
# Không cài thêm gì (không trình quản lý gói). Chạy user không phải root.
FROM python:3.12.7-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONPATH=/app

WORKDIR /app
COPY scanner /app/scanner

USER 10001:10001
ENTRYPOINT ["python", "-m", "scanner.vet"]
