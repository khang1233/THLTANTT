# THLTANTT — BÀI TẬP THỰC HÀNH LẬP TRÌNH AN NINH THÔNG TIN

**Sinh viên thực hiện:** Trần Minh Khang  
**MSSV:** 2387700027  
**GitHub Repository:** [https://github.com/khang1233/THLTANTT](https://github.com/khang1233/THLTANTT)

---

## Danh mục bài thực hành

### [Bài 1](Bài%201)
* **[Lab 1: SecureValidator](Bài%201/Lab1)** — Kiểm tra định dạng đầu vào và làm sạch dữ liệu (Email, URL, Filename, SQL, HTML).
* **[Lab 2: GitSecure](Bài%201/Lab2)** — Tự động hóa kiểm tra an toàn mã nguồn với Git pre-commit hook (Secrets scan, Permissions, Bandit SAST).
* **[Lab 3: SecureLogger](Bài%201/Lab3)** — Hệ thống ghi nhật ký an toàn (Che giấu PII, cấu trúc JSON, băm SHA-256 đối soát toàn vẹn, xoay vòng Gzip).

### [Bài 2](Bai2)
* **[CryptoToolkit](Bai2/crypto-toolkit)** — Thư viện mật mã hiện đại (Mã hóa AES-256-GCM, sinh cặp khóa RSA & chữ ký số, băm mật khẩu Argon2, giao diện CLI, Flask API, Tkinter GUI).
* **[Mini-CA](Bai2/mini-ca)** — Mô phỏng hạ tầng khóa công khai PKI & X.509 (Root CA, Intermediate CA, cấp phát chứng chỉ End-entity, xác thực chuỗi chứng chỉ, thu hồi CRL và kiểm tra trạng thái OCSP).

### [Bài 3](Bai3)
* **[SecureChat](Bai3/secure-chat)** — Ứng dụng chat bảo mật đa luồng với xác thực chứng chỉ số hai chiều (Mutual TLS 1.2+), mã hóa tin nhắn đầu-cuối (AES-256-CBC + PKCS7), quản lý kết nối và phòng chat an toàn.
* **[NetRecon](Bai3/netrecon)** — Bộ công cụ trinh sát và khám phá mạng (Quét cổng bất đồng bộ giới hạn tốc độ Asyncio Semaphore, nhận dạng dịch vụ Nmap, thu thập Banner, lập bản đồ mạng ARP, kiểm tra lỗ hổng CVE, cảnh báo qua SMTP SSL, giao diện CLI & Flask Web UI).
