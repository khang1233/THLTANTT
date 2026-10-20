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

### [Bài 4](Bai4)
* **[WebVulnScanner](Bai4/web-vuln-scanner)** — Bộ công cụ quét lỗ hổng ứng dụng web tự động (XSS Scanner, SQL Injection Tester, CSRF Detector, SSRF Tester, Report Generator, kiểm thử Unittest và giao diện Web UI Flask).
* **[JWTSecure](Bai4/jwt-security-tools)** — Bộ công cụ phân tích và bảo mật JWT & OAuth 2.0 (API Gateway xác thực Bearer Token, JWT Cracker bẻ khóa từ điển đa luồng, JWT Validator kiểm tra chữ ký & thời hạn, OAuthClient luồng Authorization Code, TokenManager quản lý Access/Refresh Token và Pytest).


### [Bài 5](Bai5)
* **[SAST-Tool](Bai5/sast-tool)** – Công cụ kiểm thử bảo mật tĩnh mã nguồn Python (Phân tích cây cú pháp AST, so khớp mẫu Regex, Security Rule Engine đa cấp, Linting Flake8, xuất báo cáo chuẩn quốc tế SARIF 2.1.0 và kiểm thử Unittest).
* **[DAST-Tool](Bai5/dast-tool)** – Nền tảng phân tích động và giám sát an ninh ứng dụng thời gian thực (Runtime Monitor CPU/RAM/Files, phát hiện rò rỉ bộ nhớ GC & tràn số nguyên 64-bit, phân tích lưu lượng mạng, phát hiện syscall nguy hiểm, hộp cát ảo Virtual Sandbox và Flask REST API).
