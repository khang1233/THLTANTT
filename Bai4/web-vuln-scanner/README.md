### Họ và Tên: Trần Minh Khang
### MSSV: 2387700027

# BÁO CÁO KỸ THUẬT: WEBVULNSCANNER
## XÂY DỰNG CÔNG CỤ TỰ ĐỘNG PHÁT HIỆN LỖ HỔNG XSS, SQLi, CSRF, SSRF & TỔNG HỢP BÁO CÁO

---

## 1. Giới thiệu và Kiến trúc Hệ thống `web-vuln-scanner`

`web-vuln-scanner` là bộ công cụ kiểm thử bảo mật ứng dụng web tĩnh và động, được module hóa theo từng loại hình lỗ hổng phổ biến nhất trong danh mục OWASP Top 10:

```text
web-vuln-scanner/
├── report/
│   ├── __init__.py                 # Khởi tạo package report
│   └── report_generator.py         # Module chuẩn hóa, làm phẳng và phân loại rủi ro lỗ hổng
├── scanners/
│   ├── __init__.py                 # Khởi tạo package scanners
│   ├── csrf_detector.py            # Phân tích biểu mẫu HTML, phát hiện thiếu hụt Anti-CSRF Token
│   ├── sql_injection_tester.py     # Thẩm định tham số URL dựa trên mẫu tiêm mã SQL Injection
│   ├── ssrf_tester.py              # Thẩm định tham số URL dựa trên regex dải IP nội bộ
│   └── xss_scanner.py              # Thăm dò lỗ hổng Reflected XSS qua HTTP GET request
├── tests/
│   ├── __init__.py                 # Khởi tạo package tests
│   ├── test_csrf.py                # Unit test kiểm tra CSRF Detector
│   ├── test_sql_injection.py       # Unit test kiểm tra SQL Injection Tester
│   ├── test_ssrf.py                # Unit test kiểm tra SSRF Tester
│   ├── test_xss.py                 # Unit test kiểm tra XSS Scanner (sử dụng unittest.mock)
│   └── test_report.py              # Unit test kiểm tra cấu trúc báo cáo của ReportGenerator
├── ui/
│   ├── templates/
│   │   ├── index.html              # Giao diện người dùng nhập URL mục tiêu và chọn scanner
│   │   └── result.html             # Giao diện báo cáo phân cấp trực quan theo mã màu rủi ro
│   └── app.py                      # Máy chủ Flask đóng vai trò Web UI cho công cụ quét
├── main.py                         # Kịch bản dòng lệnh chạy kiểm thử tích hợp 4 scanner
└── requirements.txt                # Danh sách gói phụ thuộc (Flask, requests)
```

---

## 2. Phân tích chi tiết các Module Thuật toán Scanner

### 2.1. Module `xss_scanner.py` — Reflected Cross-Site Scripting (XSS)
* **Nguyên lý hoạt động:** Gửi yêu cầu HTTP GET tới URL mục tiêu kèm tham số truy vấn `?q=<payload>`. Module sử dụng hai payload chuẩn hóa:
  * `<script>alert(1)</script>`: Kiểm tra khả năng chèn trực tiếp thẻ script thực thi JavaScript trong ngữ cảnh HTML.
  * `'><svg/onload=alert(1)>`: Kiểm tra khả năng thoát khỏi thuộc tính thẻ (`attr context`) để kích hoạt sự kiện onload của thẻ SVG.
* **Cơ chế phát hiện:** Nếu chuỗi payload được phản hồi nguyên vẹn trong nội dung trả về (`if payload in resp.text`), ứng dụng được xác định là thiếu cơ chế Output Encoding và có lỗ hổng XSS mức độ **HIGH**.

### 2.2. Module `sql_injection_tester.py` — SQL Injection (SQLi)
* **Nguyên lý hoạt động:** Trích xuất các tham số từ query string thông qua `urllib.parse.parse_qs` và đối chiếu với tập payload kiểm thử kinh điển:
  * `' OR '1'='1`: Tấn công logic Boolean Bypass xác thực.
  * `'; DROP TABLE users;--`: Tấn công thực thi nhiều câu lệnh liên tiếp (Stacked Queries).
  * `\" OR 1=1--`: Tấn công dấu nháy kép.
  * `' UNION SELECT NULL--`: Tấn công trích xuất dữ liệu qua từ khóa `UNION`.
* **Cơ chế phát hiện:** Khi tham số người dùng chứa một trong các dấu hiệu trên, module cảnh báo nguy cơ tiêm mã SQL Injection mức độ **Critical**.

### 2.3. Module `csrf_detector.py` — Cross-Site Request Forgery (CSRF)
* **Nguyên lý hoạt động:** Quét mã nguồn HTML của các biểu mẫu `<form>` để kiểm tra sự tồn tại của trường ẩn Anti-CSRF Token:
  * `name=['"]csrf_token['"]`
  * `name=['"]_csrf['"]`
  * `name=['"]csrfmiddlewaretoken['"]` (chuẩn Django)
* **Cơ chế phát hiện:** Nếu không tìm thấy bất kỳ pattern nào, module kết luận form có nguy cơ bị tấn công giả mạo yêu cầu từ trang khác (CSRF) mức độ **Medium**.

### 2.4. Module `ssrf_tester.py` — Server-Side Request Forgery (SSRF)
* **Nguyên lý hoạt động:** Quét giá trị của các tham số URL truyền vào để phát hiện hành vi ép máy chủ kết nối tới các tài nguyên nội bộ:
  * Loopback IP: `127.0.0.1`, `localhost`
  * Private Network (RFC 1918): `10.0.0.0/8`, `192.168.0.0/16`, `172.16.0.0/12`
* **Cơ chế phát hiện:** Nếu giá trị tham số khớp với regex IP nội bộ, module cảnh báo nguy cơ lộ lọt thông tin mạng nội bộ mức độ **High**.

---

## 3. Kết quả thực nghiệm

### 3.1. Chạy Unit Tests tự động (9/9 Passed)
Lệnh thực thi:
```bash
python -m unittest discover tests
```
Output:
```text
.........
----------------------------------------------------------------------
Ran 9 tests in 0.001s

OK
```

![Kết quả Unittest WebVulnScanner](../images/01_unittest_webvuln.png)

---

### 3.2. Chạy kịch bản tích hợp dòng lệnh (`main.py`)
Lệnh thực thi:
```bash
python .\main.py
```
Output:
```text
=== Vulnerability Report ===
'''Param: N/A, Desc: None, Risk: None'''
'''Param: url, Desc: Potential SSRF to internal resource, Risk: High'''
```

![Kết quả chạy main.py](../images/02_main_webvuln.png)

---

### 3.3. Kiểm thử qua giao diện Web UI (`ui/app.py`)
Khởi động máy chủ Flask:
```bash
python .\ui\app.py
```
* **Giao diện nhập liệu:**

![Giao diện Web UI Form](../images/03_web_ui_form.png)

* **Kết quả quét lỗ hổng hiển thị trên trình duyệt:**

![Kết quả Web UI](../images/04_web_ui_result.png)
