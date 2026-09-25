### Họ và Tên: Trần Minh Khang
### MSSV: 2387700027

# LAB 1: SECURE VALIDATOR LAB
## BÁO CÁO PHÂN TÍCH BẢO MẬT & THỰC NGHIỆM BYPASS ĐỘC QUYỀN

---

## 1. Mục tiêu và cấu trúc thư viện

Thư viện `securevalidator` được phát triển nhằm cung cấp các hàm kiểm định định dạng (Validation) và làm sạch dữ liệu (Sanitization) đầu vào cơ bản cho ứng dụng web, bao gồm 5 hàm chính:

```text
secure-validator-lab/
├── securevalidator/
│   ├── __init__.py
│   └── core.py
├── templates/
│   └── index.html
├── tests/
│   └── test_validators.py
├── app.py
└── requirements.txt
```

### Phân nhóm chức năng:
* **Nhóm 1 — Kiểm định định dạng (Validation - Trả về `bool`):**
  * `validate_email(email: str) -> bool`: Kiểm tra cấu trúc địa chỉ email qua regex.
  * `validate_url(url: str) -> bool`: Kiểm tra scheme và netloc của URL.
  * `validate_filename(filename: str) -> bool`: Kiểm tra ký tự phân cách đường dẫn chống Path Traversal.
* **Nhóm 2 — Làm sạch dữ liệu (Sanitization - Trả về chuỗi an toàn):**
  * `sanitize_sql_input(input_str: str) -> str`: Loại bỏ ký tự đặc biệt và từ khóa SQL injection phổ biến.
  * `sanitize_html_input(html_str: str) -> str`: Mã hóa các ký tự điều khiển HTML thành entities để phòng chống XSS.

---

## 2. Phân tích chi tiết các lỗ hổng & Kỹ thuật thực nghiệm Bypass độc quyền

### 2.1. `validate_email` — Lỗ hổng TLD dạng số & vi phạm chuẩn RFC 5322

* **Hiện trạng mã nguồn:**
  ```python
  pattern = r'^[\w\.-]+@[\w\.-]+\.\w+$'
  return re.fullmatch(pattern, email) is not None
  ```
* **Cơ chế & Điểm yếu:** 
  Regex kết thúc bằng `\.\w+$`. Ký tự `\w` trong Python đại diện cho `[a-zA-Z0-9_]`. Điều này dẫn đến việc phần đuôi tên miền cao cấp nhất (TLD) có thể chứa toàn chữ số hoặc dấu gạch dưới `_`.
* **Payload thực nghiệm bypass:**
  * `khang.tran@company.123`: TLD chỉ toàn chữ số (`.123`). Theo quy định của tổ chức ICANN, tên miền quốc tế không bao giờ được phép chỉ gồm chữ số. Hàm vẫn trả về `True` (Bypass).
  * `user@sub_domain.com`: Domain chứa dấu gạch dưới `_` (vi phạm chuẩn DNS RFC 1035).
* **Rủi ro an ninh:** 
  Dữ liệu sai quy cách có thể làm lỗi module gửi mail (MTA) hoặc bị lợi dụng trong tấn công giả mạo nguồn gốc thư tín.
* **Giải pháp khắc phục:**
  Sử dụng thư viện `email-validator` kiểm tra cú pháp chuẩn RFC và xác thực bản ghi DNS MX thực tế:
  ```python
  from email_validator import validate_email as check_email, EmailNotValidError

  def validate_email_hardened(email: str) -> bool:
      try:
          check_email(email, check_deliverability=False)
          return True
      except EmailNotValidError:
          return False
  ```

---

### 2.2. `validate_url` — Bypass SSRF qua định dạng IP Bát phân (Octal IP) & Dword IP

* **Hiện trạng mã nguồn:**
  ```python
  parsed = urllib.parse.urlparse(url)
  return parsed.scheme in ['http', 'https'] and bool(parsed.netloc)
  ```
* **Cơ chế & Điểm yếu:** 
  Hàm chỉ kiểm tra scheme thuộc `http/https` và netloc khác rỗng. Hàm không hề phân giải IP và không chặn các cách biểu diễn địa chỉ IP đặc biệt trong kiến trúc mạng TCP/IP.
* **Payload thực nghiệm bypass:**
  * `http://0177.0.0.1:8080/admin`: `0177` là số bát phân (Octal) tương đương giá trị `127` trong hệ thập phân. Khi các thư viện HTTP hoặc trình duyệt gửi request, hệ thống socket tự động chuyển đổi `0177.0.0.1` thành `127.0.0.1` (Loopback nội bộ)! Hàm `validate_url` kiểm tra thấy chuỗi netloc là ký tự hợp lệ nên cho qua hoàn toàn.
  * `http://2130706433/`: Biểu diễn IP dạng số nguyên 32-bit (Dword IP) của `127.0.0.1`.
* **Rủi ro an ninh:** 
  Đây là kỹ thuật nâng cao khai thác lỗ hổng **Server-Side Request Forgery (SSRF)** nhằm truy cập bảng điều khiển quản trị, port nội bộ hoặc đánh cắp metadata của máy chủ đám mây.
* **Giải pháp khắc phục:**
  Phải phân giải tên miền (DNS resolution) và chuẩn hóa IP về dạng nhị phân trước khi kiểm tra dải mạng Private IP:
  ```python
  import socket, ipaddress, urllib.parse

  BLOCKED_SUBNETS = [
      ipaddress.ip_network("127.0.0.0/8"),
      ipaddress.ip_network("10.0.0.0/8"),
      ipaddress.ip_network("172.16.0.0/12"),
      ipaddress.ip_network("192.168.0.0/16"),
      ipaddress.ip_network("169.254.0.0/16"),
  ]

  def validate_url_hardened(url: str) -> bool:
      try:
          parsed = urllib.parse.urlsplit(url)
          if parsed.scheme.lower() not in ("http", "https") or not parsed.hostname:
              return False
          raw_ip = socket.gethostbyname(parsed.hostname)
          target_ip = ipaddress.ip_address(raw_ip)
          return not any(target_ip in net for net in BLOCKED_SUBNETS)
      except Exception:
          return False
  ```

---

### 2.3. `validate_filename` — Tên thiết bị Windows gây DoS & NTFS Alternate Data Streams

* **Hiện trạng mã nguồn:**
  ```python
  if ".." in filename or "/" in filename or "\\" in filename:
      return False
  return os.path.basename(filename) == filename
  ```
* **Cơ chế & Điểm yếu:** 
  Hàm chỉ kiểm tra các ký tự điều hướng thư mục cơ bản (`..`, `/`, `\`), hoàn toàn bỏ sót các quy định bảo lưu của hệ điều hành Windows và hệ thống tập tin NTFS.
* **Payload thực nghiệm bypass:**
  * `CON.txt` *(hoặc `PRN`, `AUX`, `NUL`, `COM1-9`, `LPT1-9`)*: Các tên thiết bị phần cứng bảo lưu trên Windows. Khi mở file này, Windows tự động map vào cổng giao tiếp phần cứng (như máy in PRN, bàn phím CON), làm tiến trình Python bị khóa (hang) vĩnh viễn, dẫn đến **Từ chối dịch vụ (Denial of Service - DoS)**.
  * `report.pdf:secret.txt`: Kỹ thuật NTFS Alternate Data Streams (ADS) chèn luồng dữ liệu ẩn trên phân vùng NTFS mà không kích hoạt bất kỳ ký tự cấm nào.
* **Giải pháp khắc phục:**
  Kiểm tra danh sách tên thiết bị bảo lưu của Windows và làm sạch ký tự `:` của ADS:
  ```python
  import os

  WINDOWS_RESERVED = {"CON", "PRN", "AUX", "NUL", "COM1", "COM2", "LPT1"}

  def validate_filename_hardened(filename: str) -> bool:
      base = os.path.basename(filename).strip()
      file_stem = os.path.splitext(base)[0].upper()
      if file_stem in WINDOWS_RESERVED:
          return False
      if any(c in base for c in (":", "*", "?", "<", ">", "|", "\"", "\x00")):
          return False
      return True
  ```

---

### 2.4. `sanitize_sql_input` — Tautology không dùng từ khóa (`||`) & Chuỗi mã hóa Hex

* **Hiện trạng mã nguồn:**
  ```python
  sanitized = re.sub(r"(--|;|'|\"|#)", "", input_str)
  sanitized = re.sub(r"\b(OR|AND|SELECT|INSERT|DELETE|UPDATE|DROP|UNION|WHERE)\b", "", sanitized, flags=re.IGNORECASE)
  return sanitized.strip()
  ```
* **Cơ chế & Điểm yếu:** 
  Hàm sử dụng danh sách đen (Blacklist) từ khóa và ký tự nháy. Kẻ tấn công có thể xây dựng câu lệnh SQL Injection bằng toán tử thay thế hoặc định dạng Hex mà không cần dùng từ khóa hay dấu nháy bị cấm.
* **Payload thực nghiệm bypass:**
  * `1' || '1'='1`: Toán tử `||` là phép ghép logic / nối chuỗi trong chuẩn SQL ANSI (SQLite, Oracle, PostgreSQL). Biểu thức này tạo ra mệnh đề luôn đúng (tautology) giúp vượt qua đăng nhập mà không hề chứa từ khóa `OR`!
  * `0x61646d696e`: Chuỗi Hex đại diện cho `'admin'`. Kẻ tấn công so sánh `WHERE user = 0x61646d696e` mà không cần dùng dấu nháy đơn `'` hay nháy kép `"`.
* **Giải pháp khắc phục:**
  Tuyệt đối không dựa vào hàm lọc regex. Bắt buộc chuyển đổi 100% sang **Parameterized Queries (Prepared Statements)**:
  ```python
  # Chuẩn an toàn tuyệt đối:
  cursor.execute("SELECT * FROM users WHERE username = %s AND password = %s", (user_input, pass_input))
  ```

---

### 2.5. `sanitize_html_input` — XSS qua Data URI Scheme & Unquoted HTML5 Attributes

* **Hiện trạng mã nguồn:**
  ```python
  return html.escape(html_str)
  ```
* **Cơ chế & Điểm yếu:** 
  `html.escape` chỉ chuyển đổi `<, >, &, ", '`. Nếu dữ liệu được nhúng vào thuộc tính liên kết hoặc thuộc tính không dấu ngoặc kép, kẻ tấn công có thể kích hoạt JavaScript mà không cần các ký tự trên.
* **Payload thực nghiệm bypass:**
  * `data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==`: Chuỗi Data URI chứa mã độc Base64 không có bất kỳ ký tự nào bị escape. Khi chèn vào `<iframe src="{{ data }}">` hoặc `<object data="{{ data }}">`, trình duyệt tự giải mã và thực thi mã độc.
  * `1 onfocus=alert(1) autofocus`: Khi lập trình viên viết `<input value={{ data }}>` (thiếu dấu nháy bao bọc), chuỗi này không hề bị escape và sẽ tự kích hoạt sự kiện `onfocus` ngay khi tải trang.
* **Giải pháp khắc phục:**
  Kiểm tra và chỉ cho phép các scheme an toàn (`http`, `https`) đối với liên kết và áp dụng mã hóa ngữ cảnh (Contextual Output Encoding):
  ```python
  import urllib.parse, html

  SAFE_SCHEMES = {"http", "https", "mailto"}

  def sanitize_url_context(url_input: str) -> str:
      parsed = urllib.parse.urlsplit(url_input.strip())
      if parsed.scheme and parsed.scheme.lower() not in SAFE_SCHEMES:
          return "#"
      return html.escape(url_input, quote=True)
  ```

---

## 3. Tổng kết bảng so sánh Bypass

| Mục kiểm tra | Payload thực nghiệm độc quyền | Kết quả sau lọc | Cơ chế lỗ hổng |
|---|---|---|---|
| **Email** | `khang.tran@company.123` | **`Hợp lệ` (Bypass)** | Regex dùng `\w` chấp nhận TLD toàn chữ số trái quy định ICANN. |
| **URL (SSRF)** | `http://0177.0.0.1:8080/admin` | **`Hợp lệ` (Bypass)** | Biểu diễn IP dạng Bát phân (Octal) trỏ về `127.0.0.1` qua mặt parser. |
| **Filename** | `CON.txt` | **`Hợp lệ` (Bypass)** | Tên thiết bị Windows gây DoS treo máy chủ khi đọc/ghi file. |
| **SQL Input** | `1' \|\| '1'='1` | **`1 \|\| 1=1` (Bypass)** | Toán tử logic `\|\|` tạo mệnh đề luôn đúng không cần từ khóa `OR`. |
| **HTML Input** | `data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==` | **`Giữ nguyên` (Bypass)** | Chuỗi Data URI Base64 không chứa ký tự escape nhưng kích hoạt XSS trong iframe/object. |

---

## 4. Kết luận

Toàn bộ các trường hợp bypass trên đã được kiểm chứng bằng Unit Test thực nghiệm trong `test_validators.py` đạt kết quả 15/15 Pass. Điều này chứng minh rằng việc áp dụng giải pháp bảo mật theo hướng Whitelist và cơ chế thực thi an toàn cấp hệ thống (Prepared Statements, Contextual Encoding) là bắt buộc trong phát triển ứng dụng an toàn.
