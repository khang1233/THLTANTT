### Họ và Tên: Trần Minh Khang
### MSSV: 2387700027

# LAB 2: GITSECURE
## BÁO CÁO PHÂN TÍCH BẢO MẬT HỆ THỐNG PRE-COMMIT "GITSECURE"

---

## 1. Mục tiêu và phạm vi

Hệ thống **GitSecure** được triển khai dưới dạng một Client-side Git pre-commit hook (`.githooks/pre-commit`), tự động kích hoạt trước khi lệnh `git commit` được chấp thuận, nhằm:

* Phát hiện và ngăn chặn việc đẩy thông tin nhạy cảm (secrets, credentials, API keys) lên kho lưu trữ mã nguồn.
* Kiểm tra và cảnh báo quyền truy cập tệp tin (file permissions) bất thường, ngăn chặn file có quyền ghi công khai (world-writable).
* Tích hợp công cụ phân tích mã nguồn tĩnh (SAST) Bandit nhằm phát hiện các nguy cơ bảo mật trong code Python.
* Ghi nhật ký kiểm toán (audit log) phục vụ điều tra và đối soát an ninh.
* Chặn đứng tiến trình commit (`sys.exit(1)`) khi phát hiện vi phạm.

---

## 2. Các kỹ thuật bảo mật đã áp dụng

| # | Kỹ thuật bảo mật | Mô tả chi tiết | Thành phần / Hàm liên quan |
|---|---|---|---|
| 1 | **Phát hiện Secret bằng Regex** | So khớp chuỗi dữ liệu với các mẫu signature: `apikey`, `secret`, `password`, `token` và AWS Access Key (`AKIA/ASIA`). | `SENSITIVE_PATTERNS`, `scan_sensitive()` |
| 2 | **Kiểm tra phân quyền tệp (File Mode)** | Sử dụng `os.stat()` kết hợp hằng số `stat.S_IWOTH` để phát hiện tệp tin có quyền ghi cho người dùng khác (world-writable) trên Unix/Linux. | `check_permissions()` |
| 3 | **Phân tích tĩnh SAST (Bandit)** | Tự động chạy lệnh `bandit -r .` để quét lỗ hổng mã nguồn Python, lọc các cảnh báo ở mức độ nghiêm trọng cao ("SEVERITY: High"). | `run_bandit()` |
| 4 | **Bảo mật dịch chuyển trái (Shift-Left)** | Kiểm tra và ngăn chặn rủi ro bảo mật ngay tại máy trạm của lập trình viên, trước khi mã nguồn được ghi vào lịch sử Git. | `main()`, `sys.exit(1)` |
| 5 | **Tối ưu hóa phạm vi quét** | Chỉ quét các tệp tin trong danh sách chuẩn bị commit (`git diff --cached --name-only`), giúp tiết kiệm tài nguyên và tăng tốc độ commit. | `main()` |
| 6 | **Nhật ký kiểm toán (Audit Trail)** | Ghi lại mọi vi phạm kèm mốc thời gian (timestamp) vào tệp tin `gitsecure.log`. | `log()` |

---

## 3. Phân tích các lỗ hổng & Khả năng Bypass thực tế

### 3.1. Bypass ở tầng thực thi Git Hook
* **Cờ lệnh `--no-verify`:** Git cung cấp sẵn tham số `git commit --no-verify` (hoặc `-n`) cho phép bỏ qua toàn bộ pre-commit hook phía client. Vì hook chỉ chạy tại máy cục bộ của người dùng, bất kỳ lập trình viên nào cũng có thể vô hiệu hóa hàng rào bảo vệ này một cách dễ dàng.
* **Thiếu cơ chế tự động phân phối hook:** Git không tự động kích hoạt thư mục hook tùy chỉnh khi `git clone`. Lập trình viên phải tự cấu hình bằng lệnh `git config core.hooksPath .githooks`. Nếu quên thao tác này, GitSecure hoàn toàn không hoạt động.

### 3.2. Bypass ở tầng nhận diện Secret (Hạn chế của Regex tĩnh)
* **Nội suy chuỗi qua F-String (F-String Interpolation):**
  ```python
  # Regex chỉ quét chuỗi tĩnh liên tục, hoàn toàn bỏ qua biểu thức f-string:
  db_credential = f"{'pass'}{'word'} = 'SuperSecret2026!'"
  ```
* **Giá trị ngầm định trong biến môi trường (Fallback Environment Value):**
  ```python
  # Regex chỉ tìm phép gán biến tường minh, bỏ sót giá trị fallback:
  db_password = os.environ.get("DATABASE_PASSWORD", "ProductionAdmin@123")
  ```
* **Mã hóa dạng Byte Array / Hex String:**
  ```python
  # Dữ liệu nhạy cảm được chuyển thành mã hex giải mã lúc runtime:
  api_key = bytes.fromhex("346137623938636431326566").decode()
  ```
* **Cấu hình dạng tệp YAML / INI:**
  Các tệp cấu hình phân cấp không dùng cú pháp gán biến Python (`variable = 'value'`) mà sử dụng cú pháp dấu hai chấm thụt lề `credentials:\n  auth_token: secret999`, khiến regex không khớp được.

### 3.3. Bypass ở tầng kiểm tra phân quyền (Fail-open trên Windows)
* Trên hệ điều hành Windows, hàm `check_permissions()` trả về `None` (bỏ qua kiểm tra):
  ```python
  if platform.system() == "Windows":
      return None
  ```
  Điều này khiến việc kiểm tra phân quyền bị vô hiệu hóa hoàn toàn trên môi trường Windows. Đây là cơ chế "fail-open" (mất an toàn khi gặp môi trường chưa hỗ trợ), vi phạm nguyên tắc an ninh cốt lõi *Fail-safe Default*.

### 3.4. Bypass ở tầng phân tích tĩnh SAST (Bandit)
* **Kiểm tra kết quả bằng so khớp chuỗi (String-matching):** Điều kiện `"SEVERITY: High" in result.stdout` rất mong manh. Nếu Bandit thay đổi định dạng output qua các phiên bản hoặc chạy trên ngôn ngữ không phải tiếng Anh, điều kiện sẽ sai lệch và bỏ lọt lỗi.
* **Bỏ sót các lỗ hổng mức Medium/Low:** Các lỗ hổng như SQL Injection tiềm ẩn, hardcoded bind IP, sử dụng module `random` không an toàn bị bỏ qua.

### 3.5. Lỗ hổng toàn vẹn của tệp tin nhật ký
* Tệp `gitsecure.log` là văn bản thuần không có cơ chế băm hay khóa bí mật chống sửa đổi. Người dùng có quyền ghi trên máy trạm hoàn toàn có thể xóa hoặc sửa tệp log để xóa dấu vết vi phạm.

---

## 4. Đánh giá theo các nguyên tắc an ninh thông tin

| Nguyên tắc an ninh | Mức độ đáp ứng | Đánh giá & Phân tích |
|---|:---:|---|
| **Shift-Left Security** | Đạt một phần | Chặn vi phạm tại commit, nhưng dễ bị vô hiệu hóa bởi cờ `--no-verify`. |
| **Phòng thủ theo chiều sâu (Defense in Depth)** | Chưa đạt | Chỉ có một lớp duy nhất phía client; thiếu hoàn toàn cổng kiểm soát phía CI/CD server. |
| **Mặc định an toàn (Fail-Safe Defaults)** | Chưa đạt | Tự động bỏ qua kiểm tra quyền trên Windows thay vì đưa ra cảnh báo thích hợp. |
| **Khả năng kiểm toán (Auditability)** | Đạt một phần | Có ghi log nhưng tệp log thiếu tính năng bảo vệ chống giả mạo (tamper-evident). |
| **Bảo mật dữ liệu nhạy cảm (Confidentiality)** | Đạt một phần | Regex giảm thiểu sơ suất thông thường nhưng không chống được các kỹ thuật che giấu mã (obfuscation). |

---

## 5. Đề xuất giải pháp nâng cấp bảo mật

1. **Bổ sung cổng kiểm soát phía máy chủ (Server-side CI/CD Gate):** Tích hợp quy trình quét mã nguồn tương tự vào GitHub Actions / GitLab CI trên mỗi Pull Request, kết hợp Branch Protection Rules để chặn merge code vi phạm kể cả khi lập trình viên dùng `--no-verify`.
2. **Sử dụng công cụ phát hiện Secret chuyên dụng:** Tích hợp **Gitleaks** hoặc **TruffleHog** với khả năng phân tích độ hỗn loạn (Entropy Analysis) để phát hiện secret ngẫu nhiên, không phụ thuộc vào tên biến.
3. **Phân tích Bandit dạng cấu trúc JSON:** Sử dụng cờ `bandit -r . -f json` và phân tích kết quả bằng `json.loads()` thay vì so khớp chuỗi thuần túy.
4. **Bảo vệ toàn vẹn file nhật ký:** Áp dụng cơ chế băm liên kết (Hash Chaining) tương tự Lab 3 cho `gitsecure.log` để phát hiện kịp thời các hành vi xóa dấu vết.
