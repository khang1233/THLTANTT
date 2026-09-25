### Họ và Tên: Trần Minh Khang
### MSSV: 2387700027

# LAB 3: SECURELOGGER
## BÁO CÁO PHÂN TÍCH BẢO MẬT HỆ THỐNG "SECURELOGGER"

---

## 1. Mục tiêu và phạm vi

**SecureLogger** (`securelogger/logger.py`, được tích hợp trong `app.py`) là một hệ thống ghi nhật ký (logging) hướng bảo mật, được thiết kế nhằm:

* Hỗ trợ đa cấp độ log (DEBUG, INFO, WARNING, ERROR, CRITICAL) theo thư viện `logging` chuẩn của Python.
* Tự động **phát hiện và che giấu thông tin định danh cá nhân (PII)** trước khi ghi vào tệp nhật ký.
* Quản lý **xoay vòng file log (log rotation)** kèm tính năng nén dữ liệu (.gz) khi dung lượng vượt quá 1MB.
* **Phát hiện sửa đổi trái phép** trên tệp tin log (Tamper Detection) thông qua một tệp chữ ký băm song hành (`secure.log.sig`).
* Ghi log theo **cấu trúc JSON** có tổ chức để dễ dàng phân tích và tích hợp vào các hệ thống SIEM.
* Tích hợp với `SecureValidator` để lưu trữ audit trail cho endpoint `/validate`.

---

## 2. Các kỹ thuật bảo mật đã áp dụng

| # | Kỹ thuật bảo mật | Mô tả chi tiết | Thành phần liên quan |
|---|---|---|---|
| 1 | **Che giấu PII (PII Masking)** | Sử dụng Regex thay thế địa chỉ email và các chuỗi gán `token/apikey/key/password = value` bằng nhãn `<label_masked>`. | `PII_PATTERNS`, `mask_pii()` |
| 2 | **Ghi log JSON có cấu trúc** | Mỗi bản ghi log là một đối tượng JSON: `timestamp`, `level`, `message`, cùng dữ liệu bổ sung `data` và `results`. Tự động escape ký tự ngắt dòng chống Log Injection (CRLF). | `JSONFormatter` |
| 3 | **Luân phiên log theo kích thước** | Giới hạn dung lượng tối đa `MAX_LOG_SIZE = 1MB`, lưu trữ `BACKUP_COUNT = 2` bản dự phòng, ngăn chặn nguy cơ làm tràn bộ nhớ đĩa. | `RotatingFileHandler` |
| 4 | **Nén log tự động (Gzip)** | Khi xoay vòng, tệp log cũ được nén thành file `.gz`, tiết kiệm tối đa dung lượng lưu trữ. | `GZipRotator` |
| 5 | **Phát hiện giả mạo (Tamper-Evidence)** | Mỗi dòng log được băm SHA-256 và lưu tuần tự vào tệp `secure.log.sig` riêng biệt. | `hash_line()`, `append_signature()` |
| 6 | **Cô lập Logger** | Thiết lập `logger.propagate = False` nhằm ngăn ngừa log bị đẩy lên root handler ngoài ý muốn, tránh rò rỉ dữ liệu ra console. | `get_secure_logger()` |
| 7 | **Audit Trail cho API** | Mọi lượt gọi đến `/validate` (kể cả JSON lỗi) đều được ghi nhận đầy đủ kèm dữ liệu đầu vào và kết quả kiểm định. | `app.py` |

---

## 3. Phân tích các lỗ hổng & Khả năng Bypass thực tế

### 3.1. Cơ chế Tamper-Evidence yếu — Băm độc lập thiếu chuỗi liên kết (Log Truncation Attack) & Thiếu HMAC
* **Hiện trạng mã nguồn:**
  ```python
  def hash_line(line):
      return hashlib.sha256(line.encode('utf-8')).hexdigest()

  def append_signature(line):
      with open(SIGNATURE_FILE, "a", encoding="utf-8") as f:
          f.write(hash_line(line) + "\n")
  ```
* **Cơ chế & Điểm yếu:** 
  1. Mỗi dòng nhật ký được băm độc lập rải rác từng dòng mà không phụ thuộc vào giá trị băm của dòng trước đó.
  2. Băm SHA-256 thuần túy không sử dụng khóa bí mật (Secret Key).
* **Kỹ thuật Bypass độc quyền 1 — Tấn công cắt xén nhật ký (Log Truncation Attack):** 
  Nếu kẻ tấn công thực hiện hành vi vi phạm ở các dòng cuối cùng, họ chỉ cần xóa $N$ dòng log cuối trong `secure.log` và xóa tương ứng $N$ dòng chữ ký ở `secure.log.sig`. Khi công cụ kiểm toán đối soát từng dòng độc lập, các dòng còn lại vẫn khớp 100%, hệ thống hoàn toàn **không phát hiện được việc log đã bị xóa mất**!
* **Kỹ thuật Bypass độc quyền 2 — Giả mạo chữ ký (Tamper Detection Bypass):**
  Kẻ tấn công sửa nội dung một dòng bất kỳ, tự tính `hashlib.sha256(dòng_mới)` và ghi đè vào `secure.log.sig`. Do không có HMAC, chữ ký mới vẫn được coi là hợp lệ.

---

### 3.2. PII Masking rò rỉ Sub-addressing Tag & Bỏ sót dữ liệu JSON thực tế
* **Hiện trạng mã nguồn:**
  ```python
  PII_PATTERNS = {
      "email": r'[\w\.-]+@[\w\.-]+\.\w+',
      "token": r'(?i)(token|apikey|key|password)\s*=\s*["\']?[\w\-]{4,}["\']?',
  }
  ```
* **Kỹ thuật Bypass 1 — Rò rỉ định danh phụ qua dấu cộng (Sub-addressing):**
  Địa chỉ email dạng `user+sensitive_project@company.com` có dấu `+` không khớp `[\w\.-]+`. Regex chỉ nhận diện phần sau dấu `+` là email, dẫn đến việc chuỗi bị che thành `user+<email_masked>`, làm lộ tiền tố định danh nhạy cảm của người dùng vào tệp log!
* **Kỹ thuật Bypass 2 — Bỏ sót cặp key-value trong từ điển JSON / Dict:**
  Trong `app.py`, dữ liệu gửi qua request JSON là `dict` Python dùng dấu hai chấm `:`. Regex `token` chỉ tìm kiếm dấu gán bằng `=`, khiến toàn bộ mật khẩu hay token gửi qua JSON (`{"password": "MySecretPassword2026"}`) không hề bị che giấu và bị ghi nguyên văn vào file log!

---

### 3.3. Quyền truy cập tệp tin log không an toàn
* Tệp `secure.log` và `secure.log.sig` được tạo ra với quyền mặc định của hệ điều hành (thường là 644 trên Unix), cho phép mọi người dùng thông thường trên cùng server đều có thể đọc nội dung nhật ký, dẫn tới rò rỉ dữ liệu riêng tư.

---

### 3.4. Race Condition khi ghi đồng thời (Thiếu File Locking)
* Trong môi trường ứng dụng chạy nhiều tiến trình worker (như Gunicorn/uWSGI), nhiều tiến trình có thể cùng ghi vào `secure.log` và `secure.log.sig` đồng thời. Do thiếu cơ chế khóa tệp (`fcntl.flock`), thứ tự các dòng log và chữ ký băm có thể bị xáo trộn, làm sai lệch cặp đối soát (log - signature).

---

### 3.5. Cơ chế xử lý lỗi nuốt ngoại lệ (Fail-Silent)
* Trong `SecureRotatingFileHandler.emit`:
  ```python
  try:
      msg = self.format(record)
      super().emit(record)
      append_signature(msg)
  except Exception:
      self.handleError(record)
  ```
  Nếu việc ghi chữ ký vào `secure.log.sig` bị lỗi (ví dụ hết dung lượng đĩa hoặc phân quyền bị từ chối), ngoại lệ bị `handleError` nuốt âm thầm mà không hề có cảnh báo khẩn cấp, dẫn đến việc mất dấu vết kiểm toán.

---

## 4. Đánh giá theo các nguyên tắc an ninh thông tin

| Nguyên tắc an ninh | Mức độ đáp ứng | Đánh giá & Phân tích |
|---|:---:|---|
| **Tính bí mật (Confidentiality)** | Chưa đạt | Regex mask bỏ sót dữ liệu dạng JSON, làm lộ mật khẩu rõ ràng trong log. |
| **Tính toàn vẹn (Integrity / Tamper-Evidence)** | Chưa đạt | Thiếu HMAC và thiếu liên kết chuỗi băm (Hash-Chain), cho phép kẻ xấu tự tính lại chữ ký. |
| **Tính khả dụng (Availability)** | Đạt một phần | Có tính năng luân phiên log (Rotation) chống tràn đĩa, nhưng xử lý lỗi còn mang tính âm thầm. |
| **Chống chối bỏ (Non-Repudiation)** | Chưa đạt | Do chữ ký không có khóa bí mật, không thể chứng minh ai là người thực sự sinh ra dòng log. |
| **Đặc quyền tối thiểu (Least Privilege)** | Chưa đạt | Tệp tin log chưa được phân quyền hạn chế (chmod 600). |
| **Ghi log có cấu trúc (Structured Logging)** | Đạt | Định dạng JSON rõ ràng, hỗ trợ timestamp UTC chuẩn ISO 8601. |

---

## 5. Đề xuất giải pháp nâng cấp mã nguồn

### 5.1. Nâng cấp Regex PII hỗ trợ cả dấu bằng `=` và dấu hai chấm `:`
```python
PII_PATTERNS = {
    "email": r'[\w\.-]+@[\w\.-]+\.\w+',
    # Khớp cả dạng key = value và 'key': 'value'
    "token": r'(?i)(token|apikey|key|password)["\']?\s*[:=]\s*["\']?[\w\-]{4,}["\']?',
    "phone_vn": r'\b(0|\+84)\d{9,10}\b',
}
```

### 5.2. Chuyển sang sử dụng HMAC-SHA256 kết hợp chuỗi băm (Hash-Chain)
Mỗi dòng chữ ký sẽ phụ thuộc vào chữ ký của dòng log liền trước:
```python
import hmac, hashlib, os

SECRET_KEY = os.environ.get("LOG_SIGNING_KEY", "DefaultSecureKey2026").encode()
_previous_hash = ""

def sign_log_line(line: str) -> str:
    global _previous_hash
    payload = (_previous_hash + line).encode("utf-8")
    current_hash = hmac.new(SECRET_KEY, payload, hashlib.sha256).hexdigest()
    _previous_hash = current_hash
    return current_hash
```
Với cơ chế này, kẻ tấn công nếu xóa hoặc chỉnh sửa bất kỳ dòng nào sẽ làm đứt gãy toàn bộ chuỗi băm phía sau và lập tức bị phát hiện khi chạy hàm kiểm toán.

### 5.3. Xây dựng công cụ kiểm tra toàn vẹn (`verify_log`)
```python
def verify_integrity(log_path, sig_path, key):
    with open(log_path, "r", encoding="utf-8") as f_log, open(sig_path, "r", encoding="utf-8") as f_sig:
        logs = f_log.readlines()
        sigs = [s.strip() for s in f_sig.readlines()]

    if len(logs) != len(sigs):
        return False, "Số lượng dòng log và chữ ký không khớp!"

    prev_sig = ""
    for i, (log_line, expected_sig) in enumerate(zip(logs, sigs)):
        computed = hmac.new(key, (prev_sig + log_line).encode("utf-8"), hashlib.sha256).hexdigest()
        if computed != expected_sig:
            return False, f"Phát hiện can thiệp giả mạo tại dòng {i + 1}!"
        prev_sig = computed

    return True, "Toàn bộ dữ liệu nhật ký toàn vẹn và hợp lệ."
```

---

## 6. Kết luận

Hệ thống `SecureLogger` đã xây dựng được nền móng vững chắc cho việc ghi nhật ký có cấu trúc và quản lý dung lượng tự động. Tuy nhiên, để đáp ứng tiêu chuẩn an toàn cho môi trường sản xuất, cần áp dụng cơ chế HMAC-SHA256 có chuỗi liên kết băm, mở rộng bộ lọc PII cho cấu trúc JSON và thiết lập phân quyền tệp tin chặt chẽ.
