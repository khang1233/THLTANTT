### Họ và Tên: Trần Minh Khang
### MSSV: 2387700027

# BÁO CÁO KỸ THUẬT: CRYPTOTOOLKIT
## PHÂN TÍCH MẬT MÃ ỨNG DỤNG, BẢO MẬT KHÓA & KIỂM THỬ TỰ ĐỘNG

---

## 1. Giới thiệu và Kiến trúc thư viện `securecrypto`

Thư viện `securecrypto` được xây dựng nhằm cung cấp giải pháp toàn diện về mật mã học ứng dụng cho các lập trình viên phần mềm, bao gồm các chuẩn mã hóa đối xứng, bất đối xứng, dẫn xuất khóa (KDF) và băm mật khẩu hiện đại:

```text
crypto-toolkit/
├── files/
│   ├── data.txt                 # Tệp văn bản thử nghiệm gốc
│   ├── data.txt.enc             # Tệp sau khi mã hóa AES-256-GCM
│   └── data.txt.dec             # Tệp sau khi giải mã
├── securecrypto/
│   ├── __init__.py              # Định nghĩa phiên bản __version__ = "0.1.0"
│   ├── aes_utils.py             # Hàm sinh khóa PBKDF2 và mã hóa/giải mã AES-GCM
│   ├── hash_utils.py            # Băm mật khẩu bằng Argon2
│   ├── rsa_utils.py             # Sinh khóa RSA 2048-bit, ký số và xác thực chữ ký
│   ├── cli.py                   # Giao diện dòng lệnh CLI tương tác
│   ├── api.py                   # Cổng giao diện lập trình ứng dụng RESTful API (Flask)
│   └── app_gui.py               # Giao diện người dùng đồ họa Desktop (Tkinter)
├── tests/
│   ├── test_aes_utils.py        # Kiểm thử tích hợp mã hóa/giải mã tệp tin
│   ├── test_hash_utils.py       # Kiểm thử băm Argon2 và xác minh mật khẩu đúng/sai
│   └── test_rsa_utils.py        # Kiểm thử cặp khóa, ký số và phát hiện can thiệp dữ liệu
├── requirements.txt             # Danh sách gói phụ thuộc (pytest)
└── setup.py                     # Cấu hình gói và entry-point dòng lệnh CLI
```

---

## 2. Phân tích chi tiết các Module thuật toán

### 2.1. Module `aes_utils.py` — KDF & Mã hóa đối xứng xác thực (AEAD)

#### a. Cơ chế dẫn xuất khóa (PBKDF2HMAC):
```python
def derive_key_from_password(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100_000,
        backend=default_backend()
    )
    return kdf.derive(password.encode())
```
* **Salt ngẫu nhiên (16 bytes):** Sử dụng `os.urandom(16)` từ CSPRNG (Cryptographically Secure Pseudo-Random Number Generator) của hệ điều hành. Salt loại bỏ hoàn toàn khả năng tấn công bằng bảng tính sẵn (Rainbow Table) và tấn công đồng thời nhiều tài khoản (Multi-target attacks).
* **Số vòng lặp (100,000 iterations):** Tuân thủ chặt chẽ khuyến nghị an toàn của NIST SP 800-132 và OWASP Password Storage Cheat Sheet. Việc lặp 100,000 vòng tính toán HMAC-SHA256 làm chậm đáng kể tốc độ thử khóa của kẻ tấn công brute-force.
* **Độ dài khóa đầu ra (32 bytes = 256 bits):** Phù hợp hoàn hảo với chuẩn thuật toán AES-256.

#### b. Cấu trúc lưu trữ tệp mã hóa (AES-256-GCM):
* **Nonce ngẫu nhiên (12 bytes):** Chuẩn NIST SP 800-38D khuyến nghị kích thước Nonce tối ưu cho chế độ GCM là 96 bits (12 bytes) nhằm đạt hiệu năng cao nhất và tránh hiện tượng GHASH padding.
* **Cấu trúc đóng gói tệp `.enc`:**
  $$\text{Payload} = \underbrace{\text{Salt}}_{16\text{ bytes}} \;\|\; \underbrace{\text{Nonce}}_{12\text{ bytes}} \;\|\; \underbrace{\text{Ciphertext} + \text{Auth Tag}}_{N + 16\text{ bytes}}$$
* **Quy trình giải mã:** Module đọc tệp nhị phân và bóc tách chính xác các offset:
  * `salt = raw[:16]`
  * `nonce = raw[16:28]`
  * `ct = raw[28:]` (Bao gồm dữ liệu mã hóa và 16 bytes Authentication Tag ở đuôi).
* **Tính toàn vẹn (Integrity & Authenticity):** Nếu bất kỳ byte nào trong ciphertext bị can thiệp trên đường truyền hoặc bị lỗi bit, hàm `aesgcm.decrypt()` sẽ ném ngoại lệ `cryptography.exceptions.InvalidTag`, ngăn chặn hoàn toàn việc rò rỉ dữ liệu bị biến đổi (Bit-flipping attacks).

---

### 2.2. Module `hash_utils.py` — Băm mật khẩu thế hệ mới với Argon2

```python
from argon2 import PasswordHasher
ph = PasswordHasher()

def hash_password_secure(password):
    return ph.hash(password)
```

* **Tại sao không dùng SHA-256 hay MD5?** Các hàm băm thông điệp truyền thống (MD5, SHA-1, SHA-256) được thiết kế để tính toán cực nhanh trong phần cứng. Điều này giúp kẻ tấn công sử dụng các trang trại GPU hoặc chip ASIC chuyên dụng có thể tính toán hàng tỷ phép băm mỗi giây để bẻ khóa mật khẩu người dùng.
* **Cơ chế Memory-Hard của Argon2:** Argon2 là thuật toán chiến thắng cuộc thi Password Hashing Competition (PHC 2015). Thuật toán ép buộc tiến trình tính toán phải sử dụng một dung lượng bộ nhớ RAM đáng kể (mặc định 64MB) trong suốt quá trình băm. Điều này triệt tiêu hoàn toàn ưu thế song song hóa của chip GPU/ASIC vì các thiết bị này bị nghẽn băng thông bộ nhớ (Memory Bandwidth Bottleneck).
* **Định dạng chuỗi Hash Argon2:** Chuỗi trả về có dạng:
  `$argon2id$v=19$m=65536,t=3,p=4$<salt>$<hash>`
  chứa đầy đủ thông số cấu hình: phiên bản, bộ nhớ (`m`), số vòng (`t`), số luồng (`p`), và salt ngẫu nhiên tự sinh.

---

### 2.3. Module `rsa_utils.py` — Mật mã bất đối xứng & Chữ ký điện tử

```python
def generate_rsa_keypair(key_size=2048):
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=key_size
    )
    public_key = private_key.public_key()
    return private_key, public_key
```

* **Public Exponent $e = 65537$ ($2^{16} + 1$):** Số nguyên tố Fermat $F_4$ có trọng số Hamming thấp (chỉ 2 bit bật trong biểu diễn nhị phân `0x10001`), giúp tăng tốc độ mã hóa và xác thực chữ ký số nhưng hoàn toàn miễn nhiễm với các kỹ thuật tấn công Small Exponent (như Coppersmith Attack khi $e=3$).
* **Kích thước khóa 2048-bit:** Đạt tiêu chuẩn tối thiểu hiện nay theo quy định của NIST, bảo đảm khả năng chống lại việc phân tích nhân tử bằng thuật toán General Number Field Sieve (GNFS) trong tương lai gần.
* **Chữ ký số (Digital Signature):** Ký số bằng cách băm thông điệp qua SHA-256 rồi mã hóa chuỗi băm bằng khóa bí mật (`private_key.sign(data, padding.PKCS1v15(), hashes.SHA256())`). Người nhận dùng khóa công khai tương ứng để xác minh. Bất kỳ sự thay đổi nào đối với `data` đều khiến chữ ký bị từ chối (`verify_signature_rsa` trả về `False`).

---

## 3. Các kênh tương tác: CLI, REST API & Desktop GUI

### 3.1. Giao diện dòng lệnh CLI (`cli.py`)
Hỗ trợ tham số `--encrypt`, `--decrypt` và bắt buộc `--password`:
```bash
# Mã hóa tệp tin:
python securecrypto/cli.py --encrypt files/data.txt --password pass123

# Giải mã tệp tin bằng chuỗi khóa Base64 thu được:
python securecrypto/cli.py --decrypt files/data.txt.enc --password <BASE64_KEY>
```

### 3.2. RESTful API Service (`api.py`)
Triển khai trên nền Flask Framework với 2 endpoints:
* `POST /encrypt`: Nhận `multipart/form-data` gồm tệp `file` và chuỗi `password`. Lưu vào thư mục `securecrypto/upload`, mã hóa và trả về mã khóa Base64 dạng JSON.
* `POST /decrypt`: Nhận `file` đã mã hóa và mã khóa `password`. Giải mã và trả về đường dẫn tệp tin kết quả.

### 3.3. Giao diện người dùng Desktop (`app_gui.py`)
Sử dụng thư viện chuẩn `tkinter` cho phép người dùng thao tác trực quan:
* Hộp nhập mật khẩu bảo mật (ẩn ký tự dưới dạng dấu hoa thị `*`).
* Nút duyệt tệp và mã hóa tức thì.
* Nút giải mã và nhãn hiển thị trạng thái kết quả.

---

## 4. Kiểm thử tự động (Unit Tests) & Tuân thủ GitSecure

Bộ kiểm thử gồm 6 test cases độc lập thực thi qua `pytest`:
1. `test_encrypt_decrypt`: Kiểm tra mã hóa và giải mã file tạm thời, đối soát nội dung gốc.
2. `test_hash_password_and_verify`: Băm mật khẩu và đối soát tính đúng đắn với `PasswordHasher.verify()`.
3. `test_wrong_password_verification`: Băm mật khẩu và xác minh việc từ chối mật khẩu sai (`VerifyMismatchError`).
4. `test_rsa_keypair_generation`: Kiểm tra tính toàn vẹn của cặp khóa RSA được tạo.
5. `test_sign_and_verify`: Ký dữ liệu và thẩm định chữ ký thành công.
6. `test_verify_invalid_signature`: Ký dữ liệu nhưng thẩm định với dữ liệu bị giả mạo (kết quả trả về `False`).

> **Lưu ý kỹ thuật về GitSecure:**  
> Trong `test_hash_utils.py`, chuỗi mật khẩu được thiết kế có độ dài ngắn hơn 4 ký tự (ví dụ: `password = ""` hoặc `password = "123"`) nhằm đáp ứng quy chuẩn an toàn của hệ thống Pre-commit Hook GitSecure (vốn chặn regex `password\s*=\s*['"][^'"]{4,}['"]` như đã phân tích ở Bài 1 - Lab 2).

---

## 5. Kết quả thực nghiệm (Output Minh chứng)

### 5.1. Kết quả chạy Unit Tests (6/6 Passed)
Lệnh thực thi:
```bash
python -m pytest tests/
```
Output:
```text
============================= test session starts =============================
platform win32 -- Python 3.14.6, pytest-9.1.1, pluggy-1.6.0
collected 6 items

tests\test_aes_utils.py .                                                [ 16%]
tests\test_hash_utils.py ..                                              [ 50%]
tests\test_rsa_utils.py ...                                              [100%]

============================== 6 passed in 0.59s ==============================
```

![Kết quả Unit Tests](../images/01_unit_tests.png)

---

### 5.2. Kết quả mã hóa & giải mã CLI
Lệnh thực thi:
```bash
# 1. Mã hóa
python securecrypto/cli.py --encrypt files/data.txt --password pass123
# Output: GvWKL4IO/dtYfzDh2rMpACA21cHOmyRgWk7R4tfX8yA=

# 2. Giải mã
python securecrypto/cli.py --decrypt files/data.txt.enc --password GvWKL4IO/dtYfzDh2rMpACA21cHOmyRgWk7R4tfX8yA=
# Output: Decrypted. Output: files/data.txt.dec
```

![Kết quả CLI Encrypt & Decrypt](../images/02_cli_encrypt_decrypt.png)

#### Đối soát tệp tin thực tế trên Notepad (Bản rõ vs Mã hóa vs Giải mã):
So sánh trực quan dữ liệu nhị phân AES-GCM và tính toàn vẹn khi khôi phục dữ liệu gốc:

| 1. Bản rõ gốc (`data.txt`) | 2. Dữ liệu mã hóa (`data.txt.enc`) | 3. Dữ liệu giải mã (`data.txt.dec`) |
|:---:|:---:|:---:|
| ![Bản rõ Notepad](../images/notepad_plaintext.png) | ![Mã hóa Notepad](../images/notepad_encrypted.png) | ![Giải mã Notepad](../images/notepad_decrypted.png) |
| *Bản rõ ban đầu: `HUTECH University`* | *Dữ liệu ciphertext không thể đọc được* | *Khôi phục 100% nguyên vẹn nội dung gốc* |

---

### 5.3. Giao diện Desktop GUI (CryptoTkinter)
Lệnh thực thi:
```bash
python securecrypto/app_gui.py
```

![Giao diện Crypto GUI](../images/03_crypto_gui.png)

---

### 5.4. Kiểm thử RESTful API qua Postman
* **Endpoint `/encrypt`:**

![API Encrypt](../images/04_api_encrypt.png)

* **Endpoint `/decrypt`:**

![API Decrypt](../images/05_api_decrypt.png)

---

## 6. Phân tích rủi ro an ninh chuyên sâu

1. **Hiểm họa tái sử dụng Nonce (Nonce-Reuse Disaster in AES-GCM):**  
   AES-GCM sử dụng chế độ đếm (CTR mode) để tạo dòng khóa mã hóa và nhân đa thức Galois (GHASH) để xác thực. Nếu hai tệp tin khác nhau được mã hóa với cùng một Khóa và cùng một Nonce:
   $$C_1 \oplus C_2 = (P_1 \oplus K) \oplus (P_2 \oplus K) = P_1 \oplus P_2$$
   Kẻ tấn công ngay lập tức loại bỏ được khóa mã hóa và khôi phục được bản rõ qua phân tích tần số hoặc kỹ thuật Known-Plaintext Attack. Nghiêm trọng hơn, việc tái sử dụng Nonce cho phép kẻ tấn công giải phương trình đa thức trên trường Galois để thu được khóa phụ xác thực $H = E_K(0)$, từ đó có thể tự ý giả mạo Authentication Tag cho bất kỳ dữ liệu độc hại nào. Trong mã nguồn, nguy cơ này được loại trừ bằng cách luôn sinh mới Nonce ngẫu nhiên 96-bit (`os.urandom(12)`) cho mỗi phiên mã hóa.
2. **Quản lý khóa bí mật trong ứng dụng thực tế:**  
   Trong mô hình mẫu, khóa AES được trả về cho người dùng qua Base64 hoặc truyền qua CLI. Ở môi trường production, khóa mã hóa không bao giờ được truyền trực tiếp mà phải được bảo vệ bằng mô hình mã hóa phân cấp (Envelope Encryption) kết hợp dịch vụ quản lý khóa phần cứng chuyên dụng (Cloud KMS hoặc HSM).
