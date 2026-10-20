### Họ và Tên: Trần Minh Khang
### MSSV: 2387700027

# BÀI 5: PHÂN TÍCH VÀ KIỂM THỬ BẢO MẬT (SAST VÀ DAST)
## BÁO CÁO TỔNG QUAN KIỂM THỬ TĨNH (SAST-TOOL) VÀ KIỂM THỬ ĐỘNG (DAST-TOOL)

---

## 1. Giới thiệu tổng quan

Bài thực hành số 5 trang bị kiến thức và kỹ năng thực hành nền tảng vững chắc về hai trụ cột kiểm thử an ninh phần mềm hiện đại: **Static Application Security Testing (SAST - Kiểm thử bảo mật tĩnh)** và **Dynamic Application Security Testing (DAST - Kiểm thử bảo mật động)**:

1. **SAST-Tool (`Bai5/sast-tool`):** Tập trung vào việc mổ xẻ mã nguồn khi phần mềm chưa thực thi thông qua việc phân tích cây cú pháp trừu tượng (Abstract Syntax Tree - AST), so khớp mẫu biểu thức chính quy (Regex Pattern Matching), phân loại mức độ nghiêm trọng bằng Security Rule Engine, kiểm tra các chỉ số chất lượng mã với Flake8 và chuẩn hóa kết quả báo cáo theo định dạng quốc tế **SARIF 2.1.0 (Static Analysis Results Interchange Format - OASIS / ISO)**.
2. **DAST-Tool (`Bai5/dast-tool`):** Tập trung quan sát và giám sát hành vi ứng dụng trong thời gian thực thi (Runtime Security Testing - RST). DAST giám sát việc tiêu thụ tài nguyên phần cứng (CPU, RAM), kiểm tra tệp tin đang mở, phát hiện các rò rỉ bộ nhớ (Memory Leaks), kiểm tra hiện tượng tràn số nguyên 64-bit (Integer Overflow), phân tích lưu lượng giao tiếp mạng I/O, nhận diện các lệnh gọi hệ thống nguy hiểm (syscalls), cô lập thực thi trong môi trường hộp cát ảo (Virtual Sandbox) và cung cấp giao diện RESTful API giám sát thời gian thực bằng Flask.

---

## 2. Cấu trúc thư mục Bài 5

```text
Bai5/
├── sast-tool/                             # Hợp phần 1: Công cụ kiểm thử bảo mật tĩnh
│   ├── examples/
│   │   ├── vulnerable_01.py              # Mã nguồn mẫu 1 (eval, hardcoded password, pickle, flake8)
│   │   └── vulnerable_02.py              # Mã nguồn mẫu 2 (dangerous eval, exec, read_file)
│   ├── rules/
│   │   └── default_rules.json            # Cơ sở dữ liệu luật phân loại mức độ rủi ro (high, medium, low)
│   ├── sast_tool/
│   │   ├── __init__.py
│   │   ├── ast_analyzer.py               # Phân tích AST phát hiện hàm nguy hiểm (eval)
│   │   ├── code_quality_checker.py       # Kiểm tra chất lượng và chuẩn mã PEP 8 với flake8
│   │   ├── sarif_reporter.py             # Xuất báo cáo chuẩn quốc tế SARIF 2.1.0
│   │   ├── security_rule_engine.py       # Ánh xạ lỗ hổng với mức độ nghiêm trọng
│   │   ├── vuln_pattern_matcher.py       # So khớp mẫu Regex tìm mật khẩu & thư viện nguy hiểm
│   │   └── main.py                       # CLI điều phối toàn bộ quy trình phân tích SAST
│   ├── tests/
│   │   ├── __init__.py
│   │   ├── test_ast_analyzer.py          # Kiểm thử đơn vị bộ phân tích AST
│   │   ├── test_code_quality_checker.py  # Kiểm thử đơn vị bộ kiểm tra flake8
│   │   ├── test_sarif_reporter.py        # Kiểm thử đơn vị bộ sinh báo cáo SARIF
│   │   ├── test_security_rule_engine.py  # Kiểm thử đơn vị bộ quy tắc bảo mật
│   │   └── test_vuln_pattern_matcher.py  # Kiểm thử đơn vị bộ so khớp mẫu
│   ├── requirements.txt                  # flake8, sarif-om, jsonpickle
│   └── README.md                         # Báo cáo kỹ thuật chi tiết SAST-Tool
│
├── dast-tool/                             # Hợp phần 2: Công cụ kiểm thử bảo mật động
│   ├── memory_analyzer.py                # Phân tích rò rỉ GC và tràn số nguyên 64-bit
│   ├── network_traffic_analyzer.py       # Phân tích lưu lượng mạng I/O theo card mạng
│   ├── runtime_monitor.py                # Giám sát % CPU, bộ nhớ RSS, file descriptor đang mở
│   ├── security_behavior_checker.py      # Phát hiện hành vi gọi lệnh hệ thống đáng ngờ
│   ├── virtual_sandbox.py                # Hộp cát cô lập thực thi trên thư mục tạm (mkdtemp)
│   ├── main.py                           # CLI thực thi giám sát động toàn diện
│   ├── app.py                            # Flask REST API giám sát runtime (/api/monitor...)
│   ├── tests/
│   │   ├── test_memory_analyzer.py
│   │   ├── test_network_traffic_analyzer.py
│   │   ├── test_runtime_monitor.py
│   │   ├── test_security_behavior_checker.py
│   │   └── test_virtual_sandbox.py
│   ├── requirements.txt                  # psutil, flask
│   └── README.md                         # Báo cáo kỹ thuật chi tiết DAST-Tool
│
└── images/                               # 13 ảnh chụp minh chứng thực nghiệm thực tế
```

---

## 3. Bảng tổng hợp Lỗ hổng, Kỹ thuật & Công nghệ sử dụng

| Phân hệ | Thành phần | Kỹ thuật / Chuẩn áp dụng | Thư viện triển khai | Đặc tính an ninh cốt lõi |
|---|---|---|---|---|
| **SAST-Tool** | AST Analyzer | **Abstract Syntax Tree (AST)** | `ast` (Python core) | Duyệt cấu trúc cú pháp phân cấp, trích xuất dòng & cột chứa lời gọi hàm nguy hiểm `eval()`. |
| **SAST-Tool** | Vuln Pattern Matcher | **Regex Pattern Matching** | `re` | So khớp mẫu chuỗi phát hiện mật khẩu gán trực tiếp (`password = "..."`) và module `pickle`. |
| **SAST-Tool** | Security Rule Engine | **Multi-tier Rule Mapping** | `json` | Phân loại rủi ro bảo mật 3 cấp độ (High, Medium, Low) dựa trên cấu hình `default_rules.json`. |
| **SAST-Tool** | Code Quality Checker | **Linting & Code Metrics** | `flake8`, `subprocess` | Đo lường tuân thủ chuẩn PEP 8, phát hiện import thừa (F401), import sai vị trí (E402), dòng trống (E302, E305). |
| **SAST-Tool** | SARIF Reporter | **SARIF 2.1.0 Standard** | `sarif-om`, `jsonpickle` | Đóng gói toàn bộ cảnh báo thành định dạng chuẩn quốc tế, tương thích trực tiếp với VS Code và GitHub Security. |
| **DAST-Tool** | Runtime Monitor | **Process Hooking & Telemetry** | `psutil` | Giám sát tài nguyên thời gian thực: tỷ lệ CPU %, bộ nhớ RAM vật lý RSS, các file handles đang mở. |
| **DAST-Tool** | Memory Analyzer | **Garbage Collection Audit** | `gc` | Phát hiện đối tượng rò rỉ qua `gc.garbage` và kiểm tra tràn số nguyên 64-bit (`> 2^63`). |
| **DAST-Tool** | Network Analyzer | **Network I/O Counters** | `psutil` | Phân tích lưu lượng dữ liệu gửi/nhận theo từng card mạng, phát hiện kết nối C2 hoặc rò rỉ dữ liệu. |
| **DAST-Tool** | Behavior Checker | **Dangerous Syscall Detection** | `os` | So khớp hành vi nguy hiểm trong runtime (`os.system`, `eval`, `exec`). |
| **DAST-Tool** | Virtual Sandbox | **Filesystem Isolation** | `tempfile`, `subprocess` | Khởi tạo thư mục tạm cô lập (`mkdtemp`), thực thi câu lệnh không tin cậy mà không ảnh hưởng OS thật. |
| **DAST-Tool** | Flask REST API | **Centralized Security Monitoring** | `flask` | Cung cấp 5 endpoint REST API chuẩn hóa JSON phục vụ tích hợp bảng điều khiển giám sát SIEM/SOC. |

---

## 4. Hướng dẫn cài đặt và chạy thử nghiệm

### 4.1. Hợp phần 1: SAST-Tool (`Bai5/sast-tool`)
```bash
# Di chuyển vào thư mục dự án
cd Bai5/sast-tool

# 1. Cài đặt các gói phụ thuộc
pip install -r .equirements.txt

# 2. Chạy toàn bộ bộ kiểm thử đơn vị Unittest (6/6 tests passed)
python -m unittest discover tests

# 3. Phân tích tập tin mã nguồn mẫu 1 (Phát hiện 8 lỗi bảo mật & chất lượng mã)
python -m sast_tool.main .\examplesulnerable_01.py

# 4. Phân tích tập tin mã nguồn mẫu 2 (Phát hiện 4 lỗi bảo mật & chất lượng mã)
python -m sast_tool.main .\examplesulnerable_02.py
```

### 4.2. Hợp phần 2: DAST-Tool (`Bai5/dast-tool`)
```bash
# Di chuyển vào thư mục dự án
cd ../dast-tool

# 1. Cài đặt các gói phụ thuộc
pip install -r .equirements.txt

# 2. Chạy toàn bộ bộ kiểm thử đơn vị Unittest (5/5 tests passed)
python -m unittest discover -s tests

# 3. Thực thi kịch bản giám sát tiến trình cục bộ qua dòng lệnh
python .\main.py

# 4. Khởi chạy máy chủ giám sát an ninh Flask REST API (cổng 5000)
python .pp.py

# 5. Mở một cửa sổ Terminal / trình duyệt khác kiểm tra các endpoint:
# http://127.0.0.1:5000/api/monitor
# http://127.0.0.1:5000/api/memory
# http://127.0.0.1:5000/api/network
# http://127.0.0.1:5000/api/security
# curl -X POST http://127.0.0.1:5000/api/sandbox -H "Content-Type: application/json" -d "{\"command\": \"echo Hello Sandbox\"}"
```

---

## 5. Danh mục hình ảnh thực nghiệm (Output Screenshots)

Dưới đây là 13 hình ảnh minh chứng thực tế cho toàn bộ các bước thực hành của Bài 5:

### 5.1. Cài đặt các gói thư viện SAST-Tool
* **Mô tả:** Chạy lệnh `pip install -r .equirements.txt` cài đặt `flake8`, `sarif-om`, `jsonpickle`.
* **Đường dẫn ảnh:** `images/01_pip_install_sast.png`

![Cài đặt các gói thư viện SAST-Tool](images/01_pip_install_sast.png)

---

### 5.2. Chạy bộ kiểm thử đơn vị (Unit Tests) SAST-Tool
* **Mô tả:** Chạy `python -m unittest discover tests`, toàn bộ 6/6 ca kiểm thử đơn vị đều vượt qua với trạng thái `OK`.
* **Đường dẫn ảnh:** `images/02_unittest_sast.png`

![Kết quả Unit Tests SAST-Tool](images/02_unittest_sast.png)

---

### 5.3. Phân tích mã nguồn không an toàn mẫu 1 (`vulnerable_01.py`)
* **Mô tả:** Chạy CLI `python -m sast_tool.main .\examplesulnerable_01.py`, phát hiện chính xác 8 vấn đề an ninh và lưu vào `report.sarif`.
* **Đường dẫn ảnh:** `images/03_run_sast_vulnerable_01.png`

![Phân tích vulnerable_01.py phát hiện 8 lỗi](images/03_run_sast_vulnerable_01.png)

---

### 5.4. Cài đặt tiện ích mở rộng SARIF Viewer trên Visual Studio Code
* **Mô tả:** Cài đặt extension `SARIF Viewer` của Microsoft DevLabs trên VS Code để đọc tệp báo cáo chuẩn SARIF.
* **Đường dẫn ảnh:** `images/04_vs_code_sarif_extension.png`

![Cài đặt SARIF Viewer trên VS Code](images/04_vs_code_sarif_extension.png)

---

### 5.5. Trực quan hóa danh sách 8 lỗi bảo mật trên SARIF Viewer
* **Mô tả:** Mở tệp `report.sarif` trên VS Code, panel **8 SARIF Results** hiển thị danh sách 8 lỗi được phân loại: 1 High (`Use of eval`), 2 Medium (`Hardcoded password`, `pickle`), và 5 Low (lỗi Lint Flake8 PEP 8).
* **Đường dẫn ảnh:** `images/05_sarif_viewer_report.png`

![Giao diện trực quan hóa 8 lỗi trên SARIF Viewer](images/05_sarif_viewer_report.png)

---

### 5.6. Phân tích mã nguồn không an toàn mẫu 2 (`vulnerable_02.py`)
* **Mô tả:** Chạy CLI `python -m sast_tool.main .\examplesulnerable_02.py`, phát hiện chính xác 4 vấn đề an ninh và định dạng.
* **Đường dẫn ảnh:** `images/06_run_sast_vulnerable_02.png`

![Phân tích vulnerable_02.py phát hiện 4 lỗi](images/06_run_sast_vulnerable_02.png)

---

### 5.7. Thao tác Git Commit & Push SAST-Tool
* **Mô tả:** Thực hiện `git commit -m "[add] sast tool"` và kiểm tra lịch sử commit bằng `git log -1 --stat`.
* **Đường dẫn ảnh:** `images/07_git_push_sast.png`

![Git Commit và Push SAST-Tool](images/07_git_push_sast.png)

---

### 5.8. Cài đặt các gói thư viện DAST-Tool
* **Mô tả:** Chạy lệnh `pip install -r .equirements.txt` cài đặt `psutil` và `flask`.
* **Đường dẫn ảnh:** `images/08_pip_install_dast.png`

![Cài đặt thư viện DAST-Tool](images/08_pip_install_dast.png)

---

### 5.9. Chạy bộ kiểm thử đơn vị (Unit Tests) DAST-Tool
* **Mô tả:** Chạy `python -m unittest discover -s tests`, toàn bộ 5/5 ca kiểm thử đơn vị đều vượt qua với trạng thái `OK`.
* **Đường dẫn ảnh:** `images/09_unittest_dast.png`

![Kết quả Unit Tests DAST-Tool](images/09_unittest_dast.png)

---

### 5.10. Chạy kịch bản giám sát tiến trình dòng lệnh `main.py`
* **Mô tả:** Thực thi `python .\main.py` giám sát CPU Usage, Memory RSS, Open Files, Leaks, Overflow 64-bit, Network Stats, Suspicious Calls và Sandbox.
* **Đường dẫn ảnh:** `images/10_run_dast_main.png`

![Kết quả chạy CLI main.py DAST-Tool](images/10_run_dast_main.png)

---

### 5.11. Khởi chạy máy chủ giám sát an ninh Flask REST API `app.py`
* **Mô tả:** Khởi chạy dịch vụ Flask trên cổng 5000 (`http://127.0.0.1:5000`), sẵn sàng tiếp nhận các yêu cầu truy vấn giám sát từ xa.
* **Đường dẫn ảnh:** `images/11_run_dast_app.png`

![Khởi chạy Flask REST API trên cổng 5000](images/11_run_dast_app.png)

---

### 5.12. Kiểm tra phản hồi các endpoint DAST REST API
* **Mô tả:** Mở trình duyệt Chrome truy cập endpoint `http://127.0.0.1:5000/api/monitor`, server trả về phản hồi HTTP 200 dạng JSON chứa `cpu_usage: 0.0`, `memory_usage` và danh sách tệp đang mở.
* **Đường dẫn ảnh:** `images/12_test_dast_api.png`

![Kiểm tra endpoint API monitor trên trình duyệt](images/12_test_dast_api.png)

---

### 5.13. Thao tác Git Commit & Push DAST-Tool
* **Mô tả:** Kiểm tra `git log -2 --oneline` xác nhận 2 commit `[add] dast tool and lab5 documentation` và `[add] sast tool` đã được đẩy thành công lên remote repository.
* **Đường dẫn ảnh:** `images/13_git_push_dast.png`

![Kiểm tra Git Log xác nhận đã Push DAST-Tool](images/13_git_push_dast.png)

---

## 6. Cơ sở lý thuyết & Nguyên lý an ninh cốt lõi

### 6.1. Cây cú pháp trừu tượng (Abstract Syntax Tree - AST)
AST là biểu diễn dạng cây phân cấp của cấu trúc ngữ pháp mã nguồn chương trình. Mỗi nút (node) trên cây đại diện cho một thành phần ngôn ngữ như biểu thức, lệnh gán, định nghĩa hàm, điều kiện rẽ nhánh. Trong kiểm thử bảo mật tĩnh (SAST), AST cho phép phân tích toàn diện mã nguồn mà không cần thực thi chương trình, giúp phát hiện sớm các mẫu mã nguy hiểm (`eval`, `exec`), cấu trúc thiếu an toàn (vòng lặp vô hạn, thiếu xác thực) trước khi mã được triển khai thực tế.

### 6.2. Kỹ thuật Pattern Matching
Pattern Matching tìm kiếm các cấu trúc mã cụ thể thường liên quan mật thiết đến các lỗ hổng bảo mật đã biết. Có 3 dạng pattern chính:
* **Literal pattern:** Tìm kiếm trực tiếp chuỗi cụ thể (`os.system`, `eval`).
* **Structural pattern:** Dựa vào cấu trúc hình học trên cây AST (dạng biểu thức, nhánh cây).
* **Semantic pattern:** Dựa vào phân tích hành vi ngữ nghĩa (dòng chảy dữ liệu từ input người dùng $ightarrow$ xử lý $ightarrow$ thực thi).

### 6.3. Đánh giá chất lượng mã nguồn (Code Quality Metrics)
Các chỉ số định lượng đo lường độ sạch, ổn định và an toàn của mã nguồn:
* **Cyclomatic Complexity:** Số nhánh rẽ điều kiện độc lập trong một hàm. Độ phức tạp càng cao thì càng khó kiểm thử bao phủ và dễ sót lỗ hổng.
* **Function Length:** Hàm quá dài thường chứa logic chồng chéo, dễ vi phạm nguyên tắc bảo mật.
* **Nested Depth:** Cấu trúc rẽ nhánh / vòng lặp lồng nhiều tầng làm mờ luồng điều khiển.
* **Dependency Count:** Số lượng thư viện bên ngoài phụ thuộc. Càng nhiều thư viện thì bề mặt tấn công chuỗi cung ứng (Supply Chain) càng rộng.
* **Security Smell Density:** Tần suất xuất hiện các đoạn mã có "mùi nguy hiểm" (`eval`, hardcoded password, `pickle`).

### 6.4. Runtime Security Testing (RST) & Phân tích hành vi (Behavioral Analysis)
RST giám sát hành vi ứng dụng khi đang chạy trong môi trường thực thi thực tế, phát hiện các lỗ hổng mà SAST không thể thấy (Injection nảy sinh ở runtime, Race condition, Buffer overflow, Memory leak). Phân tích hành vi gồm 4 kỹ thuật:
* **Rule-based detection:** So khớp với luật định nghĩa sẵn (ví dụ đọc `/etc/passwd` và mở socket $ightarrow$ cảnh báo).
* **Heuristic Analysis:** Áp dụng tiêu chí phỏng đoán để tính điểm nguy cơ.
* **Anomaly Detection:** Phát hiện hành vi khác thường so với đường chuẩn (Baseline).
* **Machine Learning-based detection:** Trích xuất đặc trưng hành vi và phân loại bằng mô hình học máy.

### 6.5. Môi trường Hộp cát (Sandbox Analysis)
Thực thi phần mềm trong môi trường cô lập hoàn toàn để quan sát hành vi mà không ảnh hưởng hệ thống thật:
* **VM-based (VirtualBox, VMware, QEMU):** Mô phỏng OS thật, độ cô lập cao nhất.
* **Container-based (Docker, LXC, Firejail):** Nhanh hơn, nhẹ hơn, chia sẻ kernel.
* **Bare-metal (Joe Sandbox):** Chạy trên máy thật, giám sát bằng phần cứng.
* **In-memory/emulator (PANDA, Intel PIN):** Trình mô phỏng CPU/Memory quan sát chi tiết cấp thấp.

---

## 7. Liên kết báo cáo kỹ thuật chuyên sâu

* 👉 **Xem chi tiết Hợp phần 1:** [Báo cáo kỹ thuật SAST-Tool](sast-tool/README.md)
* 👉 **Xem chi tiết Hợp phần 2:** [Báo cáo kỹ thuật DAST-Tool](dast-tool/README.md)
