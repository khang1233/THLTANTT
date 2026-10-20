### Họ và Tên: Trần Minh Khang
### MSSV: 2387700027

# BÀI 5: PHÂN TÍCH VÀ KIỂM THỬ BẢO MẬT (SAST VÀ DAST)
## BÁO CÁO TỔNG QUAN KIỂM THỬ TĨNH VÀ ĐỘNG (SAST-TOOL & DAST-TOOL)

---

## 1. Giới thiệu tổng quan

Bài thực hành số 5 trang bị kiến thức và kỹ năng thực chiến toàn diện về hai phương pháp kiểm thử an ninh phần mềm trọng yếu:
1. **Static Application Security Testing (SAST):** Phân tích mã nguồn tĩnh không cần thực thi chương trình thông qua duyệt cây cú pháp trừu tượng (Abstract Syntax Tree - AST), so khớp mẫu biểu thức chính quy (Regex Pattern Matching), áp dụng hệ thống luật bảo mật đa cấp (Security Rule Engine), đo lường chỉ số chất lượng mã nguồn (Code Quality Metrics với Flake8) và chuẩn hóa kết quả báo cáo theo định dạng chuẩn công nghiệp **SARIF (Static Analysis Results Interchange Format - OASIS / ISO)**.
2. **Dynamic Application Security Testing (DAST):** Phân tích và giám sát hành vi động của ứng dụng trong thời gian thực thi (Runtime Security Testing - RST) gồm: giám sát tài nguyên CPU / RAM / tệp đang mở (`RuntimeMonitor`), phát hiện rò rỉ bộ nhớ & kiểm tra tràn số nguyên 64-bit (`MemoryAnalyzer`), phân tích lưu lượng mạng I/O (`NetworkTrafficAnalyzer`), phát hiện lệnh gọi hệ thống nguy hiểm (`SecurityBehaviorChecker`), cô lập thực thi trong môi trường hộp cát tạm thời (`VirtualSandbox`) và cung cấp giao diện RESTful API giám sát thời gian thực bằng Flask.

---

## 2. Cấu trúc thư mục Bài 5

```text
Bai5/
├── sast-tool/                             # Hợp phần 1: Công cụ kiểm thử bảo mật tĩnh
│   ├── examples/
│   │   ├── vulnerable_01.py              # Mã nguồn mẫu chứa eval, hardcoded password, pickle
│   │   └── vulnerable_02.py              # Mã nguồn mẫu chứa dangerous eval, exec, read_file
│   ├── rules/
│   │   └── default_rules.json            # Cơ sở dữ liệu luật phân loại mức độ rủi ro (high, medium, low)
│   ├── sast_tool/
│   │   ├── __init__.py
│   │   ├── ast_analyzer.py               # Phân tích AST phát hiện hàm nguy hiểm (eval)
│   │   ├── code_quality_checker.py       # Kiểm tra chất lượng và tuân thủ chuẩn mã với flake8
│   │   ├── sarif_reporter.py             # Xuất báo cáo chuẩn SARIF 2.1.0 (sarif-om & jsonpickle)
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
│   └── requirements.txt                  # flake8, sarif-om, jsonpickle
│
├── dast-tool/                             # Hợp phần 2: Công cụ kiểm thử bảo mật động
│   ├── memory_analyzer.py                # Phân tích rò rỉ GC và tràn số nguyên 64-bit
│   ├── network_traffic_analyzer.py       # Phân tích lưu lượng mạng I/O theo card mạng
│   ├── runtime_monitor.py                # Giám sát % CPU, bộ nhớ RSS, file descriptor đang mở
│   ├── security_behavior_checker.py      # Phát hiện hành vi gọi lệnh hệ thống đáng ngờ
│   ├── virtual_sandbox.py                # Hộp cát cô lập thực thi trên thư mục tạm (mkdtemp)
│   ├── main.py                           # CLI thực thi giám sát động toàn diện
│   ├── app.py                            # Flask REST API giám sát runtime (/api/monitor, /api/sandbox...)
│   ├── tests/
│   │   ├── test_memory_analyzer.py
│   │   ├── test_network_traffic_analyzer.py
│   │   ├── test_runtime_monitor.py
│   │   ├── test_security_behavior_checker.py
│   │   └── test_virtual_sandbox.py
│   └── requirements.txt                  # psutil, flask
│
└── images/                               # Ảnh chụp minh chứng thực nghiệm
```

---

## 3. Hướng dẫn chạy và kiểm thử

### 3.1 Kiểm thử SAST-Tool
```bash
cd Bai5/sast-tool
pip install -r requirements.txt

# Chạy Unit Tests
python -m unittest discover tests

# Phân tích tập tin mã nguồn mẫu 1 (Phát hiện 8 lỗi)
python -m sast_tool.main .\examples\vulnerable_01.py

# Phân tích tập tin mã nguồn mẫu 2 (Phát hiện 4 lỗi)
python -m sast_tool.main .\examples\vulnerable_02.py
```

### 3.2 Kiểm thử DAST-Tool
```bash
cd Bai5/dast-tool
pip install -r requirements.txt

# Chạy Unit Tests
python -m unittest discover -s tests

# Chạy CLI giám sát động
python .\main.py

# Khởi chạy Flask REST API
python .\app.py
```
Các endpoint API kiểm tra:
* `GET http://localhost:5000/api/monitor` - Trạng thái CPU, RAM, tệp đang mở
* `GET http://localhost:5000/api/memory` - Trạng thái bộ nhớ và kiểm tra tràn số
* `GET http://localhost:5000/api/network` - Lưu lượng I/O các giao diện mạng
* `GET http://localhost:5000/api/security` - Danh sách lệnh gọi hệ thống nguy hiểm
* `POST http://localhost:5000/api/sandbox` (Body JSON: `{"command": "echo test"}`) - Thực thi cô lập
