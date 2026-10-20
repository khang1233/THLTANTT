### Họ và Tên: Trần Minh Khang
### MSSV: 2387700027

# BÁO CÁO KỸ THUẬT: DAST-TOOL
## NỀN TẢNG PHÂN TÍCH VÀ GIÁM SÁT AN NINH TIẾN TRÌNH ĐỘNG (PYTHON DAST)

---

## 1. Giới thiệu và Kiến trúc Hệ thống `dast-tool`

`dast-tool` cung cấp giải pháp giám sát an ninh runtime và phân tích động toàn diện cho các tiến trình Python:

```text
dast-tool/
├── runtime_monitor.py                # RuntimeMonitor: Giám sát % CPU, RAM RSS, file descriptors
├── memory_analyzer.py                # MemoryAnalyzer: Phát hiện rò rỉ bộ nhớ GC và tràn số 64-bit
├── network_traffic_analyzer.py       # NetworkTrafficAnalyzer: Thống kê lưu lượng mạng I/O theo card
├── security_behavior_checker.py      # SecurityBehaviorChecker: Nhận diện lệnh gọi syscall nguy hiểm
├── virtual_sandbox.py                # VirtualSandbox: Môi trường hộp cát cách ly trên temp directory
├── main.py                           # CLI thực thi giám sát động cục bộ
├── app.py                            # Flask REST API giám sát thời gian thực
├── tests/                            # 5 ca kiểm thử đơn vị Unittest
└── requirements.txt                  # psutil, flask
```

---

## 2. Hướng dẫn thực thi

```bash
# Cài đặt thư viện
pip install -r requirements.txt

# Chạy Unit Tests
python -m unittest discover -s tests

# Chạy CLI giám sát trực tiếp
python .\main.py

# Khởi chạy Flask REST API (cổng 5000)
python .\app.py
```

### Các Endpoint API giám sát:
* `GET /api/monitor`: Giám sát CPU, RAM, open files
* `GET /api/memory`: Phát hiện memory leak và kiểm tra tràn số nguyên
* `GET /api/network`: Thống kê mạng I/O
* `GET /api/security`: Phát hiện syscalls nguy hiểm
* `POST /api/sandbox`: Thực thi câu lệnh cô lập trong sandbox

---

## 3. Kết quả thực nghiệm

1. **Unit Tests:** 5/5 ca kiểm thử đơn vị thành công (`OK`).
2. **CLI `main.py`:** Giám sát thành công PID với `CPU: 0.0%`, `Memory: ~17MB`, phát hiện syscalls `['os.system', 'eval', 'exec']`, thực thi cách ly stdout `Hello Sandbox`.
3. **Flask API `app.py`:** Lắng nghe trên `http://127.0.0.1:5000`, truy cập `/api/monitor` trả về HTTP 200 JSON.
