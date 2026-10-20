### Họ và Tên: Trần Minh Khang
### MSSV: 2387700027

# BÁO CÁO KỸ THUẬT: SAST-TOOL
## CÔNG CỤ PHÂN TÍCH VÀ KIỂM THỬ BẢO MẬT MÃ NGUỒN TĨNH (PYTHON SAST)

---

## 1. Giới thiệu và Kiến trúc Hệ thống `sast-tool`

`sast-tool` là công cụ phân tích bảo mật tĩnh được xây dựng bằng Python, tích hợp 5 thành phần cốt lõi:

```text
sast-tool/
├── examples/
│   ├── vulnerable_01.py              # File mã nguồn mẫu chứa eval(), hardcoded password, pickle
│   └── vulnerable_02.py              # File mã nguồn mẫu chứa dangerous_eval(), exec(), read_file()
├── rules/
│   └── default_rules.json            # Cấu hình mức độ rủi ro (High, Medium, Low)
├── sast_tool/
│   ├── ast_analyzer.py               # ASTAnalyzer: Duyệt AST phát hiện hàm nguy hiểm
│   ├── vuln_pattern_matcher.py       # VulnPatternMatcher: Regex so khớp mẫu mật khẩu cứng & pickle
│   ├── security_rule_engine.py       # SecurityRuleEngine: Ánh xạ luật và gán severity
│   ├── code_quality_checker.py       # CodeQualityChecker: Kiểm tra chuẩn PEP 8 bằng Flake8
│   ├── sarif_reporter.py             # SarifReporter: Xuất báo cáo chuẩn quốc tế SARIF 2.1.0
│   └── main.py                       # CLI điều phối luồng phân tích
├── tests/
│   ├── test_ast_analyzer.py
│   ├── test_code_quality_checker.py
│   ├── test_sarif_reporter.py
│   ├── test_security_rule_engine.py
│   └── test_vuln_pattern_matcher.py
└── requirements.txt                  # flake8, sarif-om, jsonpickle
```

---

## 2. Hướng dẫn thực thi

```bash
# Cài đặt thư viện
pip install -r requirements.txt

# Chạy Unit Tests
python -m unittest discover tests

# Quét phân tích file mẫu
python -m sast_tool.main .\examples\vulnerable_01.py
python -m sast_tool.main .\examples\vulnerable_02.py
```

---

## 3. Kết quả thực nghiệm

1. **Unit Tests:** 6/6 ca kiểm thử đơn vị thành công (`OK`).
2. **Quét `vulnerable_01.py`:** Phát hiện 8 issues (1 High: `Use of eval`, 2 Medium: `Hardcoded password`, `Usage of pickle`, 5 Low: `Flake8 Lint Issues`).
3. **Quét `vulnerable_02.py`:** Phát hiện 4 issues (1 High: `Use of eval`, 3 Low: `Flake8 Lint Issues`).
4. **Trực quan hóa SARIF:** Mở tệp `report.sarif` bằng tiện ích **SARIF Viewer** trong Visual Studio Code.
