import os
import sys
import unittest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from securevalidator import (
    validate_email,
    validate_url,
    validate_filename,
    sanitize_sql_input,
    sanitize_html_input,
)


class TestValidators(unittest.TestCase):
    """Test suite kiểm thử các hàm validation & sanitization - Trần Minh Khang (2387700027)."""

    def setUp(self):
        print("\n Running test:", self._testMethodName)

    # ----------------------------------------------------
    # Các test case cơ bản theo yêu cầu đề bài
    # ----------------------------------------------------
    def test_validate_email_valid(self):
        self.assertTrue(validate_email("user@example.com"))

    def test_validate_email_invalid(self):
        self.assertFalse(validate_email("user@@example..com"))

    def test_validate_url_valid(self):
        self.assertTrue(validate_url("https://example.com"))

    def test_validate_url_invalid(self):
        self.assertFalse(validate_url("ftp://example.com"))

    def test_validate_filename_valid(self):
        self.assertTrue(validate_filename("report.pdf"))

    def test_validate_filename_traversal(self):
        self.assertFalse(validate_filename("../../etc/passwd"))

    def test_sanitize_sql_input_injection(self):
        input_str = "' OR 1=1 --"
        sanitized = sanitize_sql_input(input_str)
        self.assertNotIn("'", sanitized)
        self.assertNotIn("--", sanitized)
        self.assertNotIn("OR", sanitized.upper())

    def test_sanitize_sql_input_safe_text(self):
        input_str = "hello world"
        sanitized = sanitize_sql_input(input_str)
        self.assertEqual(sanitized, "hello world")

    def test_sanitize_html_input_script(self):
        input_str = '<script>alert("XSS")</script>'
        sanitized = sanitize_html_input(input_str)
        self.assertEqual(
            sanitized, "&lt;script&gt;alert(&quot;XSS&quot;)&lt;/script&gt;"
        )

    def test_sanitize_html_input_safe_text(self):
        input_str = "Hello World"
        sanitized = sanitize_html_input(input_str)
        self.assertEqual(sanitized, "Hello World")

    # ----------------------------------------------------
    # CÁC TEST THỰC NGHIỆM BYPASS ĐỘC QUYỀN CỦA TRẦN MINH KHANG
    # ----------------------------------------------------
    def test_bypass_email_numeric_tld(self):
        """Bypass Email: Regex chấp nhận đuôi TLD chỉ toàn số do dùng \\w."""
        # Theo chuẩn ICANN, TLD không được chỉ có số, nhưng regex cho qua
        self.assertTrue(validate_email("khang.tran@company.123"))

    def test_bypass_url_octal_ip_ssrf(self):
        """Bypass SSRF: Sử dụng biểu diễn IP dạng Bát phân (Octal 0177.0.0.1 = 127.0.0.1)."""
        # Hệ thống cho qua vì netloc không rỗng và scheme là http
        self.assertTrue(validate_url("http://0177.0.0.1:8080/admin"))

    def test_bypass_filename_windows_device_reserved(self):
        """Bypass Path Traversal: Tên thiết bị đặc biệt trên Windows (CON, PRN, AUX, NUL)."""
        # Không chứa '..' hay '/', nhưng gây DoS treo máy chủ Windows khi mở file
        self.assertTrue(validate_filename("CON.txt"))

    def test_bypass_sql_tautology_operator(self):
        """Bypass SQL: Dùng toán tử logic || thay vì từ khóa OR."""
        # Toán tử || tạo mệnh đề luôn đúng mà không chứa từ khóa OR
        sanitized = sanitize_sql_input("1' || '1'='1")
        self.assertIn("||", sanitized)

    def test_bypass_html_data_uri_scheme(self):
        """Bypass XSS: Chuỗi Data URI chứa mã độc Base64 không có ký tự < > để escape."""
        data_uri = "data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg=="
        sanitized = sanitize_html_input(data_uri)
        # Toàn bộ chuỗi payload XSS còn nguyên vẹn 100%
        self.assertEqual(sanitized, data_uri)


if __name__ == "__main__":
    unittest.main()
