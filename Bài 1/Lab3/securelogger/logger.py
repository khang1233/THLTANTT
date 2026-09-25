import gzip
import hashlib
import json
import logging
import logging.handlers
import os
import re
from datetime import datetime

LOG_FILE = "secure.log"
SIGNATURE_FILE = "secure.log.sig"
MAX_LOG_SIZE = 1024 * 1024
BACKUP_COUNT = 2

PII_PATTERNS = {
    "email": r"[\w\.-]+@[\w\.-]+\.\w+",
    "token": r'(?i)(token|apikey|key|password)\s*=\s*["\']?[\w\-]{4,}["\']?',
}


def mask_pii(text: str) -> str:
    """Che giấu thông tin cá nhân (PII) trong chuỗi văn bản."""
    if not isinstance(text, str):
        text = str(text)
    for label, pattern in PII_PATTERNS.items():
        text = re.sub(pattern, f"<{label}_masked>", text, flags=re.IGNORECASE)
    return text


def hash_line(line: str) -> str:
    """Băm một dòng log bằng thuật toán SHA-256."""
    return hashlib.sha256(line.encode("utf-8")).hexdigest()


def append_signature(line: str) -> None:
    """Ghi mã băm SHA-256 của dòng log vào tệp chữ ký."""
    with open(SIGNATURE_FILE, "a", encoding="utf-8") as f:
        f.write(hash_line(line) + "\n")


class JSONFormatter(logging.Formatter):
    """Định dạng bản ghi log thành JSON có cấu trúc nhằm chống Log Injection (CRLF)."""

    def format(self, record: logging.LogRecord) -> str:
        message = mask_pii(record.getMessage())
        record_dict = {
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "level": record.levelname,
            "message": message,
        }
        if hasattr(record, "data"):
            record_dict["data"] = mask_pii(str(record.data))
        if hasattr(record, "results"):
            record_dict["results"] = mask_pii(str(record.results))
        json_line = json.dumps(record_dict, ensure_ascii=False)
        return json_line


class GZipRotator:
    """Nén tệp tin nhật ký cũ thành định dạng .gz khi luân phiên log."""

    def __call__(self, source: str, dest: str) -> None:
        with open(source, "rb") as f_in, gzip.open(dest + ".gz", "wb") as f_out:
            f_out.writelines(f_in)
        if os.path.exists(source):
            os.remove(source)


class SecureRotatingFileHandler(logging.handlers.RotatingFileHandler):
    """Handler ghi log xoay vòng mở rộng, đồng thời sinh chữ ký băm toàn vẹn."""

    def emit(self, record: logging.LogRecord) -> None:
        try:
            msg = self.format(record)
            super().emit(record)
            append_signature(msg)
        except Exception:
            self.handleError(record)


def get_secure_logger() -> logging.Logger:
    """Khởi tạo và cấu hình SecureLogger an toàn."""
    logger = logging.getLogger("secure_logger")
    logger.setLevel(logging.DEBUG)
    if not logger.handlers:
        handler = SecureRotatingFileHandler(
            LOG_FILE,
            maxBytes=MAX_LOG_SIZE,
            backupCount=BACKUP_COUNT,
            encoding="utf-8",
        )
        handler.setFormatter(JSONFormatter())
        handler.rotator = GZipRotator()
        logger.addHandler(handler)
    logger.propagate = False
    return logger


secure_logger = get_secure_logger()
