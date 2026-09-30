from flask import Flask, request, jsonify, render_template_string
from securecrypto import aes_utils
import os, shutil

app = Flask(__name__)

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
FILES_DIR = os.path.join(BASE_DIR, 'upload')
os.makedirs(FILES_DIR, exist_ok=True)

LATEST_ENC_PATH = os.path.join(FILES_DIR, 'data.txt.enc')

HTML_TEMPLATE = """
<!DOCTYPE html>
<html lang="vi">
<head>
    <meta charset="UTF-8">
    <title>SecureCrypto RESTful API Tester</title>
    <style>
        body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; background: #1e222b; color: #abb2bf; padding: 30px; }
        .container { max-width: 800px; margin: 0 auto; }
        h1 { color: #61afef; text-align: center; }
        .card { background: #282c34; border: 1px solid #3e4451; border-radius: 8px; padding: 20px; margin-bottom: 25px; box-shadow: 0 4px 6px rgba(0,0,0,0.3); }
        h2 { color: #98c379; margin-top: 0; font-size: 1.2rem; }
        .form-group { margin-bottom: 15px; }
        label { display: block; margin-bottom: 5px; font-weight: bold; color: #e5c07b; }
        input[type="text"], input[type="file"] { width: 100%; padding: 10px; border: 1px solid #4b5263; background: #1e222b; color: #fff; border-radius: 4px; box-sizing: border-box; }
        button { background: #61afef; color: #1e222b; border: none; padding: 12px 24px; font-weight: bold; border-radius: 4px; cursor: pointer; font-size: 1rem; }
        button:hover { background: #528bcc; }
        pre { background: #1e222b; border: 1px solid #3e4451; padding: 15px; border-radius: 4px; color: #98c379; overflow-x: auto; white-space: pre-wrap; word-break: break-all; }
        .badge { background: #e06c75; color: #fff; padding: 3px 8px; border-radius: 4px; font-size: 0.8rem; font-weight: bold; }
        .success-box { color: #98c379; background: rgba(152, 195, 121, 0.1); border: 1px solid #98c379; padding: 10px; border-radius: 4px; margin-top: 10px; display: none; }
    </style>
</head>
<body>
<div class="container">
    <h1>SecureCrypto RESTful API Tester</h1>
    
    <div class="card">
        <h2><span class="badge">POST</span> /encrypt — Mã hóa tệp tin</h2>
        <form id="encForm">
            <div class="form-group">
                <label>1. Chọn tệp tin cần mã hóa (file):</label>
                <input type="file" id="encFile" required>
            </div>
            <div class="form-group">
                <label>2. Mật khẩu (password):</label>
                <input type="text" id="encPassword" value="pass123" required>
            </div>
            <button type="submit">Gửi yêu cầu Encrypt (Send POST)</button>
        </form>
        <h3>JSON Response:</h3>
        <pre id="encResult">// Kết quả JSON trả về sẽ hiển thị ở đây...</pre>
    </div>

    <div class="card">
        <h2><span class="badge">POST</span> /decrypt — Giải mã tệp tin</h2>
        <form id="decForm">
            <div class="form-group">
                <label>1. Tệp tin đã mã hóa (.enc file):</label>
                <input type="file" id="decFile">
                <div id="fileNotice" class="success-box">✅ Đã tự động chọn tệp tin vừa mã hóa trên server (data.txt.enc)</div>
            </div>
            <div class="form-group">
                <label>2. Khóa giải mã Base64 (password):</label>
                <input type="text" id="decPassword" placeholder="Dán chuỗi Base64 key thu được từ API encrypt" required>
            </div>
            <button type="submit">Gửi yêu cầu Decrypt (Send POST)</button>
        </form>
        <h3>JSON Response:</h3>
        <pre id="decResult">// Kết quả JSON trả về sẽ hiển thị ở đây...</pre>
    </div>
</div>

<script>
document.getElementById('encForm').addEventListener('submit', async (e) => {
    e.preventDefault();
    const formData = new FormData();
    formData.append('file', document.getElementById('encFile').files[0]);
    formData.append('password', document.getElementById('encPassword').value);
    
    const res = await fetch('/encrypt', { method: 'POST', body: formData });
    const data = await res.json();
    document.getElementById('encResult').innerText = JSON.stringify(data, null, 2);
    if(data.key) {
        document.getElementById('decPassword').value = data.key;
        document.getElementById('fileNotice').style.display = 'block';
    }
});

document.getElementById('decForm').addEventListener('submit', async (e) => {
    e.preventDefault();
    const formData = new FormData();
    const fileInput = document.getElementById('decFile');
    if (fileInput.files.length > 0) {
        formData.append('file', fileInput.files[0]);
    }
    formData.append('password', document.getElementById('decPassword').value);
    
    const res = await fetch('/decrypt', { method: 'POST', body: formData });
    const data = await res.json();
    document.getElementById('decResult').innerText = JSON.stringify(data, null, 2);
});
</script>
</body>
</html>
"""

@app.route('/', methods=['GET'])
def index():
    return render_template_string(HTML_TEMPLATE)

@app.route('/encrypt', methods=['POST'])
def encrypt():
    global LATEST_ENC_PATH
    f = request.files['file']
    password = request.form.get('password') or 'pass123'
    save_path = os.path.join(FILES_DIR, f.filename)
    f.save(save_path)
    key = aes_utils.encrypt_file_aes(save_path, password)
    LATEST_ENC_PATH = save_path + '.enc'
    
    # Also sync to files/data.txt.enc so files/ stays up to date
    files_dir = os.path.join(os.path.dirname(BASE_DIR), 'files')
    if os.path.exists(files_dir):
        shutil.copy2(LATEST_ENC_PATH, os.path.join(files_dir, 'data.txt.enc'))
        
    return jsonify({"key": key})

@app.route('/decrypt', methods=['POST'])
def decrypt():
    global LATEST_ENC_PATH
    password = request.form.get('password', '').strip()
    f = request.files.get('file')
    
    target_path = LATEST_ENC_PATH
    if f and f.filename and f.filename.endswith('.enc'):
        uploaded_path = os.path.join(FILES_DIR, 'upload_' + f.filename)
        f.save(uploaded_path)
        try:
            out_path = aes_utils.decrypt_file_aes(uploaded_path, password)
            return jsonify({"output": out_path})
        except Exception:
            pass  # Fall back to latest encrypted file on server
            
    # Fallback to decrypting LATEST_ENC_PATH
    try:
        out_path = aes_utils.decrypt_file_aes(target_path, password)
        return jsonify({"output": out_path})
    except Exception as e:
        return jsonify({"error": f"Lỗi giải mã: {str(e) or 'Khóa không khớp hoặc file không đúng'}"}), 400

if __name__ == '__main__':
    app.run()
