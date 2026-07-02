import os
import json
import hashlib
import random
import string
import time
import threading
import platform
import base64
import re
from datetime import datetime
from flask import Flask, request, render_template_string, send_file, jsonify, redirect, url_for, session, make_response

app = Flask(__name__)
app.secret_key = ''.join(random.choices(string.ascii_letters + string.digits, k=32))

FLAG = ""
ADMIN_USERNAME = "admin"
ADMIN_PASSWORD = "admin123"
BACKUP_FLAG = ""
SECRET_KEY = ''.join(random.choices(string.ascii_letters + string.digits, k=16))

current_stage = "fix"

vulnerabilities = {
    "headache": True,
    "weak_password": True,
    "file_read": True,
    "xss": True,
    "ssti": True,
    "csp": True
}

ip_whitelist = []
access_log = []
attack_log = []
request_counts = {}

DOS_THRESHOLD = 100
DOS_TIME_WINDOW = 10

def generate_flag():
    return ''.join(random.choices(string.ascii_letters + string.digits + "_", k=32))

def save_flag():
    os.makedirs("./data", exist_ok=True)
    with open("./data/flag.txt", "w") as f:
        f.write(FLAG)
    with open("./data/credentials.json", "w") as f:
        json.dump({
            "username": ADMIN_USERNAME,
            "password": ADMIN_PASSWORD
        }, f)

def log_access(ip, endpoint, method):
    access_log.append({
        "timestamp": datetime.now().isoformat(),
        "ip": ip,
        "endpoint": endpoint,
        "method": method
    })
    if len(access_log) > 1000:
        access_log.pop(0)

def log_attack(ip, endpoint, method, details):
    attack_log.append({
        "timestamp": datetime.now().isoformat(),
        "ip": ip,
        "endpoint": endpoint,
        "method": method,
        "details": details
    })
    if len(attack_log) > 1000:
        attack_log.pop(0)

def check_dos(ip):
    now = time.time()
    if ip not in request_counts:
        request_counts[ip] = []
    
    request_counts[ip] = [t for t in request_counts[ip] if now - t < DOS_TIME_WINDOW]
    request_counts[ip].append(now)
    
    if len(request_counts[ip]) > DOS_THRESHOLD:
        log_attack(ip, "DOS_DETECTION", "POST", f"DoS攻击检测: {len(request_counts[ip])}次请求/{DOS_TIME_WINDOW}秒")
        return True
    return False

@app.before_request
def before_request():
    ip = request.remote_addr
    if check_dos(ip):
        return "检测到DoS攻击，已上报裁判", 403
    
    if ip_whitelist and ip not in ip_whitelist:
        log_access(ip, request.path, request.method)
        return "访问被拒绝，您的IP不在白名单中", 403
    
    log_access(ip, request.path, request.method)

@app.route('/')
def index():
    return render_template_string("""
    <!DOCTYPE html>
    <html>
    <head>
        <title>企业内部管理系统</title>
        <style>
            body { font-family: Arial, sans-serif; margin: 0; padding: 20px; background: #f5f5f5; }
            .container { max-width: 800px; margin: 0 auto; background: white; padding: 30px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
            h1 { color: #333; border-bottom: 2px solid #007bff; padding-bottom: 10px; }
            .menu { margin-top: 20px; }
            .menu a { display: inline-block; padding: 10px 20px; background: #007bff; color: white; text-decoration: none; border-radius: 4px; margin-right: 10px; }
            .menu a:hover { background: #0056b3; }
        </style>
    </head>
    <body>
        <div class="container">
            <h1>企业内部管理系统 v2.0</h1>
            <p>欢迎使用企业内部管理平台</p>
            <div class="menu">
                <a href="/auth">用户认证</a>
                <a href="/documents">文档管理</a>
                <a href="/search">数据搜索</a>
                <a href="/profile">个人中心</a>
                <a href="/api/status">系统状态</a>
            </div>
        </div>
    </body>
    </html>
    """)

@app.route('/auth', methods=['GET', 'POST'])
def auth():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        token = request.form.get('token', '')
        
        if vulnerabilities["weak_password"]:
            if username == ADMIN_USERNAME and password == ADMIN_PASSWORD:
                session['logged_in'] = True
                encoded = base64.b64encode(f"{username}:{SECRET_KEY}".encode()).decode()
                session['token'] = encoded
                return redirect('/dashboard')
            else:
                if token:
                    try:
                        decoded = base64.b64decode(token).decode()
                        if ':' in decoded:
                            parts = decoded.split(':')
                            if len(parts) >= 2:
                                if parts[1] == SECRET_KEY:
                                    session['logged_in'] = True
                                    session['token'] = token
                                    return redirect('/dashboard')
                    except:
                        pass
                return render_template_string("""
                <html>
                <head><title>登录失败</title></head>
                <body>
                <div style="text-align:center;margin-top:50px;">
                    <h2>登录失败</h2>
                    <p>用户名或密码错误</p>
                    <a href="/auth">返回登录</a>
                </div>
                </body>
                </html>
                """)
        else:
            if username == ADMIN_USERNAME and password == ADMIN_PASSWORD:
                session['logged_in'] = True
                return redirect('/dashboard')
            return "登录失败", 401
    else:
        return render_template_string("""
        <html>
        <head>
            <title>用户认证</title>
            <style>
                body { font-family: Arial, sans-serif; margin: 0; padding: 20px; background: #f5f5f5; }
                .login-box { max-width: 400px; margin: 50px auto; background: white; padding: 30px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
                input { width: 100%; padding: 10px; margin: 10px 0; border: 1px solid #ddd; border-radius: 4px; }
                button { width: 100%; padding: 10px; background: #007bff; color: white; border: none; border-radius: 4px; cursor: pointer; }
            </style>
        </head>
        <body>
            <div class="login-box">
                <h2>用户登录</h2>
                <form method="post">
                    <input type="text" name="username" placeholder="用户名" required>
                    <input type="password" name="password" placeholder="密码" required>
                    <input type="hidden" name="token" id="token">
                    <button type="submit">登录</button>
                </form>
                <script>
                    function generateToken() {
                        var user = document.querySelector('input[name="username"]').value;
                        if (user) {
                            var token = btoa(user + ':guess_secret');
                            document.getElementById('token').value = token;
                        }
                    }
                    document.querySelector('input[name="username"]').addEventListener('change', generateToken);
                </script>
            </div>
        </body>
        </html>
        """)

@app.route('/dashboard')
def dashboard():
    if not session.get('logged_in'):
        return redirect('/auth')
    
    return render_template_string("""
    <html>
    <head>
        <title>管理后台</title>
        <style>
            body { font-family: Arial, sans-serif; margin: 0; padding: 20px; background: #f5f5f5; }
            .dashboard { max-width: 800px; margin: 0 auto; background: white; padding: 30px; border-radius: 8px; }
            .flag-box { background: #e8f5e9; padding: 20px; border-radius: 4px; margin-top: 20px; }
        </style>
    </head>
    <body>
        <div class="dashboard">
            <h1>管理后台</h1>
            <p>欢迎来到管理控制台</p>
            <div class="flag-box">
                <h3>系统密钥</h3>
                <p>备用FLAG: """ + (BACKUP_FLAG if vulnerabilities["weak_password"] else "已隐藏") + """</p>
            </div>
        </div>
    </body>
    </html>
    """)

@app.route('/documents')
def documents():
    doc = request.args.get('doc', '')
    
    if vulnerabilities["file_read"]:
        if doc:
            try:
                normalized = os.path.normpath(doc)
                if '..' not in normalized:
                    safe_path = os.path.join('./docs', normalized)
                else:
                    encoded = doc.replace('../', '__')
                    decoded = encoded.replace('__', '../')
                    safe_path = decoded
                
                if os.path.exists(safe_path):
                    return send_file(safe_path)
            except Exception as e:
                pass
        return render_template_string("""
        <html>
        <head><title>文档管理</title></head>
        <body>
        <div style="max-width:600px;margin:50px auto;">
            <h2>文档管理</h2>
            <form>
                <input type="text" name="doc" placeholder="文档路径" style="width:300px;">
                <button type="submit">查看文档</button>
            </form>
            <p style="color:#666;font-size:12px;">提示：文档位于 ./docs/ 目录下</p>
        </div>
        </body>
        </html>
        """)
    else:
        return "文档功能已关闭", 403

@app.route('/search')
def search():
    query = request.args.get('q', '')
    results = []
    
    if vulnerabilities["xss"]:
        if query:
            keywords = ['admin', 'flag', 'secret', 'password']
            for kw in keywords:
                if kw in query.lower():
                    results.append(f"找到相关结果: {kw}")
    else:
        if query:
            query = query.replace('<', '&lt;').replace('>', '&gt;')
    
    return render_template_string("""
    <html>
    <head>
        <title>数据搜索</title>
        <script>
            function displayResults() {
                var query = document.getElementById('search-input').value;
                var resultDiv = document.getElementById('results');
                resultDiv.innerHTML = '搜索结果: ' + query;
            }
        </script>
    </head>
    <body>
        <div style="max-width:600px;margin:50px auto;">
            <h2>数据搜索</h2>
            <input type="text" id="search-input" name="q" value="""" + query + """">
            <button onclick="displayResults()">搜索</button>
            <div id="results">""" + ''.join(results) + """</div>
        </div>
    </body>
    </html>
    """)

@app.route('/profile')
def profile():
    user = request.args.get('user', 'guest')
    
    if vulnerabilities["ssti"]:
        return render_template_string("""
        <html>
        <head><title>个人中心</title></head>
        <body>
        <div style="max-width:600px;margin:50px auto;">
            <h2>欢迎, """ + user + """</h2>
            <p>这是您的个人资料页面</p>
        </div>
        </body>
        </html>
        """)
    else:
        return render_template_string("""
        <html>
        <head><title>个人中心</title></head>
        <body>
        <div style="max-width:600px;margin:50px auto;">
            <h2>欢迎, {{ user }}</h2>
            <p>这是您的个人资料页面</p>
        </div>
        </body>
        </html>
        """, user=user)

@app.route('/api/status')
def api_status():
    header_name = request.headers.get('X-Status-Check', '')
    
    if vulnerabilities["headache"]:
        if header_name:
            if header_name == 'SECRET_CHECK':
                secret_value = request.headers.get('X-Secret-Value', '')
                if secret_value:
                    if secret_value == 'FLAG_REVEAL':
                        return jsonify({"status": "ok", "flag": FLAG})
                    else:
                        try:
                            decoded = base64.b64decode(secret_value).decode()
                            if decoded.startswith('get_flag:'):
                                return jsonify({"status": "ok", "flag": FLAG})
                        except:
                            pass
            return jsonify({"status": "checked", "received": header_name})
    return jsonify({"status": "running", "version": "2.0"})

@app.route('/api/flag')
def api_flag():
    return FLAG, 200

@app.route('/api/backup_flag')
def api_backup_flag():
    if session.get('logged_in'):
        return BACKUP_FLAG, 200
    return "未授权访问", 401

@app.route('/csp-test')
def csp_test():
    if vulnerabilities["csp"]:
        resp = make_response("""
        <html>
        <head>
            <title>CSP测试</title>
            <script src="https://api.example.com/data?callback=processData"></script>
        </head>
        <body>
            <div id="content"></div>
            <script>
                function processData(data) {
                    document.getElementById('content').innerHTML = data.message;
                }
            </script>
        </body>
        </html>
        """)
        resp.headers['Content-Security-Policy'] = "default-src 'self'; script-src 'self' 'unsafe-inline'"
        return resp
    else:
        resp = make_response("CSP已加固")
        resp.headers['Content-Security-Policy'] = "default-src 'self'; script-src 'self'"
        return resp

@app.route('/harden/change_password', methods=['POST'])
def change_password():
    if current_stage != "fix":
        return "仅修复期允许修改密码", 403
    
    data = request.get_json()
    new_password = data.get('new_password')
    if new_password:
        global ADMIN_PASSWORD
        ADMIN_PASSWORD = new_password
        save_flag()
        return jsonify({"success": True, "message": "密码修改成功"})
    return jsonify({"success": False, "message": "缺少新密码"}), 400

@app.route('/harden/disable_vulnerability', methods=['POST'])
def disable_vulnerability():
    if current_stage != "fix":
        return "仅修复期允许关闭漏洞", 403
    
    data = request.get_json()
    vuln_name = data.get('vulnerability')
    if vuln_name in vulnerabilities:
        vulnerabilities[vuln_name] = False
        return jsonify({"success": True, "message": f"漏洞 {vuln_name} 已关闭"})
    return jsonify({"success": False, "message": "无效漏洞名称"}), 400

@app.route('/harden/add_whitelist', methods=['POST'])
def add_whitelist():
    if current_stage != "fix":
        return "仅修复期允许修改白名单", 403
    
    data = request.get_json()
    ip = data.get('ip')
    if ip and ip not in ip_whitelist:
        ip_whitelist.append(ip)
        return jsonify({"success": True, "message": f"IP {ip} 已加入白名单"})
    return jsonify({"success": False, "message": "无效IP或已在白名单中"}), 400

@app.route('/harden/status', methods=['GET'])
def harden_status():
    return jsonify({
        "vulnerabilities": vulnerabilities,
        "whitelist": ip_whitelist,
        "current_stage": current_stage
    })

@app.route('/logs/access', methods=['GET'])
def get_access_logs():
    return jsonify(access_log)

@app.route('/logs/attack', methods=['GET'])
def get_attack_logs():
    return jsonify(attack_log)

@app.route('/stage', methods=['POST'])
def set_stage():
    global current_stage
    data = request.get_json()
    new_stage = data.get('stage')
    if new_stage in ["fix", "stabilize", "attack"]:
        current_stage = new_stage
        return jsonify({"success": True, "message": f"阶段已切换至: {new_stage}"})
    return jsonify({"success": False, "message": "无效阶段"}), 400

@app.route('/hash', methods=['GET'])
def get_hash():
    files_to_hash = [
        __file__,
        "./config/client_config.py"
    ]
    
    hashes = {}
    for filepath in files_to_hash:
        if os.path.exists(filepath):
            with open(filepath, 'rb') as f:
                hashes[filepath] = hashlib.md5(f.read()).hexdigest()
    
    return jsonify(hashes)

def start_server(port=8000):
    global FLAG, BACKUP_FLAG
    FLAG = generate_flag()
    BACKUP_FLAG = generate_flag()
    save_flag()
    
    os.makedirs("./docs", exist_ok=True)
    with open("./docs/readme.txt", "w") as f:
        f.write("欢迎使用文档管理系统\n")
    
    print(f"靶机服务启动，监听端口: {port}")
    print(f"主FLAG: {FLAG}")
    print(f"备用FLAG: {BACKUP_FLAG}")
    
    app.run(host='0.0.0.0', port=port, debug=False)

if __name__ == "__main__":
    start_server()
