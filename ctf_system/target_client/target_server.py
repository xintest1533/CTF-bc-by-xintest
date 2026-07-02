import os
import json
import hashlib
import random
import string
import time
import threading
import platform
from datetime import datetime
from flask import Flask, request, render_template_string, send_file, jsonify, redirect, url_for, session

app = Flask(__name__)
app.secret_key = ''.join(random.choices(string.ascii_letters + string.digits, k=32))

FLAG = ""
ADMIN_USERNAME = "admin"
ADMIN_PASSWORD = "admin123"
BACKUP_FLAG = ""

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
    <html>
    <head><title>CTF靶机</title></head>
    <body>
    <h1>欢迎来到CTF靶机</h1>
    <p>这是一个包含多种漏洞的靶机系统</p>
    <ul>
        <li><a href="/login">管理员登录</a></li>
        <li><a href="/read_file">文件读取</a></li>
        <li><a href="/search">搜索</a></li>
        <li><a href="/template">模板测试</a></li>
    </ul>
    </body>
    </html>
    """)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if not vulnerabilities["weak_password"]:
        return "该漏洞已被修复", 403
    
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        if username == ADMIN_USERNAME and password == ADMIN_PASSWORD:
            session['logged_in'] = True
            return render_template_string(f"""
            <html>
            <head><title>管理员后台</title></head>
            <body>
            <h1>欢迎管理员！</h1>
            <p>备用FLAG: {BACKUP_FLAG}</p>
            </body>
            </html>
            """)
        else:
            return "登录失败", 401
    else:
        return render_template_string("""
        <html>
        <head><title>管理员登录</title></head>
        <body>
        <form method="post">
            <input type="text" name="username" placeholder="用户名"><br>
            <input type="password" name="password" placeholder="密码"><br>
            <input type="submit" value="登录">
        </form>
        </body>
        </html>
        """)

@app.route('/read_file')
def read_file():
    if not vulnerabilities["file_read"]:
        return "该漏洞已被修复", 403
    
    filename = request.args.get('file')
    if filename:
        try:
            return send_file(filename)
        except:
            return "文件读取失败", 404
    return render_template_string("""
    <html>
    <head><title>文件读取</title></head>
    <body>
    <form>
        <input type="text" name="file" placeholder="文件名"><br>
        <input type="submit" value="读取">
    </form>
    </body>
    </html>
    """)

@app.route('/search')
def search():
    if not vulnerabilities["xss"]:
        return "该漏洞已被修复", 403
    
    query = request.args.get('q', '')
    return render_template_string(f"""
    <html>
    <head><title>搜索</title></head>
    <body>
    <form>
        <input type="text" name="q" placeholder="搜索关键词"><br>
        <input type="submit" value="搜索">
    </form>
    <p>搜索结果: {query}</p>
    </body>
    </html>
    """)

@app.route('/template')
def template():
    if not vulnerabilities["ssti"]:
        return "该漏洞已被修复", 403
    
    name = request.args.get('name', 'Guest')
    return render_template_string(f"""
    <html>
    <head><title>模板测试</title></head>
    <body>
    <h1>Hello, {name}!</h1>
    </body>
    </html>
    """)

@app.route('/headache')
def headache():
    if not vulnerabilities["headache"]:
        return "该漏洞已被修复", 403
    
    custom_header = request.headers.get('X-Custom-Flag')
    if custom_header:
        return f"自定义请求头内容: {custom_header}", 200
    
    return "请在请求头中添加 X-Custom-Flag", 400

@app.route('/flag')
def get_flag():
    return FLAG, 200

@app.route('/backup_flag')
def get_backup_flag():
    if session.get('logged_in'):
        return BACKUP_FLAG, 200
    return "未授权访问", 401

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
        "./vulnerabilities/__init__.py",
        "./加固/__init__.py",
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
    
    print(f"靶机服务启动，监听端口: {port}")
    print(f"主FLAG: {FLAG}")
    print(f"备用FLAG: {BACKUP_FLAG}")
    
    app.run(host='0.0.0.0', port=port, debug=False)

if __name__ == "__main__":
    start_server()
