import os
import sys
import json
import hashlib
import random
import string
import time
import threading
import platform
import base64
import re
import pickle
import subprocess
import sqlite3
import urllib.request
from datetime import datetime
from flask import Flask, request, render_template_string, send_file, jsonify, redirect, url_for, session, make_response, send_from_directory
from werkzeug.utils import secure_filename

app = Flask(__name__)
app.secret_key = ''.join(random.choices(string.ascii_letters + string.digits, k=32))
app.config['UPLOAD_FOLDER'] = './uploads'
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024
app.config['DATABASE'] = './data/enterprise.db'

FLAG = ""
ADMIN_USERNAME = "admin"
ADMIN_PASSWORD = "admin123"
BACKUP_FLAG = ""
SECRET_KEY = ''.join(random.choices(string.ascii_letters + string.digits, k=16))

current_stage = "fix"
vulnerabilities_enabled = True
ip_whitelist = []
access_log = []
attack_log = []
request_counts = {}
DOS_THRESHOLD = 100
DOS_TIME_WINDOW = 10

os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
os.makedirs('./data', exist_ok=True)
os.makedirs('./logs', exist_ok=True)
os.makedirs('./backups', exist_ok=True)
os.makedirs('./templates', exist_ok=True)

def generate_flag():
    return ''.join(random.choices(string.ascii_letters + string.digits + "_", k=32))

def init_database():
    conn = sqlite3.connect(app.config['DATABASE'])
    c = conn.cursor()
    
    c.execute('''CREATE TABLE IF NOT EXISTS users
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  username TEXT UNIQUE NOT NULL,
                  password TEXT NOT NULL,
                  email TEXT,
                  role TEXT DEFAULT 'user',
                  created_at TEXT,
                  last_login TEXT)''')
    
    c.execute('''CREATE TABLE IF NOT EXISTS documents
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  title TEXT NOT NULL,
                  content TEXT,
                  author_id INTEGER,
                  created_at TEXT,
                  updated_at TEXT,
                  is_public INTEGER DEFAULT 0)''')
    
    c.execute('''CREATE TABLE IF NOT EXISTS messages
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  sender_id INTEGER,
                  receiver_id INTEGER,
                  title TEXT NOT NULL,
                  content TEXT,
                  created_at TEXT,
                  is_read INTEGER DEFAULT 0)''')
    
    c.execute('''CREATE TABLE IF NOT EXISTS api_keys
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  user_id INTEGER,
                  api_key TEXT UNIQUE NOT NULL,
                  name TEXT,
                  created_at TEXT,
                  expires_at TEXT)''')
    
    c.execute('''CREATE TABLE IF NOT EXISTS system_logs
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  user_id INTEGER,
                  action TEXT,
                  details TEXT,
                  ip_address TEXT,
                  created_at TEXT)''')
    
    admin_hash = hashlib.md5(ADMIN_PASSWORD.encode()).hexdigest()
    try:
        c.execute("INSERT INTO users (username, password, email, role, created_at) VALUES (?, ?, ?, ?, ?)",
                  (ADMIN_USERNAME, admin_hash, 'admin@enterprise.com', 'admin', datetime.now().isoformat()))
    except sqlite3.IntegrityError:
        pass
    
    for i in range(1, 11):
        try:
            username = f"user{i}"
            password = hashlib.md5(f"password{i}".encode()).hexdigest()
            c.execute("INSERT INTO users (username, password, email, role, created_at) VALUES (?, ?, ?, ?, ?)",
                      (username, password, f"user{i}@enterprise.com", 'user', datetime.now().isoformat()))
        except sqlite3.IntegrityError:
            pass
    
    sample_docs = [
        ("公司规章制度", "第一章 总则...", 1, 1),
        ("员工手册", "欢迎加入我们公司...", 1, 1),
        ("项目计划书", "项目背景：...", 2, 0),
        ("财务报表", "2024年第一季度...", 1, 0),
        ("技术文档", "系统架构设计...", 3, 1),
    ]
    for title, content, author, is_public in sample_docs:
        try:
            c.execute("INSERT INTO documents (title, content, author_id, created_at, updated_at, is_public) VALUES (?, ?, ?, ?, ?, ?)",
                      (title, content, author, datetime.now().isoformat(), datetime.now().isoformat(), is_public))
        except:
            pass
    
    conn.commit()
    conn.close()

def get_db():
    conn = sqlite3.connect(app.config['DATABASE'])
    conn.row_factory = sqlite3.Row
    return conn

def log_access(ip, endpoint, method, user_id=None):
    entry = {
        "timestamp": datetime.now().isoformat(),
        "ip": ip,
        "endpoint": endpoint,
        "method": method,
        "user_id": user_id
    }
    access_log.append(entry)
    if len(access_log) > 2000:
        access_log.pop(0)
    
    try:
        conn = get_db()
        conn.execute("INSERT INTO system_logs (user_id, action, details, ip_address, created_at) VALUES (?, ?, ?, ?, ?)",
                    (user_id, endpoint, method, ip, datetime.now().isoformat()))
        conn.commit()
        conn.close()
    except:
        pass

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
        log_attack(ip, "DOS_DETECTION", "POST", f"{len(request_counts[ip])}次请求/{DOS_TIME_WINDOW}秒")
        return True
    return False

@app.before_request
def before_request():
    ip = request.remote_addr
    if check_dos(ip):
        return "检测到异常访问", 403
    if ip_whitelist and ip not in ip_whitelist:
        log_access(ip, request.path, request.method)
        return "访问被拒绝", 403
    user_id = session.get('user_id')
    log_access(ip, request.path, request.method, user_id)

def render_page(title, content, show_nav=True):
    nav = ""
    if show_nav:
        logged_in = session.get('logged_in', False)
        username = session.get('username', '')
        role = session.get('role', 'user')
        nav = f"""
        <nav style="background:#2c3e50;padding:15px;">
            <div style="max-width:1200px;margin:0 auto;display:flex;justify-content:space-between;align-items:center;">
                <a href="/" style="color:white;text-decoration:none;font-size:20px;font-weight:bold;">企业管理系统</a>
                <div>
                    <a href="/" style="color:#ecf0f1;margin-right:20px;text-decoration:none;">首页</a>
                    <a href="/documents" style="color:#ecf0f1;margin-right:20px;text-decoration:none;">文档中心</a>
                    <a href="/messages" style="color:#ecf0f1;margin-right:20px;text-decoration:none;">消息中心</a>
                    <a href="/files" style="color:#ecf0f1;margin-right:20px;text-decoration:none;">文件管理</a>
                    <a href="/api/console" style="color:#ecf0f1;margin-right:20px;text-decoration:none;">API控制台</a>
                    {f'<a href="/admin" style="color:#f39c12;margin-right:20px;text-decoration:none;">管理后台</a>' if role == 'admin' else ''}
                    {f'<span style="color:#ecf0f1;">欢迎, {username}</span><a href="/logout" style="color:#e74c3c;margin-left:20px;text-decoration:none;">退出</a>' 
                     if logged_in else 
                     '<a href="/login" style="color:#ecf0f1;text-decoration:none;">登录</a>'}
                </div>
            </div>
        </nav>
        """
    
    return f"""
    <!DOCTYPE html>
    <html lang="zh-CN">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>{title} - 企业管理系统</title>
        <style>
            body {{ font-family: 'Microsoft YaHei', Arial, sans-serif; margin:0; padding:0; background:#f5f7fa; }}
            .container {{ max-width: 1200px; margin: 20px auto; padding: 0 20px; }}
            .card {{ background: white; border-radius: 8px; padding: 20px; box-shadow: 0 2px 8px rgba(0,0,0,0.1); margin-bottom: 20px; }}
            .btn {{ display: inline-block; padding: 8px 16px; background: #3498db; color: white; 
                   text-decoration: none; border-radius: 4px; border: none; cursor: pointer; font-size: 14px; }}
            .btn:hover {{ background: #2980b9; }}
            .btn-danger {{ background: #e74c3c; }}
            .btn-danger:hover {{ background: #c0392b; }}
            .btn-success {{ background: #27ae60; }}
            .btn-success:hover {{ background: #229954; }}
            table {{ width: 100%; border-collapse: collapse; }}
            th, td {{ padding: 10px; text-align: left; border-bottom: 1px solid #ddd; }}
            th {{ background: #f8f9fa; }}
            input[type=text], input[type=password], input[type=email], textarea, select {{ 
                width: 100%; padding: 8px; border: 1px solid #ddd; border-radius: 4px; box-sizing: border-box; 
            }}
            .form-group {{ margin-bottom: 15px; }}
            .form-group label {{ display: block; margin-bottom: 5px; color: #333; font-weight: 500; }}
            .alert {{ padding: 12px; border-radius: 4px; margin-bottom: 15px; }}
            .alert-error {{ background: #fadbd8; color: #c0392b; border: 1px solid #e6b0aa; }}
            .alert-success {{ background: #d5f5e3; color: #1e8449; border: 1px solid #abebc6; }}
            .alert-info {{ background: #d6eaf8; color: #2471a3; border: 1px solid #aed6f1; }}
            .footer {{ text-align: center; padding: 20px; color: #999; font-size: 12px; }}
        </style>
    </head>
    <body>
        {nav}
        <div class="container">
            {content}
        </div>
        <div class="footer">
            <p>企业内部管理系统 v3.0 © 2024</p>
        </div>
    </body>
    </html>
    """

@app.route('/')
def index():
    conn = get_db()
    public_docs = conn.execute("SELECT * FROM documents WHERE is_public = 1 ORDER BY created_at DESC LIMIT 5").fetchall()
    conn.close()
    
    docs_html = ""
    for doc in public_docs:
        docs_html += f"""
        <div style="padding:10px 0;border-bottom:1px solid #eee;">
            <a href="/documents/{doc['id']}" style="color:#3498db;text-decoration:none;font-weight:bold;">{doc['title']}</a>
            <span style="color:#999;font-size:12px;margin-left:10px;">{doc['created_at']}</span>
        </div>
        """
    
    content = f"""
    <div class="card">
        <h2>欢迎使用企业内部管理系统</h2>
        <p>本系统提供文档管理、消息通信、文件存储等功能。</p>
    </div>
    <div class="card">
        <h3>最新公告</h3>
        {docs_html if docs_html else '<p>暂无公开文档</p>'}
    </div>
    <div class="card">
        <h3>系统统计</h3>
        <div style="display:grid;grid-template-columns:repeat(4,1fr);gap:20px;text-align:center;">
            <div style="padding:20px;background:#f8f9fa;border-radius:8px;">
                <div style="font-size:24px;font-weight:bold;color:#3498db;">128</div>
                <div style="color:#666;font-size:14px;">注册用户</div>
            </div>
            <div style="padding:20px;background:#f8f9fa;border-radius:8px;">
                <div style="font-size:24px;font-weight:bold;color:#27ae60;">56</div>
                <div style="color:#666;font-size:14px;">文档数量</div>
            </div>
            <div style="padding:20px;background:#f8f9fa;border-radius:8px;">
                <div style="font-size:24px;font-weight:bold;color:#f39c12;">1024</div>
                <div style="color:#666;font-size:14px;">消息总数</div>
            </div>
            <div style="padding:20px;background:#f8f9fa;border-radius:8px;">
                <div style="font-size:24px;font-weight:bold;color:#e74c3c;">99.9%</div>
                <div style="color:#666;font-size:14px;">系统可用率</div>
            </div>
        </div>
    </div>
    """
    return render_page("首页", content)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if session.get('logged_in'):
        return redirect('/')
    
    error = ""
    if request.method == 'POST':
        username = request.form.get('username', '')
        password = request.form.get('password', '')
        remember = request.form.get('remember', '')
        
        if not username or not password:
            error = "用户名和密码不能为空"
        else:
            conn = get_db()
            password_hash = hashlib.md5(password.encode()).hexdigest()
            user = conn.execute("SELECT * FROM users WHERE username = ? AND password = ?",
                              (username, password_hash)).fetchone()
            
            if user:
                session['logged_in'] = True
                session['user_id'] = user['id']
                session['username'] = user['username']
                session['role'] = user['role']
                
                conn.execute("UPDATE users SET last_login = ? WHERE id = ?",
                           (datetime.now().isoformat(), user['id']))
                conn.commit()
                conn.close()
                
                resp = make_response(redirect('/'))
                if remember:
                    token = base64.b64encode(f"{username}:{password_hash}".encode()).decode()
                    resp.set_cookie('remember_token', token, max_age=30*24*3600)
                return resp
            else:
                error = "用户名或密码错误"
                conn.close()
    
    content = f"""
    <div style="max-width:400px;margin:50px auto;">
        <div class="card">
            <h2 style="text-align:center;margin-bottom:20px;">用户登录</h2>
            {f'<div class="alert alert-error">{error}</div>' if error else ''}
            <form method="post">
                <div class="form-group">
                    <label>用户名</label>
                    <input type="text" name="username" required>
                </div>
                <div class="form-group">
                    <label>密码</label>
                    <input type="password" name="password" required>
                </div>
                <div class="form-group">
                    <label><input type="checkbox" name="remember" value="1"> 记住我</label>
                </div>
                <button type="submit" class="btn" style="width:100%;">登录</button>
            </form>
            <p style="text-align:center;margin-top:15px;font-size:14px;">
                <a href="/forgot_password" style="color:#3498db;text-decoration:none;">忘记密码？</a>
                &nbsp;|&nbsp;
                <a href="/register" style="color:#3498db;text-decoration:none;">注册账号</a>
            </p>
        </div>
    </div>
    """
    return render_page("登录", content, show_nav=False)

@app.route('/register', methods=['GET', 'POST'])
def register():
    if session.get('logged_in'):
        return redirect('/')
    
    error = ""
    success = ""
    if request.method == 'POST':
        username = request.form.get('username', '')
        password = request.form.get('password', '')
        confirm_password = request.form.get('confirm_password', '')
        email = request.form.get('email', '')
        
        if not username or not password:
            error = "用户名和密码不能为空"
        elif password != confirm_password:
            error = "两次输入的密码不一致"
        elif len(password) < 6:
            error = "密码长度至少6位"
        else:
            conn = get_db()
            try:
                password_hash = hashlib.md5(password.encode()).hexdigest()
                conn.execute("INSERT INTO users (username, password, email, role, created_at) VALUES (?, ?, ?, ?, ?)",
                          (username, password_hash, email, 'user', datetime.now().isoformat()))
                conn.commit()
                success = "注册成功，请登录"
            except sqlite3.IntegrityError:
                error = "用户名已存在"
            conn.close()
    
    content = f"""
    <div style="max-width:400px;margin:50px auto;">
        <div class="card">
            <h2 style="text-align:center;margin-bottom:20px;">用户注册</h2>
            {f'<div class="alert alert-error">{error}</div>' if error else ''}
            {f'<div class="alert alert-success">{success}</div>' if success else ''}
            <form method="post">
                <div class="form-group">
                    <label>用户名</label>
                    <input type="text" name="username" required>
                </div>
                <div class="form-group">
                    <label>邮箱</label>
                    <input type="email" name="email">
                </div>
                <div class="form-group">
                    <label>密码</label>
                    <input type="password" name="password" required>
                </div>
                <div class="form-group">
                    <label>确认密码</label>
                    <input type="password" name="confirm_password" required>
                </div>
                <button type="submit" class="btn btn-success" style="width:100%;">注册</button>
            </form>
            <p style="text-align:center;margin-top:15px;font-size:14px;">
                已有账号？<a href="/login" style="color:#3498db;text-decoration:none;">立即登录</a>
            </p>
        </div>
    </div>
    """
    return render_page("注册", content, show_nav=False)

@app.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    error = ""
    success = ""
    
    if request.method == 'POST':
        username = request.form.get('username', '')
        email = request.form.get('email', '')
        new_password = request.form.get('new_password', '')
        
        if not username or not email:
            error = "请填写用户名和邮箱"
        elif not new_password:
            error = "请输入新密码"
        else:
            conn = get_db()
            user = conn.execute("SELECT * FROM users WHERE username = ? AND email = ?",
                              (username, email)).fetchone()
            if user:
                password_hash = hashlib.md5(new_password.encode()).hexdigest()
                conn.execute("UPDATE users SET password = ? WHERE id = ?",
                           (password_hash, user['id']))
                conn.commit()
                success = "密码重置成功"
            else:
                error = "用户名或邮箱不匹配"
            conn.close()
    
    content = f"""
    <div style="max-width:400px;margin:50px auto;">
        <div class="card">
            <h2 style="text-align:center;margin-bottom:20px;">找回密码</h2>
            {f'<div class="alert alert-error">{error}</div>' if error else ''}
            {f'<div class="alert alert-success">{success}</div>' if success else ''}
            <form method="post">
                <div class="form-group">
                    <label>用户名</label>
                    <input type="text" name="username" required>
                </div>
                <div class="form-group">
                    <label>注册邮箱</label>
                    <input type="email" name="email" required>
                </div>
                <div class="form-group">
                    <label>新密码</label>
                    <input type="password" name="new_password" required>
                </div>
                <button type="submit" class="btn" style="width:100%;">重置密码</button>
            </form>
            <p style="text-align:center;margin-top:15px;font-size:14px;">
                <a href="/login" style="color:#3498db;text-decoration:none;">返回登录</a>
            </p>
        </div>
    </div>
    """
    return render_page("找回密码", content, show_nav=False)

@app.route('/logout')
def logout():
    session.clear()
    resp = make_response(redirect('/login'))
    resp.set_cookie('remember_token', '', expires=0)
    return resp

@app.route('/profile')
def profile():
    if not session.get('logged_in'):
        return redirect('/login')
    
    conn = get_db()
    user = conn.execute("SELECT * FROM users WHERE id = ?", (session['user_id'],)).fetchone()
    conn.close()
    
    content = f"""
    <div class="card">
        <h2>个人中心</h2>
        <div style="display:grid;grid-template-columns:1fr 2fr;gap:20px;">
            <div style="text-align:center;">
                <div style="width:100px;height:100px;background:#3498db;border-radius:50%;margin:0 auto;
                           display:flex;align-items:center;justify-content:center;color:white;font-size:36px;font-weight:bold;">
                    {user['username'][0].upper()}
                </div>
                <h3>{user['username']}</h3>
                <p style="color:#666;">{user['role']}</p>
            </div>
            <div>
                <table>
                    <tr><th>用户ID</th><td>{user['id']}</td></tr>
                    <tr><th>用户名</th><td>{user['username']}</td></tr>
                    <tr><th>邮箱</th><td>{user['email'] or '未设置'}</td></tr>
                    <tr><th>角色</th><td>{user['role']}</td></tr>
                    <tr><th>注册时间</th><td>{user['created_at']}</td></tr>
                    <tr><th>最后登录</th><td>{user['last_login'] or '从未登录'}</td></tr>
                </table>
            </div>
        </div>
    </div>
    """
    return render_page("个人中心", content)

@app.route('/documents')
def documents():
    search = request.args.get('search', '')
    conn = get_db()
    
    if search and vulnerabilities_enabled:
        query = f"SELECT * FROM documents WHERE is_public = 1 AND title LIKE '%{search}%' OR content LIKE '%{search}%'"
        docs = conn.execute(query).fetchall()
    else:
        if session.get('logged_in'):
            docs = conn.execute("SELECT * FROM documents WHERE is_public = 1 OR author_id = ? ORDER BY created_at DESC",
                              (session['user_id'],)).fetchall()
        else:
            docs = conn.execute("SELECT * FROM documents WHERE is_public = 1 ORDER BY created_at DESC").fetchall()
    
    conn.close()
    
    docs_html = ""
    for doc in docs:
        docs_html += f"""
        <tr>
            <td>{doc['id']}</td>
            <td><a href="/documents/{doc['id']}" style="color:#3498db;text-decoration:none;">{doc['title']}</a></td>
            <td>{doc['author_id']}</td>
            <td>{doc['created_at']}</td>
            <td>{'公开' if doc['is_public'] else '私有'}</td>
        </tr>
        """
    
    content = f"""
    <div class="card">
        <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:20px;">
            <h2>文档中心</h2>
            {f'<a href="/documents/create" class="btn">创建文档</a>' if session.get('logged_in') else ''}
        </div>
        <form method="get" style="margin-bottom:20px;">
            <div style="display:flex;gap:10px;">
                <input type="text" name="search" value="{search}" placeholder="搜索文档标题或内容...">
                <button type="submit" class="btn">搜索</button>
            </div>
        </form>
        <table>
            <thead>
                <tr>
                    <th>ID</th>
                    <th>标题</th>
                    <th>作者ID</th>
                    <th>创建时间</th>
                    <th>状态</th>
                </tr>
            </thead>
            <tbody>
                {docs_html if docs_html else '<tr><td colspan="5" style="text-align:center;color:#999;">暂无文档</td></tr>'}
            </tbody>
        </table>
    </div>
    """
    return render_page("文档中心", content)

@app.route('/documents/create', methods=['GET', 'POST'])
def create_document():
    if not session.get('logged_in'):
        return redirect('/login')
    
    if request.method == 'POST':
        title = request.form.get('title', '')
        content = request.form.get('content', '')
        is_public = 1 if request.form.get('is_public') else 0
        
        if title:
            conn = get_db()
            conn.execute("INSERT INTO documents (title, content, author_id, created_at, updated_at, is_public) VALUES (?, ?, ?, ?, ?, ?)",
                      (title, content, session['user_id'], datetime.now().isoformat(), 
                       datetime.now().isoformat(), is_public))
            conn.commit()
            doc_id = conn.execute("SELECT last_insert_rowid()").fetchone()[0]
            conn.close()
            return redirect(f'/documents/{doc_id}')
    
    content = f"""
    <div class="card">
        <h2>创建文档</h2>
        <form method="post">
            <div class="form-group">
                <label>标题</label>
                <input type="text" name="title" required>
            </div>
            <div class="form-group">
                <label>内容</label>
                <textarea name="content" rows="15"></textarea>
            </div>
            <div class="form-group">
                <label><input type="checkbox" name="is_public" value="1"> 设为公开文档</label>
            </div>
            <button type="submit" class="btn btn-success">保存</button>
            <a href="/documents" class="btn">返回</a>
        </form>
    </div>
    """
    return render_page("创建文档", content)

@app.route('/documents/<int:doc_id>')
def view_document(doc_id):
    conn = get_db()
    doc = conn.execute("SELECT * FROM documents WHERE id = ?", (doc_id,)).fetchone()
    
    if not doc:
        conn.close()
        return render_page("文档不存在", '<div class="card"><h2>文档不存在</h2></div>')
    
    if not doc['is_public'] and doc['author_id'] != session.get('user_id'):
        if session.get('role') != 'admin':
            conn.close()
            return render_page("无权限", '<div class="card"><h2>无权限访问此文档</h2></div>')
    
    author = conn.execute("SELECT username FROM users WHERE id = ?", (doc['author_id'],)).fetchone()
    conn.close()
    
    content = f"""
    <div class="card">
        <h1>{doc['title']}</h1>
        <p style="color:#666;font-size:14px;">
            作者: {author['username'] if author else '未知'} | 
            创建时间: {doc['created_at']} | 
            {'公开' if doc['is_public'] else '私有'}
        </p>
        <hr>
        <div style="line-height:1.8;">
            {doc['content']}
        </div>
        <div style="margin-top:20px;">
            <a href="/documents/{doc_id}/edit" class="btn">编辑</a>
            <a href="/documents" class="btn">返回列表</a>
        </div>
    </div>
    """
    return render_page(doc['title'], content)

@app.route('/documents/<int:doc_id>/edit', methods=['GET', 'POST'])
def edit_document(doc_id):
    if not session.get('logged_in'):
        return redirect('/login')
    
    conn = get_db()
    doc = conn.execute("SELECT * FROM documents WHERE id = ?", (doc_id,)).fetchone()
    
    if not doc:
        conn.close()
        return "文档不存在", 404
    
    if doc['author_id'] != session['user_id'] and session.get('role') != 'admin':
        conn.close()
        return "无权限", 403
    
    if request.method == 'POST':
        title = request.form.get('title', '')
        content = request.form.get('content', '')
        is_public = 1 if request.form.get('is_public') else 0
        
        if title:
            conn.execute("UPDATE documents SET title = ?, content = ?, updated_at = ?, is_public = ? WHERE id = ?",
                      (title, content, datetime.now().isoformat(), is_public, doc_id))
            conn.commit()
            conn.close()
            return redirect(f'/documents/{doc_id}')
    
    content = f"""
    <div class="card">
        <h2>编辑文档</h2>
        <form method="post">
            <div class="form-group">
                <label>标题</label>
                <input type="text" name="title" value="{doc['title']}" required>
            </div>
            <div class="form-group">
                <label>内容</label>
                <textarea name="content" rows="15">{doc['content']}</textarea>
            </div>
            <div class="form-group">
                <label><input type="checkbox" name="is_public" value="1" {'checked' if doc['is_public'] else ''}> 设为公开文档</label>
            </div>
            <button type="submit" class="btn btn-success">保存</button>
            <a href="/documents/{doc_id}" class="btn">取消</a>
        </form>
    </div>
    """
    conn.close()
    return render_page("编辑文档", content)

@app.route('/messages')
def messages():
    if not session.get('logged_in'):
        return redirect('/login')
    
    conn = get_db()
    received = conn.execute("""
        SELECT m.*, u.username as sender_name 
        FROM messages m 
        JOIN users u ON m.sender_id = u.id 
        WHERE m.receiver_id = ? 
        ORDER BY m.created_at DESC
    """, (session['user_id'],)).fetchall()
    
    sent = conn.execute("""
        SELECT m.*, u.username as receiver_name 
        FROM messages m 
        JOIN users u ON m.receiver_id = u.id 
        WHERE m.sender_id = ? 
        ORDER BY m.created_at DESC
    """, (session['user_id'],)).fetchall()
    conn.close()
    
    received_html = ""
    for msg in received:
        received_html += f"""
        <tr>
            <td>{msg['sender_name']}</td>
            <td><a href="/messages/{msg['id']}" style="color:#3498db;text-decoration:none;">{'<b>' if not msg['is_read'] else ''}{msg['title']}{'</b>' if not msg['is_read'] else ''}</a></td>
            <td>{msg['created_at']}</td>
        </tr>
        """
    
    sent_html = ""
    for msg in sent:
        sent_html += f"""
        <tr>
            <td>{msg['receiver_name']}</td>
            <td><a href="/messages/{msg['id']}" style="color:#3498db;text-decoration:none;">{msg['title']}</a></td>
            <td>{msg['created_at']}</td>
        </tr>
        """
    
    content = f"""
    <div class="card">
        <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:20px;">
            <h2>消息中心</h2>
            <a href="/messages/send" class="btn">发送消息</a>
        </div>
        <h3>收到的消息</h3>
        <table>
            <thead>
                <tr><th>发件人</th><th>标题</th><th>时间</th></tr>
            </thead>
            <tbody>
                {received_html if received_html else '<tr><td colspan="3" style="text-align:center;color:#999;">暂无消息</td></tr>'}
            </tbody>
        </table>
        <h3 style="margin-top:30px;">已发送</h3>
        <table>
            <thead>
                <tr><th>收件人</th><th>标题</th><th>时间</th></tr>
            </thead>
            <tbody>
                {sent_html if sent_html else '<tr><td colspan="3" style="text-align:center;color:#999;">暂无消息</td></tr>'}
            </tbody>
        </table>
    </div>
    """
    return render_page("消息中心", content)

@app.route('/messages/send', methods=['GET', 'POST'])
def send_message():
    if not session.get('logged_in'):
        return redirect('/login')
    
    conn = get_db()
    users = conn.execute("SELECT id, username FROM users WHERE id != ?", (session['user_id'],)).fetchall()
    
    if request.method == 'POST':
        receiver_id = request.form.get('receiver_id')
        title = request.form.get('title', '')
        content = request.form.get('content', '')
        
        if receiver_id and title:
            conn.execute("INSERT INTO messages (sender_id, receiver_id, title, content, created_at) VALUES (?, ?, ?, ?, ?)",
                      (session['user_id'], receiver_id, title, content, datetime.now().isoformat()))
            conn.commit()
            conn.close()
            return redirect('/messages')
    
    options = ""
    for u in users:
        options += f'<option value="{u["id"]}">{u["username"]}</option>'
    
    content = f"""
    <div class="card">
        <h2>发送消息</h2>
        <form method="post">
            <div class="form-group">
                <label>收件人</label>
                <select name="receiver_id" required>
                    <option value="">请选择</option>
                    {options}
                </select>
            </div>
            <div class="form-group">
                <label>标题</label>
                <input type="text" name="title" required>
            </div>
            <div class="form-group">
                <label>内容</label>
                <textarea name="content" rows="10"></textarea>
            </div>
            <button type="submit" class="btn btn-success">发送</button>
            <a href="/messages" class="btn">返回</a>
        </form>
    </div>
    """
    conn.close()
    return render_page("发送消息", content)

@app.route('/messages/<int:msg_id>')
def view_message(msg_id):
    if not session.get('logged_in'):
        return redirect('/login')
    
    conn = get_db()
    msg = conn.execute("""
        SELECT m.*, su.username as sender_name, ru.username as receiver_name
        FROM messages m 
        JOIN users su ON m.sender_id = su.id 
        JOIN users ru ON m.receiver_id = ru.id 
        WHERE m.id = ?
    """, (msg_id,)).fetchone()
    
    if not msg:
        conn.close()
        return "消息不存在", 404
    
    if msg['sender_id'] != session['user_id'] and msg['receiver_id'] != session['user_id']:
        if session.get('role') != 'admin':
            conn.close()
            return "无权限", 403
    
    if msg['receiver_id'] == session['user_id'] and not msg['is_read']:
        conn.execute("UPDATE messages SET is_read = 1 WHERE id = ?", (msg_id,))
        conn.commit()
    
    content = f"""
    <div class="card">
        <h2>{msg['title']}</h2>
        <p style="color:#666;font-size:14px;">
            发件人: {msg['sender_name']} | 收件人: {msg['receiver_name']} | 时间: {msg['created_at']}
        </p>
        <hr>
        <div style="line-height:1.8;">
            {msg['content']}
        </div>
        <div style="margin-top:20px;">
            <a href="/messages" class="btn">返回列表</a>
        </div>
    </div>
    """
    conn.close()
    return render_page(msg['title'], content)

@app.route('/files')
def file_manager():
    if not session.get('logged_in'):
        return redirect('/login')
    
    user_folder = os.path.join(app.config['UPLOAD_FOLDER'], str(session['user_id']))
    os.makedirs(user_folder, exist_ok=True)
    
    files = []
    for filename in os.listdir(user_folder):
        filepath = os.path.join(user_folder, filename)
        if os.path.isfile(filepath):
            stat = os.stat(filepath)
            files.append({
                'name': filename,
                'size': stat.st_size,
                'time': datetime.fromtimestamp(stat.st_mtime).isoformat()
            })
    
    files_html = ""
    for f in files:
        size_kb = f"{f['size']/1024:.2f} KB"
        files_html += f"""
        <tr>
            <td>{f['name']}</td>
            <td>{size_kb}</td>
            <td>{f['time']}</td>
            <td>
                <a href="/files/download/{f['name']}" class="btn" style="padding:4px 8px;font-size:12px;">下载</a>
                <a href="/files/delete/{f['name']}" class="btn btn-danger" style="padding:4px 8px;font-size:12px;">删除</a>
            </td>
        </tr>
        """
    
    content = f"""
    <div class="card">
        <h2>文件管理</h2>
        <div style="margin-bottom:20px;padding:20px;background:#f8f9fa;border-radius:8px;">
            <h3>上传文件</h3>
            <form action="/files/upload" method="post" enctype="multipart/form-data">
                <div class="form-group">
                    <input type="file" name="file">
                </div>
                <button type="submit" class="btn btn-success">上传</button>
            </form>
        </div>
        <h3>我的文件</h3>
        <table>
            <thead>
                <tr><th>文件名</th><th>大小</th><th>上传时间</th><th>操作</th></tr>
            </thead>
            <tbody>
                {files_html if files_html else '<tr><td colspan="4" style="text-align:center;color:#999;">暂无文件</td></tr>'}
            </tbody>
        </table>
    </div>
    """
    return render_page("文件管理", content)

@app.route('/files/upload', methods=['POST'])
def upload_file():
    if not session.get('logged_in'):
        return redirect('/login')
    
    if 'file' not in request.files:
        return redirect('/files')
    
    file = request.files['file']
    if file.filename == '':
        return redirect('/files')
    
    user_folder = os.path.join(app.config['UPLOAD_FOLDER'], str(session['user_id']))
    os.makedirs(user_folder, exist_ok=True)
    
    if file:
        filename = file.filename
        filepath = os.path.join(user_folder, filename)
        file.save(filepath)
    
    return redirect('/files')

@app.route('/files/download/<filename>')
def download_file(filename):
    if not session.get('logged_in'):
        return redirect('/login')
    
    user_folder = os.path.join(app.config['UPLOAD_FOLDER'], str(session['user_id']))
    filepath = os.path.join(user_folder, filename)
    
    if os.path.exists(filepath):
        return send_file(filepath, as_attachment=True)
    else:
        return "文件不存在", 404

@app.route('/files/delete/<filename>')
def delete_file(filename):
    if not session.get('logged_in'):
        return redirect('/login')
    
    user_folder = os.path.join(app.config['UPLOAD_FOLDER'], str(session['user_id']))
    filepath = os.path.join(user_folder, filename)
    
    if os.path.exists(filepath):
        os.remove(filepath)
    
    return redirect('/files')

@app.route('/api/console')
def api_console():
    if not session.get('logged_in'):
        return redirect('/login')
    
    conn = get_db()
    api_keys = conn.execute("SELECT * FROM api_keys WHERE user_id = ? ORDER BY created_at DESC",
                          (session['user_id'],)).fetchall()
    conn.close()
    
    keys_html = ""
    for key in api_keys:
        keys_html += f"""
        <tr>
            <td>{key['name']}</td>
            <td><code style="background:#f0f0f0;padding:2px 6px;border-radius:3px;">{key['api_key']}</code></td>
            <td>{key['created_at']}</td>
            <td><a href="/api/keys/{key['id']}/delete" class="btn btn-danger" style="padding:4px 8px;font-size:12px;">删除</a></td>
        </tr>
        """
    
    content = f"""
    <div class="card">
        <h2>API控制台</h2>
        <p style="color:#666;">使用API Key调用系统接口，实现自动化操作</p>
    </div>
    <div class="card">
        <h3>我的API Key</h3>
        <form action="/api/keys/create" method="post" style="margin-bottom:20px;">
            <div style="display:flex;gap:10px;">
                <input type="text" name="name" placeholder="Key名称" required style="flex:1;">
                <button type="submit" class="btn btn-success">创建Key</button>
            </div>
        </form>
        <table>
            <thead>
                <tr><th>名称</th><th>API Key</th><th>创建时间</th><th>操作</th></tr>
            </thead>
            <tbody>
                {keys_html if keys_html else '<tr><td colspan="4" style="text-align:center;color:#999;">暂无API Key</td></tr>'}
            </tbody>
        </table>
    </div>
    <div class="card">
        <h3>接口测试</h3>
        <div class="form-group">
            <label>目标URL</label>
            <input type="text" id="api_url" value="http://127.0.0.1:5000/api/status">
        </div>
        <button onclick="testApi()" class="btn">测试请求</button>
        <div id="api_result" style="margin-top:15px;padding:10px;background:#f8f9fa;border-radius:4px;display:none;"></div>
        <script>
            function testApi() {{
                var url = document.getElementById('api_url').value;
                var resultDiv = document.getElementById('api_result');
                resultDiv.style.display = 'block';
                resultDiv.innerHTML = '请求中...';
                fetch('/api/proxy?url=' + encodeURIComponent(url))
                    .then(r => r.text())
                    .then(data => {{
                        resultDiv.innerText = data;
                    }})
                    .catch(err => {{
                        resultDiv.innerText = '请求失败: ' + err;
                    }});
            }}
        </script>
    </div>
    """
    return render_page("API控制台", content)

@app.route('/api/keys/create', methods=['POST'])
def create_api_key():
    if not session.get('logged_in'):
        return redirect('/login')
    
    name = request.form.get('name', '')
    if name:
        api_key = ''.join(random.choices(string.ascii_letters + string.digits, k=32))
        conn = get_db()
        conn.execute("INSERT INTO api_keys (user_id, api_key, name, created_at) VALUES (?, ?, ?, ?)",
                  (session['user_id'], api_key, name, datetime.now().isoformat()))
        conn.commit()
        conn.close()
    
    return redirect('/api/console')

@app.route('/api/keys/<int:key_id>/delete')
def delete_api_key(key_id):
    if not session.get('logged_in'):
        return redirect('/login')
    
    conn = get_db()
    conn.execute("DELETE FROM api_keys WHERE id = ? AND user_id = ?", (key_id, session['user_id']))
    conn.commit()
    conn.close()
    
    return redirect('/api/console')

@app.route('/api/proxy')
def api_proxy():
    if not session.get('logged_in'):
        return jsonify({"error": "未登录"}), 401
    
    url = request.args.get('url', '')
    if not url:
        return jsonify({"error": "缺少url参数"}), 400
    
    try:
        response = urllib.request.urlopen(url, timeout=5)
        return response.read()
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/status')
def api_status():
    return jsonify({
        "status": "ok",
        "version": "3.0.0",
        "timestamp": datetime.now().isoformat()
    })

@app.route('/admin')
def admin_panel():
    if not session.get('logged_in') or session.get('role') != 'admin':
        return render_page("无权限", '<div class="card"><h2>无权限访问管理后台</h2></div>')
    
    conn = get_db()
    user_count = conn.execute("SELECT COUNT(*) as count FROM users").fetchone()['count']
    doc_count = conn.execute("SELECT COUNT(*) as count FROM documents").fetchone()['count']
    msg_count = conn.execute("SELECT COUNT(*) as count FROM messages").fetchone()['count']
    log_count = conn.execute("SELECT COUNT(*) as count FROM system_logs").fetchone()['count']
    
    recent_users = conn.execute("SELECT * FROM users ORDER BY created_at DESC LIMIT 5").fetchall()
    recent_logs = conn.execute("SELECT * FROM system_logs ORDER BY created_at DESC LIMIT 10").fetchall()
    conn.close()
    
    users_html = ""
    for u in recent_users:
        users_html += f"""
        <tr>
            <td>{u['id']}</td>
            <td>{u['username']}</td>
            <td>{u['role']}</td>
            <td>{u['created_at']}</td>
        </tr>
        """
    
    logs_html = ""
    for log in recent_logs:
        logs_html += f"""
        <tr>
            <td>{log['id']}</td>
            <td>{log['user_id'] or '未知'}</td>
            <td>{log['action']}</td>
            <td>{log['ip_address']}</td>
            <td>{log['created_at']}</td>
        </tr>
        """
    
    content = f"""
    <div class="card">
        <h2>管理后台</h2>
        <div style="display:grid;grid-template-columns:repeat(4,1fr);gap:20px;text-align:center;margin-bottom:20px;">
            <div style="padding:20px;background:#e8f5e9;border-radius:8px;">
                <div style="font-size:28px;font-weight:bold;color:#27ae60;">{user_count}</div>
                <div style="color:#666;">用户总数</div>
            </div>
            <div style="padding:20px;background:#e3f2fd;border-radius:8px;">
                <div style="font-size:28px;font-weight:bold;color:#2196f3;">{doc_count}</div>
                <div style="color:#666;">文档总数</div>
            </div>
            <div style="padding:20px;background:#fff3e0;border-radius:8px;">
                <div style="font-size:28px;font-weight:bold;color:#ff9800;">{msg_count}</div>
                <div style="color:#666;">消息总数</div>
            </div>
            <div style="padding:20px;background:#fce4ec;border-radius:8px;">
                <div style="font-size:28px;font-weight:bold;color:#e91e63;">{log_count}</div>
                <div style="color:#666;">系统日志</div>
            </div>
        </div>
    </div>
    <div class="card">
        <h3>系统工具</h3>
        <div style="display:flex;gap:10px;flex-wrap:wrap;">
            <a href="/admin/backup" class="btn">数据备份</a>
            <a href="/admin/restore" class="btn">数据恢复</a>
            <a href="/admin/users" class="btn">用户管理</a>
            <a href="/admin/logs" class="btn">系统日志</a>
            <a href="/admin/import" class="btn btn-success">数据导入</a>
        </div>
    </div>
    <div class="card">
        <h3>最新用户</h3>
        <table>
            <thead>
                <tr><th>ID</th><th>用户名</th><th>角色</th><th>注册时间</th></tr>
            </thead>
            <tbody>
                {users_html}
            </tbody>
        </table>
    </div>
    <div class="card">
        <h3>系统日志</h3>
        <table>
            <thead>
                <tr><th>ID</th><th>用户ID</th><th>操作</th><th>IP</th><th>时间</th></tr>
            </thead>
            <tbody>
                {logs_html}
            </tbody>
        </table>
    </div>
    """
    return render_page("管理后台", content)

@app.route('/admin/backup')
def admin_backup():
    if not session.get('logged_in') or session.get('role') != 'admin':
        return "无权限", 403
    
    backup_name = f"backup_{datetime.now().strftime('%Y%m%d_%H%M%S')}.db"
    backup_path = os.path.join('./backups', backup_name)
    
    import shutil
    shutil.copy2(app.config['DATABASE'], backup_path)
    
    return send_file(backup_path, as_attachment=True)

@app.route('/admin/restore', methods=['GET', 'POST'])
def admin_restore():
    if not session.get('logged_in') or session.get('role') != 'admin':
        return "无权限", 403
    
    message = ""
    if request.method == 'POST':
        if 'file' in request.files:
            file = request.files['file']
            if file.filename:
                file.save(app.config['DATABASE'])
                message = "数据恢复成功"
    
    content = f"""
    <div class="card">
        <h2>数据恢复</h2>
        {f'<div class="alert alert-success">{message}</div>' if message else ''}
        <form method="post" enctype="multipart/form-data">
            <div class="form-group">
                <label>选择备份文件</label>
                <input type="file" name="file" accept=".db">
            </div>
            <button type="submit" class="btn btn-danger">恢复数据</button>
            <a href="/admin" class="btn">返回</a>
        </form>
    </div>
    """
    return render_page("数据恢复", content)

@app.route('/admin/users')
def admin_users():
    if not session.get('logged_in') or session.get('role') != 'admin':
        return "无权限", 403
    
    conn = get_db()
    users = conn.execute("SELECT * FROM users ORDER BY created_at DESC").fetchall()
    conn.close()
    
    users_html = ""
    for u in users:
        users_html += f"""
        <tr>
            <td>{u['id']}</td>
            <td>{u['username']}</td>
            <td>{u['email'] or '-'}</td>
            <td>{u['role']}</td>
            <td>{u['created_at']}</td>
            <td>
                <a href="/admin/users/{u['id']}/edit" class="btn" style="padding:4px 8px;font-size:12px;">编辑</a>
                <a href="/admin/users/{u['id']}/delete" class="btn btn-danger" style="padding:4px 8px;font-size:12px;">删除</a>
            </td>
        </tr>
        """
    
    content = f"""
    <div class="card">
        <h2>用户管理</h2>
        <table>
            <thead>
                <tr><th>ID</th><th>用户名</th><th>邮箱</th><th>角色</th><th>注册时间</th><th>操作</th></tr>
            </thead>
            <tbody>
                {users_html}
            </tbody>
        </table>
        <div style="margin-top:20px;">
            <a href="/admin" class="btn">返回</a>
        </div>
    </div>
    """
    return render_page("用户管理", content)

@app.route('/admin/logs')
def admin_logs():
    if not session.get('logged_in') or session.get('role') != 'admin':
        return "无权限", 403
    
    conn = get_db()
    logs = conn.execute("SELECT * FROM system_logs ORDER BY created_at DESC LIMIT 100").fetchall()
    conn.close()
    
    logs_html = ""
    for log in logs:
        logs_html += f"""
        <tr>
            <td>{log['id']}</td>
            <td>{log['user_id'] or '-'}</td>
            <td>{log['action']}</td>
            <td>{log['details'] or '-'}</td>
            <td>{log['ip_address']}</td>
            <td>{log['created_at']}</td>
        </tr>
        """
    
    content = f"""
    <div class="card">
        <h2>系统日志</h2>
        <table>
            <thead>
                <tr><th>ID</th><th>用户ID</th><th>操作</th><th>详情</th><th>IP</th><th>时间</th></tr>
            </thead>
            <tbody>
                {logs_html}
            </tbody>
        </table>
        <div style="margin-top:20px;">
            <a href="/admin" class="btn">返回</a>
        </div>
    </div>
    """
    return render_page("系统日志", content)

@app.route('/admin/import', methods=['GET', 'POST'])
def admin_import():
    if not session.get('logged_in') or session.get('role') != 'admin':
        return "无权限", 403
    
    message = ""
    if request.method == 'POST':
        if 'file' in request.files:
            file = request.files['file']
            if file.filename:
                try:
                    data = pickle.loads(file.read())
                    message = f"导入成功，共 {len(data) if isinstance(data, list) else '?'} 条数据"
                except Exception as e:
                    message = f"导入失败: {str(e)}"
    
    content = f"""
    <div class="card">
        <h2>数据导入</h2>
        {f'<div class="alert alert-info">{message}</div>' if message else ''}
        <form method="post" enctype="multipart/form-data">
            <div class="form-group">
                <label>选择数据文件 (.pkl)</label>
                <input type="file" name="file">
            </div>
            <p style="color:#666;font-size:12px;">支持pickle序列化格式的数据文件</p>
            <button type="submit" class="btn btn-success">导入</button>
            <a href="/admin" class="btn">返回</a>
        </form>
    </div>
    """
    return render_page("数据导入", content)

@app.route('/admin/system_info')
def admin_system_info():
    if not session.get('logged_in') or session.get('role') != 'admin':
        return "无权限", 403
    
    cmd = request.args.get('cmd', 'uname -a')
    output = ""
    if cmd:
        try:
            output = subprocess.check_output(cmd, shell=True, stderr=subprocess.STDOUT, timeout=5).decode('utf-8', errors='ignore')
        except subprocess.TimeoutExpired:
            output = "命令执行超时"
        except Exception as e:
            output = f"执行失败: {str(e)}"
    
    content = f"""
    <div class="card">
        <h2>系统信息</h2>
        <form method="get">
            <div class="form-group">
                <label>执行命令</label>
                <input type="text" name="cmd" value="{cmd}">
            </div>
            <button type="submit" class="btn">执行</button>
        </form>
        <div style="margin-top:15px;padding:15px;background:#1a1a1a;color:#0f0;border-radius:4px;
                   font-family:monospace;white-space:pre-wrap;max-height:400px;overflow:auto;">
            {output or '输出将显示在这里...'}
        </div>
        <div style="margin-top:20px;">
            <a href="/admin" class="btn">返回</a>
        </div>
    </div>
    """
    return render_page("系统信息", content)

@app.route('/harden/status', methods=['GET'])
def harden_status():
    return jsonify({
        "vulnerabilities_enabled": vulnerabilities_enabled,
        "whitelist": ip_whitelist,
        "current_stage": current_stage
    })

@app.route('/harden/change_password', methods=['POST'])
def change_password():
    if current_stage != "fix":
        return jsonify({"success": False, "message": "仅修复期允许修改密码"}), 403
    
    if not session.get('logged_in'):
        return jsonify({"success": False, "message": "未登录"}), 401
    
    data = request.get_json()
    new_password = data.get('new_password')
    if new_password:
        global ADMIN_PASSWORD
        if session.get('role') == 'admin':
            ADMIN_PASSWORD = new_password
            password_hash = hashlib.md5(new_password.encode()).hexdigest()
            conn = get_db()
            conn.execute("UPDATE users SET password = ? WHERE username = ?", (password_hash, ADMIN_USERNAME))
            conn.commit()
            conn.close()
            return jsonify({"success": True, "message": "密码修改成功"})
    return jsonify({"success": False, "message": "缺少参数"}), 400

@app.route('/harden/disable_vulnerabilities', methods=['POST'])
def disable_vulnerabilities():
    if current_stage != "fix":
        return jsonify({"success": False, "message": "仅修复期允许关闭漏洞"}), 403
    
    global vulnerabilities_enabled
    vulnerabilities_enabled = False
    return jsonify({"success": True, "message": "漏洞防护已启用"})

@app.route('/harden/add_whitelist', methods=['POST'])
def add_whitelist():
    if current_stage != "fix":
        return jsonify({"success": False, "message": "仅修复期允许修改白名单"}), 403
    
    data = request.get_json()
    ip = data.get('ip')
    if ip and ip not in ip_whitelist:
        ip_whitelist.append(ip)
        return jsonify({"success": True, "message": f"IP {ip} 已加入白名单"})
    return jsonify({"success": False, "message": "无效IP或已在白名单中"}), 400

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
    files_to_hash = [__file__]
    hashes = {}
    for filepath in files_to_hash:
        if os.path.exists(filepath):
            with open(filepath, 'rb') as f:
                hashes[filepath] = hashlib.md5(f.read()).hexdigest()
    return jsonify(hashes)

@app.route('/debug/info')
def debug_info():
    if request.args.get('debug') == '1':
        import traceback
        info = {
            "python_version": sys.version,
            "platform": platform.platform(),
            "current_user": session.get('username'),
            "current_role": session.get('role'),
            "database": app.config['DATABASE'],
            "upload_folder": app.config['UPLOAD_FOLDER'],
            "flag": FLAG,
            "backup_flag": BACKUP_FLAG,
            "secret_key": app.secret_key,
            "env": dict(os.environ)
        }
        return jsonify(info)
    return "Not Found", 404

@app.route('/announcements')
def announcements():
    conn = get_db()
    try:
        conn.execute("SELECT * FROM announcements WHERE 1=0")
    except:
        pass
    
    sample_announcements = [
        {"id": 1, "title": "系统升级通知", "content": "系统将于本周六凌晨进行升级维护", "created_at": "2024-01-15T10:00:00", "important": 1},
        {"id": 2, "title": "年度表彰大会", "content": "本年度优秀员工评选即将开始", "created_at": "2024-01-14T09:00:00", "important": 0},
        {"id": 3, "title": "新员工入职培训", "content": "新员工请于下周一参加入职培训", "created_at": "2024-01-13T14:00:00", "important": 0},
        {"id": 4, "title": "春节放假安排", "content": "春节假期为2月10日至2月17日", "created_at": "2024-01-12T16:00:00", "important": 1},
        {"id": 5, "title": "技术分享会", "content": "本周五下午3点举行技术分享会", "created_at": "2024-01-11T11:00:00", "important": 0},
    ]
    
    ann_html = ""
    for ann in sample_announcements:
        badge = f'<span style="background:#e74c3c;color:white;padding:2px 8px;border-radius:10px;font-size:12px;">重要</span>' if ann["important"] else ""
        ann_html += f"""
        <div style="padding:15px;border-bottom:1px solid #eee;">
            <h4 style="margin:0 0 8px 0;">
                <a href="/announcements/{ann['id']}" style="color:#333;text-decoration:none;">{ann['title']}</a>
                {badge}
            </h4>
            <p style="color:#666;margin:0 0 8px 0;font-size:14px;">{ann['content'][:50]}...</p>
            <span style="color:#999;font-size:12px;">{ann['created_at']}</span>
        </div>
        """
    
    content = f"""
    <div class="card">
        <h2>公告中心</h2>
        {ann_html}
    </div>
    <div class="card">
        <h3>快速链接</h3>
        <div style="display:grid;grid-template-columns:repeat(4,1fr);gap:15px;">
            <a href="/tasks" style="padding:20px;background:#f8f9fa;border-radius:8px;text-align:center;text-decoration:none;color:#333;">
                <div style="font-size:24px;margin-bottom:8px;">📋</div>
                <div>任务管理</div>
            </a>
            <a href="/calendar" style="padding:20px;background:#f8f9fa;border-radius:8px;text-align:center;text-decoration:none;color:#333;">
                <div style="font-size:24px;margin-bottom:8px;">📅</div>
                <div>日程安排</div>
            </a>
            <a href="/votes" style="padding:20px;background:#f8f9fa;border-radius:8px;text-align:center;text-decoration:none;color:#333;">
                <div style="font-size:24px;margin-bottom:8px;">🗳️</div>
                <div>投票中心</div>
            </a>
            <a href="/reports" style="padding:20px;background:#f8f9fa;border-radius:8px;text-align:center;text-decoration:none;color:#333;">
                <div style="font-size:24px;margin-bottom:8px;">📊</div>
                <div>数据报表</div>
            </a>
        </div>
    </div>
    """
    return render_page("公告中心", content)

@app.route('/announcements/<int:ann_id>')
def view_announcement(ann_id):
    sample_announcements = {
        1: {"id": 1, "title": "系统升级通知", "content": "系统将于本周六凌晨2:00-6:00进行升级维护，期间系统将暂停服务。\n\n升级内容：\n1. 优化数据库查询性能\n2. 新增文件管理模块\n3. 修复已知安全漏洞\n4. 提升用户界面体验\n\n请各部门提前做好相关工作安排，给您带来的不便敬请谅解。", "created_at": "2024-01-15T10:00:00", "author": "系统管理员"},
        2: {"id": 2, "title": "年度表彰大会", "content": "本年度优秀员工评选即将开始，请各部门于1月31日前提交候选人名单。\n\n评选标准：\n- 工作业绩突出\n- 团队协作优秀\n- 创新能力强\n- 出勤率高\n\n表彰大会将于2月底举行，获奖员工将获得奖金和荣誉证书。", "created_at": "2024-01-14T09:00:00", "author": "人力资源部"},
        3: {"id": 3, "title": "新员工入职培训", "content": "新员工请于下周一上午9点到会议室A参加入职培训。\n\n培训内容：\n1. 公司文化与规章制度\n2. 办公系统使用指南\n3. 安全保密教育\n4. 部门介绍与岗位认识\n\n请携带身份证、学历证书复印件及一寸照片两张。", "created_at": "2024-01-13T14:00:00", "author": "人力资源部"},
        4: {"id": 4, "title": "春节放假安排", "content": "根据国家法定节假日安排，2024年春节放假安排如下：\n\n放假时间：2月10日（除夕）至2月17日（初七），共8天\n调休上班：2月4日（周日）、2月18日（周日）\n\n请各部门：\n1. 做好节前安全检查\n2. 安排好值班人员\n3. 关闭办公设备电源\n4. 锁好门窗\n\n祝大家春节快乐！", "created_at": "2024-01-12T16:00:00", "author": "行政部"},
        5: {"id": 5, "title": "技术分享会", "content": "本周五下午3点在会议室B举行技术分享会，欢迎各位技术同事参加。\n\n分享主题：微服务架构实践与思考\n分享人：张工\n\n主要内容：\n1. 微服务架构概述\n2. 服务拆分原则\n3. 服务治理与监控\n4. 踩坑经验总结\n\n请提前10分钟入场，带上笔记本。", "created_at": "2024-01-11T11:00:00", "author": "技术部"},
    }
    
    ann = sample_announcements.get(ann_id)
    if not ann:
        return render_page("公告不存在", '<div class="card"><h2>公告不存在</h2></div>')
    
    content = f"""
    <div class="card">
        <h2>{ann['title']}</h2>
        <p style="color:#666;font-size:14px;">
            发布人: {ann['author']} | 发布时间: {ann['created_at']}
        </p>
        <hr>
        <div style="line-height:1.8;white-space:pre-wrap;">
            {ann['content']}
        </div>
        <div style="margin-top:20px;">
            <a href="/announcements" class="btn">返回列表</a>
        </div>
    </div>
    """
    return render_page(ann['title'], content)

@app.route('/tasks')
def task_list():
    if not session.get('logged_in'):
        return redirect('/login')
    
    sample_tasks = [
        {"id": 1, "title": "完成季度报告", "status": "进行中", "priority": "高", "deadline": "2024-01-20", "assignee": "张三"},
        {"id": 2, "title": "代码审查", "status": "待开始", "priority": "中", "deadline": "2024-01-22", "assignee": "李四"},
        {"id": 3, "title": "客户需求调研", "status": "已完成", "priority": "低", "deadline": "2024-01-18", "assignee": "王五"},
        {"id": 4, "title": "系统测试", "status": "进行中", "priority": "高", "deadline": "2024-01-25", "assignee": session.get('username', 'user')},
        {"id": 5, "title": "文档编写", "status": "待开始", "priority": "中", "deadline": "2024-01-30", "assignee": "赵六"},
        {"id": 6, "title": "性能优化", "status": "进行中", "priority": "高", "deadline": "2024-01-28", "assignee": session.get('username', 'user')},
    ]
    
    status_colors = {
        "已完成": "#27ae60",
        "进行中": "#f39c12",
        "待开始": "#95a5a6"
    }
    priority_colors = {
        "高": "#e74c3c",
        "中": "#f39c12",
        "低": "#27ae60"
    }
    
    tasks_html = ""
    for task in sample_tasks:
        status_color = status_colors.get(task["status"], "#999")
        priority_color = priority_colors.get(task["priority"], "#999")
        tasks_html += f"""
        <tr>
            <td>{task['id']}</td>
            <td><a href="/tasks/{task['id']}" style="color:#3498db;text-decoration:none;">{task['title']}</a></td>
            <td><span style="color:{status_color};font-weight:bold;">{task['status']}</span></td>
            <td><span style="color:{priority_color};">{task['priority']}</span></td>
            <td>{task['deadline']}</td>
            <td>{task['assignee']}</td>
        </tr>
        """
    
    my_count = sum(1 for t in sample_tasks if t["assignee"] == session.get('username', ''))
    done_count = sum(1 for t in sample_tasks if t["status"] == "已完成")
    in_progress_count = sum(1 for t in sample_tasks if t["status"] == "进行中")
    pending_count = sum(1 for t in sample_tasks if t["status"] == "待开始")
    
    content = f"""
    <div class="card">
        <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:20px;">
            <h2>任务管理</h2>
            <button class="btn btn-success">新建任务</button>
        </div>
        <div style="display:grid;grid-template-columns:repeat(4,1fr);gap:15px;margin-bottom:20px;">
            <div style="padding:15px;background:#e8f5e9;border-radius:8px;text-align:center;">
                <div style="font-size:20px;font-weight:bold;color:#27ae60;">{my_count}</div>
                <div style="font-size:12px;color:#666;">我的任务</div>
            </div>
            <div style="padding:15px;background:#fff3e0;border-radius:8px;text-align:center;">
                <div style="font-size:20px;font-weight:bold;color:#ff9800;">{in_progress_count}</div>
                <div style="font-size:12px;color:#666;">进行中</div>
            </div>
            <div style="padding:15px;background:#f3e5f5;border-radius:8px;text-align:center;">
                <div style="font-size:20px;font-weight:bold;color:#9c27b0;">{pending_count}</div>
                <div style="font-size:12px;color:#666;">待开始</div>
            </div>
            <div style="padding:15px;background:#e3f2fd;border-radius:8px;text-align:center;">
                <div style="font-size:20px;font-weight:bold;color:#2196f3;">{done_count}</div>
                <div style="font-size:12px;color:#666;">已完成</div>
            </div>
        </div>
        <div style="margin-bottom:15px;display:flex;gap:10px;">
            <select style="width:auto;">
                <option>全部状态</option>
                <option>进行中</option>
                <option>已完成</option>
                <option>待开始</option>
            </select>
            <select style="width:auto;">
                <option>全部优先级</option>
                <option>高</option>
                <option>中</option>
                <option>低</option>
            </select>
            <input type="text" placeholder="搜索任务..." style="flex:1;">
            <button class="btn">搜索</button>
        </div>
        <table>
            <thead>
                <tr><th>ID</th><th>任务标题</th><th>状态</th><th>优先级</th><th>截止日期</th><th>负责人</th></tr>
            </thead>
            <tbody>
                {tasks_html}
            </tbody>
        </table>
    </div>
    """
    return render_page("任务管理", content)

@app.route('/tasks/<int:task_id>')
def task_detail(task_id):
    if not session.get('logged_in'):
        return redirect('/login')
    
    sample_task = {
        "id": task_id,
        "title": f"任务 {task_id}",
        "description": "这是一个示例任务的详细描述。\n\n任务目标：\n1. 完成指定功能的开发\n2. 编写单元测试\n3. 进行代码审查\n4. 部署到测试环境\n\n验收标准：\n- 功能正常运行\n- 测试覆盖率达到80%以上\n- 代码符合规范",
        "status": "进行中",
        "priority": "高",
        "deadline": "2024-01-20",
        "assignee": "张三",
        "creator": "李四",
        "created_at": "2024-01-10T09:00:00",
        "progress": 65,
        "comments": [
            {"user": "李四", "content": "任务已创建，请尽快开始", "time": "2024-01-10T09:05:00"},
            {"user": "张三", "content": "收到，已开始需求分析", "time": "2024-01-10T10:00:00"},
            {"user": "张三", "content": "目前进度约65%，预计可按期完成", "time": "2024-01-15T14:00:00"},
        ]
    }
    
    comments_html = ""
    for c in sample_task["comments"]:
        comments_html += f"""
        <div style="padding:10px 0;border-bottom:1px solid #eee;">
            <div style="display:flex;justify-content:space-between;">
                <strong>{c['user']}</strong>
                <span style="color:#999;font-size:12px;">{c['time']}</span>
            </div>
            <p style="margin:5px 0 0 0;color:#666;">{c['content']}</p>
        </div>
        """
    
    content = f"""
    <div class="card">
        <div style="display:flex;justify-content:space-between;align-items:flex-start;">
            <div>
                <h2>{sample_task['title']}</h2>
                <p style="color:#666;font-size:14px;">
                    创建人: {sample_task['creator']} | 负责人: {sample_task['assignee']} | 
                    创建时间: {sample_task['created_at']}
                </p>
            </div>
            <div style="text-align:right;">
                <span style="background:#f39c12;color:white;padding:4px 12px;border-radius:20px;">{sample_task['status']}</span>
                <span style="background:#e74c3c;color:white;padding:4px 12px;border-radius:20px;margin-left:8px;">{sample_task['priority']}</span>
            </div>
        </div>
        <div style="margin:20px 0;">
            <div style="display:flex;justify-content:space-between;margin-bottom:5px;">
                <span>进度</span>
                <span>{sample_task['progress']}%</span>
            </div>
            <div style="height:10px;background:#eee;border-radius:5px;">
                <div style="width:{sample_task['progress']}%;height:100%;background:#3498db;border-radius:5px;"></div>
            </div>
        </div>
        <hr>
        <h3>任务描述</h3>
        <div style="line-height:1.8;white-space:pre-wrap;color:#333;">
            {sample_task['description']}
        </div>
        <div style="margin-top:20px;padding:15px;background:#f8f9fa;border-radius:8px;">
            <p><strong>截止日期:</strong> {sample_task['deadline']}</p>
        </div>
    </div>
    <div class="card">
        <h3>评论 ({len(sample_task['comments'])})</h3>
        {comments_html}
        <div style="margin-top:15px;">
            <textarea placeholder="添加评论..." rows="3" style="width:100%;"></textarea>
            <div style="text-align:right;margin-top:8px;">
                <button class="btn">发表评论</button>
            </div>
        </div>
    </div>
    """
    return render_page(sample_task['title'], content)

@app.route('/calendar')
def calendar():
    if not session.get('logged_in'):
        return redirect('/login')
    
    today = datetime.now()
    year = today.year
    month = today.month
    
    import calendar
    cal = calendar.monthcalendar(year, month)
    
    events = [
        {"date": today.day, "title": "团队周会", "time": "10:00", "color": "#3498db"},
        {"date": today.day + 2, "title": "项目评审", "time": "14:00", "color": "#e74c3c"},
        {"date": today.day + 5, "title": "客户拜访", "time": "09:00", "color": "#27ae60"},
        {"date": 20, "title": "月度总结", "time": "15:00", "color": "#f39c12"},
        {"date": 25, "title": "技术培训", "time": "14:00", "color": "#9b59b6"},
    ]
    
    day_names = ['一', '二', '三', '四', '五', '六', '日']
    header_html = "".join(f'<th style="text-align:center;padding:10px;">{name}</th>' for name in day_names)
    
    body_html = ""
    for week in cal:
        row = ""
        for day in week:
            if day == 0:
                row += '<td style="height:80px;background:#fafafa;"></td>'
            else:
                day_events = [e for e in events if e["date"] == day]
                events_html = ""
                for e in day_events:
                    events_html += f'<div style="font-size:11px;background:{e["color"]};color:white;padding:2px 4px;margin:1px 0;border-radius:3px;overflow:hidden;">{e["title"]}</div>'
                
                is_today = day == today.day
                bg = "#e3f2fd" if is_today else "white"
                row += f'''
                <td style="height:80px;width:14%;vertical-align:top;padding:5px;background:{bg};border:1px solid #eee;">
                    <div style="font-weight:bold;{"color:#2196f3;" if is_today else "color:#333;"}">{day}</div>
                    {events_html}
                </td>
                '''
        body_html += f"<tr>{row}</tr>"
    
    upcoming_events_html = ""
    for e in events[:5]:
        upcoming_events_html += f"""
        <div style="padding:10px 0;border-bottom:1px solid #eee;display:flex;gap:10px;">
            <div style="width:4px;background:{e['color']};border-radius:2px;"></div>
            <div style="flex:1;">
                <div style="font-weight:bold;">{e['title']}</div>
                <div style="color:#666;font-size:12px;">{month}月{e['date']}日 {e['time']}</div>
            </div>
        </div>
        """
    
    content = f"""
    <div class="card">
        <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:20px;">
            <h2>{year}年{month}月</h2>
            <div>
                <button class="btn">上个月</button>
                <button class="btn">今天</button>
                <button class="btn">下个月</button>
            </div>
        </div>
        <table style="width:100%;border-collapse:collapse;">
            <thead>
                <tr style="background:#f8f9fa;">
                    {header_html}
                </tr>
            </thead>
            <tbody>
                {body_html}
            </tbody>
        </table>
    </div>
    <div class="card">
        <h3>近期安排</h3>
        {upcoming_events_html}
        <div style="margin-top:15px;">
            <button class="btn btn-success">添加日程</button>
        </div>
    </div>
    """
    return render_page("日程安排", content)

@app.route('/votes')
def votes():
    if not session.get('logged_in'):
        return redirect('/login')
    
    sample_votes = [
        {"id": 1, "title": "年会节目投票", "status": "进行中", "options": 5, "votes": 128, "end_time": "2024-01-20"},
        {"id": 2, "title": "团建地点选择", "status": "已结束", "options": 4, "votes": 56, "end_time": "2024-01-10"},
        {"id": 3, "title": "食堂菜色改进建议", "status": "进行中", "options": 6, "votes": 89, "end_time": "2024-01-25"},
        {"id": 4, "title": "新办公区装修风格", "status": "进行中", "options": 3, "votes": 45, "end_time": "2024-01-22"},
    ]
    
    votes_html = ""
    for v in sample_votes:
        status_color = "#27ae60" if v["status"] == "进行中" else "#95a5a6"
        votes_html += f"""
        <tr>
            <td>{v['id']}</td>
            <td><a href="/votes/{v['id']}" style="color:#3498db;text-decoration:none;">{v['title']}</a></td>
            <td><span style="color:{status_color};font-weight:bold;">{v['status']}</span></td>
            <td>{v['options']}</td>
            <td>{v['votes']}</td>
            <td>{v['end_time']}</td>
        </tr>
        """
    
    active_count = sum(1 for v in sample_votes if v["status"] == "进行中")
    total_votes = sum(v["votes"] for v in sample_votes)
    
    content = f"""
    <div class="card">
        <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:20px;">
            <h2>投票中心</h2>
            <button class="btn btn-success">发起投票</button>
        </div>
        <div style="display:grid;grid-template-columns:repeat(3,1fr);gap:15px;margin-bottom:20px;">
            <div style="padding:15px;background:#e8f5e9;border-radius:8px;text-align:center;">
                <div style="font-size:24px;font-weight:bold;color:#27ae60;">{active_count}</div>
                <div style="font-size:12px;color:#666;">进行中的投票</div>
            </div>
            <div style="padding:15px;background:#e3f2fd;border-radius:8px;text-align:center;">
                <div style="font-size:24px;font-weight:bold;color:#2196f3;">{len(sample_votes)}</div>
                <div style="font-size:12px;color:#666;">总投票数</div>
            </div>
            <div style="padding:15px;background:#f3e5f5;border-radius:8px;text-align:center;">
                <div style="font-size:24px;font-weight:bold;color:#9c27b0;">{total_votes}</div>
                <div style="font-size:12px;color:#666;">总投票人次</div>
            </div>
        </div>
        <table>
            <thead>
                <tr><th>ID</th><th>投票标题</th><th>状态</th><th>选项数</th><th>投票数</th><th>截止时间</th></tr>
            </thead>
            <tbody>
                {votes_html}
            </tbody>
        </table>
    </div>
    """
    return render_page("投票中心", content)

@app.route('/votes/<int:vote_id>')
def vote_detail(vote_id):
    if not session.get('logged_in'):
        return redirect('/login')
    
    sample_vote = {
        "id": vote_id,
        "title": f"投票 {vote_id}",
        "description": "请选择您认为最合适的选项，每人限投一票。",
        "status": "进行中",
        "options": [
            {"id": 1, "text": "选项A - 方案一", "votes": 35},
            {"id": 2, "text": "选项B - 方案二", "votes": 28},
            {"id": 3, "text": "选项C - 方案三", "votes": 45},
            {"id": 4, "text": "选项D - 方案四", "votes": 20},
        ],
        "total_votes": 128,
        "creator": "管理员",
        "created_at": "2024-01-10T09:00:00",
        "end_time": "2024-01-20T18:00:00"
    }
    
    total = sample_vote["total_votes"]
    options_html = ""
    for opt in sample_vote["options"]:
        percent = (opt["votes"] / total * 100) if total > 0 else 0
        options_html += f"""
        <div style="margin-bottom:15px;">
            <div style="display:flex;justify-content:space-between;margin-bottom:5px;">
                <label style="cursor:pointer;">
                    <input type="radio" name="vote"> {opt['text']}
                </label>
                <span style="color:#666;">{opt['votes']}票 ({percent:.1f}%)</span>
            </div>
            <div style="height:20px;background:#eee;border-radius:10px;overflow:hidden;">
                <div style="width:{percent}%;height:100%;background:#3498db;"></div>
            </div>
        </div>
        """
    
    content = f"""
    <div class="card">
        <div style="display:flex;justify-content:space-between;align-items:flex-start;">
            <div>
                <h2>{sample_vote['title']}</h2>
                <p style="color:#666;font-size:14px;">
                    创建人: {sample_vote['creator']} | 创建时间: {sample_vote['created_at']}
                </p>
            </div>
            <span style="background:#27ae60;color:white;padding:4px 12px;border-radius:20px;">{sample_vote['status']}</span>
        </div>
        <p style="color:#333;line-height:1.6;">{sample_vote['description']}</p>
        <p style="color:#e74c3c;"><strong>截止时间:</strong> {sample_vote['end_time']}</p>
        <hr>
        <form>
            {options_html}
            <div style="text-align:right;margin-top:20px;">
                <button type="button" class="btn btn-success">提交投票</button>
            </div>
        </form>
        <div style="margin-top:15px;padding:10px;background:#f8f9fa;border-radius:4px;text-align:center;">
            已有 <strong>{sample_vote['total_votes']}</strong> 人参与投票
        </div>
    </div>
    <div style="margin-top:20px;">
        <a href="/votes" class="btn">返回列表</a>
    </div>
    """
    return render_page(sample_vote['title'], content)

@app.route('/reports')
def reports():
    if not session.get('logged_in'):
        return redirect('/login')
    
    content = f"""
    <div class="card">
        <h2>数据报表</h2>
        <p style="color:#666;">查看系统各项数据统计分析</p>
    </div>
    <div class="card">
        <h3>用户增长趋势</h3>
        <div style="height:250px;display:flex;align-items:flex-end;justify-content:space-around;padding:20px 0;border-bottom:1px solid #eee;">
            <div style="text-align:center;">
                <div style="width:40px;background:#3498db;height:80px;border-radius:4px 4px 0 0;"></div>
                <div style="font-size:12px;color:#666;margin-top:5px;">1月</div>
            </div>
            <div style="text-align:center;">
                <div style="width:40px;background:#3498db;height:120px;border-radius:4px 4px 0 0;"></div>
                <div style="font-size:12px;color:#666;margin-top:5px;">2月</div>
            </div>
            <div style="text-align:center;">
                <div style="width:40px;background:#3498db;height:95px;border-radius:4px 4px 0 0;"></div>
                <div style="font-size:12px;color:#666;margin-top:5px;">3月</div>
            </div>
            <div style="text-align:center;">
                <div style="width:40px;background:#3498db;height:150px;border-radius:4px 4px 0 0;"></div>
                <div style="font-size:12px;color:#666;margin-top:5px;">4月</div>
            </div>
            <div style="text-align:center;">
                <div style="width:40px;background:#3498db;height:130px;border-radius:4px 4px 0 0;"></div>
                <div style="font-size:12px;color:#666;margin-top:5px;">5月</div>
            </div>
            <div style="text-align:center;">
                <div style="width:40px;background:#3498db;height:170px;border-radius:4px 4px 0 0;"></div>
                <div style="font-size:12px;color:#666;margin-top:5px;">6月</div>
            </div>
            <div style="text-align:center;">
                <div style="width:40px;background:#27ae60;height:200px;border-radius:4px 4px 0 0;"></div>
                <div style="font-size:12px;color:#666;margin-top:5px;">7月</div>
            </div>
        </div>
    </div>
    <div class="card">
        <h3>系统使用情况</h3>
        <div style="display:grid;grid-template-columns:repeat(2,1fr);gap:20px;">
            <div>
                <h4>功能模块访问量</h4>
                <div style="padding:10px 0;">
                    <div style="display:flex;justify-content:space-between;margin-bottom:3px;">
                        <span>文档中心</span>
                        <span>45%</span>
                    </div>
                    <div style="height:8px;background:#eee;border-radius:4px;">
                        <div style="width:45%;height:100%;background:#3498db;border-radius:4px;"></div>
                    </div>
                </div>
                <div style="padding:10px 0;">
                    <div style="display:flex;justify-content:space-between;margin-bottom:3px;">
                        <span>消息中心</span>
                        <span>25%</span>
                    </div>
                    <div style="height:8px;background:#eee;border-radius:4px;">
                        <div style="width:25%;height:100%;background:#e74c3c;border-radius:4px;"></div>
                    </div>
                </div>
                <div style="padding:10px 0;">
                    <div style="display:flex;justify-content:space-between;margin-bottom:3px;">
                        <span>文件管理</span>
                        <span>15%</span>
                    </div>
                    <div style="height:8px;background:#eee;border-radius:4px;">
                        <div style="width:15%;height:100%;background:#27ae60;border-radius:4px;"></div>
                    </div>
                </div>
                <div style="padding:10px 0;">
                    <div style="display:flex;justify-content:space-between;margin-bottom:3px;">
                        <span>任务管理</span>
                        <span>10%</span>
                    </div>
                    <div style="height:8px;background:#eee;border-radius:4px;">
                        <div style="width:10%;height:100%;background:#f39c12;border-radius:4px;"></div>
                    </div>
                </div>
                <div style="padding:10px 0;">
                    <div style="display:flex;justify-content:space-between;margin-bottom:3px;">
                        <span>其他</span>
                        <span>5%</span>
                    </div>
                    <div style="height:8px;background:#eee;border-radius:4px;">
                        <div style="width:5%;height:100%;background:#9b59b6;border-radius:4px;"></div>
                    </div>
                </div>
            </div>
            <div>
                <h4>用户活跃度分布</h4>
                <div style="padding:20px;text-align:center;">
                    <div style="width:150px;height:150px;border-radius:50%;background:conic-gradient(#3498db 0% 35%,#27ae60 35% 60%,#f39c12 60% 80%,#95a5a6 80% 100%);margin:0 auto;display:flex;align-items:center;justify-content:center;">
                        <div style="width:100px;height:100px;background:white;border-radius:50%;display:flex;align-items:center;justify-content:center;">
                            <div style="text-align:center;">
                                <div style="font-size:24px;font-weight:bold;">128</div>
                                <div style="font-size:12px;color:#666;">总用户</div>
                            </div>
                        </div>
                    </div>
                    <div style="margin-top:15px;font-size:12px;">
                        <span style="color:#3498db;">■ 活跃 35%</span>
                        <span style="color:#27ae60;margin-left:10px;">■ 一般 25%</span>
                        <span style="color:#f39c12;margin-left:10px;">■ 低频 20%</span>
                        <span style="color:#95a5a6;margin-left:10px;">■ 休眠 20%</span>
                    </div>
                </div>
            </div>
        </div>
    </div>
    <div class="card">
        <h3>导出报表</h3>
        <div style="display:flex;gap:10px;">
            <select style="width:auto;">
                <option>用户数据报表</option>
                <option>文档统计报表</option>
                <option>系统日志报表</option>
                <option>综合数据报表</option>
            </select>
            <select style="width:auto;">
                <option>Excel格式</option>
                <option>PDF格式</option>
                <option>CSV格式</option>
            </select>
            <button class="btn btn-success">导出</button>
        </div>
    </div>
    """
    return render_page("数据报表", content)

@app.errorhandler(404)
def page_not_found(e):
    content = f"""
    <div class="card" style="text-align:center;padding:50px;">
        <h1 style="font-size:48px;color:#e74c3c;">404</h1>
        <h2>页面未找到</h2>
        <p>您访问的页面不存在</p>
        <p style="color:#999;font-size:12px;">请求路径: {request.path}</p>
        <a href="/" class="btn">返回首页</a>
    </div>
    """
    return render_page("404", content), 404

@app.errorhandler(500)
def server_error(e):
    import traceback
    error_detail = traceback.format_exc()
    content = f"""
    <div class="card">
        <h1 style="color:#e74c3c;">服务器错误</h1>
        <p>发生了一个内部错误</p>
        <pre style="background:#f8f9fa;padding:15px;border-radius:4px;overflow:auto;">{error_detail}</pre>
        <a href="/" class="btn">返回首页</a>
    </div>
    """
    return render_page("500", content), 500

def start_server(port=8000):
    global FLAG, BACKUP_FLAG
    FLAG = generate_flag()
    BACKUP_FLAG = generate_flag()
    
    with open("./data/flag.txt", "w") as f:
        f.write(FLAG)
    with open("./data/backup_flag.txt", "w") as f:
        f.write(BACKUP_FLAG)
    with open("./data/credentials.json", "w") as f:
        json.dump({"username": ADMIN_USERNAME, "password": ADMIN_PASSWORD}, f)
    
    init_database()
    
    print(f"靶机服务启动，监听端口: {port}")
    print(f"主FLAG: {FLAG}")
    print(f"备用FLAG: {BACKUP_FLAG}")
    print(f"管理员账号: {ADMIN_USERNAME}/{ADMIN_PASSWORD}")
    
    app.run(host='0.0.0.0', port=port, debug=False, threaded=True)

if __name__ == "__main__":
    start_server()
