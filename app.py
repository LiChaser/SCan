from flask import Flask, request, render_template, redirect, url_for, session, jsonify
from flask_socketio import SocketIO, emit
from flask_cors import CORS
import sqlite3
import hashlib
import socket
import requests
from concurrent.futures import ThreadPoolExecutor, as_completed
import builtwith
from bs4 import BeautifulSoup
import re
import html
import os
from threading import Event, Thread
import re
from urllib.parse import urljoin, urlparse
import logging
import json
import subprocess
import dns.resolver
from datetime import datetime, timedelta
from service.port_scanner import PortScanner
from service.dir_scanner import DirScanner
from service.ai_read import AIDebugger
from functools import wraps
import sys

logging.basicConfig(level=logging.DEBUG)

app = Flask(__name__)
CORS(app, resources={r"/*": {"origins": "*"}})
app.secret_key = 'Licharse_is_here'  # 设置一个安全的密钥

socketio = SocketIO(
    app,
    cors_allowed_origins="*",
    async_mode='gevent',
    logger=True,
    engineio_logger=True
)

# 数据库连接
def get_db():
    db = sqlite3.connect('instance/users.db')
    db.row_factory = sqlite3.Row
    return db

# 创建用户表和统计表
def init_db():
    # 确保 instance 目录存在
    os.makedirs('instance', exist_ok=True)
    
    # 如果数据库文件存在，先删除它
    db_path = os.path.join('instance', 'users.db')
    if os.path.exists(db_path):
        os.remove(db_path)
    
    db = get_db()
    db.execute('''
        CREATE TABLE IF NOT EXISTS users (
            username TEXT PRIMARY KEY,
            password TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    db.execute('''
        CREATE TABLE IF NOT EXISTS scan_stats (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT,
            scan_type TEXT,
            target TEXT,
            status TEXT,
            debugger_scans INTEGER DEFAULT 0,
            last_scan TIMESTAMP,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (username) REFERENCES users (username)
        )
    ''')
    
    db.execute('''
        CREATE TABLE IF NOT EXISTS scan_results (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_id INTEGER,
            result_data TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (scan_id) REFERENCES scan_stats (id)
        )
    ''')
    
    db.commit()
    db.close()

init_db()

# 更新扫描统计
def update_scan_stats(username, scan_type, target, status):
    db = get_db()
    try:
        db.execute(
            'INSERT INTO scan_stats (username, scan_type, target, status) VALUES (?, ?, ?, ?)',
            (username, scan_type, target, status)
        )
        db.commit()
    finally:
        db.close()

# 获取用户统计信息
def get_user_stats(username):
    db = get_db()
    try:
        today = datetime.now().date()
        today_start = datetime.combine(today, datetime.min.time())
        today_end = datetime.combine(today, datetime.max.time())
        
        stats = {
            'today_scans': db.execute(
                'SELECT COUNT(*) FROM scan_stats WHERE username = ? AND created_at BETWEEN ? AND ?',
                (username, today_start, today_end)
            ).fetchone()[0],
            
            'total_vulnerabilities': db.execute(
                'SELECT COUNT(*) FROM scan_results WHERE result_data LIKE ?',
                ('%vulnerability%',)
            ).fetchone()[0],
            
            'total_targets': db.execute(
                'SELECT COUNT(DISTINCT target) FROM scan_stats WHERE username = ?',
                (username,)
            ).fetchone()[0],
            
            'completed_reports': db.execute(
                'SELECT COUNT(*) FROM scan_stats WHERE username = ? AND status = ?',
                (username, 'completed')
            ).fetchone()[0]
        }
        return stats
    finally:
        db.close()

# 注册
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = hashlib.sha256(request.form['password'].encode()).hexdigest()
        
        db = get_db()
        try:
            db.execute('INSERT INTO users (username, password) VALUES (?, ?)', (username, password))
            db.commit()
            return redirect(url_for('login'))
        except sqlite3.IntegrityError:
            return render_template('register.html', error="用户名已存在")
        finally:
            db.close()
    return render_template('register.html')

# 登录
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = hashlib.sha256(request.form['password'].encode()).hexdigest()
        
        db = get_db()
        user = db.execute('SELECT * FROM users WHERE username = ? AND password = ?', (username, password)).fetchone()
        db.close()
        
        if user:
            session['logged_in'] = True
            session['username'] = username
            return redirect(url_for('dashboard'))
        else:
            return render_template('login.html', error="用户名或密码错误")
    return render_template('login.html')

# 获取用户统计信息
@app.route('/api/stats')
def get_stats():
    if not session.get('logged_in'):
        return jsonify({'error': '未登录'}), 401
    
    stats = get_user_stats(session['username'])
    return jsonify(stats)

# 仪表盘
@app.route('/dashboard')
def dashboard():
    if not session.get('logged_in'):
        return redirect(url_for('login'))
    
    stats = get_user_stats(session['username'])
    return render_template('dashboard.html', stats=stats)

# 端口扫描
@app.route('/scan')
def scan():
    if not session.get('logged_in'):
        return redirect(url_for('login'))
    return render_template('scan.html')

# 创建端口扫描器实例
port_scanner = PortScanner(socketio)

@socketio.on('start_scan')
def handle_scan(data):
    try:
        target = data['target']
        start_port = int(data['start_port'])
        end_port = int(data['end_port'])
        
        # 构建端口范围字符串
        ports = f"{start_port}-{end_port}"
        
        # 更新扫描统计
        if 'username' in session:
            update_scan_stats(session['username'], 'port_scan', target, 'started')
        
        # 开始扫描
        port_scanner.start_scan(target, ports)
        
    except Exception as e:
        logging.error(f"扫描过程中发生错误: {str(e)}")
        emit('scan_error', {'error': str(e)})

@socketio.on('stop_scan')
def handle_stop_scan():
    port_scanner.stop()
    emit('scan_stopped', {'message': '扫描已停止'})

# 目录扫描
@app.route('/dirscan')
def dirscan():
    if not session.get('logged_in'):
        return redirect(url_for('login'))
    return render_template('dirscan.html')

# 创建目录扫描器实例
dir_scanner = DirScanner(socketio)

@socketio.on('start_dirscan')
def handle_dirscan(data):
    try:
        target_url = data['target_url']
        use_default = data.get('use_default', False)
        wordlist = data.get('wordlist', '')
        
        # 更新扫描统计
        if 'username' in session:
            update_scan_stats(session['username'], 'dir_scan', target_url, 'started')
        
        # 开始扫描
        dir_scanner.start_scan(
            target_url=target_url,
            use_default=use_default,
            custom_wordlist=wordlist
        )
        
    except Exception as e:
        logging.error(f"目录扫描过程中发生错误: {str(e)}")
        if 'username' in session:
            update_scan_stats(session['username'], 'dir_scan', target_url, 'error')
        emit('dirscan_error', {'error': str(e)})

@socketio.on('stop_dirscan')
def handle_stop_dirscan():
    dir_scanner.stop()
    emit('dirscan_stopped', {'message': '扫描已停止'})

# 指纹探测
@app.route('/fingerprint')
def fingerprint():
    if not session.get('logged_in'):
        return redirect(url_for('login'))
    return render_template('fingerprint.html')

@socketio.on('start_fingerprint')
def handle_fingerprint(data):
    target_url = data['target_url']
    timeout = data.get('timeout', 60)  # 默认超时时间为60秒
    
    logging.debug(f"Starting fingerprint scan for {target_url} with timeout {timeout}")
    
    try:
        current_dir = os.path.dirname(os.path.abspath(__file__))
        dddd_path = os.path.join(current_dir, 'dddd.exe')
        
        logging.debug(f"dddd.exe path: {dddd_path}")
        logging.debug(f"Running command: {dddd_path} -t {target_url}")
        
        process = subprocess.Popen([dddd_path, '-t', target_url], stdout=subprocess.PIPE, stderr=subprocess.PIPE, bufsize=1, universal_newlines=False)
        
        while True:
            output = process.stdout.readline()
            if output == b'' and process.poll() is not None:
                break
            if output:
                try:
                    decoded_output = output.decode('gbk').strip()
                except UnicodeDecodeError:
                    decoded_output = output.decode('utf-8', errors='ignore').strip()
                
                logging.debug(f"Raw output: {decoded_output}")
                emit('fingerprint_update', {'output': decoded_output})
        
        rc = process.poll()
        if rc == 0:
            emit('fingerprint_complete', {'message': '扫描完成'})
            logging.debug("Scan completed successfully")
        else:
            stderr_output = process.stderr.read()
            try:
                error_message = stderr_output.decode('gbk')
            except UnicodeDecodeError:
                error_message = stderr_output.decode('utf-8', errors='ignore')
            emit('fingerprint_error', {'error': f'扫描失败: {error_message}'})
            logging.error(f"Scan failed: {error_message}")
    except Exception as e:
        logging.exception("An error occurred during fingerprint scan")
        emit('fingerprint_error', {'error': str(e)})

@socketio.on('stop_fingerprint')
def handle_stop_fingerprint():
    emit('fingerprint_stopped', {'message': '在当前模式下无法停止扫描，请等待扫描完成'})
# 渲染首页
@app.route('/')
def index():
    return render_template('index.html')

# 登出
@app.route('/logout')
def logout():
    session.pop('logged_in', None)
    session.pop('username', None)
    return redirect(url_for('index'))

def load_default_wordlist():
    wordlist_path = os.path.join(os.path.dirname(__file__), 'default_wordlist.txt')
    with open(wordlist_path, 'r', encoding='utf-8') as f:
        return [line.strip() for line in f if line.strip()]

# 创建服务实例 (在socketio初始
# 化后)
debugger_instance = AIDebugger(socketio)

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get('logged_in'):
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

@app.route('/Ai_debugger')
@login_required
def ai_debugger():
    return render_template('Ai_debugger.html')

@socketio.on('start_debug')
def handle_start_debug(data):
    try:
        # 使用绝对路径
        main_path = r"C:\Users\14844\Desktop\Homework\1\Licharser\扫描器\AI_JS_DEBUGGER\main.py"
        cmd = [sys.executable, main_path]
        
        # 使用 subprocess.Popen 打开新终端
        subprocess.Popen(
            cmd,
            creationflags=subprocess.CREATE_NEW_CONSOLE
        )
        
        emit('debugger_status', {
            'type': 'info',
            'message': '已打开调试终端'
        })
            
    except Exception as e:
        emit('debugger_status', {
            'type': 'error',
            'message': f'启动调试器失败: {str(e)}'
        })

@socketio.on('stop_debug')
def handle_stop_debug():
    try:
        debugger_instance.stop()
        emit('debugger_status', {
            'type': 'info',
            'message': '调试器已停止'
        })
    except Exception as e:
        emit('debugger_status', {
            'type': 'error',
            'message': f'停止调试器失败: {str(e)}'
        })

# 子域名枚举
@app.route('/subdomain')
def subdomain():
    if not session.get('logged_in'):
        return redirect(url_for('login'))
    return render_template('subdomain.html')

# 添加全局变量来控制子域名枚举和爬虫进程
subdomain_stop_event = Event()
crawler_stop_event = Event()

@socketio.on('start_subdomain_enum')
def handle_subdomain_enum(data):
    global subdomain_stop_event
    subdomain_stop_event.clear()
    domain = data['domain']
    subdomains = []
    try:
        common_subdomains = ['www', 'mail', 'ftp', 'localhost', 'webmail', 'smtp', 'pop', 'ns1', 'webdisk', 'ns2', 'cpanel', 'whm', 'autodiscover', 'autoconfig', 'm', 'imap', 'test', 'ns', 'blog', 'pop3', 'dev', 'www2', 'admin', 'forum', 'news', 'vpn', 'ns3', 'mail2', 'new', 'mysql', 'old', 'lists', 'support', 'mobile', 'mx', 'static', 'docs', 'beta', 'shop', 'sql', 'secure', 'demo', 'cp', 'calendar', 'wiki', 'web', 'media', 'email', 'images', 'img', 'www1', 'intranet', 'portal', 'video', 'sip', 'dns2', 'api', 'cdn', 'stats', 'dns1', 'ns4', 'www3', 'dns', 'search', 'staging', 'server', 'mx1', 'chat', 'wap', 'my', 'svn', 'mail1', 'sites', 'proxy', 'ads', 'host', 'crm', 'cms', 'backup', 'mx2', 'lyncdiscover', 'info', 'apps', 'download', 'remote', 'db', 'forums', 'store', 'relay', 'files', 'newsletter', 'app', 'live', 'owa', 'en', 'start', 'sms', 'office', 'exchange', 'ipv4']
        
        for subdomain in common_subdomains:
            if subdomain_stop_event.is_set():
                emit('subdomain_stopped', {'message': '枚举已停止'})
                return
            try:
                host = f"{subdomain}.{domain}"
                answers = dns.resolver.resolve(host, 'A')
                if answers:
                    subdomains.append(host)
                    emit('subdomain_found', {'subdomain': host})
            except dns.resolver.NXDOMAIN:
                pass
            except dns.resolver.NoAnswer:
                pass
            except dns.exception.Timeout:
                pass
        
        emit('subdomain_complete', {'message': '子域名枚举完成', 'count': len(subdomains)})
    except Exception as e:
        emit('subdomain_error', {'error': str(e)})

@socketio.on('stop_subdomain_enum')
def handle_stop_subdomain_enum():
    global subdomain_stop_event
    subdomain_stop_event.set()

# 网站爬虫
@app.route('/crawler')
def crawler():
    if not session.get('logged_in'):
        return redirect(url_for('login'))
    return render_template('crawler.html')

@socketio.on('start_crawl')
def handle_crawl(data):
    global crawler_stop_event
    crawler_stop_event.clear()
    url = data['url']
    max_pages = data.get('max_pages', 100)  # 默认最多爬取100页
    visited = set()
    to_visit = [url]
    
    try:
        while to_visit and len(visited) < max_pages:
            if crawler_stop_event.is_set():
                emit('crawl_stopped', {'message': '爬虫已停止'})
                return
            current_url = to_visit.pop(0)
            if current_url not in visited:
                visited.add(current_url)
                try:
                    response = requests.get(current_url, timeout=5)
                    if 'text/html' in response.headers.get('Content-Type', ''):
                        soup = BeautifulSoup(response.text, 'html.parser')
                        emit('page_crawled', {'url': current_url, 'title': soup.title.string if soup.title else 'No title'})
                        
                        for link in soup.find_all('a', href=True):
                            absolute_link = urljoin(current_url, link['href'])
                            if urlparse(absolute_link).netloc == urlparse(url).netloc and absolute_link not in visited:
                                to_visit.append(absolute_link)
                except requests.RequestException:
                    pass
        
        emit('crawl_complete', {'message': '爬虫完成', 'pages_crawled': len(visited)})
    except Exception as e:
        emit('crawl_error', {'error': str(e)})

@socketio.on('stop_crawl')
def handle_stop_crawl():
    global crawler_stop_event
    crawler_stop_event.set()

@socketio.on('debugger_input')
def handle_debugger_input(data):
    """处理调试器输入"""
    if not session.get('logged_in'):
        emit('debugger_status', {
            'type': 'error',
            'message': '请先登录'
        })
        return
        
    try:
        debugger_instance.send_input(data)
    except Exception as e:
        emit('debugger_status', {
            'type': 'error',
            'message': f'处理输入失败: {str(e)}'
        })

if __name__ == '__main__':
    socketio.run(app, debug=True, host='127.0.0.1', port=5000)
