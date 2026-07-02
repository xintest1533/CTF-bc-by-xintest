import os
import configparser
import sys
import platform

CONFIG_FILE = "./ip_config.ini"

def load_ip_config():
    config = configparser.ConfigParser()
    
    if not os.path.exists(CONFIG_FILE):
        config['NETWORK'] = {
            'primary_ip': '',
            'backup_ip': ''
        }
        with open(CONFIG_FILE, 'w') as f:
            config.write(f)
        return None, None
    
    config.read(CONFIG_FILE)
    
    if 'NETWORK' not in config:
        config['NETWORK'] = {
            'primary_ip': '',
            'backup_ip': ''
        }
        with open(CONFIG_FILE, 'w') as f:
            config.write(f)
        return None, None
    
    primary_ip = config['NETWORK'].get('primary_ip', '').strip()
    backup_ip = config['NETWORK'].get('backup_ip', '').strip()
    
    return primary_ip, backup_ip

def validate_ip_config():
    primary_ip, backup_ip = load_ip_config()
    
    if not primary_ip:
        show_error("错误：未配置主内网IP（primary_ip）")
        show_error("请在 ip_config.ini 文件中配置 primary_ip 字段后重新启动")
        sys.exit(1)
    
    return primary_ip, backup_ip

def show_error(message):
    os_type = platform.system()
    
    if os_type == 'Windows':
        try:
            import ctypes
            ctypes.windll.user32.MessageBoxW(0, message, "CTF靶机客户端错误", 0x10)
        except:
            print(f"\033[91m{message}\033[0m")
    else:
        print(f"\033[91m{message}\033[0m")

def show_warning(message):
    os_type = platform.system()
    
    if os_type == 'Windows':
        try:
            import ctypes
            ctypes.windll.user32.MessageBoxW(0, message, "CTF靶机客户端警告", 0x40)
        except:
            print(f"\033[93m{message}\033[0m")
    else:
        print(f"\033[93m{message}\033[0m")

def show_info(message):
    os_type = platform.system()
    
    if os_type == 'Windows':
        try:
            import ctypes
            ctypes.windll.user32.MessageBoxW(0, message, "CTF靶机客户端信息", 0x40)
        except:
            print(f"\033[92m{message}\033[0m")
    else:
        print(f"\033[92m{message}\033[0m")

def get_current_ip(primary_ip, backup_ip):
    return primary_ip, backup_ip

def switch_to_backup_ip(primary_ip, backup_ip):
    if backup_ip:
        show_info(f"网络异常，切换至备用IP: {backup_ip}")
        return backup_ip
    return primary_ip
