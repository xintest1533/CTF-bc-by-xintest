import os
import configparser
import sys
import platform
import re

CONFIG_FILE = "./ip_config.ini"

def load_ip_config():
    config = configparser.ConfigParser()
    
    if not os.path.exists(CONFIG_FILE):
        config['NETWORK'] = {
            'primary_ip': '',
            'backup_ip': ''
        }
        try:
            with open(CONFIG_FILE, 'w') as f:
                config.write(f)
        except Exception as e:
            show_error(f"创建配置文件失败: {str(e)}")
        return None, None
    
    try:
        config.read(CONFIG_FILE)
    except Exception as e:
        show_error(f"读取配置文件失败: {str(e)}")
        return None, None
    
    if 'NETWORK' not in config:
        config['NETWORK'] = {
            'primary_ip': '',
            'backup_ip': ''
        }
        try:
            with open(CONFIG_FILE, 'w') as f:
                config.write(f)
        except Exception as e:
            show_error(f"更新配置文件失败: {str(e)}")
        return None, None
    
    primary_ip = config['NETWORK'].get('primary_ip', '').strip()
    backup_ip = config['NETWORK'].get('backup_ip', '').strip()
    
    return primary_ip, backup_ip

def validate_ip_address(ip):
    if not ip:
        return False, "IP地址不能为空"
    
    pattern = r'^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$'
    if not re.match(pattern, ip):
        return False, f"无效的IP地址格式: {ip}"
    
    if ip.startswith('127.') or ip == '0.0.0.0':
        return False, "不能使用回环地址或0.0.0.0"
    
    return True, "IP地址有效"

def validate_ip_config():
    primary_ip, backup_ip = load_ip_config()
    
    if not primary_ip:
        show_error("错误：未配置主内网IP（primary_ip）")
        show_error("请在 ip_config.ini 文件中配置 primary_ip 字段后重新启动")
        sys.exit(1)
    
    valid, message = validate_ip_address(primary_ip)
    if not valid:
        show_error(f"错误：{message}")
        sys.exit(1)
    
    if backup_ip:
        valid, message = validate_ip_address(backup_ip)
        if not valid:
            show_warning(f"警告：{message}，将忽略备用IP")
            backup_ip = ""
    
    show_info(f"主IP: {primary_ip}")
    if backup_ip:
        show_info(f"备用IP: {backup_ip}")
    
    return primary_ip, backup_ip

def get_local_ip_addresses():
    os_type = platform.system()
    ip_list = []
    
    if os_type == 'Windows':
        try:
            import subprocess
            result = subprocess.check_output(['ipconfig'], text=True)
            for line in result.split('\n'):
                if 'IPv4 Address' in line:
                    ip = line.split(':')[-1].strip()
                    if ip and not ip.startswith('127.'):
                        ip_list.append(ip)
        except Exception as e:
            show_warning(f"获取本地IP失败: {str(e)}")
    else:
        try:
            import subprocess
            result = subprocess.check_output(['ip', 'addr'], text=True)
            for line in result.split('\n'):
                if 'inet ' in line and 'brd' in line:
                    ip = line.split()[1].split('/')[0]
                    if ip and not ip.startswith('127.'):
                        ip_list.append(ip)
        except Exception as e:
            try:
                result = subprocess.check_output(['ifconfig'], text=True)
                for line in result.split('\n'):
                    if 'inet ' in line:
                        ip = line.split()[1]
                        if ip and not ip.startswith('127.'):
                            ip_list.append(ip)
            except Exception as e2:
                show_warning(f"获取本地IP失败: {str(e2)}")
    
    return ip_list

def validate_ip_in_local_network(primary_ip):
    local_ips = get_local_ip_addresses()
    if local_ips and primary_ip not in local_ips:
        show_warning(f"警告：配置的IP({primary_ip})不在本机网卡IP列表中")
        show_warning(f"本机网卡IP: {', '.join(local_ips)}")
    return True

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

def generate_sample_config():
    sample = """[NETWORK]
primary_ip = 192.168.1.100
backup_ip = 192.168.1.101
"""
    try:
        with open(CONFIG_FILE, 'w') as f:
            f.write(sample)
        show_info("已生成示例配置文件")
    except Exception as e:
        show_error(f"生成配置文件失败: {str(e)}")