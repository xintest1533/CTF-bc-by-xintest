import os
import sys
import threading
import time
import platform

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from utils.ip_config import validate_ip_config, show_error, show_warning, show_info
from utils.heartbeat_client import HeartbeatClient
from target_server import start_server, FLAG, BACKUP_FLAG

def main():
    print("=" * 50)
    print("CTF攻防对抗赛事 - 选手客户端启动")
    print("=" * 50)
    
    os_type = platform.system()
    print(f"操作系统: {os_type}")
    
    print("\n正在校验IP配置...")
    primary_ip, backup_ip = validate_ip_config()
    
    print(f"主内网IP: {primary_ip}")
    if backup_ip:
        print(f"备用IP: {backup_ip}")
    else:
        show_warning("未配置备用IP，网络异常时无法自动切换")
    
    player_id = input("\n请输入选手ID: ").strip()
    if not player_id:
        show_error("选手ID不能为空")
        sys.exit(1)
    
    judge_addresses = input("请输入裁判服务地址（多个地址用逗号分隔）: ").strip()
    if not judge_addresses:
        judge_addresses = "127.0.0.1"
    
    judge_list = [addr.strip() for addr in judge_addresses.split(",")]
    
    print("\n正在启动心跳客户端...")
    heartbeat_client = HeartbeatClient(
        player_id=player_id,
        primary_ip=primary_ip,
        judge_addresses=judge_list,
        judge_port=9999,
        interval=5
    )
    
    if backup_ip:
        heartbeat_client.set_backup_ip(backup_ip)
    
    heartbeat_thread = threading.Thread(target=heartbeat_client.run, daemon=True)
    heartbeat_thread.start()
    
    print("正在启动靶机服务...")
    print(f"主FLAG: {FLAG}")
    print(f"备用FLAG: {BACKUP_FLAG}")
    
    try:
        start_server(port=8000)
    except KeyboardInterrupt:
        print("\n正在停止客户端...")
        heartbeat_client.stop()
        print("客户端已停止")

if __name__ == "__main__":
    main()
