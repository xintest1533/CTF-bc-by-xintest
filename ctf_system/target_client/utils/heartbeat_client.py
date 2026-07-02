import socket
import json
import time
import threading
import os
import platform
from datetime import datetime

class HeartbeatClient:
    def __init__(self, player_id, primary_ip, judge_addresses, judge_port=9999, interval=5):
        self.player_id = player_id
        self.primary_ip = primary_ip
        self.backup_ip = ""
        self.judge_addresses = judge_addresses
        self.judge_port = judge_port
        self.interval = interval
        
        self.current_ip = primary_ip
        self.current_judge_index = 0
        self.socket = None
        self.running = False
        self.reconnect_count = 0
        self.has_revive_chance = True
        self.last_reconnect_time = 0
        self.connection_status = "disconnected"
        
        self.os_type = platform.system()
        
        self.log_file = os.path.join("./logs", "heartbeat.log")
        os.makedirs("./logs", exist_ok=True)
    
    def log(self, message):
        timestamp = datetime.now().isoformat()
        log_entry = f"[{timestamp}] {message}\n"
        with open(self.log_file, "a", encoding="utf-8") as f:
            f.write(log_entry)
        print(log_entry.strip())
    
    def connect(self):
        if self.socket:
            try:
                self.socket.close()
            except:
                pass
        
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.settimeout(10)
        
        for _ in range(len(self.judge_addresses)):
            judge_addr = self.judge_addresses[self.current_judge_index]
            try:
                self.socket.connect((judge_addr, self.judge_port))
                self.connection_status = "connected"
                self.reconnect_count = 0
                self.log(f"成功连接到裁判服务: {judge_addr}:{self.judge_port}")
                return True
            except Exception as e:
                self.log(f"连接失败: {judge_addr}:{self.judge_port}, 错误: {str(e)}")
                self.current_judge_index = (self.current_judge_index + 1) % len(self.judge_addresses)
        
        self.connection_status = "disconnected"
        return False
    
    def send_heartbeat(self):
        heartbeat_data = {
            "player_id": self.player_id,
            "primary_ip": self.current_ip,
            "os_type": self.os_type
        }
        
        try:
            if self.socket:
                self.socket.sendall(json.dumps(heartbeat_data).encode('utf-8'))
                return True
        except Exception as e:
            self.log(f"发送心跳失败: {str(e)}")
        
        return False
    
    def reconnect(self):
        now = time.time()
        
        if now - self.last_reconnect_time < 5:
            time.sleep(5 - (now - self.last_reconnect_time))
        
        self.last_reconnect_time = now
        
        if not self.has_revive_chance and self.reconnect_count >= 1:
            self.log("已使用复活机会，无法继续重连")
            return False
        
        self.reconnect_count += 1
        self.log(f"尝试重连 ({self.reconnect_count})...")
        
        if self.connect():
            if self.reconnect_count > 1:
                self.log("重连成功！")
            return True
        
        return False
    
    def run(self):
        self.running = True
        
        if not self.connect():
            self.log("无法连接到裁判服务，开始重连...")
        
        while self.running:
            try:
                if self.connection_status == "connected":
                    if not self.send_heartbeat():
                        self.connection_status = "disconnected"
                        self.log("心跳发送失败，连接已断开")
                else:
                    if not self.reconnect():
                        elapsed = time.time() - self.last_reconnect_time
                        if elapsed > 30:
                            self.log("重连超时超过30秒，将被判定淘汰")
                
                time.sleep(self.interval)
                
            except Exception as e:
                self.log(f"心跳线程异常: {str(e)}")
                self.connection_status = "disconnected"
    
    def stop(self):
        self.running = False
        if self.socket:
            try:
                self.socket.close()
            except:
                pass
        self.log("心跳客户端已停止")
    
    def set_backup_ip(self, backup_ip):
        self.backup_ip = backup_ip
    
    def switch_ip(self):
        if self.backup_ip and self.current_ip == self.primary_ip:
            self.current_ip = self.backup_ip
            self.log(f"切换至备用IP: {self.current_ip}")
            return True
        elif self.backup_ip and self.current_ip == self.backup_ip:
            self.current_ip = self.primary_ip
            self.log(f"切换回主IP: {self.current_ip}")
            return True
        return False
    
    def use_revive_chance(self):
        if self.has_revive_chance:
            self.has_revive_chance = False
            self.reconnect_count = 0
            self.log("使用复活机会，重置断线倒计时")
            return True
        return False
