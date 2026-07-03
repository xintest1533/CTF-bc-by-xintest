import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import socket
import threading
import json
import time
from datetime import datetime

from config.judge_config import config

class PlayerState:
    def __init__(self, player_id, primary_ip, os_type="unknown"):
        self.player_id = player_id
        self.primary_ip = primary_ip
        self.os_type = os_type
        self.last_heartbeat = time.time()
        self.status = "online"
        self.reconnect_count = 0
        self.has_revive_chance = True
        self.eliminated = False
        self.elimination_reason = ""
        self.elimination_time = None
    
    def update_heartbeat(self):
        self.last_heartbeat = time.time()
        self.status = "online"
    
    def check_timeout(self):
        now = time.time()
        elapsed = now - self.last_heartbeat
        
        if self.eliminated:
            return
        
        if elapsed > config.DISCONNECT_PENALTY_TIME:
            self.eliminated = True
            self.elimination_reason = "心跳超时淘汰"
            self.elimination_time = datetime.now().isoformat()
            self.status = "eliminated"
            log_event("elimination", f"选手 {self.player_id} 因心跳超时被淘汰")
        elif elapsed > config.DISCONNECT_WARNING_TIME:
            self.status = "warning"

class HeartbeatServer:
    def __init__(self):
        self.players = {}
        self.lock = threading.Lock()
        self.server_socket = None
        self.running = False
        self._buffer_size = 4096
    
    def handle_client(self, client_socket, client_address):
        client_socket.settimeout(60)
        try:
            while self.running:
                data = client_socket.recv(self._buffer_size)
                if not data:
                    break
                
                try:
                    heartbeat_data = json.loads(data.decode('utf-8'))
                    player_id = heartbeat_data.get('player_id')
                    primary_ip = heartbeat_data.get('primary_ip')
                    os_type = heartbeat_data.get('os_type', 'unknown')
                    
                    with self.lock:
                        if player_id not in self.players:
                            self.players[player_id] = PlayerState(player_id, primary_ip, os_type)
                            log_event("connection", f"新选手连接: {player_id} ({primary_ip}, {os_type})")
                        
                        player = self.players[player_id]
                        player.primary_ip = primary_ip
                        player.update_heartbeat()
                        
                except json.JSONDecodeError:
                    log_event("error", f"无效心跳数据: {client_address}")
                
                time.sleep(config.HEARTBEAT_INTERVAL)
                
        except socket.timeout:
            log_event("error", f"客户端超时: {client_address}")
        except Exception as e:
            log_event("error", f"客户端处理异常: {client_address}, {str(e)}")
        finally:
            client_socket.close()
    
    def check_timeouts(self):
        while self.running:
            time.sleep(1)
            with self.lock:
                for player in list(self.players.values()):
                    player.check_timeout()
    
    def start(self):
        self.running = True
        
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server_socket.bind((config.JUDGE_TCP_ADDRESSES[0], config.TCP_HEARTBEAT_PORT))
        self.server_socket.listen(200)
        self.server_socket.settimeout(1.0)
        
        log_event("server", f"TCP心跳服务启动于 {config.JUDGE_TCP_ADDRESSES[0]}:{config.TCP_HEARTBEAT_PORT}")
        
        timeout_thread = threading.Thread(target=self.check_timeouts, daemon=True)
        timeout_thread.start()
        
        while self.running:
            try:
                client_socket, client_address = self.server_socket.accept()
                client_thread = threading.Thread(target=self.handle_client, args=(client_socket, client_address), daemon=True)
                client_thread.start()
            except socket.timeout:
                continue
            except Exception as e:
                if self.running:
                    log_event("error", f"接受连接异常: {str(e)}")
    
    def stop(self):
        self.running = False
        if self.server_socket:
            self.server_socket.close()
        log_event("server", "TCP心跳服务已停止")

def log_event(event_type, message):
    timestamp = datetime.now().isoformat()
    log_entry = f"[{timestamp}] [{event_type}] {message}\n"
    
    log_file = os.path.join(config.LOG_DIR, "heartbeat.log")
    with open(log_file, "a", encoding="utf-8") as f:
        f.write(log_entry)

if __name__ == "__main__":
    server = HeartbeatServer()
    try:
        server.start()
    except KeyboardInterrupt:
        server.stop()
