import time
import os
import hashlib
import json
from datetime import datetime
from collections import defaultdict

class AntiCheatSystem:
    def __init__(self):
        self.dos_detections = {}
        self.hash_records = {}
        self.violation_log = []
        
        self.dos_threshold = 100
        self.dos_time_window = 10
        
        self.log_file = os.path.join("./logs", "anti_cheat.log")
        self.hash_file = os.path.join("./data", "hash_records.json")
        
        os.makedirs("./logs", exist_ok=True)
        os.makedirs("./data", exist_ok=True)
    
    def log(self, message):
        timestamp = datetime.now().isoformat()
        log_entry = f"[{timestamp}] {message}\n"
        with open(self.log_file, "a", encoding="utf-8") as f:
            f.write(log_entry)
        print(log_entry.strip())
    
    def log_violation(self, player_id, violation_type, details):
        violation = {
            "timestamp": datetime.now().isoformat(),
            "player_id": player_id,
            "violation_type": violation_type,
            "details": details
        }
        self.violation_log.append(violation)
        
        violation_log_file = os.path.join("./logs", "violations.log")
        with open(violation_log_file, "a", encoding="utf-8") as f:
            f.write(json.dumps(violation, ensure_ascii=False) + "\n")
        
        self.log(f"违规记录 - {player_id}: {violation_type} - {details}")
    
    def check_dos(self, player_id, ip):
        now = time.time()
        
        if ip not in self.dos_detections:
            self.dos_detections[ip] = {
                "requests": [],
                "player_id": player_id
            }
        
        self.dos_detections[ip]["requests"] = [
            t for t in self.dos_detections[ip]["requests"] 
            if now - t < self.dos_time_window
        ]
        
        self.dos_detections[ip]["requests"].append(now)
        
        request_count = len(self.dos_detections[ip]["requests"])
        
        if request_count > self.dos_threshold:
            self.log_violation(player_id, "DOS_ATTACK", 
                              f"检测到DoS攻击: {request_count}次请求/{self.dos_time_window}秒")
            return True
        
        return False
    
    def record_hash(self, player_id, file_path, file_hash):
        if player_id not in self.hash_records:
            self.hash_records[player_id] = {}
        
        self.hash_records[player_id][file_path] = {
            "hash": file_hash,
            "timestamp": datetime.now().isoformat()
        }
        
        with open(self.hash_file, "w", encoding="utf-8") as f:
            json.dump(self.hash_records, f, indent=2)
    
    def verify_hash(self, player_id, file_path, current_hash):
        if player_id not in self.hash_records:
            return True, "未找到选手哈希记录"
        
        if file_path not in self.hash_records[player_id]:
            return True, "未找到文件哈希记录"
        
        original_hash = self.hash_records[player_id][file_path]["hash"]
        
        if original_hash != current_hash:
            self.log_violation(player_id, "HASH_MISMATCH",
                              f"文件 {file_path} 哈希值不匹配")
            return False, "哈希值不匹配"
        
        return True, "哈希值验证通过"
    
    def verify_all_hashes(self, player_id, hashes):
        results = []
        all_valid = True
        
        for file_path, current_hash in hashes.items():
            valid, message = self.verify_hash(player_id, file_path, current_hash)
            results.append({
                "file": file_path,
                "valid": valid,
                "message": message
            })
            if not valid:
                all_valid = False
        
        return all_valid, results
    
    def load_hash_records(self):
        if os.path.exists(self.hash_file):
            with open(self.hash_file, "r", encoding="utf-8") as f:
                self.hash_records = json.load(f)
    
    def get_violations(self):
        return self.violation_log
    
    def get_player_violations(self, player_id):
        return [v for v in self.violation_log if v["player_id"] == player_id]
    
    def check_ip_config_modification(self, player_id, ip_config_hash, stage):
        if stage not in ["stabilize", "attack"]:
            return True, "当前阶段允许修改IP配置"
        
        if player_id not in self.hash_records:
            return True, "未找到选手记录"
        
        if "ip_config.ini" not in self.hash_records[player_id]:
            return True, "未找到IP配置文件哈希记录"
        
        original_hash = self.hash_records[player_id]["ip_config.ini"]["hash"]
        
        if original_hash != ip_config_hash:
            self.log_violation(player_id, "IP_CONFIG_MODIFICATION",
                              f"{stage}阶段修改了IP配置文件")
            return False, "IP配置文件被修改"
        
        return True, "IP配置文件未被修改"

class HashCalculator:
    @staticmethod
    def calculate_file_hash(file_path):
        if not os.path.exists(file_path):
            return None
        
        sha256_hash = hashlib.sha256()
        
        try:
            with open(file_path, 'rb') as f:
                for chunk in iter(lambda: f.read(8192), b''):
                    sha256_hash.update(chunk)
            return sha256_hash.hexdigest()
        except Exception as e:
            return None
    
    @staticmethod
    def calculate_directory_hash(directory):
        hashes = {}
        
        for root, dirs, files in os.walk(directory):
            for file in files:
                if file.endswith('.py') or file.endswith('.json') or file.endswith('.ini'):
                    file_path = os.path.join(root, file)
                    file_hash = HashCalculator.calculate_file_hash(file_path)
                    if file_hash:
                        rel_path = os.path.relpath(file_path, directory)
                        hashes[rel_path] = file_hash
        
        return hashes
