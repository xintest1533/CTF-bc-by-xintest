import os
from dataclasses import dataclass
from typing import List

@dataclass
class ClientConfig:
    PLAYER_ID: str = ""
    PRIMARY_IP: str = ""
    BACKUP_IP: str = ""
    
    JUDGE_TCP_ADDRESSES: List[str] = None
    JUDGE_TCP_PORT: int = 9999
    JUDGE_HTTP_ADDRESS: str = "http://127.0.0.1:8080"
    
    TARGET_PORT: int = 8000
    
    HEARTBEAT_INTERVAL: int = 5
    RECONNECT_TIMEOUT: int = 30
    MAX_RECONNECT_ATTEMPTS: int = 1
    
    LOG_DIR: str = "./logs"
    FLAG_FILE: str = "./data/flag.txt"
    CREDENTIALS_FILE: str = "./data/credentials.json"
    IP_CONFIG_FILE: str = "./ip_config.ini"
    
    DOS_THRESHOLD: int = 100
    DOS_TIME_WINDOW: int = 10
    
    def __post_init__(self):
        if self.JUDGE_TCP_ADDRESSES is None:
            self.JUDGE_TCP_ADDRESSES = ["127.0.0.1"]
        
        os.makedirs(self.LOG_DIR, exist_ok=True)
        os.makedirs(os.path.dirname(self.FLAG_FILE), exist_ok=True)

config = ClientConfig()
