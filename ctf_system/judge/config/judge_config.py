import os
from dataclasses import dataclass
from typing import List

@dataclass
class JudgeConfig:
    TCP_HEARTBEAT_PORT: int = 9999
    HTTP_SUBMIT_PORT: int = 8080
    DASHBOARD_PORT: int = 8000
    
    HEARTBEAT_INTERVAL: int = 5
    DISCONNECT_WARNING_TIME: int = 10
    DISCONNECT_PENALTY_TIME: int = 30
    
    FLAG_SUBMIT_RATE_LIMIT: int = 3
    FLAG_SUBMIT_TIME_WINDOW: int = 60
    
    MAX_PLAYER_RECONNECTS: int = 1
    
    FIX_PERIOD_MINUTES: int = 120
    STABILIZE_PERIOD_MINUTES: int = 5
    ATTACK_PERIOD_MINUTES: int = 60
    
    DOS_THRESHOLD: int = 100
    DOS_TIME_WINDOW: int = 10
    
    JUDGE_TCP_ADDRESSES: List[str] = None
    JUDGE_HTTP_ADDRESS: str = "0.0.0.0"
    
    LOG_DIR: str = "./logs"
    DATA_DIR: str = "./data"
    
    def __post_init__(self):
        if self.JUDGE_TCP_ADDRESSES is None:
            self.JUDGE_TCP_ADDRESSES = ["0.0.0.0"]
        
        os.makedirs(self.LOG_DIR, exist_ok=True)
        os.makedirs(self.DATA_DIR, exist_ok=True)

config = JudgeConfig()
