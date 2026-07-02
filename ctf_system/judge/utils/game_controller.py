import time
import threading
import json
import os
from datetime import datetime, timedelta
from enum import Enum

class GameStage(Enum):
    FIX = "fix"
    STABILIZE = "stabilize"
    ATTACK = "attack"
    FINISHED = "finished"

class GameController:
    def __init__(self):
        self.current_stage = GameStage.FIX
        self.stage_start_time = datetime.now()
        
        self.fix_duration = timedelta(minutes=30)
        self.stabilize_duration = timedelta(minutes=5)
        self.attack_duration = timedelta(minutes=60)
        
        self.stage_timers = {
            GameStage.FIX: self.fix_duration,
            GameStage.STABILIZE: self.stabilize_duration,
            GameStage.ATTACK: self.attack_duration
        }
        
        self.running = False
        self.paused = False
        self.pause_start_time = None
        
        self.players = {}
        self.eliminated_players = {}
        
        self.warning_callbacks = []
        self.stage_change_callbacks = []
        
        self.broadcast_queue = []
        
        self.log_file = os.path.join("./logs", "game_controller.log")
        os.makedirs("./logs", exist_ok=True)
    
    def log(self, message):
        timestamp = datetime.now().isoformat()
        log_entry = f"[{timestamp}] {message}\n"
        with open(self.log_file, "a", encoding="utf-8") as f:
            f.write(log_entry)
        print(log_entry.strip())
    
    def add_player(self, player_id, primary_ip, os_type="unknown"):
        if player_id not in self.players:
            self.players[player_id] = {
                "primary_ip": primary_ip,
                "os_type": os_type,
                "status": "online",
                "eliminated": False,
                "elimination_time": None,
                "elimination_reason": None,
                "flag_captured": [],
                "vulnerabilities_fixed": []
            }
            self.log(f"选手 {player_id} 加入比赛 ({primary_ip}, {os_type})")
    
    def eliminate_player(self, player_id, reason):
        if player_id in self.players and not self.players[player_id]["eliminated"]:
            self.players[player_id]["eliminated"] = True
            self.players[player_id]["elimination_time"] = datetime.now().isoformat()
            self.players[player_id]["elimination_reason"] = reason
            self.players[player_id]["status"] = "eliminated"
            
            self.eliminated_players[player_id] = self.players[player_id]
            self.log(f"选手 {player_id} 被淘汰: {reason}")
            
            self.broadcast(f"选手 {player_id} 被淘汰: {reason}")
    
    def register_flag_capture(self, attacker_id, target_id, flag):
        if attacker_id in self.players:
            self.players[attacker_id]["flag_captured"].append({
                "target_id": target_id,
                "flag": flag,
                "timestamp": datetime.now().isoformat()
            })
            self.log(f"选手 {attacker_id} 成功捕获 {target_id} 的FLAG")
    
    def get_stage_remaining_time(self):
        if self.current_stage == GameStage.FINISHED:
            return timedelta(0)
        
        elapsed = datetime.now() - self.stage_start_time
        
        if self.paused and self.pause_start_time:
            elapsed -= (datetime.now() - self.pause_start_time)
        
        remaining = self.stage_timers[self.current_stage] - elapsed
        
        if remaining < timedelta(0):
            return timedelta(0)
        
        return remaining
    
    def get_stage_name(self):
        stage_names = {
            GameStage.FIX: "修复调试期",
            GameStage.STABILIZE: "稳定校验期",
            GameStage.ATTACK: "自由攻防期",
            GameStage.FINISHED: "比赛结束"
        }
        return stage_names[self.current_stage]
    
    def switch_stage(self, new_stage):
        if new_stage in GameStage:
            self.current_stage = new_stage
            self.stage_start_time = datetime.now()
            
            self.log(f"阶段切换: {self.get_stage_name()}")
            self.broadcast(f"阶段切换: {self.get_stage_name()}")
            
            for callback in self.stage_change_callbacks:
                callback(new_stage)
    
    def schedule_warnings(self):
        remaining = self.get_stage_remaining_time()
        minutes_remaining = int(remaining.total_seconds() / 60)
        
        if minutes_remaining == 5:
            self.log("距离阶段切换还有5分钟")
            self.broadcast("警告：距离阶段切换还有5分钟！")
            for callback in self.warning_callbacks:
                callback(5)
        
        elif minutes_remaining == 1:
            self.log("距离阶段切换还有1分钟")
            self.broadcast("警告：距离阶段切换还有1分钟！")
            for callback in self.warning_callbacks:
                callback(1)
    
    def run(self):
        self.running = True
        self.log("比赛控制器启动")
        self.broadcast("比赛开始！当前阶段：修复调试期")
        
        while self.running and self.current_stage != GameStage.FINISHED:
            if not self.paused:
                self.schedule_warnings()
                
                if self.get_stage_remaining_time() <= timedelta(0):
                    if self.current_stage == GameStage.FIX:
                        self.switch_stage(GameStage.STABILIZE)
                    elif self.current_stage == GameStage.STABILIZE:
                        self.switch_stage(GameStage.ATTACK)
                    elif self.current_stage == GameStage.ATTACK:
                        self.switch_stage(GameStage.FINISHED)
            
            time.sleep(1)
        
        self.log("比赛结束")
        self.broadcast("比赛结束！")
    
    def pause(self):
        if not self.paused:
            self.paused = True
            self.pause_start_time = datetime.now()
            self.log("比赛暂停")
            self.broadcast("比赛临时暂停")
    
    def resume(self):
        if self.paused and self.pause_start_time:
            self.stage_start_time += (datetime.now() - self.pause_start_time)
            self.paused = False
            self.pause_start_time = None
            self.log("比赛恢复")
            self.broadcast("比赛恢复")
    
    def broadcast(self, message):
        self.broadcast_queue.append({
            "timestamp": datetime.now().isoformat(),
            "message": message
        })
        if len(self.broadcast_queue) > 100:
            self.broadcast_queue.pop(0)
    
    def get_broadcasts(self):
        return self.broadcast_queue
    
    def get_player_status(self, player_id):
        return self.players.get(player_id, None)
    
    def get_all_players(self):
        return self.players
    
    def get_online_players(self):
        return {k: v for k, v in self.players.items() if v["status"] == "online"}
    
    def get_eliminated_players(self):
        return self.eliminated_players
    
    def stop(self):
        self.running = False
        self.log("比赛控制器停止")
    
    def add_warning_callback(self, callback):
        self.warning_callbacks.append(callback)
    
    def add_stage_change_callback(self, callback):
        self.stage_change_callbacks.append(callback)
    
    def calculate_rankings(self):
        survivors = [p for p in self.players.values() if not p["eliminated"]]
        
        if not survivors:
            eliminated = sorted(self.eliminated_players.values(), 
                               key=lambda x: x["elimination_time"] or "", reverse=True)
            return eliminated
        
        rankings = []
        
        for player in survivors:
            captured_count = len(player["flag_captured"])
            fixed_count = len(player["vulnerabilities_fixed"])
            
            score = captured_count * 10 + fixed_count
            
            rankings.append({
                "player_id": player["player_id"],
                "primary_ip": player["primary_ip"],
                "os_type": player["os_type"],
                "status": "survivor",
                "flags_captured": captured_count,
                "vulnerabilities_fixed": fixed_count,
                "score": score
            })
        
        rankings.sort(key=lambda x: x["score"], reverse=True)
        
        eliminated = sorted(self.eliminated_players.values(),
                           key=lambda x: x["elimination_time"] or "", reverse=True)
        
        for player in eliminated:
            rankings.append({
                "player_id": player["player_id"],
                "primary_ip": player["primary_ip"],
                "os_type": player["os_type"],
                "status": "eliminated",
                "elimination_reason": player["elimination_reason"],
                "elimination_time": player["elimination_time"]
            })
        
        return rankings
