import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import json
import time
from datetime import datetime
from flask import Flask, request, jsonify
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from functools import lru_cache

from config.judge_config import config

app = Flask(__name__)
limiter = Limiter(get_remote_address, app=app)

flags = {}
flag_submissions = {}
submission_log = []
current_stage = "fix"

stage_timers = {
    "fix_end_time": 0,
    "stabilize_end_time": 0,
    "attack_end_time": 0
}

def load_flags():
    flags_file = os.path.join(config.DATA_DIR, "flags.json")
    if os.path.exists(flags_file):
        try:
            with open(flags_file, "r", encoding="utf-8") as f:
                return json.load(f)
        except:
            return {}
    return {}

def save_flags():
    flags_file = os.path.join(config.DATA_DIR, "flags.json")
    try:
        os.makedirs(os.path.dirname(flags_file), exist_ok=True)
        with open(flags_file, "w", encoding="utf-8") as f:
            json.dump(flags, f, indent=2)
    except Exception as e:
        log_submission("error", f"保存FLAG失败: {str(e)}")

def register_player(player_id, flag):
    flags[player_id] = {
        "flag": flag,
        "eliminated": False,
        "elimination_time": None,
        "eliminated_by": None
    }
    save_flags()
    log_submission("register", f"选手 {player_id} 注册，FLAG: {flag}")

def validate_flag(target_id, submitted_flag):
    if target_id not in flags:
        return False, "目标选手不存在"
    
    if flags[target_id]["eliminated"]:
        return False, "目标选手已被淘汰"
    
    if flags[target_id]["flag"] == submitted_flag:
        return True, "验证成功"
    
    return False, "FLAG不匹配"

def log_submission(event_type, message):
    timestamp = datetime.now().isoformat()
    log_entry = {
        "timestamp": timestamp,
        "type": event_type,
        "message": message
    }
    submission_log.append(log_entry)
    
    if len(submission_log) > 10000:
        submission_log.pop(0)
    
    log_file = os.path.join(config.LOG_DIR, "submission.log")
    try:
        os.makedirs(os.path.dirname(log_file), exist_ok=True)
        with open(log_file, "a", encoding="utf-8") as f:
            f.write(json.dumps(log_entry, ensure_ascii=False) + "\n")
    except Exception as e:
        print(f"日志写入失败: {str(e)}")

@app.route('/submit_flag', methods=['POST'])
@limiter.limit(f"{config.FLAG_SUBMIT_RATE_LIMIT} per {config.FLAG_SUBMIT_TIME_WINDOW} seconds")
def submit_flag():
    global current_stage
    
    if current_stage != "attack":
        return jsonify({
            "success": False,
            "message": f"当前阶段不允许提交FLAG（当前阶段: {current_stage}）"
        }), 403
    
    try:
        data = request.get_json()
        if not data:
            return jsonify({
                "success": False,
                "message": "无效的JSON数据"
            }), 400
        
        attacker_id = data.get('attacker_id')
        target_id = data.get('target_id')
        flag = data.get('flag')
        
        if not all([attacker_id, target_id, flag]):
            return jsonify({
                "success": False,
                "message": "缺少必要参数（attacker_id, target_id, flag）"
            }), 400
        
        if attacker_id == target_id:
            return jsonify({
                "success": False,
                "message": "不允许提交自己的FLAG"
            }), 400
        
        success, reason = validate_flag(target_id, flag)
        
        if success:
            flags[target_id]["eliminated"] = True
            flags[target_id]["elimination_time"] = datetime.now().isoformat()
            flags[target_id]["eliminated_by"] = attacker_id
            save_flags()
            
            log_submission("flag_capture", {
                "attacker_id": attacker_id,
                "target_id": target_id,
                "flag": flag,
                "timestamp": datetime.now().isoformat()
            })
            
            return jsonify({
                "success": True,
                "message": f"FLAG提交成功！选手 {target_id} 已被淘汰"
            })
        else:
            log_submission("flag_failed", {
                "attacker_id": attacker_id,
                "target_id": target_id,
                "reason": reason,
                "timestamp": datetime.now().isoformat()
            })
            
            return jsonify({
                "success": False,
                "message": reason
            }), 401
            
    except Exception as e:
        log_submission("error", f"FLAG提交异常: {str(e)}")
        return jsonify({
            "success": False,
            "message": "服务器内部错误"
        }), 500

@app.route('/register', methods=['POST'])
def register():
    try:
        data = request.get_json()
        if not data:
            return jsonify({"success": False, "message": "无效的JSON数据"}), 400
        
        player_id = data.get('player_id')
        flag = data.get('flag')
        
        if not player_id or not flag:
            return jsonify({"success": False, "message": "缺少必要参数（player_id, flag）"}), 400
        
        if player_id in flags:
            return jsonify({"success": False, "message": "选手已注册"}), 409
        
        register_player(player_id, flag)
        
        return jsonify({
            "success": True,
            "message": "注册成功"
        })
    except Exception as e:
        log_submission("error", f"注册异常: {str(e)}")
        return jsonify({"success": False, "message": "服务器内部错误"}), 500

@app.route('/stage', methods=['GET', 'POST'])
def stage():
    global current_stage
    
    if request.method == 'GET':
        return jsonify({
            "current_stage": current_stage,
            "timers": stage_timers
        })
    else:
        try:
            data = request.get_json()
            if not data:
                return jsonify({"success": False, "message": "无效的JSON数据"}), 400
            
            new_stage = data.get('stage')
            if new_stage in ["fix", "stabilize", "attack", "finished"]:
                current_stage = new_stage
                log_submission("stage_change", f"阶段切换: {new_stage}")
                return jsonify({"success": True, "message": f"阶段已切换至: {new_stage}"})
            return jsonify({"success": False, "message": "无效阶段"}), 400
        except Exception as e:
            log_submission("error", f"阶段切换异常: {str(e)}")
            return jsonify({"success": False, "message": "服务器内部错误"}), 500

@app.route('/status', methods=['GET'])
def status():
    return jsonify({
        "flags_count": len(flags),
        "current_stage": current_stage,
        "submissions_count": len(submission_log)
    })

@app.route('/players', methods=['GET'])
def players():
    return jsonify({
        "players": [{"player_id": pid, "eliminated": data["eliminated"]} for pid, data in flags.items()]
    })

@app.route('/ping', methods=['GET'])
def ping():
    return jsonify({"status": "ok", "timestamp": datetime.now().isoformat()})

@app.errorhandler(404)
def not_found(error):
    return jsonify({"success": False, "message": "未找到接口"}), 404

@app.errorhandler(429)
def rate_limit_exceeded(error):
    return jsonify({"success": False, "message": "请求过于频繁，请稍后重试"}), 429

if __name__ == "__main__":
    flags = load_flags()
    try:
        app.run(host=config.JUDGE_HTTP_ADDRESS, port=config.HTTP_SUBMIT_PORT, debug=False, threaded=True)
    except Exception as e:
        log_submission("error", f"服务启动失败: {str(e)}")