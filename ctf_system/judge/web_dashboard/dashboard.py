import os
import json
import time
from datetime import datetime, timedelta
from flask import Flask, render_template_string, jsonify, request

app = Flask(__name__)

game_controller = None
heartbeat_server = None
submit_server = None

def set_controllers(controller, heartbeat, submit):
    global game_controller, heartbeat_server, submit_server
    game_controller = controller
    heartbeat_server = heartbeat
    submit_server = submit

def format_timedelta(td):
    hours = td.seconds // 3600
    minutes = (td.seconds % 3600) // 60
    seconds = td.seconds % 60
    return f"{hours:02d}:{minutes:02d}:{seconds:02d}"

@app.route('/')
def index():
    return render_template_string("""
    <!DOCTYPE html>
    <html lang="zh-CN">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>CTF攻防对抗赛事 - 裁判看板</title>
        <style>
            * { margin: 0; padding: 0; box-sizing: border-box; }
            body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background: #1a1a2e; color: #fff; }
            .header { background: #16213e; padding: 20px; text-align: center; border-bottom: 2px solid #e94560; }
            .header h1 { font-size: 24px; margin-bottom: 10px; }
            .stage-info { display: flex; justify-content: center; gap: 30px; }
            .stage { padding: 10px 20px; border-radius: 20px; font-weight: bold; }
            .stage.fix { background: #2ecc71; color: #fff; }
            .stage.stabilize { background: #f39c12; color: #fff; }
            .stage.attack { background: #e74c3c; color: #fff; }
            .stage.finished { background: #95a5a6; color: #fff; }
            .content { padding: 20px; display: grid; grid-template-columns: 1fr 1fr; gap: 20px; }
            .card { background: #16213e; border-radius: 10px; padding: 20px; }
            .card h2 { color: #e94560; margin-bottom: 15px; font-size: 18px; }
            .player-list { list-style: none; max-height: 400px; overflow-y: auto; }
            .player-item { display: flex; justify-content: space-between; align-items: center; padding: 10px; 
                          background: rgba(255,255,255,0.05); margin-bottom: 5px; border-radius: 5px; }
            .player-item.online { border-left: 3px solid #2ecc71; }
            .player-item.warning { border-left: 3px solid #f39c12; }
            .player-item.eliminated { border-left: 3px solid #e74c3c; opacity: 0.6; }
            .os-badge { font-size: 10px; padding: 2px 5px; border-radius: 3px; }
            .os-windows { background: #0078d7; }
            .os-linux { background: #fcc624; color: #000; }
            .os-macos { background: #555; }
            .stats { display: grid; grid-template-columns: repeat(3, 1fr); gap: 15px; }
            .stat-box { text-align: center; padding: 15px; background: rgba(255,255,255,0.05); border-radius: 5px; }
            .stat-value { font-size: 24px; font-weight: bold; color: #e94560; }
            .stat-label { font-size: 12px; color: #aaa; }
            .log-list { list-style: none; max-height: 200px; overflow-y: auto; font-size: 12px; }
            .log-item { padding: 5px 0; border-bottom: 1px solid rgba(255,255,255,0.1); }
            .log-time { color: #aaa; margin-right: 10px; }
            .log-message { color: #fff; }
            .flag-submission { background: rgba(46, 204, 113, 0.1); padding: 10px; border-radius: 5px; margin-bottom: 5px; }
            .flag-submission.success { border-left: 3px solid #2ecc71; }
            .flag-submission.failed { border-left: 3px solid #e74c3c; }
            .ranking-table { width: 100%; border-collapse: collapse; }
            .ranking-table th, .ranking-table td { padding: 8px; text-align: left; border-bottom: 1px solid rgba(255,255,255,0.1); }
            .ranking-table th { background: rgba(255,255,255,0.05); }
            .rank-1 { background: rgba(243, 156, 18, 0.2); }
            .rank-2 { background: rgba(156, 163, 175, 0.2); }
            .rank-3 { background: rgba(184, 115, 51, 0.2); }
            .controls { display: flex; gap: 10px; margin-top: 20px; }
            .btn { padding: 10px 20px; border: none; border-radius: 5px; cursor: pointer; font-weight: bold; }
            .btn-primary { background: #e94560; color: #fff; }
            .btn-secondary { background: #3498db; color: #fff; }
            .btn-danger { background: #e74c3c; color: #fff; }
            .btn-success { background: #2ecc71; color: #fff; }
        </style>
    </head>
    <body>
        <div class="header">
            <h1>CTF攻防对抗赛事 - 裁判看板</h1>
            <div class="stage-info">
                <div class="stage" id="current-stage">加载中...</div>
                <div class="stage" id="remaining-time">--:--:--</div>
            </div>
        </div>
        
        <div class="content">
            <div class="card">
                <h2>选手状态</h2>
                <div class="stats">
                    <div class="stat-box">
                        <div class="stat-value" id="online-count">0</div>
                        <div class="stat-label">在线</div>
                    </div>
                    <div class="stat-box">
                        <div class="stat-value" id="warning-count">0</div>
                        <div class="stat-label">警告</div>
                    </div>
                    <div class="stat-box">
                        <div class="stat-value" id="eliminated-count">0</div>
                        <div class="stat-label">淘汰</div>
                    </div>
                </div>
                <ul class="player-list" id="player-list"></ul>
            </div>
            
            <div class="card">
                <h2>实时战报</h2>
                <ul class="log-list" id="broadcast-logs"></ul>
            </div>
            
            <div class="card">
                <h2>FLAG提交流水</h2>
                <ul class="log-list" id="flag-submissions"></ul>
            </div>
            
            <div class="card">
                <h2>当前排名</h2>
                <table class="ranking-table" id="ranking-table">
                    <thead>
                        <tr>
                            <th>排名</th>
                            <th>选手ID</th>
                            <th>操作系统</th>
                            <th>状态</th>
                            <th>得分</th>
                            <th>淘汰原因</th>
                        </tr>
                    </thead>
                    <tbody></tbody>
                </table>
            </div>
        </div>
        
        <div class="content">
            <div class="card">
                <h2>赛事控制</h2>
                <div class="controls">
                    <button class="btn btn-primary" onclick="startGame()">开始比赛</button>
                    <button class="btn btn-secondary" onclick="pauseGame()">暂停比赛</button>
                    <button class="btn btn-success" onclick="resumeGame()">恢复比赛</button>
                    <button class="btn btn-danger" onclick="stopGame()">结束比赛</button>
                </div>
                <div class="controls" style="margin-top: 10px;">
                    <button class="btn" style="background: #2ecc71;" onclick="switchStage('fix')">修复期</button>
                    <button class="btn" style="background: #f39c12;" onclick="switchStage('stabilize')">稳定期</button>
                    <button class="btn" style="background: #e74c3c;" onclick="switchStage('attack')">攻击期</button>
                    <button class="btn" style="background: #95a5a6;" onclick="switchStage('finished')">结束</button>
                </div>
            </div>
        </div>
        
        <script>
            function updateDashboard() {
                fetch('/api/status')
                    .then(res => res.json())
                    .then(data => {
                        document.getElementById('current-stage').textContent = data.stage_name;
                        document.getElementById('current-stage').className = 'stage ' + data.stage;
                        document.getElementById('remaining-time').textContent = data.remaining_time;
                        
                        document.getElementById('online-count').textContent = data.online_count;
                        document.getElementById('warning-count').textContent = data.warning_count;
                        document.getElementById('eliminated-count').textContent = data.eliminated_count;
                        
                        let playerList = document.getElementById('player-list');
                        playerList.innerHTML = '';
                        data.players.forEach(p => {
                            let item = document.createElement('li');
                            item.className = 'player-item ' + p.status;
                            let osClass = 'os-' + p.os_type.toLowerCase();
                            if (!['os-windows', 'os-linux', 'os-macos'].includes(osClass)) osClass = 'os-linux';
                            item.innerHTML = `
                                <div>
                                    <strong>${p.player_id}</strong>
                                    <span class="os-badge ${osClass}">${p.os_type}</span>
                                </div>
                                <div style="text-align: right;">
                                    <div style="font-size: 12px; color: #aaa;">${p.primary_ip}</div>
                                    ${p.eliminated ? '<div style="font-size: 12px; color: #e74c3c;">' + p.elimination_reason + '</div>' : ''}
                                </div>
                            `;
                            playerList.appendChild(item);
                        });
                        
                        let broadcastLogs = document.getElementById('broadcast-logs');
                        broadcastLogs.innerHTML = '';
                        data.broadcasts.slice(-20).forEach(log => {
                            let item = document.createElement('li');
                            item.className = 'log-item';
                            item.innerHTML = `<span class="log-time">${log.timestamp}</span><span class="log-message">${log.message}</span>`;
                            broadcastLogs.appendChild(item);
                        });
                        
                        let flagSubmissions = document.getElementById('flag-submissions');
                        flagSubmissions.innerHTML = '';
                        data.flag_submissions.slice(-20).forEach(sub => {
                            let item = document.createElement('div');
                            item.className = 'flag-submission ' + (sub.success ? 'success' : 'failed');
                            item.innerHTML = `
                                <div style="font-weight: bold;">${sub.success ? '✓ 成功' : '✗ 失败'}</div>
                                <div style="font-size: 12px;">${sub.attacker_id} → ${sub.target_id}</div>
                                <div style="font-size: 10px; color: #aaa;">${sub.timestamp}</div>
                            `;
                            flagSubmissions.appendChild(item);
                        });
                        
                        let rankingTable = document.getElementById('ranking-table');
                        let tbody = rankingTable.querySelector('tbody');
                        tbody.innerHTML = '';
                        data.rankings.forEach((rank, index) => {
                            let row = document.createElement('tr');
                            if (index < 3) row.className = 'rank-' + (index + 1);
                            row.innerHTML = `
                                <td>${index + 1}</td>
                                <td>${rank.player_id}</td>
                                <td>${rank.os_type}</td>
                                <td>${rank.status === 'survivor' ? '存活' : '淘汰'}</td>
                                <td>${rank.score || '-'}</td>
                                <td>${rank.elimination_reason || '-'}</td>
                            `;
                            tbody.appendChild(row);
                        });
                    });
            }
            
            function startGame() {
                fetch('/api/start', { method: 'POST' });
            }
            
            function pauseGame() {
                fetch('/api/pause', { method: 'POST' });
            }
            
            function resumeGame() {
                fetch('/api/resume', { method: 'POST' });
            }
            
            function stopGame() {
                fetch('/api/stop', { method: 'POST' });
            }
            
            function switchStage(stage) {
                fetch('/api/stage', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ stage: stage })
                });
            }
            
            setInterval(updateDashboard, 2000);
            updateDashboard();
        </script>
    </body>
    </html>
    """)

@app.route('/api/status')
def api_status():
    if game_controller is None:
        return jsonify({
            "stage": "unknown",
            "stage_name": "未知",
            "remaining_time": "--:--:--",
            "players": [],
            "online_count": 0,
            "warning_count": 0,
            "eliminated_count": 0,
            "broadcasts": [],
            "flag_submissions": [],
            "rankings": []
        })
    
    remaining = game_controller.get_stage_remaining_time()
    
    players = []
    online_count = 0
    warning_count = 0
    eliminated_count = 0
    
    for player_id, data in game_controller.get_all_players().items():
        players.append({
            "player_id": player_id,
            "primary_ip": data["primary_ip"],
            "os_type": data["os_type"],
            "status": data["status"],
            "eliminated": data["eliminated"],
            "elimination_reason": data.get("elimination_reason", "")
        })
        if data["status"] == "online":
            online_count += 1
        elif data["status"] == "warning":
            warning_count += 1
        elif data["status"] == "eliminated":
            eliminated_count += 1
    
    flag_submissions = []
    if submit_server:
        flag_submissions = [s for s in submit_server.submission_log if s["type"] in ["flag_capture", "flag_failed"]][-20:]
    
    return jsonify({
        "stage": game_controller.current_stage.value,
        "stage_name": game_controller.get_stage_name(),
        "remaining_time": format_timedelta(remaining),
        "players": players,
        "online_count": online_count,
        "warning_count": warning_count,
        "eliminated_count": eliminated_count,
        "broadcasts": game_controller.get_broadcasts()[-20:],
        "flag_submissions": flag_submissions,
        "rankings": game_controller.calculate_rankings()
    })

@app.route('/api/start', methods=['POST'])
def api_start():
    if game_controller:
        game_controller.run()
        return jsonify({"success": True, "message": "比赛已开始"})
    return jsonify({"success": False, "message": "控制器未初始化"})

@app.route('/api/pause', methods=['POST'])
def api_pause():
    if game_controller:
        game_controller.pause()
        return jsonify({"success": True, "message": "比赛已暂停"})
    return jsonify({"success": False, "message": "控制器未初始化"})

@app.route('/api/resume', methods=['POST'])
def api_resume():
    if game_controller:
        game_controller.resume()
        return jsonify({"success": True, "message": "比赛已恢复"})
    return jsonify({"success": False, "message": "控制器未初始化"})

@app.route('/api/stop', methods=['POST'])
def api_stop():
    if game_controller:
        game_controller.stop()
        return jsonify({"success": True, "message": "比赛已结束"})
    return jsonify({"success": False, "message": "控制器未初始化"})

@app.route('/api/stage', methods=['POST'])
def api_stage():
    if game_controller:
        data = request.get_json()
        stage = data.get('stage')
        from judge.utils.game_controller import GameStage
        if stage:
            game_controller.switch_stage(GameStage(stage))
            return jsonify({"success": True, "message": f"阶段已切换至: {stage}"})
    return jsonify({"success": False, "message": "无效操作"})

if __name__ == "__main__":
    app.run(host='0.0.0.0', port=8000, debug=False)
