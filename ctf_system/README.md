# CTF攻防对抗赛事系统

一套完整的对等双向CTF攻防对抗赛事系统，包含公网裁判服务和跨平台选手本地靶机客户端。

## 项目结构

```
ctf_system/
├── judge/                    # 裁判服务
│   ├── config/               # 配置文件
│   │   └── judge_config.py
│   ├── tcp_heartbeat/        # TCP心跳服务
│   │   └── heartbeat_server.py
│   ├── http_submit/          # HTTP FLAG提交接口
│   │   └── submit_server.py
│   ├── web_dashboard/        # Web可视化看板
│   │   └── dashboard.py
│   └── utils/                # 工具模块
│       ├── game_controller.py
│       └── anti_cheat.py
├── target_client/            # 选手客户端
│   ├── config/               # 配置文件
│   │   └── client_config.py
│   ├── utils/                # 工具模块
│   │   ├── ip_config.py
│   │   └── heartbeat_client.py
│   ├── scripts/              # 脚本
│   │   └── submit_flag.py
│   ├── target_server.py      # 靶机服务（含6类漏洞）
│   ├── run_client.py         # 客户端启动入口
│   └── ip_config.ini         # IP配置文件
├── scripts/                  # 辅助脚本
│   ├── firewall/             # 防火墙关闭脚本
│   ├── connectivity/         # 连通性检测脚本
│   └── startup/              # 启动脚本
└── requirements.txt          # 依赖包
```

## 功能特性

### 裁判服务
- TCP长连接心跳服务（9999端口）
- HTTP FLAG提交接口（8080端口）
- Web可视化看板（8000端口）
- 三阶段比赛时序控制
- 选手状态管理与淘汰机制
- 防作弊与公平机制

### 靶机客户端
- 6类内置漏洞：HEADache、弱密码、任意文件读取、XSS、SSTI、CSP
- 修复期加固接口
- 跨平台IP配置校验
- 断线重连与复活机制
- 本地日志持久化

### 跨平台支持
- Windows、Mac、Linux全平台适配
- 统一防火墙关闭脚本
- 统一连通性检测脚本

## 快速开始

### 环境要求
- Python 3.7+
- 安装依赖：`pip install -r requirements.txt`

### 启动裁判服务
```bash
cd ctf_system
python judge/tcp_heartbeat/heartbeat_server.py &
python judge/http_submit/submit_server.py &
python judge/web_dashboard/dashboard.py &
```

### 启动选手客户端
```bash
cd ctf_system/target_client
# 先配置 ip_config.ini
python run_client.py
```

## 比赛流程

1. **修复调试期（30分钟）**：修改源码、修复漏洞、修改密码
2. **稳定校验期（5分钟）**：禁止修改，仅查看日志
3. **自由攻防期（60分钟）**：渗透其他选手靶机，提交FLAG

## FLAG提交

```bash
# curl方式
curl -X POST http://<裁判IP>:8080/submit_flag \
  -H "Content-Type: application/json" \
  -d '{"attacker_id":"player1","target_id":"player2","flag":"FLAG{xxx}"}'

# Python脚本方式
python submit_flag.py player1 player2 FLAG{xxx}
```

## 配置说明

### ip_config.ini
```ini
[NETWORK]
primary_ip = 192.168.1.100
backup_ip = 192.168.1.101
```

## 安全规则
- 未关闭防火墙者禁止参赛
- DoS攻击者直接淘汰
- 稳定/攻击期修改源码判定违规
- 断线超30秒未重连判定淘汰
- 每位选手仅一次复活机会
