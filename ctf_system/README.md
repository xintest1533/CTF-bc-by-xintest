# CTF攻防对抗赛事系统

## 简介

一套完整的对等双向CTF攻防对抗赛事系统，支持Windows/Mac/Linux全平台参赛，包含公网裁判服务和跨平台选手本地靶机客户端。

## 项目结构

```
ctf_system/
├── judge/
│   ├── config/judge_config.py
│   ├── tcp_heartbeat/heartbeat_server.py
│   ├── http_submit/submit_server.py
│   ├── web_dashboard/dashboard.py
│   └── utils/
│       ├── game_controller.py
│       └── anti_cheat.py
├── target_client/
│   ├── config/client_config.py
│   ├── target_server.py
│   ├── run_client.py
│   ├── ip_config.ini
│   ├── utils/
│   │   ├── ip_config.py
│   │   └── heartbeat_client.py
│   └── scripts/submit_flag.py
├── scripts/
│   ├── firewall/
│   ├── connectivity/
│   └── startup/
├── requirements.txt
└── README.md
```

## 环境要求

- Python 3.7+
- pip install -r requirements.txt

## 快速开始

### 1. 安装依赖

```bash
cd ctf_system
pip install -r requirements.txt
```

### 2. 启动裁判服务

**方式一：一键部署（推荐）**

```bash
# 下载并执行一键部署脚本
wget https://gitee.com/ctf-platform/ctf-attack-defense-system/raw/master/scripts/startup/deploy_judge.sh -O deploy.sh
sudo chmod +x deploy.sh
sudo ./deploy.sh
```

脚本会自动完成：
- 克隆代码到 `/opt/ctf-attack-defense-system`
- 安装 Python 依赖
- 配置防火墙（firewalld/ufw/iptables）
- 创建 systemd 服务并开机自启
- 验证服务状态

**方式二：手动启动**

```bash
# 方式一：分别启动
python judge/tcp_heartbeat/heartbeat_server.py &
python judge/http_submit/submit_server.py &
python judge/web_dashboard/dashboard.py &

# 方式二：使用启动脚本
bash scripts/startup/start_judge.sh
```

服务端口：
- TCP心跳服务: 9999
- HTTP提交接口: 8080
- Web可视化看板: 8000

### 3. 启动选手客户端

**第一步：配置IP**

编辑 `target_client/ip_config.ini`：

```ini
[NETWORK]
primary_ip = 192.168.1.100
backup_ip = 192.168.1.101
```

**第二步：关闭防火墙**

Windows：
```cmd
scripts\firewall\disable_firewall_windows.bat
```

Linux：
```bash
sudo bash scripts/firewall/disable_firewall_linux.sh
```

Mac：
```bash
sudo bash scripts/firewall/disable_firewall_mac.sh
```

**第三步：检测连通性**

Windows：
```cmd
scripts\connectivity\check_connectivity_windows.bat
```

Linux：
```bash
bash scripts/connectivity/check_connectivity_linux.sh
```

Mac：
```bash
bash scripts/connectivity/check_connectivity_mac.sh
```

**第四步：启动客户端**

```bash
cd target_client
python run_client.py
```

## 比赛流程

### 第一阶段：修复调试期（2小时）

允许操作：
- 修改靶机源码
- 调用加固接口修复漏洞
- 修改默认密码 admin/admin123
- 内网扫描探测其他选手

禁止操作：
- 提交FLAG
- DoS压测

### 第二阶段：稳定校验期（5分钟）

允许操作：
- 查看本机访问日志

禁止操作：
- 修改靶机代码
- 重启客户端
- 修改IP配置文件

淘汰条件：
- TCP心跳断线超30秒
- 靶机Web服务进程崩溃

### 第三阶段：自由攻防期（60分钟）

允许操作：
- 查看本机攻击日志
- 渗透其他选手靶机
- 提交FLAG

禁止操作：
- 修改自身防御配置
- 修改IP配置文件

## 漏洞说明

靶机为企业内部管理系统，共2000+行代码，内置7类漏洞，需在修复期（2小时）发现并修复：

### 漏洞一：SQL注入漏洞

位置：`/documents?search=`

触发点：文档搜索功能的search参数直接拼接SQL查询

特征：通过构造恶意搜索语句，可绕过查询限制获取数据库全部数据

难度：★★★☆☆

### 漏洞二：任意文件上传漏洞

位置：`/files/upload`

触发点：文件上传功能未校验文件类型和扩展名

特征：可上传任意类型文件（包括.php、.py等可执行文件），上传路径可预测

难度：★★☆☆☆

### 漏洞三：命令执行漏洞

位置：`/admin/system_info`

触发点：系统信息页面的cmd参数直接传入shell执行

特征：管理员可执行任意系统命令，获取服务器完全控制权

难度：★★★☆☆

### 漏洞四：反序列化漏洞

位置：`/admin/import`

触发点：数据导入功能使用pickle反序列化用户上传文件

特征：上传恶意构造的.pkl文件，可在服务器执行任意代码

难度：★★★★☆

### 漏洞五：SSRF服务端请求伪造

位置：`/api/proxy`

触发点：API代理功能的url参数由用户控制

特征：可利用服务器发起内网请求，探测内网服务，读取本地文件

难度：★★★☆☆

### 漏洞六：越权访问（IDOR）

位置：`/documents/<id>`

触发点：文档详情页未校验文档归属权

特征：普通用户可遍历文档ID，访问其他用户的私有文档

难度：★★☆☆☆

### 漏洞七：敏感信息泄露

位置：`/debug/info?debug=1`

触发点：调试接口未禁用，传入debug=1参数可触发

特征：泄露FLAG、SECRET_KEY、数据库路径、环境变量等敏感信息

难度：★☆☆☆☆

## 默认账号

| 账号 | 密码 | 角色 |
|------|------|------|
| admin | admin123 | 管理员 |
| user1 | password1 | 普通用户 |
| user2 | password2 | 普通用户 |
| ... | ... | ... |

管理员账号可访问管理后台，包含系统信息、数据导入等高危功能。

## FLAG提交

### 方式一：curl

```bash
curl -X POST http://<裁判IP>:8080/submit_flag \
  -H "Content-Type: application/json" \
  -d '{"attacker_id":"player1","target_id":"player2","flag":"FLAG{xxx}"}'
```

### 方式二：Python脚本

```bash
python target_client/scripts/submit_flag.py player1 player2 FLAG{xxx}
```

### 方式三：PowerShell（Windows）

```powershell
Invoke-RestMethod -Uri "http://<裁判IP>:8080/submit_flag" `
  -Method POST `
  -ContentType "application/json" `
  -Body '{"attacker_id":"player1","target_id":"player2","flag":"FLAG{xxx}"}'
```

## 排名规则

1. 存活选手优先
2. 同存活选手按得分排名（捕获FLAG数×10 + 修复漏洞数）
3. 同淘汰选手按FLAG被提交时间排序（越晚越高）
4. 未被淘汰且未捕获FLAG者按漏洞修复得分排名

## 管理接口

### 查看加固状态

```bash
curl http://localhost:8000/harden/status
```

### 添加IP白名单

```bash
curl -X POST http://localhost:8000/harden/add_whitelist \
  -H "Content-Type: application/json" \
  -d '{"ip": "192.168.1.100"}'
```

### 查看访问日志

```bash
curl http://localhost:8000/logs/access
```

### 查看攻击日志

```bash
curl http://localhost:8000/logs/attack
```

## 配置说明

### 自定义比赛阶段时长

编辑 `judge/config/judge_config.py`，修改以下字段：

```python
FIX_PERIOD_MINUTES = 120        # 修复调试期（分钟），默认120分钟（2小时）
STABILIZE_PERIOD_MINUTES = 5    # 稳定校验期（分钟），默认5分钟
ATTACK_PERIOD_MINUTES = 60      # 自由攻防期（分钟），默认60分钟
```

修改后重启裁判服务即可生效。

### ip_config.ini

```ini
[NETWORK]
primary_ip = 主内网IP（必填）
backup_ip = 备用内网IP（可选）
```

启动校验规则：
- 无primary_ip：弹窗报错终止程序
- 仅primary_ip：正常运行
- 双IP齐全：断线时自动切换备用IP

### judge_config.py 完整配置

```python
TCP_HEARTBEAT_PORT = 9999       # TCP心跳服务端口
HTTP_SUBMIT_PORT = 8080         # HTTP提交接口端口
DASHBOARD_PORT = 8000           # Web看板端口

HEARTBEAT_INTERVAL = 5          # 心跳间隔（秒）
DISCONNECT_WARNING_TIME = 10    # 断线警告时间（秒）
DISCONNECT_PENALTY_TIME = 30    # 断线淘汰时间（秒）

FLAG_SUBMIT_RATE_LIMIT = 3      # 每分钟提交次数限制
FLAG_SUBMIT_TIME_WINDOW = 60    # 限流时间窗口（秒）

FIX_PERIOD_MINUTES = 120        # 修复调试期（分钟）
STABILIZE_PERIOD_MINUTES = 5    # 稳定校验期（分钟）
ATTACK_PERIOD_MINUTES = 60      # 自由攻防期（分钟）

DOS_THRESHOLD = 100             # DoS检测阈值（次）
DOS_TIME_WINDOW = 10            # DoS检测时间窗口（秒）
```

## 裁判Web看板

访问地址：`http://<裁判IP>:8000`

功能：
- 实时展示当前阶段和剩余时间
- 选手在线/离线/淘汰状态
- FLAG提交流水
- 当前排名
- 赛事控制（开始/暂停/结束/切换阶段）

## 安全规则

1. 未关闭防火墙者禁止参赛
2. DoS攻击者（10秒超100次请求）直接淘汰
3. 稳定/攻击期修改源码判定违规淘汰
4. 断线超30秒未重连判定淘汰
5. 每位选手仅一次复活机会
6. 禁止提交自己的FLAG

## 故障处理

### 集体VPN断连

裁判可通过Web看板暂停比赛，暂停期间不计算断线倒计时。

### 客户端断线

- 0-10秒：离线警告
- 10-30秒：持续倒计时重连
- 超30秒：淘汰（可使用复活机会重置）

### 服务器崩溃

TCP心跳和HTTP提交分离解耦，单一进程崩溃不影响另一服务。

## 跨平台适配

| 平台 | 防火墙脚本 | 连通性脚本 | 启动脚本 |
|------|-----------|-----------|---------|
| Windows | disable_firewall_windows.bat | check_connectivity_windows.bat | start_client_windows.bat |
| Linux | disable_firewall_linux.sh | check_connectivity_linux.sh | start_client.sh |
| Mac | disable_firewall_mac.sh | check_connectivity_mac.sh | start_client.sh |

## 注意事项

1. 所有选手需接入同一局域网或VPN
2. 靶机端口由选手自定义（默认8000）
3. 选手之间通过内网IP+端口互相访问
4. 源码哈希在校验期和攻击期会被裁判校验
5. 仅允许修改密码和配置类文件

## 源码获取

### Gitee镜像地址

```
https://gitee.com/ctf-platform/ctf-attack-defense-system.git
```

### 克隆指令

```bash
git clone https://gitee.com/ctf-platform/ctf-attack-defense-system.git
cd ctf-attack-defense-system
```

### 版本信息

| 版本 | 代码行数 | 漏洞数 | 准备时间 | 核心特性 | 发布日期 |
|------|---------|--------|---------|---------|---------|
| v3.2 | 2182行 | 7个 | 可自定义（默认2小时） | 阶段时长可配置、配置化架构 | 2024-01 |
| v3.1 | 2182行 | 7个 | 2小时 | 企业管理系统靶机、2000+代码 | 2024-01 |
| v3.0 | 1560行 | 6个 | 30分钟 | 基础漏洞、跨平台支持 | 2024-01 |

### 本地构建

```bash
pip install -r requirements.txt
python target_server.py
```

## 许可证

MIT License
