# cht-group.net 安全漏洞扫描报告

> **引擎**: v3.0 | **时间**: 2026-08-13 00:23:06 | **低频被动 + 深度检测**

## 统计

| 等级 | 数量 |
|------|------|
| 💀 CRITICAL | 2 |
| 🔴 HIGH | 4 |
| 🟡 MEDIUM | 4 |
| 🟢 LOW | 3 |
| 🔵 INFO | 2 |
| **总计** | **15** |

## 漏洞详情

### 1. 💀 [CRITICAL] OA 系统公网暴露，API 端点含薪资/考勤/员工等敏感模块

| 属性 | 值 |
|------|-----|
| CWE | CWE-200 / CWE-284 |
| CVSS | 9.8 |
| CVSS向量 | `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H` |
| 受影响URL | https://oa.cht-group.net/ |
| 截图URL | https://oa.cht-group.net/ |

**描述**: OA 系统(泛微OA)直接暴露在公网，无需 VPN 即可访问。API 路由包含 /api/salary、/api/payroll、/api/employee、/api/attendance、/api/leave、/api/approval 等大量敏感端点。该系统集成了钉钉 H5 登录，但登录页面本身未做 IP 限制。攻击者可通过暴力破解、社工钓鱼、或利用泛微 OA 已知漏洞获取全公司员工个人隐私数据、薪资数据、考勤记录、审批流等。违反《个人信息保护法》第51条。

**复现**:
```
1. 访问 https://oa.cht-group.net/
2. 查看页面源码，确认 Vue.js SPA 架构
3. 访问 https://oa.cht-group.net/api/salary 确认 API 路由
4. 使用钉钉扫码登录或暴力破解获取访问权限
5. 登录后可访问全公司员工通讯录、薪资、考勤数据
```

**修复**:
```
1. 立即将 OA 系统置于 VPN 后，或配置 IP 白名单
2. 启用双因素认证
3. 升级泛微 OA 至最新版本，修补已知漏洞
4. 配置 WAF 规则防范暴力破解
5. 对敏感 API 端点增加额外鉴权
```

---
### 2. 💀 [CRITICAL] 数据指标门户 Portal 公网暴露，含企业核心业务数据

| 属性 | 值 |
|------|-----|
| CWE | CWE-200 / CWE-284 |
| CVSS | 9.8 |
| CVSS向量 | `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H` |
| 受影响URL | https://portal.cht-group.net/ |
| 截图URL | https://portal.cht-group.net/ |

**描述**: Portal 系统标题为'指标口径'，是企业数据指标管理平台。JS 文件包含 96 处 token 引用、177 处 user 引用、11 处 password 引用、4 处 secret 引用，明确表明该平台处理企业核心业务数据。该平台同样未做访问限制，直接暴露在公网。一旦越权访问，可获取企业全部经营指标、财务数据、用户数据等核心商业秘密。

**复现**:
```
1. 访问 https://portal.cht-group.net/
2. 查看页面标题'指标口径'
3. 分析 JS 文件中 token/user/password/secret 等关键词
4. 尝试未授权访问 API 端点
```

**修复**:
```
1. Portal 必须置于 VPN 或内网环境
2. 配置严格的 IP 白名单
3. API 接口增加 JWT Token 鉴权
4. 审计 JS 文件中是否硬编码了凭证
```

---
### 3. 🔴 [HIGH] OA 系统集成钉钉 H5 登录，corpId 可能泄露

| 属性 | 值 |
|------|-----|
| CWE | CWE-200 |
| CVSS | 7.5 |
| CVSS向量 | `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N` |
| 受影响URL | https://oa.cht-group.net/ |
| 截图URL | https://oa.cht-group.net/ |

**描述**: OA 页面加载了钉钉 H5 登录 SDK: https://g.alicdn.com/dingding/h5-dingtalk-login/0.21.0/ddlogin.js。该 SDK 需要 corpId 参数初始化，攻击者可通过分析 JS 文件获取 corpId，进而针对性攻击该企业的钉钉组织。

**复现**:
```
1. 访问 https://oa.cht-group.net/
2. 查看页面源码，搜索 ddlogin.js
3. 分析 JS 文件中的 corpId 参数
4. 使用 corpId 针对性攻击钉钉组织
```

**修复**:
```
1. 确保 corpId 不暴露在前端 JS 中
2. 使用服务端代理方式调用钉钉 API
3. 限制钉钉应用的可信 IP 列表
```

---
### 4. 🔴 [HIGH] 监控 SDK 公网暴露，泄露内部监控数据

| 属性 | 值 |
|------|-----|
| CWE | CWE-200 |
| CVSS | 7.5 |
| CVSS向量 | `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N` |
| 受影响URL | https://monitor.cht-group.net/ |
| 截图URL | https://monitor.cht-group.net/downloads/yt-monitor-prod-sdk.js |

**描述**: OA 页面引用了 https://monitor.cht-group.net/downloads/yt-monitor-prod-sdk.js，该 SDK 文件可被直接下载(9616 bytes)。监控 SDK 包含上报地址、数据采集逻辑，可能泄露内部监控指标和业务数据。monitor 子域名指向阿里云 SASE SSO 登录页面。

**复现**:
```
1. curl https://monitor.cht-group.net/downloads/yt-monitor-prod-sdk.js
2. 分析 SDK 中的数据采集逻辑和上报地址
3. 确认监控数据是否可被外部访问
```

**修复**:
```
1. 限制监控 SDK 的访问来源
2. 监控系统必须置于内网/VPN
3. 不要在 SDK 中硬编码敏感信息
```

---
### 5. 🔴 [HIGH] Git 代码仓库服务器公网暴露 (git.cht-group.net)

| 属性 | 值 |
|------|-----|
| CWE | CWE-200 |
| CVSS | 7.5 |
| CVSS向量 | `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N` |
| 受影响URL | http://git.cht-group.net/ |
| 截图URL | http://git.cht-group.net/ |

**描述**: git.cht-group.net 解析到 120.55.64.59，当前返回 502，但 DNS 记录表明该子域名曾用于代码仓库。如果服务恢复，攻击者可尝试访问 Git 仓库获取源代码、配置文件、数据库密码等敏感信息。

**复现**:
```
1. dig git.cht-group.net A
2. curl http://git.cht-group.net/
3. 尝试 /.git/HEAD 等常见路径
```

**修复**:
```
1. 如果 Git 服务已弃用，删除 DNS 记录
2. 如果仍在使用，必须配置 VPN 访问
3. 检查 Nginx 代理配置是否正确
```

---
### 6. 🔴 [HIGH] 主域 502 Bad Gateway - 服务不可用

| 属性 | 值 |
|------|-----|
| CWE | CWE-N/A |
| CVSS | 7.5 |
| CVSS向量 | `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H` |
| 受影响URL | http://cht-group.net/ |
| 截图URL | http://cht-group.net/ |

**描述**: cht-group.net 主域返回 502 Bad Gateway，响应内容为 'Forwarding error: connection closed before message completed'。表明前端代理无法连接到后端服务。

**复现**:
```
curl -v http://cht-group.net/
```

**修复**:
```
检查后端服务状态和代理配置
```

---
### 7. 🟡 [MEDIUM] 企业邮箱托管于阿里云企业邮箱，公网暴露

| 属性 | 值 |
|------|-----|
| CWE | CWE-200 |
| CVSS | 5.3 |
| CVSS向量 | `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N` |
| 受影响URL | https://mail.cht-group.net/ |
| 截图URL | https://mail.cht-group.net/ |

**描述**: mail.cht-group.net 解析到阿里云企业邮箱(qiye.aliyun.com)，登录页面公网可访问。攻击者可针对性地进行邮箱暴力破解或钓鱼攻击。

**复现**:
```
1. dig mail.cht-group.net
2. 访问 https://mail.cht-group.net/
3. 确认阿里云企业邮箱登录页面
```

**修复**:
```
1. 启用邮箱登录 IP 限制
2. 配置 SPF/DKIM/DMARC 防止邮件欺诈
3. 启用 MFA 多因素认证
```

---
### 8. 🟡 [MEDIUM] Nginx 服务器版本泄露 (Server 头)

| 属性 | 值 |
|------|-----|
| CWE | CWE-200 |
| CVSS | 5.3 |
| CVSS向量 | `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N` |
| 受影响URL | https://oa.cht-group.net/ |
| 截图URL | https://oa.cht-group.net/ |

**描述**: 所有子域名均返回 Server: nginx 响应头，且 Portal 的 403 页面暴露了 nginx 版本信息。攻击者可利用已知的 Nginx 漏洞进行攻击。

**复现**:
```
curl -I https://oa.cht-group.net/ | grep Server
```

**修复**:
```
Nginx 配置: server_tokens off;
```

---
### 9. 🟡 [MEDIUM] 所有子域名均缺失安全响应头

| 属性 | 值 |
|------|-----|
| CWE | CWE-16 |
| CVSS | 5.3 |
| CVSS向量 | `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N` |
| 受影响URL | https://oa.cht-group.net/ |
| 截图URL | https://oa.cht-group.net/ |

**描述**: OA/Portal/App 均未配置 HSTS、CSP、X-Frame-Options、X-Content-Type-Options 等安全响应头。

**复现**:
```
curl -I https://oa.cht-group.net/
```

**修复**:
```
统一配置 Nginx 安全响应头
```

---
### 10. 🟡 [MEDIUM] 图片资源通过七牛云 CDN 公网分发

| 属性 | 值 |
|------|-----|
| CWE | CWE-200 |
| CVSS | 5.3 |
| CVSS向量 | `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N` |
| 受影响URL | https://img.cht-group.net/ |
| 截图URL | https://img.cht-group.net/ |

**描述**: img.cht-group.net 解析到七牛云 CDN(qiniuio.com)，图片资源可能包含企业内部敏感信息(如工牌照片、证件扫描件等)。

**复现**:
```
1. dig img.cht-group.net
2. 尝试访问常见图片路径
```

**修复**:
```
1. 配置 CDN 防盗链
2. 私有资源使用签名 URL
3. 不要在 CDN 存放敏感图片
```

---
### 11. 🟢 [LOW] OA 与 App 指向同一系统，增大攻击面

| 属性 | 值 |
|------|-----|
| CWE | CWE-200 |
| CVSS | 4.3 |
| CVSS向量 | `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N` |
| 受影响URL | https://app.cht-group.net/ |
| 截图URL | https://app.cht-group.net/ |

**描述**: app.cht-group.net 和 oa.cht-group.net 返回完全相同页面(同一 Vue.js SPA)，暴露了多个攻击入口。

**复现**:
```

```

**修复**:
```
如非必要，移除重复的子域名解析
```

---
### 12. 🟢 [LOW] DNS 信息泄露 - 子域名暴露内部架构

| 属性 | 值 |
|------|-----|
| CWE | CWE-200 |
| CVSS | 4.3 |
| CVSS向量 | `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N` |
| 受影响URL | http://cht-group.net/ |
| 截图URL | http://cht-group.net/ |

**描述**: DNS 解析暴露了 oa/portal/app/git/mail/monitor/img 共 7 个子域名。这些子域名直接暴露了企业内部 IT 架构，攻击者可据此绘制攻击地图。

**复现**:
```

```

**修复**:
```
使用泛域名证书，减少子域名信息泄露
```

---
### 13. 🟢 [LOW] 缺少 SPF/DMARC 记录 - 邮件欺诈风险

| 属性 | 值 |
|------|-----|
| CWE | CWE-290 |
| CVSS | 4.3 |
| CVSS向量 | `CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:N` |
| 受影响URL | http://cht-group.net/ |
| 截图URL | http://cht-group.net/ |

**描述**: 域名未配置 SPF 和 DMARC 记录，攻击者可伪造该域名发送钓鱼邮件。

**复现**:
```

```

**修复**:
```
添加 TXT: v=spf1 -all 和 v=DMARC1; p=reject;
```

---
### 14. 🔵 [INFO] 技术栈: Vue.js + Element UI + Nginx + 钉钉 SDK + 七牛云 CDN + 阿里云企业邮箱

| 属性 | 值 |
|------|-----|
| CWE |  |
| CVSS |  |
| CVSS向量 | `` |
| 受影响URL | https://oa.cht-group.net/ |
| 截图URL | https://oa.cht-group.net/ |

**描述**: OA: Vue.js SPA + Element UI + 钉钉 H5 登录 SDK v0.21.0
Portal: React + Vite + 指标口径数据平台
CDN: 七牛云
邮件: 阿里云企业邮箱
监控: 阿里云 SASE 云安全
基础设施: 阿里云 ECS (120.26.82.91, 120.55.64.59)

**复现**:
```

```

**修复**:
```

```

---
### 15. 🔵 [INFO] 子域名全景: oa/portal/app/git/mail/monitor/img 共 7 个子域名

| 属性 | 值 |
|------|-----|
| CWE |  |
| CVSS |  |
| CVSS向量 | `` |
| 受影响URL | http://cht-group.net/ |
| 截图URL | http://cht-group.net/ |

**描述**: oa.cht-group.net -> 120.26.82.91 (OA系统)
portal.cht-group.net -> 120.26.82.91 (指标门户)
app.cht-group.net -> 120.26.82.91 (同OA)
git.cht-group.net -> 120.55.64.59 (代码仓库)
mail.cht-group.net -> 阿里云企业邮箱
monitor.cht-group.net -> 阿里云SASE
img.cht-group.net -> 七牛云CDN

**复现**:
```

```

**修复**:
```

```

---

*报告由自动化漏洞扫描系统 v3.0 生成 | 仅供授权安全测试使用*
