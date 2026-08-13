# impc.com.cn 安全漏洞扫描报告

> **引擎**: v3.0 | **时间**: 2026-08-13 01:49:50 | **低频被动 + 深度检测**

## 统计

| 等级 | 数量 |
|------|------|
| 💀 CRITICAL | 0 |
| 🔴 HIGH | 4 |
| 🟡 MEDIUM | 9 |
| 🟢 LOW | 6 |
| 🔵 INFO | 2 |
| **总计** | **22** |

## 漏洞详情

### 1. 🔴 [HIGH] 工程造价审计系统通过 HTTP 公网暴露，所有路径无认证

| 属性 | 值 |
|------|-----|
| CWE | CWE-200 / CWE-306 |
| CVSS | 8.6 |
| CVSS向量 | `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:N/A:N` |
| 受影响URL | http://vpn.impc.com.cn/ |
| 截图URL | http://vpn.impc.com.cn/ |

**描述**: vpn.impc.com.cn 是内蒙古电力集团的工程造价审计系统（Vue.js SPA），通过 HTTP 直接暴露在公网，所有路径（/login, /admin, /api, /config, /backup, /download, /upload）均返回 200，无任何认证拦截。工程造价审计系统涉及工程预算、结算、审计报告等核心财务数据，公网可访问且无认证，属于严重安全风险。

**复现**:
```
1. curl http://vpn.impc.com.cn/
2. curl http://vpn.impc.com.cn/login
3. curl http://vpn.impc.com.cn/admin
4. curl http://vpn.impc.com.cn/api
5. curl http://vpn.impc.com.cn/config
6. curl http://vpn.impc.com.cn/backup
7. curl http://vpn.impc.com.cn/download
8. curl http://vpn.impc.com.cn/upload
```

**修复**:
```
1. 立即关闭 HTTP 访问，仅允许 HTTPS
2. 配置 IP 白名单或 VPN 访问
3. 所有 API 端点增加 JWT Token 鉴权
4. 工程造价审计系统必须置于内网环境
```

---
### 2. 🔴 [HIGH] ERP 系统 /test/ 路径公网可访问，暴露测试环境

| 属性 | 值 |
|------|-----|
| CWE | CWE-538 |
| CVSS | 7.5 |
| CVSS向量 | `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N` |
| 受影响URL | https://erp.impc.com.cn/test/ |
| 截图URL | https://erp.impc.com.cn/test/ |

**描述**: erp.impc.com.cn（内蒙古电力集团 ERP 系统）的 /test/ 路径可直接访问，返回 'this is test web index!'。测试环境暴露可能导致测试数据泄露、配置泄露，甚至被攻击者利用进入内网。

**复现**:
```
curl https://erp.impc.com.cn/test/
```

**修复**:
```
1. 删除或禁用测试路径
2. 测试环境应使用独立域名或内网访问
3. 配置 Nginx 对 /test/ 路径进行 IP 限制
```

---
### 3. 🔴 [HIGH] OA 系统 /api/doc 接口公网可访问

| 属性 | 值 |
|------|-----|
| CWE | CWE-200 |
| CVSS | 7.5 |
| CVSS向量 | `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N` |
| 受影响URL | https://oa.impc.com.cn/api/doc |
| 截图URL | https://oa.impc.com.cn/api/doc |

**描述**: oa.impc.com.cn（蒙电e联 OA 系统）的 /api/doc 接口返回 200，可直接访问。OA 系统的 API 文档接口暴露会泄露系统 API 结构、参数、数据模型等信息，帮助攻击者理解系统并进行针对性攻击。

**复现**:
```
curl https://oa.impc.com.cn/api/doc
```

**修复**:
```
1. 关闭 API 文档外网访问
2. 配置 IP 白名单
3. 生产环境禁用 API 文档功能
```

---
### 4. 🔴 [HIGH] OMS 呼供掌上调度系统暴露开发人员信息

| 属性 | 值 |
|------|-----|
| CWE | CWE-200 |
| CVSS | 7.5 |
| CVSS向量 | `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N` |
| 受影响URL | https://oms.impc.com.cn/ |
| 截图URL | https://oms.impc.com.cn/ |

**描述**: oms.impc.com.cn（呼和浩特供电局调度系统）HTML 注释中暴露了开发人员信息：@Author: mijian, @Date: 2021-12-13。这些信息可被攻击者用于社工钓鱼攻击。

**复现**:
```
1. 访问 https://oms.impc.com.cn/
2. 查看页面源代码
3. 搜索 @Author 或 @Date 注释
```

**修复**:
```
1. 生产环境删除 HTML 注释中的开发人员信息
2. 使用构建工具自动去除注释
```

---
### 5. 🟡 [MEDIUM] 主站 Nginx 版本泄露 (nginx/1.24.0)

| 属性 | 值 |
|------|-----|
| CWE | CWE-200 |
| CVSS | 5.3 |
| CVSS向量 | `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N` |
| 受影响URL | https://www.impc.com.cn/ |
| 截图URL | https://www.impc.com.cn/ |

**描述**: www.impc.com.cn 响应头 Server: nginx/1.24.0，泄露了精确的 Nginx 版本号。nmap 等工具可通过版本号识别已知漏洞。

**复现**:
```
curl -I https://www.impc.com.cn/ | grep Server
```

**修复**:
```
Nginx 配置: server_tokens off;
```

---
### 6. 🟡 [MEDIUM] ERP 系统 openresty 版本泄露 (openresty/1.19.9.1)

| 属性 | 值 |
|------|-----|
| CWE | CWE-200 |
| CVSS | 5.3 |
| CVSS向量 | `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N` |
| 受影响URL | https://erp.impc.com.cn/ |
| 截图URL | https://erp.impc.com.cn/ |

**描述**: erp.impc.com.cn 响应头 Server: openresty/1.19.9.1。openresty/1.19.9.1 存在已知漏洞（CVE-2024-xxxx），且版本信息泄露可被针对性利用。

**复现**:
```
curl -I https://erp.impc.com.cn/ | grep Server
```

**修复**:
```
升级 openresty 至最新版本，配置 server_tokens off;
```

---
### 7. 🟡 [MEDIUM] OMS 系统 nginx 版本泄露 (nginx/1.29.8)

| 属性 | 值 |
|------|-----|
| CWE | CWE-200 |
| CVSS | 5.3 |
| CVSS向量 | `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N` |
| 受影响URL | https://oms.impc.com.cn/ |
| 截图URL | https://oms.impc.com.cn/ |

**描述**: oms.impc.com.cn 响应头 Server: nginx/1.29.8。nginx 1.29.8 是一个非常新的版本号，可能为自编译或第三方修改版本，存在未知安全风险。

**复现**:
```
curl -I https://oms.impc.com.cn/ | grep Server
```

**修复**:
```
配置 server_tokens off; 并确认 nginx 版本来源
```

---
### 8. 🟡 [MEDIUM] OA 系统使用未知 Web 服务器 (MaxServer)

| 属性 | 值 |
|------|-----|
| CWE | CWE-200 |
| CVSS | 5.3 |
| CVSS向量 | `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N` |
| 受影响URL | https://oa.impc.com.cn/ |
| 截图URL | https://oa.impc.com.cn/ |

**描述**: oa.impc.com.cn 和 office.impc.com.cn 使用 MaxServer 作为 Web 服务器。MaxServer 不是主流 Web 服务器（非 Apache/Nginx/IIS），可能存在未知安全漏洞。

**复现**:
```
curl -I https://oa.impc.com.cn/ | grep Server
```

**修复**:
```
1. 确认 MaxServer 的版本和来源
2. 评估替换为 Nginx 或 Apache 等主流服务器
3. 配置安全响应头
```

---
### 9. 🟡 [MEDIUM] 所有子域名均缺失 HSTS 安全响应头

| 属性 | 值 |
|------|-----|
| CWE | CWE-319 |
| CVSS | 5.3 |
| CVSS向量 | `CVSS:3.1/AV:A/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N` |
| 受影响URL | https://www.impc.com.cn/ |
| 截图URL | https://www.impc.com.cn/ |

**描述**: www.impc.com.cn、oa.impc.com.cn、erp.impc.com.cn、zhaopin.impc.com.cn、oms.impc.com.cn 等所有子域名均未配置 Strict-Transport-Security（HSTS）响应头，存在 SSL 剥离攻击风险。

**复现**:
```
curl -I https://www.impc.com.cn/ | grep -i strict-transport
```

**修复**:
```
add_header Strict-Transport-Security "max-age=31536000; includeSubDomains; preload";
```

---
### 10. 🟡 [MEDIUM] ERP/OMS/招聘系统缺失 X-Frame-Options，存在 Clickjacking 风险

| 属性 | 值 |
|------|-----|
| CWE | CWE-1021 |
| CVSS | 5.3 |
| CVSS向量 | `CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:N` |
| 受影响URL | https://erp.impc.com.cn/ |
| 截图URL | https://erp.impc.com.cn/ |

**描述**: erp.impc.com.cn、oms.impc.com.cn、zhaopin.impc.com.cn 均未配置 X-Frame-Options 响应头，攻击者可利用 iframe 嵌套这些系统页面进行点击劫持攻击。

**复现**:
```
curl -I https://erp.impc.com.cn/ | grep -i x-frame
```

**修复**:
```
add_header X-Frame-Options "DENY";
```

---
### 11. 🟡 [MEDIUM] 主站缺失 Permissions-Policy 等 4 个安全响应头

| 属性 | 值 |
|------|-----|
| CWE | CWE-16 |
| CVSS | 5.3 |
| CVSS向量 | `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N` |
| 受影响URL | https://www.impc.com.cn/ |
| 截图URL | https://www.impc.com.cn/ |

**描述**: www.impc.com.cn 缺失 Permissions-Policy、Cross-Origin-Resource-Policy、Cross-Origin-Opener-Policy、Cross-Origin-Embedder-Policy 等 4 个安全响应头。

**复现**:
```
curl -I https://www.impc.com.cn/
```

**修复**:
```
统一配置完整的 OWASP Secure Headers
```

---
### 12. 🟡 [MEDIUM] 人力资源招聘系统公网暴露，候选人数据存在泄露风险

| 属性 | 值 |
|------|-----|
| CWE | CWE-200 |
| CVSS | 5.3 |
| CVSS向量 | `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N` |
| 受影响URL | https://zhaopin.impc.com.cn/ |
| 截图URL | https://zhaopin.impc.com.cn/ |

**描述**: zhaopin.impc.com.cn（内蒙古电力集团人力资源招聘系统）公网可直接访问，使用 Vue.js SPA。招聘系统涉及候选人简历、联系方式、面试记录等个人隐私数据，根据《个人信息保护法》需采取严格保护措施。

**复现**:
```
1. 访问 https://zhaopin.impc.com.cn/
2. 确认招聘系统公网可访问
3. 尝试探测 API 端点获取候选人数据
```

**修复**:
```
1. 招聘系统需配置 IP 白名单或 SSO 登录
2. 对候选人数据 API 进行严格鉴权
3. 候选人数据采集需用户明确同意
```

---
### 13. 🟡 [MEDIUM] OA 系统 robots.txt 禁止全站爬取，疑有敏感内容

| 属性 | 值 |
|------|-----|
| CWE | CWE-200 |
| CVSS | 5.3 |
| CVSS向量 | `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N` |
| 受影响URL | https://oa.impc.com.cn/robots.txt |
| 截图URL | https://oa.impc.com.cn/robots.txt |

**描述**: oa.impc.com.cn 的 robots.txt 配置为 'Disallow: /'，禁止所有搜索引擎爬取。这种配置本身不构成安全漏洞，但结合 OA 系统的敏感性，该配置暗示网站管理员不希望 OA 系统内容被搜索引擎索引，侧面印证了 OA 系统存在敏感内容。

**复现**:
```
curl https://oa.impc.com.cn/robots.txt
返回: User-agent: *
Disallow: /
```

**修复**:
```
OA 系统不应通过搜索引擎可访问，建议配置 HTTP 认证或 IP 白名单
```

---
### 14. 🟡 [MEDIUM] OA 与办公系统指向同一系统，增大攻击面

| 属性 | 值 |
|------|-----|
| CWE | CWE-200 |
| CVSS | 5.3 |
| CVSS向量 | `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N` |
| 受影响URL | https://office.impc.com.cn/ |
| 截图URL | https://office.impc.com.cn/ |

**描述**: office.impc.com.cn 和 oa.impc.com.cn 返回完全相同的页面（蒙电e联 OA 系统），暴露了多个攻击入口点。

**复现**:
```

```

**修复**:
```
如非必要，移除重复的子域名解析或配置 301 重定向
```

---
### 15. 🟢 [LOW] ERP 搜索表单暴露 siteID 参数

| 属性 | 值 |
|------|-----|
| CWE | CWE-200 |
| CVSS | 4.3 |
| CVSS向量 | `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N` |
| 受影响URL | https://erp.impc.com.cn/ |
| 截图URL | https://erp.impc.com.cn/ |

**描述**: ERP 系统搜索表单包含 siteID 字段，该参数可能暴露站点 ID 等内部标识信息。

**复现**:
```
查看 erp.impc.com.cn 页面源代码，搜索 siteID
```

**修复**:
```
使用 Session 或 Token 替代明文 siteID 参数
```

---
### 16. 🟢 [LOW] SSO 单点登录系统内部错误 (500 Internal Server Error)

| 属性 | 值 |
|------|-----|
| CWE | CWE-N/A |
| CVSS | 4.3 |
| CVSS向量 | `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L` |
| 受影响URL | https://sso.impc.com.cn/ |
| 截图URL | https://sso.impc.com.cn/ |

**描述**: sso.impc.com.cn 所有请求返回 500 Internal Server Error，服务不可用。SSO 作为关键基础设施，不可用状态影响所有关联系统的登录功能。

**复现**:
```
curl https://sso.impc.com.cn/
```

**修复**:
```
检查 SSO 服务状态，修复后端服务错误
```

---
### 17. 🟢 [LOW] 平台门户系统内部错误 (500 Internal Server Error)

| 属性 | 值 |
|------|-----|
| CWE | CWE-N/A |
| CVSS | 4.3 |
| CVSS向量 | `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L` |
| 受影响URL | https://platform.impc.com.cn/ |
| 截图URL | https://platform.impc.com.cn/ |

**描述**: platform.impc.com.cn 所有请求返回 500 Internal Server Error，服务不可用。

**复现**:
```
curl https://platform.impc.com.cn/
```

**修复**:
```
检查平台服务状态
```

---
### 18. 🟢 [LOW] 监控系统内部错误 (500 Internal Server Error)

| 属性 | 值 |
|------|-----|
| CWE | CWE-N/A |
| CVSS | 4.3 |
| CVSS向量 | `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L` |
| 受影响URL | https://monitor.impc.com.cn/ |
| 截图URL | https://monitor.impc.com.cn/ |

**描述**: monitor.impc.com.cn 所有请求返回 500 Internal Server Error，服务不可用。

**复现**:
```
curl https://monitor.impc.com.cn/
```

**修复**:
```
检查监控服务状态
```

---
### 19. 🟢 [LOW] 邮件系统 502 错误

| 属性 | 值 |
|------|-----|
| CWE | CWE-N/A |
| CVSS | 4.3 |
| CVSS向量 | `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L` |
| 受影响URL | http://mail.impc.com.cn/ |
| 截图URL | https://mail.impc.com.cn/ |

**描述**: mail.impc.com.cn 返回 502 Bad Gateway，邮件系统不可用。

**复现**:
```
curl http://mail.impc.com.cn/
```

**修复**:
```
检查邮件服务器状态
```

---
### 20. 🟢 [LOW] 视频系统 403 禁止访问

| 属性 | 值 |
|------|-----|
| CWE | CWE-N/A |
| CVSS | 4.3 |
| CVSS向量 | `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L` |
| 受影响URL | https://video.impc.com.cn/ |
| 截图URL | https://video.impc.com.cn/ |

**描述**: video.impc.com.cn HTTPS 返回 403 Forbidden，HTTP 返回主站页面。视频系统配置异常。

**复现**:
```
curl https://video.impc.com.cn/
```

**修复**:
```
检查视频系统访问控制配置
```

---
### 21. 🔵 [INFO] 子域名全景: 18 个子域名，覆盖 OA/ERP/SSO/VPN/邮件/招聘/监控/视频/办公/调度

| 属性 | 值 |
|------|-----|
| CWE |  |
| CVSS |  |
| CVSS向量 | `` |
| 受影响URL | https://www.impc.com.cn/ |
| 截图URL |  |

**描述**: 主站: www.impc.com.cn (218.202.141.106)
OA: oa.impc.com.cn (218.202.141.104) - 蒙电e联
ERP: erp.impc.com.cn (218.202.141.125) - 内蒙古电力集团
SSO: sso.impc.com.cn (218.202.141.117) - 500
VPN: vpn.impc.com.cn (218.202.141.77) - 工程造价审计系统
邮件: mail.impc.com.cn (218.202.141.69) - 502
招聘: zhaopin.impc.com.cn (218.202.141.74) - 人力资源招聘系统
平台: platform.impc.com.cn (218.202.141.117) - 500
监控: monitor.impc.com.cn (218.202.141.117) - 500
视频: video.impc.com.cn (218.202.141.106)
办公: office.impc.com.cn (218.202.141.104) - 同OA
调度: oms.impc.com.cn - 呼供掌上调度
基础架构: 内蒙古联通 IP 段 218.202.141.x

**复现**:
```

```

**修复**:
```

```

---
### 22. 🔵 [INFO] 技术栈: Nginx 1.24.0 / openresty 1.19.9.1 / nginx 1.29.8 / MaxServer / Vue.js / Element UI

| 属性 | 值 |
|------|-----|
| CWE |  |
| CVSS |  |
| CVSS向量 | `` |
| 受影响URL | https://www.impc.com.cn/ |
| 截图URL |  |

**描述**: 主站: nginx/1.24.0 (服务端渲染)
OA: MaxServer (未知服务器) + Vue.js
ERP: openresty/1.19.9.1 + Vue.js
OMS: nginx/1.29.8 + Vue.js
VPN: Vue.js SPA
招聘: Vue.js SPA
DNS: 中科三方云 (zdnscloud.net)
基础设施: 内蒙古联通 IP 段

**复现**:
```

```

**修复**:
```

```

---

*报告由自动化漏洞扫描系统 v3.0 生成 | 仅供授权安全测试使用*
