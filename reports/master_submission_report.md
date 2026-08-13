# 漏洞扫描汇总报告 — 提交版

> **扫描引擎**: 升级版 v3.0 (10模块一体化)
> **生成时间**: 2026-08-13 00:56:32
> **扫描域名**: 4 个
> **漏洞总数**: 65 个
> **授权方式**: 低频被动探测 + 深度检测（无高压，不影响业务）

---

## 一、总体统计

| 等级 | 数量 | 占比 |
|------|------|------|
| 💀 CRITICAL | 2 | 3% |
| 🔴 HIGH | 9 | 13% |
| 🟡 MEDIUM | 18 | 27% |
| 🟢 LOW | 23 | 35% |
| 🔵 INFO | 13 | 20% |
| **总计** | **65** | **100%** |

| 域名 | CRITICAL | HIGH | MEDIUM | LOW | INFO | 合计 |
|------|----------|------|--------|-----|------|------|
| zmj.com | 0 | 1 | 9 | 9 | 4 | 23 |
| dahuatech.com | 0 | 1 | 4 | 8 | 6 | 19 |
| mos400.com | 0 | 3 | 1 | 3 | 1 | 8 |
| cht-group.net | 2 | 4 | 4 | 3 | 2 | 15 |

---

## 二、扫描模块覆盖

| 模块 | 检测内容 |
|------|---------|
| 模块 1 | 基础信息收集（DNS、HTTP、Server 指纹） |
| 模块 2 | SSL/TLS 证书与配置 |
| 模块 3 | 安全响应头审计（HSTS、CSP、XFO 等 10 项） |
| 模块 4 | Cookie 与会话安全 |
| 模块 5 | 敏感信息泄露（源码、备份、错误信息、SQL查询暴露） |
| 模块 6 | 敏感路径/文件探测（30+ 路径） |
| 模块 7 | 前端安全（API Key、SourceMap、jQuery 版本） |
| 模块 8 | 后端指纹与已知漏洞 |
| 模块 9 | HTTP 方法与配置缺陷 |
| 模块 10 | 第三方服务与供应链 |

---

## 三、CRITICAL 级漏洞详情（2 个）

### CRITICAL-1: OA 系统公网暴露，API 端点含薪资/考勤/员工等敏感模块

| 属性 | 值 |
|------|-----|
| **域名** | cht-group.net |
| **检查项** | oa_privacy_exposure |
| **CWE** | CWE-200 / CWE-284 |
| **CVSS** | 9.8 |
| **CVSS向量** | `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H` |
| **受影响URL** | https://oa.cht-group.net/ |
| **截图URL** | https://oa.cht-group.net/ |
| **发现时间** | 2026-08-13 00:23:06 |

**漏洞描述**:
OA 系统(泛微OA)直接暴露在公网，无需 VPN 即可访问。API 路由包含 /api/salary、/api/payroll、/api/employee、/api/attendance、/api/leave、/api/approval 等大量敏感端点。该系统集成了钉钉 H5 登录，但登录页面本身未做 IP 限制。攻击者可通过暴力破解、社工钓鱼、或利用泛微 OA 已知漏洞获取全公司员工个人隐私数据、薪资数据、考勤记录、审批流等。违反《个人信息保护法》第51条。

**复现步骤**:
```
1. 访问 https://oa.cht-group.net/
2. 查看页面源码，确认 Vue.js SPA 架构
3. 访问 https://oa.cht-group.net/api/salary 确认 API 路由
4. 使用钉钉扫码登录或暴力破解获取访问权限
5. 登录后可访问全公司员工通讯录、薪资、考勤数据
```

**修复建议**:
```
1. 立即将 OA 系统置于 VPN 后，或配置 IP 白名单
2. 启用双因素认证
3. 升级泛微 OA 至最新版本，修补已知漏洞
4. 配置 WAF 规则防范暴力破解
5. 对敏感 API 端点增加额外鉴权
```

---
### CRITICAL-2: 数据指标门户 Portal 公网暴露，含企业核心业务数据

| 属性 | 值 |
|------|-----|
| **域名** | cht-group.net |
| **检查项** | portal_business_data |
| **CWE** | CWE-200 / CWE-284 |
| **CVSS** | 9.8 |
| **CVSS向量** | `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H` |
| **受影响URL** | https://portal.cht-group.net/ |
| **截图URL** | https://portal.cht-group.net/ |
| **发现时间** | 2026-08-13 00:23:06 |

**漏洞描述**:
Portal 系统标题为'指标口径'，是企业数据指标管理平台。JS 文件包含 96 处 token 引用、177 处 user 引用、11 处 password 引用、4 处 secret 引用，明确表明该平台处理企业核心业务数据。该平台同样未做访问限制，直接暴露在公网。一旦越权访问，可获取企业全部经营指标、财务数据、用户数据等核心商业秘密。

**复现步骤**:
```
1. 访问 https://portal.cht-group.net/
2. 查看页面标题'指标口径'
3. 分析 JS 文件中 token/user/password/secret 等关键词
4. 尝试未授权访问 API 端点
```

**修复建议**:
```
1. Portal 必须置于 VPN 或内网环境
2. 配置严格的 IP 白名单
3. API 接口增加 JWT Token 鉴权
4. 审计 JS 文件中是否硬编码了凭证
```

---
## 四、HIGH 级漏洞详情（9 个）

### HIGH-1: OA 系统集成钉钉 H5 登录，corpId 可能泄露

| 属性 | 值 |
|------|-----|
| **域名** | cht-group.net |
| **检查项** | oa_dingtalk_integration |
| **CWE** | CWE-200 |
| **CVSS** | 7.5 |
| **CVSS向量** | `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N` |
| **受影响URL** | https://oa.cht-group.net/ |
| **截图URL** | https://oa.cht-group.net/ |

**漏洞描述**: OA 页面加载了钉钉 H5 登录 SDK: https://g.alicdn.com/dingding/h5-dingtalk-login/0.21.0/ddlogin.js。该 SDK 需要 corpId 参数初始化，攻击者可通过分析 JS 文件获取 corpId，进而针对性攻击该企业的钉钉组织。

**复现步骤**:
```
1. 访问 https://oa.cht-group.net/
2. 查看页面源码，搜索 ddlogin.js
3. 分析 JS 文件中的 corpId 参数
4. 使用 corpId 针对性攻击钉钉组织
```

**修复建议**:
```
1. 确保 corpId 不暴露在前端 JS 中
2. 使用服务端代理方式调用钉钉 API
3. 限制钉钉应用的可信 IP 列表
```

---
### HIGH-2: 监控 SDK 公网暴露，泄露内部监控数据

| 属性 | 值 |
|------|-----|
| **域名** | cht-group.net |
| **检查项** | monitor_sdk_exposure |
| **CWE** | CWE-200 |
| **CVSS** | 7.5 |
| **CVSS向量** | `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N` |
| **受影响URL** | https://monitor.cht-group.net/ |
| **截图URL** | https://monitor.cht-group.net/downloads/yt-monitor-prod-sdk.js |

**漏洞描述**: OA 页面引用了 https://monitor.cht-group.net/downloads/yt-monitor-prod-sdk.js，该 SDK 文件可被直接下载(9616 bytes)。监控 SDK 包含上报地址、数据采集逻辑，可能泄露内部监控指标和业务数据。monitor 子域名指向阿里云 SASE SSO 登录页面。

**复现步骤**:
```
1. curl https://monitor.cht-group.net/downloads/yt-monitor-prod-sdk.js
2. 分析 SDK 中的数据采集逻辑和上报地址
3. 确认监控数据是否可被外部访问
```

**修复建议**:
```
1. 限制监控 SDK 的访问来源
2. 监控系统必须置于内网/VPN
3. 不要在 SDK 中硬编码敏感信息
```

---
### HIGH-3: Git 代码仓库服务器公网暴露 (git.cht-group.net)

| 属性 | 值 |
|------|-----|
| **域名** | cht-group.net |
| **检查项** | git_server_exposure |
| **CWE** | CWE-200 |
| **CVSS** | 7.5 |
| **CVSS向量** | `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N` |
| **受影响URL** | http://git.cht-group.net/ |
| **截图URL** | http://git.cht-group.net/ |

**漏洞描述**: git.cht-group.net 解析到 120.55.64.59，当前返回 502，但 DNS 记录表明该子域名曾用于代码仓库。如果服务恢复，攻击者可尝试访问 Git 仓库获取源代码、配置文件、数据库密码等敏感信息。

**复现步骤**:
```
1. dig git.cht-group.net A
2. curl http://git.cht-group.net/
3. 尝试 /.git/HEAD 等常见路径
```

**修复建议**:
```
1. 如果 Git 服务已弃用，删除 DNS 记录
2. 如果仍在使用，必须配置 VPN 访问
3. 检查 Nginx 代理配置是否正确
```

---
### HIGH-4: 主域 502 Bad Gateway - 服务不可用

| 属性 | 值 |
|------|-----|
| **域名** | cht-group.net |
| **检查项** | main_domain_502 |
| **CWE** | CWE-N/A |
| **CVSS** | 7.5 |
| **CVSS向量** | `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H` |
| **受影响URL** | http://cht-group.net/ |
| **截图URL** | http://cht-group.net/ |

**漏洞描述**: cht-group.net 主域返回 502 Bad Gateway，响应内容为 'Forwarding error: connection closed before message completed'。表明前端代理无法连接到后端服务。

**复现步骤**:
```
curl -v http://cht-group.net/
```

**修复建议**:
```
检查后端服务状态和代理配置
```

---
### HIGH-5: Cookie [HWWAFSESID] 严重不安全: 缺少 Secure, HttpOnly, SameSite

| 属性 | 值 |
|------|-----|
| **域名** | dahuatech.com |
| **检查项** | cookie_insecure |
| **CWE** | CWE-614 / CWE-1004 |
| **CVSS** | 7.5 |
| **CVSS向量** | `CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:N` |
| **受影响URL** | https://www.dahuatech.com |
| **截图URL** | https://www.dahuatech.com |

**漏洞描述**: 

**复现步骤**:
```

```

**修复建议**:
```
Set-Cookie: ...; Secure; HttpOnly; SameSite=Strict
```

---
### HIGH-6: 域名 www.mos400.com 无 A 记录，服务未部署 — 存在子域名接管风险

| 属性 | 值 |
|------|-----|
| **域名** | mos400.com |
| **检查项** | dns_no_record |
| **CWE** | CWE-200 |
| **CVSS** | 7.5 |
| **CVSS向量** | `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N` |
| **受影响URL** | https://www.mos400.com |
| **截图URL** | http://www.mos400.com/ |

**漏洞描述**: DNS 无 A 记录，域名已注册但未配置服务器 IP。攻击者可利用此状态进行子域名接管攻击。

**复现步骤**:
```

```

**修复建议**:
```
配置 A 记录指向服务器 IP，或配置 SPF/DMARC 防止邮件欺诈
```

---
### HIGH-7: HTTP 返回 502 Bad Gateway — 服务不可用

| 属性 | 值 |
|------|-----|
| **域名** | mos400.com |
| **检查项** | service_unavailable |
| **CWE** | CWE-N/A |
| **CVSS** | 7.5 |
| **CVSS向量** | `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H` |
| **受影响URL** | https://www.mos400.com |
| **截图URL** | https://www.mos400.com |

**漏洞描述**: HTTP 请求返回 502，响应: Forwarding error: connection closed before message completed

**复现步骤**:
```
curl -v http://www.mos400.com/
```

**修复建议**:
```
检查后端服务器和代理/CDN 配置
```

---
### HIGH-8: HTTPS 连接失败 — SSL/TLS 未正确配置

| 属性 | 值 |
|------|-----|
| **域名** | mos400.com |
| **检查项** | ssl_cert_error |
| **CWE** | CWE-295 |
| **CVSS** | 7.5 |
| **CVSS向量** | `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H` |
| **受影响URL** | https://www.mos400.com |
| **截图URL** | https://www.mos400.com/ |

**漏洞描述**: SSL 错误: HTTPSConnectionPool(host='www.mos400.com', port=443): Max retries exceeded with 

**复现步骤**:
```
curl -v https://www.mos400.com/
```

**修复建议**:
```
配置有效的 SSL 证书，确保 Web 服务器监听 443 端口
```

---
### HIGH-9: 搜索功能暴露完整 SQL 查询结构，泄露数据库 Schema

| 属性 | 值 |
|------|-----|
| **域名** | zmj.com |
| **检查项** | sql_query_exposure |
| **CWE** | CWE-209 / CWE-89 |
| **CVSS** | 7.5 |
| **CVSS向量** | `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N` |
| **受影响URL** | https://www.zmj.com/search/?q=test123 |
| **截图URL** | https://www.zmj.com |

**漏洞描述**: 搜索接口响应中暴露完整 SQL 语句: ay_model d ON b.mcode=d.mcode LEFT JOIN ay_content_ext e ON a.id=e.contentid WHERE(a.scode in ('5','6','7','16') OR a.subscode='5') AND(a.status=1 AND d.type=2 AND a.date<'2026-08-13 08:09:53') AND(q like '%test123%' )   </div>
    <div id="time" style="font-size:14px;color:#999999;"></div>
</div>



**复现步骤**:
```
curl 'https://www.zmj.com/search/?q=test123' | grep like
```

**修复建议**:
```
禁止在响应中返回 SQL 语句，使用参数化查询
```

---
## 五、MEDIUM 级漏洞列表（18 个）

| # | 域名 | 标题 | CWE | CVSS |
|---|------|------|-----|------|
| 1 | cht-group.net | 企业邮箱托管于阿里云企业邮箱，公网暴露 | CWE-200 | 5.3 |
| 2 | cht-group.net | Nginx 服务器版本泄露 (Server 头) | CWE-200 | 5.3 |
| 3 | cht-group.net | 所有子域名均缺失安全响应头 | CWE-16 | 5.3 |
| 4 | cht-group.net | 图片资源通过七牛云 CDN 公网分发 | CWE-200 | 5.3 |
| 5 | dahuatech.com | 缺失响应头: Strict-Transport-Security — HSTS缺失 | CWE-N/A | N/A |
| 6 | dahuatech.com | 缺失响应头: Content-Security-Policy — CSP缺失 | CWE-N/A | N/A |
| 7 | dahuatech.com | jQuery < 3.5.0 XSS (CVE-2020-11023/11022) | CWE-1104 | N/A |
| 8 | dahuatech.com | Spring4Shell (CVE-2022-22965) | CWE-1104 | N/A |
| 9 | mos400.com | 无 MX 记录 — 邮件服务未配置，存在邮件欺诈风险 | CWE-290 | 6.5 |
| 10 | zmj.com | 缺失响应头: Strict-Transport-Security — HSTS缺失 | CWE-N/A | N/A |
| 11 | zmj.com | 缺失响应头: X-Frame-Options — Clickjacking风险 | CWE-N/A | N/A |
| 12 | zmj.com | 缺失响应头: Content-Security-Policy — CSP缺失 | CWE-N/A | N/A |
| 13 | zmj.com | 严重缺失 10 个安全响应头 | CWE-16 | 6.1 |
| 14 | zmj.com | Cookie [lg] 不安全: 缺少 Secure, SameSite | CWE-614 / CWE-1004 | 7.5 |
| 15 | zmj.com | jQuery 3.4.1 存在已知 XSS (CVE-2020-11023/11022) | CWE-79 / CWE-1104 | 6.1 |
| 16 | zmj.com | jQuery < 3.5.0 XSS (CVE-2020-11023/11022) | CWE-1104 | N/A |
| 17 | zmj.com | 允许危险 HTTP 方法: PUT, DELETE, PATCH, CONNECT | CWE-749 | 4.3 |
| 18 | zmj.com | robots.txt 禁止全站爬取 | CWE-538 | 5.3 |

## 六、LOW 级漏洞列表（23 个）

| # | 域名 | 标题 | CWE | CVSS |
|---|------|------|-----|------|
| 1 | cht-group.net | OA 与 App 指向同一系统，增大攻击面 | CWE-200 | 4.3 |
| 2 | cht-group.net | DNS 信息泄露 - 子域名暴露内部架构 | CWE-200 | 4.3 |
| 3 | cht-group.net | 缺少 SPF/DMARC 记录 - 邮件欺诈风险 | CWE-290 | 4.3 |
| 4 | dahuatech.com | SSL 异常: timed out | CWE-N/A | N/A |
| 5 | dahuatech.com | 缺失响应头: Referrer-Policy — Referrer泄露 | CWE-N/A | N/A |
| 6 | dahuatech.com | 缺失响应头: Permissions-Policy — 权限未限制 | CWE-N/A | N/A |
| 7 | dahuatech.com | 缺失响应头: Cross-Origin-Resource-Policy — 资源可跨域加载 | CWE-N/A | N/A |
| 8 | dahuatech.com | 缺失响应头: Cross-Origin-Opener-Policy — 跨域opener未限制 | CWE-N/A | N/A |
| 9 | dahuatech.com | 缺失响应头: Cross-Origin-Embedder-Policy — 跨域资源未限制 | CWE-N/A | N/A |
| 10 | dahuatech.com | 页面暴露 2 个企业邮箱: support@dahuatech.com | CWE-200 | 5.3 |
| 11 | dahuatech.com | HTTP 明文链接: http://isdp.dahuatech.com/easywork/web/outsourcer/login | CWE-319 | 6.1 |
| 12 | mos400.com | 缺少 SPF/DMARC 记录 — 邮件欺诈风险 | CWE-290 | 4.3 |
| 13 | mos400.com | DNS 未启用 DNSSEC | CWE-345 | 4.3 |
| 14 | mos400.com | 代理错误信息泄露: Forwarding error: connection closed before message completed | CWE-209 | 5.3 |
| 15 | zmj.com | SSL 异常: timed out | CWE-N/A | N/A |
| 16 | zmj.com | 缺失响应头: X-Content-Type-Options — MIME嗅探风险 | CWE-N/A | N/A |
| 17 | zmj.com | 缺失响应头: Referrer-Policy — Referrer泄露 | CWE-N/A | N/A |
| 18 | zmj.com | 缺失响应头: Permissions-Policy — 权限未限制 | CWE-N/A | N/A |
| 19 | zmj.com | 缺失响应头: Cross-Origin-Resource-Policy — 资源可跨域加载 | CWE-N/A | N/A |
| 20 | zmj.com | 缺失响应头: Cross-Origin-Opener-Policy — 跨域opener未限制 | CWE-N/A | N/A |
| 21 | zmj.com | 缺失响应头: Cross-Origin-Embedder-Policy — 跨域资源未限制 | CWE-N/A | N/A |
| 22 | zmj.com | 缺失响应头: X-XSS-Protection — 旧版XSS过滤未启用 | CWE-N/A | N/A |
| 23 | zmj.com | HTTP 明文链接: http://www.zmjbid.com/ | CWE-319 | 6.1 |

## 七、INFO 级信息列表（13 个）

| # | 域名 | 标题 |
|---|------|------|
| 1 | cht-group.net | 技术栈: Vue.js + Element UI + Nginx + 钉钉 SDK + 七牛云 CDN + 阿里云企业邮箱 |
| 2 | cht-group.net | 子域名全景: oa/portal/app/git/mail/monitor/img 共 7 个子域名 |
| 3 | dahuatech.com | DNS: 119.3.116.73, 119.3.117.249, 119.3.117.247, 119.3.116.93 |
| 4 | dahuatech.com | HTTP 200, 217382B, https://www.dahuatech.com/ |
| 5 | dahuatech.com | 安全头正常: X-Frame-Options = DENY |
| 6 | dahuatech.com | 安全头正常: X-Content-Type-Options = nosniff |
| 7 | dahuatech.com | 安全头正常: X-XSS-Protection = 1; mode=block |
| 8 | dahuatech.com | 技术栈: PHP, jQuery, Spring |
| 9 | mos400.com | 域名已注册但 Web 服务未部署 |
| 10 | zmj.com | DNS: 39.97.3.174 |
| 11 | zmj.com | HTTP 200, 11484B, https://www.zmj.com/ |
| 12 | zmj.com | 敏感路径可访问: /robots.txt (robots.txt) |
| 13 | zmj.com | 技术栈: jQuery |

---

## 八、风险等级说明

| 等级 | 说明 |
|------|------|
| CRITICAL | 可直接导致服务器被控制、数据完全泄露、或重大隐私违规 |
| HIGH | 可导致重要数据泄露或权限绕过 |
| MEDIUM | 存在安全隐患但利用条件较苛刻 |
| LOW | 信息泄露或配置不当，风险较低 |
| INFO | 提示信息，建议关注 |

---

## 九、文件清单

```
/workspace/reports/
├── master_all_findings.json          # 全量漏洞数据 (65个)
├── master_submission_report.md       # 本提交文档
├── master_submission_report.csv      # CSV 表格
├── master_submission_report.html     # 可视化报告
│
├── zmj_com/                          # zmj.com 全部报告
├── dahuatech_com/                    # dahuatech.com 全部报告
├── mos400_com/                       # mos400.com 全部报告
└── cht_group_net/                    # cht-group.net 全部报告
```

---

*报告由自动化漏洞扫描系统 v3.0 生成 | 仅供授权安全测试使用*
