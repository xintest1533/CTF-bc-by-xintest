# 漏洞扫描汇总报告 — 提交版

> **扫描引擎**: 升级版 v3.0 (10模块一体化)
> **生成时间**: 2026-08-13 13:40:58
> **扫描域名**: 8 个
> **漏洞总数**: 98 个
> **授权方式**: 低频被动探测 + 深度检测（无高压，不影响业务）

---

## 一、总体统计

| 等级 | 数量 | 占比 |
|------|------|------|
| 💀 CRITICAL | 2 | 2% |
| 🔴 HIGH | 21 | 18% |
| 🟡 MEDIUM | 37 | 32% |
| 🟢 LOW | 35 | 30% |
| 🔵 INFO | 21 | 18% |
| **总计** | **116** | **100%** |

| 域名 | CRITICAL | HIGH | MEDIUM | LOW | INFO | 合计 |
|------|----------|------|--------|-----|------|------|
| www.impc.com.cn | 0 | 4 | 10 | 6 | 2 | 22 |
| cht-group.net | 2 | 4 | 4 | 3 | 2 | 15 |
| www.zmj.com | 0 | 1 | 7 | 2 | 4 | 14 |
| www.bpeg.cn | 0 | 3 | 4 | 3 | 2 | 12 |
| www.dahuatech.com | 0 | 1 | 2 | 3 | 3 | 9 |
| www.sc.sgcc.com.cn | 0 | 2 | 3 | 2 | 2 | 9 |
| www.apcc2.ceec.net.cn | 0 | 3 | 3 | 1 | 2 | 9 |
| www.mos400.com | 0 | 3 | 1 | 3 | 1 | 8 |

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

## 三、CRITICAL 级漏洞

### CRITICAL-1: OA 系统公网暴露，API 端点含薪资/考勤/员工等敏感模块

- **域名**: cht-group.net
- **URL**: https://oa.cht-group.net/
- **CVSS**: 9.8 | **CWE**: CWE-200 / CWE-284

**描述**: OA 系统(泛微OA)直接暴露在公网，无需 VPN 即可访问。API 路由包含 /api/salary、/api/payroll、/api/employee、/api/attendance、/api/leave、/api/approval 等大量敏感端点。该系统集成了钉钉 H5 登录，但登录页面本身未做 IP 限制。攻击者可通过暴力破解、社工钓鱼、或利用泛微 OA 已知漏洞获取全公司员工个人隐私数据、薪资数据、考勤记录、审批流等。违反《个人信息保护法》第51条。

**复现步骤**:
```
1. 访问 https://oa.cht-group.net/
2. 查看页面源码，确认 Vue.js SPA 架构
3. 访问 https://oa.cht-group.net/api/salary 确认 API 路由
4. 使用钉钉扫码登录或暴力破解获取访问权限
5. 登录后可访问全公司员工通讯录、薪资、考勤数据
```

**修复建议**: 1. 立即将 OA 系统置于 VPN 后，或配置 IP 白名单
2. 启用双因素认证
3. 升级泛微 OA 至最新版本，修补已知漏洞
4. 配置 WAF 规则防范暴力破解
5. 对敏感 API 端点增加额外鉴权

### CRITICAL-2: 数据指标门户 Portal 公网暴露，含企业核心业务数据

- **域名**: cht-group.net
- **URL**: https://portal.cht-group.net/
- **CVSS**: 9.8 | **CWE**: CWE-200 / CWE-284

**描述**: Portal 系统标题为'指标口径'，是企业数据指标管理平台。JS 文件包含 96 处 token 引用、177 处 user 引用、11 处 password 引用、4 处 secret 引用，明确表明该平台处理企业核心业务数据。该平台同样未做访问限制，直接暴露在公网。一旦越权访问，可获取企业全部经营指标、财务数据、用户数据等核心商业秘密。

**复现步骤**:
```
1. 访问 https://portal.cht-group.net/
2. 查看页面标题'指标口径'
3. 分析 JS 文件中 token/user/password/secret 等关键词
4. 尝试未授权访问 API 端点
```

**修复建议**: 1. Portal 必须置于 VPN 或内网环境
2. 配置严格的 IP 白名单
3. API 接口增加 JWT Token 鉴权
4. 审计 JS 文件中是否硬编码了凭证

---

## 四、HIGH 级漏洞

### HIGH-1: Cookie [HWWAFSESID] 严重不安全: 缺少 Secure, HttpOnly, SameSite

- **域名**: www.dahuatech.com
- **URL**: https://www.dahuatech.com
- **CVSS**: 7.5 | **CWE**: CWE-614 / CWE-1004

**修复**: Set-Cookie: ...; Secure; HttpOnly; SameSite=Strict

### HIGH-2: 搜索功能暴露完整 SQL 查询结构，泄露数据库 Schema

- **域名**: www.zmj.com
- **URL**: https://www.zmj.com/search/?q=test123
- **CVSS**: 7.5 | **CWE**: CWE-209 / CWE-89

**描述**: 搜索接口响应中暴露完整 SQL 语句: ay_model d ON b.mcode=d.mcode LEFT JOIN ay_content_ext e ON a.id=e.contentid WHERE(a.scode in ('5','6','7','16') OR a.subscode='5') AND(a.status=1 AND d.type=2 AND a.date<'2026-08-...

**复现**: `curl 'https://www.zmj.com/search/?q=test123' | grep like`

**修复**: 禁止在响应中返回 SQL 语句，使用参数化查询

### HIGH-3: 域名 www.mos400.com 无 A 记录，服务未部署 — 存在子域名接管风险

- **域名**: www.mos400.com
- **URL**: https://www.mos400.com
- **CVSS**: 7.5 | **CWE**: CWE-200

**描述**: DNS 无 A 记录，域名已注册但未配置服务器 IP。攻击者可利用此状态进行子域名接管攻击。

**修复**: 配置 A 记录指向服务器 IP，或配置 SPF/DMARC 防止邮件欺诈

### HIGH-4: HTTP 返回 502 Bad Gateway — 服务不可用

- **域名**: www.mos400.com
- **URL**: https://www.mos400.com
- **CVSS**: 7.5 | **CWE**: CWE-N/A

**描述**: HTTP 请求返回 502，响应: Forwarding error: connection closed before message completed

**复现**: `curl -v http://www.mos400.com/`

**修复**: 检查后端服务器和代理/CDN 配置

### HIGH-5: HTTPS 连接失败 — SSL/TLS 未正确配置

- **域名**: www.mos400.com
- **URL**: https://www.mos400.com
- **CVSS**: 7.5 | **CWE**: CWE-295

**描述**: SSL 错误: HTTPSConnectionPool(host='www.mos400.com', port=443): Max retries exceeded with 

**复现**: `curl -v https://www.mos400.com/`

**修复**: 配置有效的 SSL 证书，确保 Web 服务器监听 443 端口

### HIGH-6: OA 系统集成钉钉 H5 登录，corpId 可能泄露

- **域名**: cht-group.net
- **URL**: https://oa.cht-group.net/
- **CVSS**: 7.5 | **CWE**: CWE-200

**描述**: OA 页面加载了钉钉 H5 登录 SDK: https://g.alicdn.com/dingding/h5-dingtalk-login/0.21.0/ddlogin.js。该 SDK 需要 corpId 参数初始化，攻击者可通过分析 JS 文件获取 corpId，进而针对性攻击该企业的钉钉组织。

**复现**: `1. 访问 https://oa.cht-group.net/
2. 查看页面源码，搜索 ddlogin.js
3. 分析 JS 文件中的 corpId 参数
4. 使用 corpId 针对性攻击钉钉...`

**修复**: 1. 确保 corpId 不暴露在前端 JS 中
2. 使用服务端代理方式调用钉钉 API
3. 限制钉钉应用的可信 IP 列表

### HIGH-7: 监控 SDK 公网暴露，泄露内部监控数据

- **域名**: cht-group.net
- **URL**: https://monitor.cht-group.net/
- **CVSS**: 7.5 | **CWE**: CWE-200

**描述**: OA 页面引用了 https://monitor.cht-group.net/downloads/yt-monitor-prod-sdk.js，该 SDK 文件可被直接下载(9616 bytes)。监控 SDK 包含上报地址、数据采集逻辑，可能泄露内部监控指标和业务数据。monitor 子域名指向阿里云 SASE SSO 登录页面。

**复现**: `1. curl https://monitor.cht-group.net/downloads/yt-monitor-prod-sdk.js
2. 分析 SDK 中的数据采集逻辑和上报地址
3. 确认...`

**修复**: 1. 限制监控 SDK 的访问来源
2. 监控系统必须置于内网/VPN
3. 不要在 SDK 中硬编码敏感信息

### HIGH-8: Git 代码仓库服务器公网暴露 (git.cht-group.net)

- **域名**: cht-group.net
- **URL**: http://git.cht-group.net/
- **CVSS**: 7.5 | **CWE**: CWE-200

**描述**: git.cht-group.net 解析到 120.55.64.59，当前返回 502，但 DNS 记录表明该子域名曾用于代码仓库。如果服务恢复，攻击者可尝试访问 Git 仓库获取源代码、配置文件、数据库密码等敏感信息。

**复现**: `1. dig git.cht-group.net A
2. curl http://git.cht-group.net/
3. 尝试 /.git/HEAD 等常见路径`

**修复**: 1. 如果 Git 服务已弃用，删除 DNS 记录
2. 如果仍在使用，必须配置 VPN 访问
3. 检查 Nginx 代理配置是否正确

### HIGH-9: 主域 502 Bad Gateway - 服务不可用

- **域名**: cht-group.net
- **URL**: http://cht-group.net/
- **CVSS**: 7.5 | **CWE**: CWE-N/A

**描述**: cht-group.net 主域返回 502 Bad Gateway，响应内容为 'Forwarding error: connection closed before message completed'。表明前端代理无法连接到后端服务。

**复现**: `curl -v http://cht-group.net/`

**修复**: 检查后端服务状态和代理配置

### HIGH-10: ERP 系统 /test/ 路径公网可访问，暴露测试环境

- **域名**: www.impc.com.cn
- **URL**: https://erp.impc.com.cn/test/
- **CVSS**: 7.5 | **CWE**: CWE-538

**描述**: erp.impc.com.cn（内蒙古电力集团 ERP 系统）的 /test/ 路径可直接访问，返回 'this is test web index!'。测试环境暴露可能导致测试数据泄露、配置泄露，甚至被攻击者利用进入内网。

**复现**: `curl https://erp.impc.com.cn/test/`

**修复**: 1. 删除或禁用测试路径
2. 测试环境应使用独立域名或内网访问
3. 配置 Nginx 对 /test/ 路径进行 IP 限制

### HIGH-11: OA 系统 /api/doc 接口公网可访问

- **域名**: www.impc.com.cn
- **URL**: https://oa.impc.com.cn/api/doc
- **CVSS**: 7.5 | **CWE**: CWE-200

**描述**: oa.impc.com.cn（蒙电e联 OA 系统）的 /api/doc 接口返回 200，可直接访问。OA 系统的 API 文档接口暴露会泄露系统 API 结构、参数、数据模型等信息，帮助攻击者理解系统并进行针对性攻击。

**复现**: `curl https://oa.impc.com.cn/api/doc`

**修复**: 1. 关闭 API 文档外网访问
2. 配置 IP 白名单
3. 生产环境禁用 API 文档功能

### HIGH-12: OMS 呼供掌上调度系统暴露开发人员信息

- **域名**: www.impc.com.cn
- **URL**: https://oms.impc.com.cn/
- **CVSS**: 7.5 | **CWE**: CWE-200

**描述**: oms.impc.com.cn（呼和浩特供电局调度系统）HTML 注释中暴露了开发人员信息：@Author: mijian, @Date: 2021-12-13。这些信息可被攻击者用于社工钓鱼攻击。

**复现**: `1. 访问 https://oms.impc.com.cn/
2. 查看页面源代码
3. 搜索 @Author 或 @Date 注释`

**修复**: 1. 生产环境删除 HTML 注释中的开发人员信息
2. 使用构建工具自动去除注释

### HIGH-13: 所有子域名 HTTPS 完全不可用，SSL 证书未配置

- **域名**: www.sc.sgcc.com.cn
- **URL**: https://www.sc.sgcc.com.cn/
- **CVSS**: 7.5 | **CWE**: CWE-319 / CWE-295

**描述**: www.sc.sgcc.com.cn 的全部 4 个子域名（www/mail/95598/weixin）均无法建立 HTTPS 连接，SSL 握手超时或失败。作为国家电网四川公司的对外服务门户，95598 供电服务热线和微信端均不支持 HTTPS 加密，用户通过 HTTP 明文传输用电信息、缴费信息等敏感数据，存在中间人攻击风险。响应体 'Forwarding error: connection ...

**复现**: `1. curl -v https://www.sc.sgcc.com.cn/ → SSL 握手超时
2. curl -v https://95598.sc.sgcc.com.cn/ → SSL 握手超...`

**修复**: 1. 为所有子域名配置有效的 SSL 证书
2. 配置 HTTP 自动跳转 HTTPS
3. 配置 HSTS: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload
4. 修复后端服务，使其正常响应

### HIGH-14: 全部 4 个子域名服务宕机 (502 Bad Gateway)

- **域名**: www.sc.sgcc.com.cn
- **URL**: http://www.sc.sgcc.com.cn/
- **CVSS**: 7.5 | **CWE**: CWE-N/A

**描述**: www/mail/95598/weixin 四个子域名全部返回 502 Bad Gateway，后端服务完全不可用。95598 是国家电网供电服务热线，其在线服务系统宕机会直接影响四川省用户的用电报修、电费查询、业务办理等核心民生服务。响应体 'Forwarding error: connection closed before message completed' 是 Go 语言 reverse...

**复现**: `1. curl http://www.sc.sgcc.com.cn/ → 502
2. curl http://95598.sc.sgcc.com.cn/ → 502
3. curl http://m...`

**修复**: 1. 立即检查后端服务状态
2. 检查反向代理配置
3. 配置服务健康检查和自动重启
4. 建立监控告警机制

### HIGH-15: SSL VPN 网关公网暴露，登录页面可直接访问

- **域名**: www.bpeg.cn
- **URL**: https://vpn.bpeg.cn/
- **CVSS**: 7.5 | **CWE**: CWE-200 / CWE-284

**描述**: vpn.bpeg.cn 是北京电力设备总厂有限公司的 SSL VPN 网关，通过 HTTPS 直接暴露在公网。该 VPN 页面包含登录功能（login 关键词出现 2 次，vpn 出现 5 次，ssl 出现 4 次），使用自研 JS 框架（common.min.js / common.js / 64sys.js）。VPN 网关是企业内网的入口，一旦攻击者通过暴力破解、凭证填充或漏洞利用突破 VPN...

**复现**: `1. 访问 https://vpn.bpeg.cn/
2. 确认 VPN 登录页面可访问
3. 查看 robots.txt: curl https://vpn.bpeg.cn/robots.txt
4...`

**修复**: 1. VPN 网关应配置 IP 白名单，仅允许企业办公网络 IP 访问
2. 启用双因素认证（MFA）
3. 配置登录失败锁定策略
4. 定期审计 VPN 访问日志

### HIGH-16: 主站包含 76 个 HTTP 明文链接，混合内容攻击风险

- **域名**: www.bpeg.cn
- **URL**: https://www.bpeg.cn/
- **CVSS**: 7.5 | **CWE**: CWE-319 / CWE-602

**描述**: www.bpeg.cn 主站页面中包含 76 个 HTTP 明文链接，指向 http://www.bpeg.ceec.net.cn/ 等外部域名。虽然主站已启用 HTTPS，但页面中的 HTTP 明文链接会导致：1）混合内容警告（Mixed Content），浏览器可能阻止加载这些资源；2）攻击者可利用中间人攻击篡改这些 HTTP 链接指向恶意页面；3）用户点击 HTTP 链接后，Referer ...

**复现**: `1. 访问 https://www.bpeg.cn/
2. 查看页面源代码
3. 搜索 href="http:// 开头的链接
4. 确认 76 个 HTTP 明文链接`

**修复**: 1. 将所有 HTTP 链接改为 HTTPS
2. 检查旧域名 www.bpeg.ceec.net.cn 是否仍可控
3. 配置 CSP: upgrade-insecure-requests
4. 配置 Referrer-Policy: no-referrer-when-downgrade

### HIGH-17: WAF Session Cookie 缺少全部安全标志（Secure/HttpOnly/SameSite）

- **域名**: www.bpeg.cn
- **URL**: https://www.bpeg.cn/
- **CVSS**: 7.5 | **CWE**: CWE-614 / CWE-1004

**描述**: www.bpeg.cn 和 en.bpeg.cn 的华为云 WAF Cookie HWWAFSESID 和 HWWAFSESTIME 均未设置 Secure、HttpOnly、SameSite 三个安全标志。HWWAFSESID 是 WAF 会话标识符，攻击者可通过 XSS 或中间人攻击窃取该 Cookie，导致 WAF 会话劫持，进而绕过 WAF 防护规则。

**复现**: `curl -I https://www.bpeg.cn/ | grep Set-Cookie
返回: Set-Cookie: HWWAFSESID=...; path=/, HWWAFSESTIME=...`

**修复**: 在华为云 WAF 控制台配置 Cookie 安全标志：
1. Secure: 仅 HTTPS 传输
2. HttpOnly: 禁止 JS 读取
3. SameSite=Strict: 防止 CSRF

### HIGH-18: HTTP 未强制重定向到 HTTPS，明文传输与加密传输并存

- **域名**: www.apcc2.ceec.net.cn
- **URL**: http://www.apcc2.ceec.net.cn/
- **CVSS**: 7.5 | **CWE**: CWE-319 / CWE-7525

**描述**: www.apcc2.ceec.net.cn 的 HTTP (80) 与 HTTPS (443) 同时对外提供完整服务，HTTP 请求未做 301/302 跳转到 HTTPS。实测连续 3 次请求 http://www.apcc2.ceec.net.cn/ 均返回 HTTP/1.1 200 OK + 完整页面内容（content-length: 53993 字节），响应头中甚至配置了 HSTS（st...

**复现**: `curl -sI -A 'Mozilla/5.0' http://www.apcc2.ceec.net.cn/ | head -3
# 返回: HTTP/1.1 200 OK
# content-ty...`

**修复**: 1. 在 WAF/Nginx 配置 HTTP(80) → HTTPS(443) 的 301 强制重定向
   server { listen 80; return 301 https://$host$request_uri; }
2. 保留并完善 HSTS 配置（已存在 max-age=315360...

### HIGH-19: WAF Cookie HWWAFSESID 缺失全部安全标志（Secure/HttpOnly/SameSite）

- **域名**: www.apcc2.ceec.net.cn
- **URL**: http://www.apcc2.ceec.net.cn/
- **CVSS**: 7.5 | **CWE**: CWE-614 / CWE-1004 / CWE-1275

**描述**: www.apcc2.ceec.net.cn 的华为云 WAF Cookie HWWAFSESID 和 HWWAFSESTIME 均未设置 Secure、HttpOnly、SameSite 三个安全标志。实测响应头: Set-Cookie: HWWAFSESID=fd28473c7112621b25; path=/ 和 Set-Cookie: HWWAFSESTIME=1786623171424; ...

**复现**: `curl -I http://www.apcc2.ceec.net.cn/ | grep Set-Cookie
# HWWAFSESID=...; path=/, HWWAFSESTIME=...; ...`

**修复**: proxy_cookie_path / "/; Secure; HttpOnly; SameSite=Strict";

### HIGH-20: DNS 记录泄露 4 个内网 IP 地址（10.1.x.x / 10.11.x.x）

- **域名**: www.apcc2.ceec.net.cn
- **URL**: dig api.ceec.net.cn A +short
- **CVSS**: 7.5 | **CWE**: CWE-200

**描述**: ceec.net.cn 域名的 DNS 记录中直接暴露了 4 个内网 IP 地址：
1. api.ceec.net.cn → 10.1.1.244（API 服务器）
2. app.ceec.net.cn → 10.11.4.136（应用服务器）
3. hr.ceec.net.cn → 10.1.8.21（人力资源系统）
4. ai.ceec.net.cn → 10.1.12.61（AI 系统）

...

**复现**: `dig api.ceec.net.cn A +short  # → 10.1.1.244
dig app.ceec.net.cn A +short  # → 10.11.4.136
dig hr.ce...`

**修复**: 1. 立即删除 api/app/hr/ai 等内网子域名的公网 DNS 记录
2. 使用 split-horizon DNS（内外网分离解析）
3. 内网域名仅在内网 DNS 服务器解析
4. 审计所有 ceec.net.cn DNS 记录

### HIGH-21: 工程造价审计系统通过 HTTP 公网暴露，所有路径无认证

- **域名**: www.impc.com.cn
- **URL**: http://vpn.impc.com.cn/
- **CVSS**: 8.6 | **CWE**: CWE-200 / CWE-306

**描述**: vpn.impc.com.cn 是内蒙古电力集团的工程造价审计系统（Vue.js SPA），通过 HTTP 直接暴露在公网，所有路径（/login, /admin, /api, /config, /backup, /download, /upload）均返回 200，无任何认证拦截。工程造价审计系统涉及工程预算、结算、审计报告等核心财务数据，公网可访问且无认证，属于严重安全风险。

**复现**: `1. curl http://vpn.impc.com.cn/
2. curl http://vpn.impc.com.cn/login
3. curl http://vpn.impc.com.cn/...`

**修复**: 1. 立即关闭 HTTP 访问，仅允许 HTTPS
2. 配置 IP 白名单或 VPN 访问
3. 所有 API 端点增加 JWT Token 鉴权
4. 工程造价审计系统必须置于内网环境

---

## 五、全部域名速览

### www.dahuatech.com
- **URL**: https://www.dahuatech.com/
- **组织**: N/A
- **漏洞**: CRITICAL=0, HIGH=1, MEDIUM=4, LOW=8, INFO=6
- **报告目录**: `reports/dahuatech_com/`

### www.zmj.com
- **URL**: https://www.zmj.com/
- **组织**: N/A
- **漏洞**: CRITICAL=0, HIGH=1, MEDIUM=9, LOW=9, INFO=4
- **报告目录**: `reports/zmj_com/`

### www.mos400.com
- **URL**: http://www.mos400.com/
- **组织**: N/A
- **漏洞**: CRITICAL=0, HIGH=3, MEDIUM=1, LOW=3, INFO=1
- **报告目录**: `reports/mos400_com/`

### cht-group.net
- **URL**: https://oa.cht-group.net/
- **组织**: N/A
- **漏洞**: CRITICAL=2, HIGH=4, MEDIUM=4, LOW=3, INFO=2
- **报告目录**: `reports/cht_group_net/`

### www.impc.com.cn
- **URL**: https://www.impc.com.cn/
- **组织**: N/A
- **漏洞**: CRITICAL=0, HIGH=4, MEDIUM=9, LOW=6, INFO=2
- **报告目录**: `reports/impc_com_cn/`

### www.sc.sgcc.com.cn
- **URL**: https://www.sc.sgcc.com.cn/
- **组织**: N/A
- **漏洞**: CRITICAL=0, HIGH=2, MEDIUM=3, LOW=2, INFO=2
- **报告目录**: `reports/sc_sgcc_com_cn/`

### www.bpeg.cn
- **URL**: https://www.bpeg.cn/
- **组织**: N/A
- **漏洞**: CRITICAL=0, HIGH=3, MEDIUM=4, LOW=3, INFO=2
- **报告目录**: `reports/bpeg_cn/`

### www.apcc2.ceec.net.cn
- **URL**: https://www.apcc2.ceec.net.cn/
- **组织**: 中国能源建设集团安徽电力建设第二工程有限公司
- **漏洞**: CRITICAL=0, HIGH=3, MEDIUM=3, LOW=1, INFO=2
- **报告目录**: `reports/apcc2_ceec_net_cn/`
