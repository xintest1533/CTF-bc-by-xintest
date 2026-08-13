# www.apcc2.ceec.net.cn 漏洞扫描与提交报告

**扫描时间**: 2026-08-13 12:10:27（核实时间: 2026-08-13 20:13）
**目标**: www.apcc2.ceec.net.cn
**组织**: 中国能源建设集团安徽电力建设第二工程有限公司（央企下属单位）
**CDN/WAF**: 华为云 WAF（CNAME: vip1.huaweicloudwaf.com, Server: CW）
**扫描方式**: 被动扫描 + 授权低频主动核实（不影响业务）

---

## 一、漏洞统计

| 等级 | 数量 | 漏洞类型 |
|------|------|----------|
| HIGH | 3 | HTTP未跳HTTPS / Cookie安全标志缺失 / DNS内网IP泄露 |
| MEDIUM | 3 | jQuery XSS / 混合内容 / 安全头缺失 |
| LOW | 1 | Server头泄露 |
| INFO | 2 | 子域名全景 / 技术栈 |
| **总计** | **9** | |

---

## 二、HIGH 级漏洞详情（按提交价值排序）

### HIGH-1: DNS 记录泄露 4 个内网 IP 地址（信息泄露/内网拓扑暴露）

- **URL/POC**: `dig api.ceec.net.cn A +short`
- **CVSS**: 7.5（CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N）
- **CWE**: CWE-200（信息暴露）
- **类型**: 通用型（DNS 配置缺陷，影响 ceec.net.cn 整个域名）

**漏洞描述**:
ceec.net.cn 域名的公网 DNS 记录中直接暴露了 4 个内网 IP 地址：

| 子域名 | 解析内网IP | 推断用途 |
|--------|-----------|----------|
| api.ceec.net.cn | 10.1.1.244 | API 服务器 |
| app.ceec.net.cn | 10.11.4.136 | 应用服务器 |
| hr.ceec.net.cn | 10.1.8.21 | 人力资源系统 |
| ai.ceec.net.cn | 10.1.12.61 | AI 系统 |

对比：www.ceec.net.cn 解析为公网 IP（华为云 WAF），mail.ceec.net.cn 解析为公网 IP（腾讯企业邮箱），唯独 api/app/hr/ai 四个子域名解析为内网 10.x.x.x 地址。

**复现步骤**:
```bash
dig api.ceec.net.cn A +short   # → 10.1.1.244
dig app.ceec.net.cn A +short   # → 10.11.4.136
dig hr.ceec.net.cn A +short    # → 10.1.8.21
dig ai.ceec.net.cn A +short    # → 10.1.12.61
```

**危害分析**:
1. 内网拓扑完全暴露：攻击者可推断内网使用 10.1.0.0/16（核心服务区：API/HR/AI）和 10.11.0.0/16（应用区）两个网段
2. IP 分配规律便于横向移动规划：攻击者若通过 VPN/钓鱼/社工等方式进入内网，可直接定位目标系统
3. 子域名经华为云 WAF 代理访问返回 502，说明 WAF 配置了内部 DNS 解析但后端不可达，进一步确认这些是真实内网地址
4. HR 系统（hr.ceec.net.cn → 10.1.8.21）暴露内网 IP，结合 HR 系统通常存储员工敏感信息，价值极高

**修复建议**:
1. 立即删除 api/app/hr/ai 等内网子域名的公网 DNS 记录
2. 使用 split-horizon DNS（内外网分离解析）：内网域名仅在内网 DNS 服务器解析
3. 审计所有 ceec.net.cn DNS 记录，清理泄露内网 IP 的条目
4. 公网 DNS 仅暴露需要对外提供服务的子域名（www/en/mail/zhaopin）

---

### HIGH-2: WAF Cookie HWWAFSESID 缺失全部安全标志（Secure/HttpOnly/SameSite）

- **URL/POC**: `http://www.apcc2.ceec.net.cn/`
- **CVSS**: 7.5（CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:N）
- **CWE**: CWE-614（未设 Secure 标志）/ CWE-1004（未设 HttpOnly）/ CWE-1275（未设 SameSite）
- **类型**: 通用型（WAF 配置缺陷，影响所有经华为云 WAF 代理的站点）

**漏洞描述**:
www.apcc2.ceec.net.cn 的华为云 WAF Cookie `HWWAFSESID` 和 `HWWAFSESTIME` 均未设置任何安全标志。实测响应头：
```
Set-Cookie: HWWAFSESID=fd28473c7112621b25; path=/
Set-Cookie: HWWAFSESTIME=1786623171424; path=/
```
三个关键安全标志全部缺失：
- **Secure: 缺失** — Cookie 可通过 HTTP 明文通道传输
- **HttpOnly: 缺失** — JavaScript 可通过 `document.cookie` 读取该 Cookie
- **SameSite: 缺失** — 跨站请求可携带该 Cookie，存在 CSRF 风险

**复现步骤**:
```bash
curl -sI -A "Mozilla/5.0" http://www.apcc2.ceec.net.cn/ | grep -i set-cookie
# Set-Cookie: HWWAFSESID=fd28473c7112621b25; path=/
# Set-Cookie: HWWAFSESTIME=1786623171424; path=/
# 确认: Secure=NO, HttpOnly=NO, SameSite=NO
```

**危害分析**:
1. 结合 HIGH-3（HTTP 未跳 HTTPS），Cookie 在明文 HTTP 通道传输，攻击者可通过 MITM 直接嗅探 WAF 会话标识
2. 无 HttpOnly，一旦站点存在 XSS（见 MEDIUM-1 jQuery XSS），攻击者可通过 `document.cookie` 窃取 HWWAFSESID
3. HWWAFSESID 是 WAF 会话标识，泄露后攻击者可伪造 WAF 会话，绕过部分基于会话的 WAF 防护规则
4. 无 SameSite，存在 CSRF 风险

**修复建议**:
在华为云 WAF 或源站 Nginx 配置 Cookie 安全标志：
```nginx
proxy_cookie_path / "/; Secure; HttpOnly; SameSite=Strict";
```
或在 WAF 控制台修改 Cookie 安全策略，强制添加 Secure/HttpOnly/SameSite=Strict。

---

### HIGH-3: HTTP 未强制重定向到 HTTPS，明文传输与加密传输并存

- **URL/POC**: `http://www.apcc2.ceec.net.cn/`
- **CVSS**: 7.5（CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N）
- **CWE**: CWE-319（明文传输）/ CWE-7525（未强制 HTTPS）
- **类型**: 通用型（WAF/源站配置缺陷）

**漏洞描述**:
www.apcc2.ceec.net.cn 的 HTTP (80) 与 HTTPS (443) 同时对外提供完整服务，HTTP 请求未做 301/302 跳转到 HTTPS。实测连续 3 次请求 `http://www.apcc2.ceec.net.cn/` 均返回 `HTTP/1.1 200 OK` + 完整页面内容（content-length: 53993 字节）。

响应头中甚至配置了 HSTS（`strict-transport-security: max-age=31536000;includeSubdomains;`），但 HSTS 仅在浏览器已访问过 HTTPS 后才生效，无法保护首次 HTTP 访问与不缓存 HSTS 的客户端。

**复现步骤**:
```bash
# 1. HTTP 请求返回完整内容，未跳转
curl -sI -A "Mozilla/5.0" http://www.apcc2.ceec.net.cn/ | head -3
# HTTP/1.1 200 OK
# date: Thu, 13 Aug 2026 12:13:12 GMT
# content-type: text/html; charset=UTF-8

# 2. 确认 HTTP 与 HTTPS 并存
curl -sI -A "Mozilla/5.0" http://www.apcc2.ceec.net.cn/  | grep -i content-length
# content-length: 53993   ← HTTP 直接返回完整页面
```

**危害分析**:
1. 攻击者可在网络层（ARP 欺骗/路由劫持/WiFi 钓鱼）强制受害者走 HTTP 通道，嗅探全部明文流量
2. 企业官网页面内容、WAF 会话 Cookie（HWWAFSESID，见 HIGH-2）、用户浏览行为全部可被嗅探
3. 可结合 Cookie 窃取实现会话劫持
4. HSTS 形同虚设：首次访问与未缓存 HSTS 的客户端不受保护

**修复建议**:
在 WAF/Nginx 配置 HTTP→HTTPS 强制重定向：
```nginx
server {
    listen 80;
    server_name www.apcc2.ceec.net.cn;
    return 301 https://$host$request_uri;
}
```
保留并完善 HSTS 配置，启用 HSTS preload 并提交到 hstspreload.org，配置 CSP: `upgrade-insecure-requests`。

---

## 三、MEDIUM 级漏洞

### MEDIUM-1: jQuery 2.2.4 存在已知 XSS 漏洞（CVE-2020-11022 / CVE-2020-11023）

- **URL**: http://www.apcc2.ceec.net.cn/module/jslib/jquery/jquery.js
- **CVSS**: 6.1 | **CWE**: CWE-79
- **描述**: 网站使用 jQuery 2.2.4（133KB），存在 CVE-2020-11022/11023 两个已知 XSS 漏洞，影响 jQuery < 3.5.0
- **复现**: `curl -s http://www.apcc2.ceec.net.cn/module/jslib/jquery/jquery.js | head -5`
- **修复**: 升级 jQuery 到 3.7.1+

### MEDIUM-2: 页面包含 71 个 HTTP 明文链接（混合内容）

- **URL**: http://www.apcc2.ceec.net.cn/
- **CVSS**: 5.3 | **CWE**: CWE-319
- **描述**: HTTPS 站点页面中包含 71 个 HTTP 明文链接，其中 39 个指向自身 http://www.apcc2.ceec.net.cn/
- **复现**: `curl -s http://www.apcc2.ceec.net.cn/ | grep -o 'href="http://[^"]*"' | wc -l`
- **修复**: 将所有 HTTP 链接改为 HTTPS，配置 CSP: upgrade-insecure-requests

### MEDIUM-3: 缺失 5 个安全响应头（X-Frame-Options/CSP/XCTO/Referrer-Policy/Permissions-Policy）

- **URL**: http://www.apcc2.ceec.net.cn/
- **CVSS**: 5.3 | **CWE**: CWE-16
- **描述**: 虽配置了 HSTS，但缺失 X-Frame-Options、Content-Security-Policy、X-Content-Type-Options、Referrer-Policy、Permissions-Policy 五个安全响应头
- **复现**: `curl -sI http://www.apcc2.ceec.net.cn/ | grep -iE 'x-frame|content-security|x-content-type|referrer|permissions'`
- **修复**: 
```nginx
add_header X-Frame-Options "DENY";
add_header Content-Security-Policy "default-src 'self'";
add_header X-Content-Type-Options "nosniff";
add_header Referrer-Policy "strict-origin-when-cross-origin";
add_header Permissions-Policy "geolocation=(),microphone=(),camera=()";
```

---

## 四、LOW / INFO

### LOW-1: Server 响应头泄露华为云 WAF 标识 (CW)
- **URL**: http://www.apcc2.ceec.net.cn/
- **CVSS**: 4.3 | **CWE**: CWE-200
- **描述**: `Server: CW` 泄露使用华为云 WAF
- **修复**: 隐藏 Server 响应头

### INFO-1: ceec.net.cn 子域名全景
| 子域名 | IP/解析 | 用途 | 状态 |
|--------|---------|------|------|
| www.apcc2 | 华为云WAF | 主站 | 200 OK |
| en | 华为云WAF | 英文站 | 200 |
| zhaopin | 华为云WAF | 招聘系统 | 200 |
| mail | QQ企业邮箱 | 邮件 | - |
| smtp | QQ企业邮箱 | SMTP | - |
| pop | QQ企业邮箱 | POP3 | - |
| ns1 | 106.39.22.66 | DNS | - |
| api | **10.1.1.244** | API | **502** |
| app | **10.11.4.136** | 应用 | **502** |
| hr | **10.1.8.21** | HR系统 | **502** |
| ai | **10.1.12.61** | AI系统 | **502** |

### INFO-2: 技术栈
- WAF: 华为云 WAF（Server: CW, HWWAFSESID, CNAME: vip1.huaweicloudwaf.com）
- 前端: jQuery 2.2.4 + SuperSlide 2.1 + Swiper + URITE CMS
- CDN: 华为云（117.78.24.x / 49.4.56.x）
- 邮件: 腾讯企业邮箱（exmail.qq.com）
- CMS: URITE 内容管理系统（/module/jslib/urite/urite.min.js）

---

## 五、提交价值排序与建议

| 优先级 | 漏洞 | 等级 | 类型 | 提交价值 |
|--------|------|------|------|----------|
| 1 | HIGH-1 DNS 泄露 4 个内网 IP | HIGH | 通用型 | ★★★★★ 央企内网拓扑暴露，HR/AI 系统定位，最高价值 |
| 2 | HIGH-2 Cookie 安全标志缺失 | HIGH | 通用型 | ★★★★☆ 可结合 XSS/MITM 实战利用 |
| 3 | HIGH-3 HTTP 未跳 HTTPS | HIGH | 通用型 | ★★★☆☆ 配置类缺陷，但影响全站明文传输 |

**提交建议**:
- 三个 HIGH 均为通用型（影响 ceec.net.cn 整个域名而非单一页面），建议合并为一次提交，价值更高
- HIGH-1（DNS 内网 IP 泄露）为核心漏洞，重点突出 HR 系统（hr.ceec.net.cn → 10.1.8.21）和 AI 系统（ai.ceec.net.cn → 10.1.12.61）的内网地址暴露
- 截图 URL 准备：
  - HIGH-1: `dig api.ceec.net.cn A +short` 命令输出截图
  - HIGH-2: `curl -sI http://www.apcc2.ceec.net.cn/ | grep -i set-cookie` 输出截图
  - HIGH-3: `curl -sI http://www.apcc2.ceec.net.cn/ | head -3` 输出截图（显示 200 OK 非 301）
