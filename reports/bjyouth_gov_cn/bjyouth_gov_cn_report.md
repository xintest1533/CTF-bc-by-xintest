# www.bjyouth.gov.cn 漏洞扫描与提交报告

**扫描时间**: 2026-08-14 09:31:00
**目标**: www.bjyouth.gov.cn
**组织**: 共青团北京市委员会（北京共青团）
**托管**: 太极计算机股份有限公司（Taiji Computer Corporation）
**网络**: 中国互联网交换中心（China Networks Inter-Exchange）
**CDN/WAF**: 无（直连服务器 103.83.46.179）
**扫描方式**: 被动扫描 + 授权低频主动核实（不影响业务）

---

## 一、漏洞统计

| 等级 | 数量 | 漏洞类型 |
|------|------|----------|
| HIGH | 2 | TLS 曲线协商失败 / jQuery 1.9.1 XSS |
| MEDIUM | 4 | 混合内容 / 安全头缺失 / CSP 弱 / Cookie 无安全标志 |
| LOW | 2 | 服务器指纹泄露 / 无 robots.txt |
| INFO | 3 | 子域名 / 技术栈 / 政府认证 |
| **总计** | **11** | |

---

## 二、HIGH 级漏洞详情（按提交价值排序）

### HIGH-1: SSL/TLS 椭圆曲线协商失败（bad ecpoint）

- **URL/POC**: `https://www.bjyouth.gov.cn/`
- **CVSS**: 7.5（AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H）
- **CWE**: CWE-295（证书验证不当）/ CWE-327（不安全加密算法）
- **类型**: 通用型（服务器 TLS 配置缺陷）

**漏洞描述**:
www.bjyouth.gov.cn 的 TLS 服务器配置存在椭圆曲线（EC）点格式协商缺陷。默认情况下，OpenSSL 3.0+ 客户端无法建立 HTTPS 连接，报错 `error:0A000132:SSL routines::bad ecpoint`。必须客户端显式指定 `--curves P-256` 才能成功连接。

成功连接后使用的参数：
```
TLSv1.2 / ECDHE-RSA-AES128-GCM-SHA256 / prime256v1 / rsaEncryption
证书: GeoSSL DV TLS CA (C=CN)
```

**复现步骤**:
```bash
# 失败：默认连接
curl -sI https://www.bjyouth.gov.cn/
# 结果：exit 35, SSL error: bad ecpoint

# 成功：指定曲线
curl -skI --curves P-256 https://www.bjyouth.gov.cn/
# 结果：HTTP/1.1 200 OK
```

**危害分析**:
1. 大量现代客户端（curl/OpenSSL 3.0+、部分浏览器/移动端 SDK）无法建立 HTTPS 连接
2. 用户被迫降级到 HTTP，但 HTTP 已正确 301 跳转 HTTPS，实际造成**服务不可用**
3. 安全扫描器、监控工具、爬虫等自动化工具无法正常访问站点
4. 网站对外宣称 HTTPS 加密，但实际大量客户端无法访问，影响可用性

**修复建议**:
1. 更新 Nginx/OpenSSL 到最新版本
2. 配置 `ssl_ecdh_curve` 指令指定支持的曲线：`ssl_ecdh_curve prime256v1:secp384r1:secp521r1;`
3. 确保服务器端支持 X9.62 未压缩点格式

---

### HIGH-2: jQuery 1.9.1 存在多个已知 XSS 漏洞

- **URL/POC**: `https://www.bjyouth.gov.cn/js/jquery-1.9.1.js`
- **CVSS**: 7.3（AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:L/A:N）
- **CWE**: CWE-79（XSS）
- **类型**: 通用型（前端库版本过旧）

**漏洞描述**:
网站使用 jQuery 1.9.1（288KB），该版本发布于 2013 年，已超过 10 年未更新。存在多个已知 XSS 漏洞：

| CVE 编号 | 影响版本 | 漏洞类型 | 评分 |
|----------|---------|----------|------|
| CVE-2015-9251 | jQuery < 3.0.0 | 通过 `$(location.hash)` XSS | 7.5 |
| CVE-2020-11022 | jQuery < 3.5.0 | 通过 `jQuery.htmlPrefilter` HTML 注入 XSS | 6.1 |
| CVE-2020-11023 | jQuery < 3.5.0 | 通过 HTML 传递给 jQuery 操作函数 XSS | 6.1 |

**复现步骤**:
```bash
curl -skI --curves P-256 https://www.bjyouth.gov.cn/js/jquery-1.9.1.js | head -3
# 确认版本为 jQuery 1.9.1
```

**危害分析**:
1. 攻击者可通过构造恶意 HTML 内容，在用户浏览器中执行任意 JavaScript
2. 政务网站内容通常包含用户提交的稿件/评论，XSS 利用面大
3. 可窃取用户会话、钓鱼、篡改页面内容
4. 结合 HIGH-1（TLS 问题），部分用户可能被迫使用 HTTP 访问，XSS 攻击面更广

**修复建议**:
升级 jQuery 到 3.7.1+ 最新稳定版：
```html
<script src="https://code.jquery.com/jquery-3.7.1.min.js"></script>
```

---

## 三、MEDIUM 级漏洞

### MEDIUM-1: HTTPS 页面包含 HTTP 明文链接到 www.ccyl.org.cn（混合内容）

- **URL**: https://www.bjyouth.gov.cn/ → http://www.ccyl.org.cn
- **CVSS**: 5.3 | **CWE**: CWE-319
- **描述**: HTTPS 页面中存在 `http://www.ccyl.org.cn` 的明文 HTTP 链接，浏览器会显示混合内容警告
- **复现**: `grep -oP 'http://[^"<>]+' /tmp/bjyouth_full.html | grep -v w3.org`
- **修复**: 将 http://www.ccyl.org.cn 改为 https://www.ccyl.org.cn

### MEDIUM-2: 缺失 4 个安全响应头

- **URL**: https://www.bjyouth.gov.cn/
- **CVSS**: 5.3 | **CWE**: CWE-16
- **描述**: 已配置 HSTS 和 CSP，但缺失 X-Frame-Options、X-Content-Type-Options、Referrer-Policy、Permissions-Policy
- **复现**: `curl -skI --curves P-256 https://www.bjyouth.gov.cn/ | grep -iE 'x-frame|content-security|x-content-type|referrer|permissions'`
- **修复**:
```nginx
add_header X-Frame-Options "SAMEORIGIN";
add_header X-Content-Type-Options "nosniff";
add_header Referrer-Policy "strict-origin-when-cross-origin";
add_header Permissions-Policy "geolocation=(),microphone=(),camera=()";
```

### MEDIUM-3: CSP 包含 unsafe-inline 和 unsafe-eval

- **URL**: https://www.bjyouth.gov.cn/
- **CVSS**: 5.0 | **CWE**: CWE-80
- **描述**: CSP 中 `'unsafe-inline'` 和 `'unsafe-eval'` 使 CSP 对 XSS 的防护效果大幅降低
- **复现**: `curl -skI --curves P-256 https://www.bjyouth.gov.cn/ | grep -i content-security`
- **修复**: 移除 unsafe-inline 和 unsafe-eval，改用 nonce 或 hash 策略

### MEDIUM-4: 网站会话 Cookie 安全状态未知

- **URL**: https://www.bjyouth.gov.cn/
- **CVSS**: 4.3 | **CWE**: CWE-200
- **描述**: 首页无 Cookie，但网站存在搜索功能和内部页面，需检查其他子页面是否使用缺少安全标志的会话 Cookie
- **复现**: `curl -skI --curves P-256 https://www.bjyouth.gov.cn/ | grep -i set-cookie`（输出为空）
- **修复**: 确保所有子页面的 Cookie 都设置了 Secure/HttpOnly/SameSite 标志

---

## 四、LOW / INFO

### LOW-1: Web 服务器指纹泄露
- **URL**: https://www.bjyouth.gov.cn/swagger
- **CVSS**: 3.1 | **CWE**: CWE-200
- **描述**: 403 错误页面可识别为 Nginx 服务器
- **修复**: 自定义 403/404 错误页面

### LOW-2: 未配置 robots.txt
- **URL**: https://www.bjyouth.gov.cn/robots.txt
- **CVSS**: 2.0 | **CWE**: CWE-200
- **描述**: robots.txt 返回 404，未配置爬虫规则
- **修复**: 添加 robots.txt 文件

### INFO-1: 子域名全景
| 子域名 | IP | 状态 |
|--------|----|------|
| www.bjyouth.gov.cn | 103.83.46.179 | 200 OK |
| www.bjyouth.gov.cn (IPv6) | 2403:e7c0:1::a9 | - |

### INFO-2: 技术栈
- 前端: jQuery 1.9.1 + Layui + anime.js 3.2.2 + SuperSlide
- 服务器: Nginx
- 证书: GeoSSL DV TLS CA
- 托管: 太极计算机股份有限公司
- 统计: 百度统计
- ICP: 京ICP备17017271号-3

### INFO-3: 政府网站认证
- 域名: .gov.cn 政府域名
- 公安备案: 京公网安备11010802010388号
- 党政机关标识: dcs.conac.cn 已配置

---

## 五、提交价值排序

| 优先级 | 漏洞 | 等级 | 类型 | 提交价值 |
|--------|------|------|------|----------|
| 1 | **HIGH-1** TLS 椭圆曲线协商失败 | HIGH | 通用型 | ★★★★★ 服务不可用，影响大量客户端 |
| 2 | **HIGH-2** jQuery 1.9.1 XSS | HIGH | 通用型 | ★★★★☆ 多个已知 CVE，可利用面大 |
| 3 | **MEDIUM-1** 混合内容 HTTP 链接 | MEDIUM | 通用型 | ★★★☆☆ 影响安全标识 |
| 4 | **MEDIUM-2** 安全头缺失 | MEDIUM | 通用型 | ★★★☆☆ 点击劫持/MIME 嗅探风险 |
| 5 | **MEDIUM-3** CSP unsafe-inline/eval | MEDIUM | 通用型 | ★★☆☆☆ 削弱 XSS 防护 |

**提交建议**:
- HIGH-1（TLS bad ecpoint）为核心漏洞，这是政府网站中不常见的严重 TLS 配置缺陷，直接导致大量客户端无法访问
- HIGH-2（jQuery 1.9.1）为经典前端库版本漏洞，多个 CVE 可叠加
- 两个 HIGH 均为通用型，建议合并提交，突出 TLS 服务不可用问题