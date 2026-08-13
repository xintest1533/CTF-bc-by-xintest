# mos400.com 安全漏洞扫描报告

> **引擎**: v3.0 | **时间**: 2026-08-13 00:10:47 | **低频被动 + 深度检测**

## 统计

| 等级 | 数量 |
|------|------|
| 💀 CRITICAL | 0 |
| 🔴 HIGH | 3 |
| 🟡 MEDIUM | 1 |
| 🟢 LOW | 3 |
| 🔵 INFO | 1 |
| **总计** | **8** |

## 漏洞详情

### 1. 🔴 [HIGH] 域名 www.mos400.com 无 A 记录，服务未部署 — 存在子域名接管风险

| 属性 | 值 |
|------|-----|
| CWE | CWE-200 |
| CVSS | 7.5 |
| CVSS向量 | `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N` |
| 受影响URL | https://www.mos400.com |
| 截图URL | http://www.mos400.com/ |

**描述**: DNS 无 A 记录，域名已注册但未配置服务器 IP。攻击者可利用此状态进行子域名接管攻击。

**复现**:
```

```

**修复**:
```
配置 A 记录指向服务器 IP，或配置 SPF/DMARC 防止邮件欺诈
```

---
### 2. 🔴 [HIGH] HTTP 返回 502 Bad Gateway — 服务不可用

| 属性 | 值 |
|------|-----|
| CWE | CWE-N/A |
| CVSS | 7.5 |
| CVSS向量 | `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H` |
| 受影响URL | https://www.mos400.com |
| 截图URL | https://www.mos400.com |

**描述**: HTTP 请求返回 502，响应: Forwarding error: connection closed before message completed

**复现**:
```
curl -v http://www.mos400.com/
```

**修复**:
```
检查后端服务器和代理/CDN 配置
```

---
### 3. 🔴 [HIGH] HTTPS 连接失败 — SSL/TLS 未正确配置

| 属性 | 值 |
|------|-----|
| CWE | CWE-295 |
| CVSS | 7.5 |
| CVSS向量 | `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H` |
| 受影响URL | https://www.mos400.com |
| 截图URL | https://www.mos400.com/ |

**描述**: SSL 错误: HTTPSConnectionPool(host='www.mos400.com', port=443): Max retries exceeded with 

**复现**:
```
curl -v https://www.mos400.com/
```

**修复**:
```
配置有效的 SSL 证书，确保 Web 服务器监听 443 端口
```

---
### 4. 🟡 [MEDIUM] 无 MX 记录 — 邮件服务未配置，存在邮件欺诈风险

| 属性 | 值 |
|------|-----|
| CWE | CWE-290 |
| CVSS | 6.5 |
| CVSS向量 | `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N` |
| 受影响URL | https://www.mos400.com |
| 截图URL | https://www.mos400.com |

**描述**: 缺少 MX 记录，且无 SPF/DMARC，攻击者可伪造该域名发送钓鱼邮件

**复现**:
```

```

**修复**:
```
配置 SPF: v=spf1 -all 和 DMARC: v=DMARC1; p=reject
```

---
### 5. 🟢 [LOW] 缺少 SPF/DMARC 记录 — 邮件欺诈风险

| 属性 | 值 |
|------|-----|
| CWE | CWE-290 |
| CVSS | 4.3 |
| CVSS向量 | `CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:N` |
| 受影响URL | https://www.mos400.com |
| 截图URL | https://www.mos400.com |

**描述**: 

**复现**:
```

```

**修复**:
```
添加 TXT: v=spf1 -all 和 v=DMARC1; p=reject;
```

---
### 6. 🟢 [LOW] DNS 未启用 DNSSEC

| 属性 | 值 |
|------|-----|
| CWE | CWE-345 |
| CVSS | 4.3 |
| CVSS向量 | `CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:L/A:N` |
| 受影响URL | https://www.mos400.com |
| 截图URL | https://www.mos400.com |

**描述**: 

**复现**:
```

```

**修复**:
```
在域名注册商处启用 DNSSEC
```

---
### 7. 🟢 [LOW] 代理错误信息泄露: Forwarding error: connection closed before message completed

| 属性 | 值 |
|------|-----|
| CWE | CWE-209 |
| CVSS | 5.3 |
| CVSS向量 | `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N` |
| 受影响URL | https://www.mos400.com |
| 截图URL | https://www.mos400.com |

**描述**: 

**复现**:
```

```

**修复**:
```
配置自定义错误页面，隐藏内部错误信息
```

---
### 8. 🔵 [INFO] 域名已注册但 Web 服务未部署

| 属性 | 值 |
|------|-----|
| CWE | CWE-N/A |
| CVSS | N/A |
| CVSS向量 | `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N` |
| 受影响URL | https://www.mos400.com |
| 截图URL | https://www.mos400.com |

**描述**: DNS 探测发现域名已注册但无可用 Web 服务，建议确认域名用途并正确配置

**复现**:
```

```

**修复**:
```
联系域名管理员确认服务配置
```

---

*报告由自动化漏洞扫描系统 v3.0 生成 | 仅供授权安全测试使用*
