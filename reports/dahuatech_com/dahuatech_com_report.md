# dahuatech.com 安全漏洞扫描报告

> **引擎**: v3.0 | **时间**: 2026-08-13 00:10:04 | **低频被动 + 深度检测**

## 统计

| 等级 | 数量 |
|------|------|
| 💀 CRITICAL | 0 |
| 🔴 HIGH | 1 |
| 🟡 MEDIUM | 4 |
| 🟢 LOW | 8 |
| 🔵 INFO | 6 |
| **总计** | **19** |

## 漏洞详情

### 1. 🔴 [HIGH] Cookie [HWWAFSESID] 严重不安全: 缺少 Secure, HttpOnly, SameSite

| 属性 | 值 |
|------|-----|
| CWE | CWE-614 / CWE-1004 |
| CVSS | 7.5 |
| CVSS向量 | `CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:N` |
| 受影响URL | https://www.dahuatech.com |
| 截图URL | https://www.dahuatech.com |

**描述**: 

**复现**:
```

```

**修复**:
```
Set-Cookie: ...; Secure; HttpOnly; SameSite=Strict
```

---
### 2. 🟡 [MEDIUM] 缺失响应头: Strict-Transport-Security — HSTS缺失

| 属性 | 值 |
|------|-----|
| CWE | CWE-N/A |
| CVSS | N/A |
| CVSS向量 | `` |
| 受影响URL | https://www.dahuatech.com |
| 截图URL | https://www.dahuatech.com |

**描述**: 

**复现**:
```
curl -I https://www.dahuatech.com | grep -i 'Strict-Transport-Security'  # 无返回
```

**修复**:
```
Nginx: add_header Strict-Transport-Security "max-age=31536000; includeSubDomains; preload";
```

---
### 3. 🟡 [MEDIUM] 缺失响应头: Content-Security-Policy — CSP缺失

| 属性 | 值 |
|------|-----|
| CWE | CWE-N/A |
| CVSS | N/A |
| CVSS向量 | `` |
| 受影响URL | https://www.dahuatech.com |
| 截图URL | https://www.dahuatech.com |

**描述**: 

**复现**:
```
curl -I https://www.dahuatech.com | grep -i 'Content-Security-Policy'  # 无返回
```

**修复**:
```
Nginx: add_header Content-Security-Policy "default-src 'self'";
```

---
### 4. 🟡 [MEDIUM] jQuery < 3.5.0 XSS (CVE-2020-11023/11022)

| 属性 | 值 |
|------|-----|
| CWE | CWE-1104 |
| CVSS | N/A |
| CVSS向量 | `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N` |
| 受影响URL | https://www.dahuatech.com |
| 截图URL | https://www.dahuatech.com |

**描述**: 

**复现**:
```

```

**修复**:
```
升级 jQuery 至最新版本
```

---
### 5. 🟡 [MEDIUM] Spring4Shell (CVE-2022-22965)

| 属性 | 值 |
|------|-----|
| CWE | CWE-1104 |
| CVSS | N/A |
| CVSS向量 | `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N` |
| 受影响URL | https://www.dahuatech.com |
| 截图URL | https://www.dahuatech.com |

**描述**: 

**复现**:
```

```

**修复**:
```
升级 Spring 至最新版本
```

---
### 6. 🟢 [LOW] SSL 异常: timed out

| 属性 | 值 |
|------|-----|
| CWE | CWE-N/A |
| CVSS | N/A |
| CVSS向量 | `` |
| 受影响URL | https://www.dahuatech.com |
| 截图URL | https://www.dahuatech.com |

**描述**: 

**复现**:
```

```

**修复**:
```

```

---
### 7. 🟢 [LOW] 缺失响应头: Referrer-Policy — Referrer泄露

| 属性 | 值 |
|------|-----|
| CWE | CWE-N/A |
| CVSS | N/A |
| CVSS向量 | `` |
| 受影响URL | https://www.dahuatech.com |
| 截图URL | https://www.dahuatech.com |

**描述**: 

**复现**:
```
curl -I https://www.dahuatech.com | grep -i 'Referrer-Policy'  # 无返回
```

**修复**:
```
Nginx: add_header Referrer-Policy "strict-origin-when-cross-origin";
```

---
### 8. 🟢 [LOW] 缺失响应头: Permissions-Policy — 权限未限制

| 属性 | 值 |
|------|-----|
| CWE | CWE-N/A |
| CVSS | N/A |
| CVSS向量 | `` |
| 受影响URL | https://www.dahuatech.com |
| 截图URL | https://www.dahuatech.com |

**描述**: 

**复现**:
```
curl -I https://www.dahuatech.com | grep -i 'Permissions-Policy'  # 无返回
```

**修复**:
```
Nginx: add_header Permissions-Policy "geolocation=(), microphone=(), camera=()";
```

---
### 9. 🟢 [LOW] 缺失响应头: Cross-Origin-Resource-Policy — 资源可跨域加载

| 属性 | 值 |
|------|-----|
| CWE | CWE-N/A |
| CVSS | N/A |
| CVSS向量 | `` |
| 受影响URL | https://www.dahuatech.com |
| 截图URL | https://www.dahuatech.com |

**描述**: 

**复现**:
```
curl -I https://www.dahuatech.com | grep -i 'Cross-Origin-Resource-Policy'  # 无返回
```

**修复**:
```
Nginx: add_header Cross-Origin-Resource-Policy "same-origin";
```

---
### 10. 🟢 [LOW] 缺失响应头: Cross-Origin-Opener-Policy — 跨域opener未限制

| 属性 | 值 |
|------|-----|
| CWE | CWE-N/A |
| CVSS | N/A |
| CVSS向量 | `` |
| 受影响URL | https://www.dahuatech.com |
| 截图URL | https://www.dahuatech.com |

**描述**: 

**复现**:
```
curl -I https://www.dahuatech.com | grep -i 'Cross-Origin-Opener-Policy'  # 无返回
```

**修复**:
```
Nginx: add_header Cross-Origin-Opener-Policy "same-origin";
```

---
### 11. 🟢 [LOW] 缺失响应头: Cross-Origin-Embedder-Policy — 跨域资源未限制

| 属性 | 值 |
|------|-----|
| CWE | CWE-N/A |
| CVSS | N/A |
| CVSS向量 | `` |
| 受影响URL | https://www.dahuatech.com |
| 截图URL | https://www.dahuatech.com |

**描述**: 

**复现**:
```
curl -I https://www.dahuatech.com | grep -i 'Cross-Origin-Embedder-Policy'  # 无返回
```

**修复**:
```
Nginx: add_header Cross-Origin-Embedder-Policy "require-corp";
```

---
### 12. 🟢 [LOW] 页面暴露 2 个企业邮箱: support@dahuatech.com

| 属性 | 值 |
|------|-----|
| CWE | CWE-200 |
| CVSS | 5.3 |
| CVSS向量 | `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N` |
| 受影响URL | https://www.dahuatech.com |
| 截图URL | https://www.dahuatech.com |

**描述**: 

**复现**:
```

```

**修复**:
```
使用联系表单代替直接暴露邮箱
```

---
### 13. 🟢 [LOW] HTTP 明文链接: http://isdp.dahuatech.com/easywork/web/outsourcer/login

| 属性 | 值 |
|------|-----|
| CWE | CWE-319 |
| CVSS | 6.1 |
| CVSS向量 | `CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N` |
| 受影响URL | https://www.dahuatech.com |
| 截图URL | https://www.dahuatech.com |

**描述**: 

**复现**:
```

```

**修复**:
```
升级为 HTTPS
```

---
### 14. 🔵 [INFO] DNS: 119.3.116.73, 119.3.117.249, 119.3.117.247, 119.3.116.93

| 属性 | 值 |
|------|-----|
| CWE | CWE-N/A |
| CVSS | N/A |
| CVSS向量 | `` |
| 受影响URL | https://www.dahuatech.com |
| 截图URL | https://www.dahuatech.com |

**描述**: 

**复现**:
```

```

**修复**:
```

```

---
### 15. 🔵 [INFO] HTTP 200, 217382B, https://www.dahuatech.com/

| 属性 | 值 |
|------|-----|
| CWE | CWE-N/A |
| CVSS | N/A |
| CVSS向量 | `` |
| 受影响URL | https://www.dahuatech.com |
| 截图URL | https://www.dahuatech.com |

**描述**: 

**复现**:
```

```

**修复**:
```

```

---
### 16. 🔵 [INFO] 安全头正常: X-Frame-Options = DENY

| 属性 | 值 |
|------|-----|
| CWE | CWE-N/A |
| CVSS | N/A |
| CVSS向量 | `` |
| 受影响URL | https://www.dahuatech.com |
| 截图URL | https://www.dahuatech.com |

**描述**: 

**复现**:
```

```

**修复**:
```

```

---
### 17. 🔵 [INFO] 安全头正常: X-Content-Type-Options = nosniff

| 属性 | 值 |
|------|-----|
| CWE | CWE-N/A |
| CVSS | N/A |
| CVSS向量 | `` |
| 受影响URL | https://www.dahuatech.com |
| 截图URL | https://www.dahuatech.com |

**描述**: 

**复现**:
```

```

**修复**:
```

```

---
### 18. 🔵 [INFO] 安全头正常: X-XSS-Protection = 1; mode=block

| 属性 | 值 |
|------|-----|
| CWE | CWE-N/A |
| CVSS | N/A |
| CVSS向量 | `` |
| 受影响URL | https://www.dahuatech.com |
| 截图URL | https://www.dahuatech.com |

**描述**: 

**复现**:
```

```

**修复**:
```

```

---
### 19. 🔵 [INFO] 技术栈: PHP, jQuery, Spring

| 属性 | 值 |
|------|-----|
| CWE | CWE-N/A |
| CVSS | N/A |
| CVSS向量 | `` |
| 受影响URL | https://www.dahuatech.com |
| 截图URL | https://www.dahuatech.com |

**描述**: 

**复现**:
```

```

**修复**:
```

```

---

*报告由自动化漏洞扫描系统 v3.0 生成 | 仅供授权安全测试使用*
