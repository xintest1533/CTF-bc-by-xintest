# zmj.com 安全漏洞扫描报告

> **引擎**: v3.0 | **时间**: 2026-08-13 00:10:00 | **低频被动 + 深度检测**

## 统计

| 等级 | 数量 |
|------|------|
| 💀 CRITICAL | 0 |
| 🔴 HIGH | 1 |
| 🟡 MEDIUM | 9 |
| 🟢 LOW | 9 |
| 🔵 INFO | 4 |
| **总计** | **23** |

## 漏洞详情

### 1. 🔴 [HIGH] 搜索功能暴露完整 SQL 查询结构，泄露数据库 Schema

| 属性 | 值 |
|------|-----|
| CWE | CWE-209 / CWE-89 |
| CVSS | 7.5 |
| CVSS向量 | `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N` |
| 受影响URL | https://www.zmj.com/search/?q=test123 |
| 截图URL | https://www.zmj.com |

**描述**: 搜索接口响应中暴露完整 SQL 语句: ay_model d ON b.mcode=d.mcode LEFT JOIN ay_content_ext e ON a.id=e.contentid WHERE(a.scode in ('5','6','7','16') OR a.subscode='5') AND(a.status=1 AND d.type=2 AND a.date<'2026-08-13 08:09:53') AND(q like '%test123%' )   </div>
    <div id="time" style="font-size:14px;color:#999999;"></div>
</div>



**复现**:
```
curl 'https://www.zmj.com/search/?q=test123' | grep like
```

**修复**:
```
禁止在响应中返回 SQL 语句，使用参数化查询
```

---
### 2. 🟡 [MEDIUM] 缺失响应头: Strict-Transport-Security — HSTS缺失

| 属性 | 值 |
|------|-----|
| CWE | CWE-N/A |
| CVSS | N/A |
| CVSS向量 | `` |
| 受影响URL | https://www.zmj.com |
| 截图URL | https://www.zmj.com |

**描述**: 

**复现**:
```
curl -I https://www.zmj.com | grep -i 'Strict-Transport-Security'  # 无返回
```

**修复**:
```
Nginx: add_header Strict-Transport-Security "max-age=31536000; includeSubDomains; preload";
```

---
### 3. 🟡 [MEDIUM] 缺失响应头: X-Frame-Options — Clickjacking风险

| 属性 | 值 |
|------|-----|
| CWE | CWE-N/A |
| CVSS | N/A |
| CVSS向量 | `` |
| 受影响URL | https://www.zmj.com |
| 截图URL | https://www.zmj.com |

**描述**: 

**复现**:
```
curl -I https://www.zmj.com | grep -i 'X-Frame-Options'  # 无返回
```

**修复**:
```
Nginx: add_header X-Frame-Options "DENY";
```

---
### 4. 🟡 [MEDIUM] 缺失响应头: Content-Security-Policy — CSP缺失

| 属性 | 值 |
|------|-----|
| CWE | CWE-N/A |
| CVSS | N/A |
| CVSS向量 | `` |
| 受影响URL | https://www.zmj.com |
| 截图URL | https://www.zmj.com |

**描述**: 

**复现**:
```
curl -I https://www.zmj.com | grep -i 'Content-Security-Policy'  # 无返回
```

**修复**:
```
Nginx: add_header Content-Security-Policy "default-src 'self'";
```

---
### 5. 🟡 [MEDIUM] 严重缺失 10 个安全响应头

| 属性 | 值 |
|------|-----|
| CWE | CWE-16 |
| CVSS | 6.1 |
| CVSS向量 | `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N` |
| 受影响URL | https://www.zmj.com |
| 截图URL | https://www.zmj.com |

**描述**: 

**复现**:
```

```

**修复**:
```
参考 OWASP Secure Headers Project 一次性配置
```

---
### 6. 🟡 [MEDIUM] Cookie [lg] 不安全: 缺少 Secure, SameSite

| 属性 | 值 |
|------|-----|
| CWE | CWE-614 / CWE-1004 |
| CVSS | 7.5 |
| CVSS向量 | `CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:N` |
| 受影响URL | https://www.zmj.com |
| 截图URL | https://www.zmj.com |

**描述**: 

**复现**:
```

```

**修复**:
```
添加: Secure, SameSite
```

---
### 7. 🟡 [MEDIUM] jQuery 3.4.1 存在已知 XSS (CVE-2020-11023/11022)

| 属性 | 值 |
|------|-----|
| CWE | CWE-79 / CWE-1104 |
| CVSS | 6.1 |
| CVSS向量 | `CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N` |
| 受影响URL | https://www.zmj.com |
| 截图URL | https://www.zmj.com |

**描述**: 

**复现**:
```

```

**修复**:
```
升级 jQuery >= 3.5.0
```

---
### 8. 🟡 [MEDIUM] jQuery < 3.5.0 XSS (CVE-2020-11023/11022)

| 属性 | 值 |
|------|-----|
| CWE | CWE-1104 |
| CVSS | N/A |
| CVSS向量 | `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N` |
| 受影响URL | https://www.zmj.com |
| 截图URL | https://www.zmj.com |

**描述**: 

**复现**:
```

```

**修复**:
```
升级 jQuery 至最新版本
```

---
### 9. 🟡 [MEDIUM] 允许危险 HTTP 方法: PUT, DELETE, PATCH, CONNECT

| 属性 | 值 |
|------|-----|
| CWE | CWE-749 |
| CVSS | 4.3 |
| CVSS向量 | `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N` |
| 受影响URL | https://www.zmj.com |
| 截图URL | https://www.zmj.com |

**描述**: 

**复现**:
```
curl -X PUT https://www.zmj.com -v
```

**修复**:
```
仅允许 GET/POST/HEAD 方法
```

---
### 10. 🟡 [MEDIUM] robots.txt 禁止全站爬取

| 属性 | 值 |
|------|-----|
| CWE | CWE-538 |
| CVSS | 5.3 |
| CVSS向量 | `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N` |
| 受影响URL | https://www.zmj.com |
| 截图URL | https://www.zmj.com |

**描述**: 

**复现**:
```

```

**修复**:
```
检查 robots.txt 配置
```

---
### 11. 🟢 [LOW] SSL 异常: timed out

| 属性 | 值 |
|------|-----|
| CWE | CWE-N/A |
| CVSS | N/A |
| CVSS向量 | `` |
| 受影响URL | https://www.zmj.com |
| 截图URL | https://www.zmj.com |

**描述**: 

**复现**:
```

```

**修复**:
```

```

---
### 12. 🟢 [LOW] 缺失响应头: X-Content-Type-Options — MIME嗅探风险

| 属性 | 值 |
|------|-----|
| CWE | CWE-N/A |
| CVSS | N/A |
| CVSS向量 | `` |
| 受影响URL | https://www.zmj.com |
| 截图URL | https://www.zmj.com |

**描述**: 

**复现**:
```
curl -I https://www.zmj.com | grep -i 'X-Content-Type-Options'  # 无返回
```

**修复**:
```
Nginx: add_header X-Content-Type-Options "nosniff";
```

---
### 13. 🟢 [LOW] 缺失响应头: Referrer-Policy — Referrer泄露

| 属性 | 值 |
|------|-----|
| CWE | CWE-N/A |
| CVSS | N/A |
| CVSS向量 | `` |
| 受影响URL | https://www.zmj.com |
| 截图URL | https://www.zmj.com |

**描述**: 

**复现**:
```
curl -I https://www.zmj.com | grep -i 'Referrer-Policy'  # 无返回
```

**修复**:
```
Nginx: add_header Referrer-Policy "strict-origin-when-cross-origin";
```

---
### 14. 🟢 [LOW] 缺失响应头: Permissions-Policy — 权限未限制

| 属性 | 值 |
|------|-----|
| CWE | CWE-N/A |
| CVSS | N/A |
| CVSS向量 | `` |
| 受影响URL | https://www.zmj.com |
| 截图URL | https://www.zmj.com |

**描述**: 

**复现**:
```
curl -I https://www.zmj.com | grep -i 'Permissions-Policy'  # 无返回
```

**修复**:
```
Nginx: add_header Permissions-Policy "geolocation=(), microphone=(), camera=()";
```

---
### 15. 🟢 [LOW] 缺失响应头: Cross-Origin-Resource-Policy — 资源可跨域加载

| 属性 | 值 |
|------|-----|
| CWE | CWE-N/A |
| CVSS | N/A |
| CVSS向量 | `` |
| 受影响URL | https://www.zmj.com |
| 截图URL | https://www.zmj.com |

**描述**: 

**复现**:
```
curl -I https://www.zmj.com | grep -i 'Cross-Origin-Resource-Policy'  # 无返回
```

**修复**:
```
Nginx: add_header Cross-Origin-Resource-Policy "same-origin";
```

---
### 16. 🟢 [LOW] 缺失响应头: Cross-Origin-Opener-Policy — 跨域opener未限制

| 属性 | 值 |
|------|-----|
| CWE | CWE-N/A |
| CVSS | N/A |
| CVSS向量 | `` |
| 受影响URL | https://www.zmj.com |
| 截图URL | https://www.zmj.com |

**描述**: 

**复现**:
```
curl -I https://www.zmj.com | grep -i 'Cross-Origin-Opener-Policy'  # 无返回
```

**修复**:
```
Nginx: add_header Cross-Origin-Opener-Policy "same-origin";
```

---
### 17. 🟢 [LOW] 缺失响应头: Cross-Origin-Embedder-Policy — 跨域资源未限制

| 属性 | 值 |
|------|-----|
| CWE | CWE-N/A |
| CVSS | N/A |
| CVSS向量 | `` |
| 受影响URL | https://www.zmj.com |
| 截图URL | https://www.zmj.com |

**描述**: 

**复现**:
```
curl -I https://www.zmj.com | grep -i 'Cross-Origin-Embedder-Policy'  # 无返回
```

**修复**:
```
Nginx: add_header Cross-Origin-Embedder-Policy "require-corp";
```

---
### 18. 🟢 [LOW] 缺失响应头: X-XSS-Protection — 旧版XSS过滤未启用

| 属性 | 值 |
|------|-----|
| CWE | CWE-N/A |
| CVSS | N/A |
| CVSS向量 | `` |
| 受影响URL | https://www.zmj.com |
| 截图URL | https://www.zmj.com |

**描述**: 

**复现**:
```
curl -I https://www.zmj.com | grep -i 'X-XSS-Protection'  # 无返回
```

**修复**:
```
Nginx: add_header X-XSS-Protection "1; mode=block";
```

---
### 19. 🟢 [LOW] HTTP 明文链接: http://www.zmjbid.com/

| 属性 | 值 |
|------|-----|
| CWE | CWE-319 |
| CVSS | 6.1 |
| CVSS向量 | `CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N` |
| 受影响URL | https://www.zmj.com |
| 截图URL | https://www.zmj.com |

**描述**: 

**复现**:
```

```

**修复**:
```
升级为 HTTPS
```

---
### 20. 🔵 [INFO] DNS: 39.97.3.174

| 属性 | 值 |
|------|-----|
| CWE | CWE-N/A |
| CVSS | N/A |
| CVSS向量 | `` |
| 受影响URL | https://www.zmj.com |
| 截图URL | https://www.zmj.com |

**描述**: 

**复现**:
```

```

**修复**:
```

```

---
### 21. 🔵 [INFO] HTTP 200, 11484B, https://www.zmj.com/

| 属性 | 值 |
|------|-----|
| CWE | CWE-N/A |
| CVSS | N/A |
| CVSS向量 | `` |
| 受影响URL | https://www.zmj.com |
| 截图URL | https://www.zmj.com |

**描述**: 

**复现**:
```

```

**修复**:
```

```

---
### 22. 🔵 [INFO] 敏感路径可访问: /robots.txt (robots.txt)

| 属性 | 值 |
|------|-----|
| CWE | CWE-200 |
| CVSS | 5.3 |
| CVSS向量 | `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N` |
| 受影响URL | https://www.zmj.com/robots.txt |
| 截图URL | https://www.zmj.com |

**描述**: /robots.txt 可被公开访问

**复现**:
```
curl https://www.zmj.com/robots.txt
```

**修复**:
```
限制 /robots.txt 访问权限
```

---
### 23. 🔵 [INFO] 技术栈: jQuery

| 属性 | 值 |
|------|-----|
| CWE | CWE-N/A |
| CVSS | N/A |
| CVSS向量 | `` |
| 受影响URL | https://www.zmj.com |
| 截图URL | https://www.zmj.com |

**描述**: 

**复现**:
```

```

**修复**:
```

```

---

*报告由自动化漏洞扫描系统 v3.0 生成 | 仅供授权安全测试使用*
