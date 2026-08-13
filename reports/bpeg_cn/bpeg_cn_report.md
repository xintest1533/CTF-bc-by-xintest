# www.bpeg.cn 漏洞扫描报告

**扫描时间**: 2026-08-13 10:45:46
**目标**: www.bpeg.cn (北京电力设备总厂有限公司)
**子域名**: www / oa / vpn / en (共 4 个)

---

## 漏洞统计

| 等级 | 数量 |
|------|------|
| HIGH | 3 |
| MEDIUM | 4 |
| LOW | 3 |
| INFO | 2 |
| **总计** | **12** |

---

## HIGH 级漏洞

### HIGH-1: SSL VPN 网关公网暴露
- **URL**: https://vpn.bpeg.cn/
- **CVSS**: 7.5
- **CWE**: CWE-200 / CWE-284
- **描述**: VPN 网关登录页面公网可访问，是企业内网入口

### HIGH-2: 主站 76 个 HTTP 明文链接（混合内容）
- **URL**: https://www.bpeg.cn/
- **CVSS**: 7.5
- **CWE**: CWE-319 / CWE-602
- **描述**: 76 个 HTTP 链接指向旧域名 www.bpeg.ceec.net.cn

### HIGH-3: WAF Cookie 缺少全部安全标志
- **URL**: https://www.bpeg.cn/
- **CVSS**: 7.5
- **CWE**: CWE-614 / CWE-1004
- **描述**: HWWAFSESID Cookie 无 Secure/HttpOnly/SameSite

---

## 子域名全景

| 子域名 | IP | 用途 | 状态 |
|--------|-----|------|------|
| www | 124.70.125.x | 主站 | 200 OK |
| oa | 218.249.223.100 | OA系统 | 502 |
| vpn | 218.249.223.69 | SSL VPN | 200 |
| en | 116.205.x.x | 英文站 | 200 OK |
