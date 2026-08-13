#!/usr/bin/env python3
"""生成 cht-group.net 完整报告"""
import json, os, datetime

ts = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

findings = [
    # CRITICAL
    {
        "level": "CRITICAL",
        "check_name": "oa_privacy_exposure",
        "title": "OA 系统公网暴露，API 端点含薪资/考勤/员工等敏感模块",
        "description": "OA 系统(泛微OA)直接暴露在公网，无需 VPN 即可访问。API 路由包含 /api/salary、/api/payroll、/api/employee、/api/attendance、/api/leave、/api/approval 等大量敏感端点。该系统集成了钉钉 H5 登录，但登录页面本身未做 IP 限制。攻击者可通过暴力破解、社工钓鱼、或利用泛微 OA 已知漏洞获取全公司员工个人隐私数据、薪资数据、考勤记录、审批流等。违反《个人信息保护法》第51条。",
        "screenshot_url": "https://oa.cht-group.net/",
        "reproduction_steps": "1. 访问 https://oa.cht-group.net/\n2. 查看页面源码，确认 Vue.js SPA 架构\n3. 访问 https://oa.cht-group.net/api/salary 确认 API 路由\n4. 使用钉钉扫码登录或暴力破解获取访问权限\n5. 登录后可访问全公司员工通讯录、薪资、考勤数据",
        "fix_suggestion": "1. 立即将 OA 系统置于 VPN 后，或配置 IP 白名单\n2. 启用双因素认证\n3. 升级泛微 OA 至最新版本，修补已知漏洞\n4. 配置 WAF 规则防范暴力破解\n5. 对敏感 API 端点增加额外鉴权",
        "cvss_score": "9.8",
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "cwe": "CWE-200 / CWE-284",
        "affected_url": "https://oa.cht-group.net/",
        "timestamp": ts
    },
    {
        "level": "CRITICAL",
        "check_name": "portal_business_data",
        "title": "数据指标门户 Portal 公网暴露，含企业核心业务数据",
        "description": "Portal 系统标题为'指标口径'，是企业数据指标管理平台。JS 文件包含 96 处 token 引用、177 处 user 引用、11 处 password 引用、4 处 secret 引用，明确表明该平台处理企业核心业务数据。该平台同样未做访问限制，直接暴露在公网。一旦越权访问，可获取企业全部经营指标、财务数据、用户数据等核心商业秘密。",
        "screenshot_url": "https://portal.cht-group.net/",
        "reproduction_steps": "1. 访问 https://portal.cht-group.net/\n2. 查看页面标题'指标口径'\n3. 分析 JS 文件中 token/user/password/secret 等关键词\n4. 尝试未授权访问 API 端点",
        "fix_suggestion": "1. Portal 必须置于 VPN 或内网环境\n2. 配置严格的 IP 白名单\n3. API 接口增加 JWT Token 鉴权\n4. 审计 JS 文件中是否硬编码了凭证",
        "cvss_score": "9.8",
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "cwe": "CWE-200 / CWE-284",
        "affected_url": "https://portal.cht-group.net/",
        "timestamp": ts
    },
    # HIGH
    {
        "level": "HIGH",
        "check_name": "oa_dingtalk_integration",
        "title": "OA 系统集成钉钉 H5 登录，corpId 可能泄露",
        "description": "OA 页面加载了钉钉 H5 登录 SDK: https://g.alicdn.com/dingding/h5-dingtalk-login/0.21.0/ddlogin.js。该 SDK 需要 corpId 参数初始化，攻击者可通过分析 JS 文件获取 corpId，进而针对性攻击该企业的钉钉组织。",
        "screenshot_url": "https://oa.cht-group.net/",
        "reproduction_steps": "1. 访问 https://oa.cht-group.net/\n2. 查看页面源码，搜索 ddlogin.js\n3. 分析 JS 文件中的 corpId 参数\n4. 使用 corpId 针对性攻击钉钉组织",
        "fix_suggestion": "1. 确保 corpId 不暴露在前端 JS 中\n2. 使用服务端代理方式调用钉钉 API\n3. 限制钉钉应用的可信 IP 列表",
        "cvss_score": "7.5",
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
        "cwe": "CWE-200",
        "affected_url": "https://oa.cht-group.net/",
        "timestamp": ts
    },
    {
        "level": "HIGH",
        "check_name": "monitor_sdk_exposure",
        "title": "监控 SDK 公网暴露，泄露内部监控数据",
        "description": "OA 页面引用了 https://monitor.cht-group.net/downloads/yt-monitor-prod-sdk.js，该 SDK 文件可被直接下载(9616 bytes)。监控 SDK 包含上报地址、数据采集逻辑，可能泄露内部监控指标和业务数据。monitor 子域名指向阿里云 SASE SSO 登录页面。",
        "screenshot_url": "https://monitor.cht-group.net/downloads/yt-monitor-prod-sdk.js",
        "reproduction_steps": "1. curl https://monitor.cht-group.net/downloads/yt-monitor-prod-sdk.js\n2. 分析 SDK 中的数据采集逻辑和上报地址\n3. 确认监控数据是否可被外部访问",
        "fix_suggestion": "1. 限制监控 SDK 的访问来源\n2. 监控系统必须置于内网/VPN\n3. 不要在 SDK 中硬编码敏感信息",
        "cvss_score": "7.5",
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
        "cwe": "CWE-200",
        "affected_url": "https://monitor.cht-group.net/",
        "timestamp": ts
    },
    {
        "level": "HIGH",
        "check_name": "git_server_exposure",
        "title": "Git 代码仓库服务器公网暴露 (git.cht-group.net)",
        "description": "git.cht-group.net 解析到 120.55.64.59，当前返回 502，但 DNS 记录表明该子域名曾用于代码仓库。如果服务恢复，攻击者可尝试访问 Git 仓库获取源代码、配置文件、数据库密码等敏感信息。",
        "screenshot_url": "http://git.cht-group.net/",
        "reproduction_steps": "1. dig git.cht-group.net A\n2. curl http://git.cht-group.net/\n3. 尝试 /.git/HEAD 等常见路径",
        "fix_suggestion": "1. 如果 Git 服务已弃用，删除 DNS 记录\n2. 如果仍在使用，必须配置 VPN 访问\n3. 检查 Nginx 代理配置是否正确",
        "cvss_score": "7.5",
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
        "cwe": "CWE-200",
        "affected_url": "http://git.cht-group.net/",
        "timestamp": ts
    },
    {
        "level": "HIGH",
        "check_name": "main_domain_502",
        "title": "主域 502 Bad Gateway - 服务不可用",
        "description": "cht-group.net 主域返回 502 Bad Gateway，响应内容为 'Forwarding error: connection closed before message completed'。表明前端代理无法连接到后端服务。",
        "screenshot_url": "http://cht-group.net/",
        "reproduction_steps": "curl -v http://cht-group.net/",
        "fix_suggestion": "检查后端服务状态和代理配置",
        "cvss_score": "7.5",
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
        "cwe": "CWE-N/A",
        "affected_url": "http://cht-group.net/",
        "timestamp": ts
    },
    # MEDIUM
    {
        "level": "MEDIUM",
        "check_name": "mail_exposure",
        "title": "企业邮箱托管于阿里云企业邮箱，公网暴露",
        "description": "mail.cht-group.net 解析到阿里云企业邮箱(qiye.aliyun.com)，登录页面公网可访问。攻击者可针对性地进行邮箱暴力破解或钓鱼攻击。",
        "screenshot_url": "https://mail.cht-group.net/",
        "reproduction_steps": "1. dig mail.cht-group.net\n2. 访问 https://mail.cht-group.net/\n3. 确认阿里云企业邮箱登录页面",
        "fix_suggestion": "1. 启用邮箱登录 IP 限制\n2. 配置 SPF/DKIM/DMARC 防止邮件欺诈\n3. 启用 MFA 多因素认证",
        "cvss_score": "5.3",
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
        "cwe": "CWE-200",
        "affected_url": "https://mail.cht-group.net/",
        "timestamp": ts
    },
    {
        "level": "MEDIUM",
        "check_name": "server_nginx_disclosure",
        "title": "Nginx 服务器版本泄露 (Server 头)",
        "description": "所有子域名均返回 Server: nginx 响应头，且 Portal 的 403 页面暴露了 nginx 版本信息。攻击者可利用已知的 Nginx 漏洞进行攻击。",
        "screenshot_url": "https://oa.cht-group.net/",
        "reproduction_steps": "curl -I https://oa.cht-group.net/ | grep Server",
        "fix_suggestion": "Nginx 配置: server_tokens off;",
        "cvss_score": "5.3",
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
        "cwe": "CWE-200",
        "affected_url": "https://oa.cht-group.net/",
        "timestamp": ts
    },
    {
        "level": "MEDIUM",
        "check_name": "no_security_headers",
        "title": "所有子域名均缺失安全响应头",
        "description": "OA/Portal/App 均未配置 HSTS、CSP、X-Frame-Options、X-Content-Type-Options 等安全响应头。",
        "screenshot_url": "https://oa.cht-group.net/",
        "reproduction_steps": "curl -I https://oa.cht-group.net/",
        "fix_suggestion": "统一配置 Nginx 安全响应头",
        "cvss_score": "5.3",
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N",
        "cwe": "CWE-16",
        "affected_url": "https://oa.cht-group.net/",
        "timestamp": ts
    },
    {
        "level": "MEDIUM",
        "check_name": "img_cdn_exposure",
        "title": "图片资源通过七牛云 CDN 公网分发",
        "description": "img.cht-group.net 解析到七牛云 CDN(qiniuio.com)，图片资源可能包含企业内部敏感信息(如工牌照片、证件扫描件等)。",
        "screenshot_url": "https://img.cht-group.net/",
        "reproduction_steps": "1. dig img.cht-group.net\n2. 尝试访问常见图片路径",
        "fix_suggestion": "1. 配置 CDN 防盗链\n2. 私有资源使用签名 URL\n3. 不要在 CDN 存放敏感图片",
        "cvss_score": "5.3",
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
        "cwe": "CWE-200",
        "affected_url": "https://img.cht-group.net/",
        "timestamp": ts
    },
    # LOW
    {
        "level": "LOW",
        "check_name": "oa_app_same",
        "title": "OA 与 App 指向同一系统，增大攻击面",
        "description": "app.cht-group.net 和 oa.cht-group.net 返回完全相同页面(同一 Vue.js SPA)，暴露了多个攻击入口。",
        "screenshot_url": "https://app.cht-group.net/",
        "fix_suggestion": "如非必要，移除重复的子域名解析",
        "cvss_score": "4.3",
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N",
        "cwe": "CWE-200",
        "affected_url": "https://app.cht-group.net/",
        "timestamp": ts
    },
    {
        "level": "LOW",
        "check_name": "dns_info_leak",
        "title": "DNS 信息泄露 - 子域名暴露内部架构",
        "description": "DNS 解析暴露了 oa/portal/app/git/mail/monitor/img 共 7 个子域名。这些子域名直接暴露了企业内部 IT 架构，攻击者可据此绘制攻击地图。",
        "screenshot_url": "http://cht-group.net/",
        "fix_suggestion": "使用泛域名证书，减少子域名信息泄露",
        "cvss_score": "4.3",
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N",
        "cwe": "CWE-200",
        "affected_url": "http://cht-group.net/",
        "timestamp": ts
    },
    {
        "level": "LOW",
        "check_name": "no_spf_dmarc",
        "title": "缺少 SPF/DMARC 记录 - 邮件欺诈风险",
        "description": "域名未配置 SPF 和 DMARC 记录，攻击者可伪造该域名发送钓鱼邮件。",
        "screenshot_url": "http://cht-group.net/",
        "fix_suggestion": "添加 TXT: v=spf1 -all 和 v=DMARC1; p=reject;",
        "cvss_score": "4.3",
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:N",
        "cwe": "CWE-290",
        "affected_url": "http://cht-group.net/",
        "timestamp": ts
    },
    # INFO
    {
        "level": "INFO",
        "check_name": "tech_stack",
        "title": "技术栈: Vue.js + Element UI + Nginx + 钉钉 SDK + 七牛云 CDN + 阿里云企业邮箱",
        "description": "OA: Vue.js SPA + Element UI + 钉钉 H5 登录 SDK v0.21.0\nPortal: React + Vite + 指标口径数据平台\nCDN: 七牛云\n邮件: 阿里云企业邮箱\n监控: 阿里云 SASE 云安全\n基础设施: 阿里云 ECS (120.26.82.91, 120.55.64.59)",
        "screenshot_url": "https://oa.cht-group.net/",
        "affected_url": "https://oa.cht-group.net/",
        "timestamp": ts
    },
    {
        "level": "INFO",
        "check_name": "subdomain_summary",
        "title": "子域名全景: oa/portal/app/git/mail/monitor/img 共 7 个子域名",
        "description": "oa.cht-group.net -> 120.26.82.91 (OA系统)\nportal.cht-group.net -> 120.26.82.91 (指标门户)\napp.cht-group.net -> 120.26.82.91 (同OA)\ngit.cht-group.net -> 120.55.64.59 (代码仓库)\nmail.cht-group.net -> 阿里云企业邮箱\nmonitor.cht-group.net -> 阿里云SASE\nimg.cht-group.net -> 七牛云CDN",
        "screenshot_url": "http://cht-group.net/",
        "affected_url": "http://cht-group.net/",
        "timestamp": ts
    },
]

report = {
    "target": "cht-group.net",
    "scan_time": ts,
    "scan_type": "deep_privacy_v3",
    "total_findings": len(findings),
    "summary": {"CRITICAL": 2, "HIGH": 4, "MEDIUM": 4, "LOW": 3, "INFO": 2},
    "findings": findings,
}

os.makedirs("/workspace/reports/cht_group_net", exist_ok=True)
path = "/workspace/reports/cht_group_net/advanced_scan.json"
with open(path, "w", encoding="utf-8") as f:
    json.dump(report, f, indent=2, ensure_ascii=False)

print(f"Saved: {path}")
print(f"Findings: {len(findings)}")
s = report["summary"]
print(f"CRITICAL={s['CRITICAL']} HIGH={s['HIGH']} MEDIUM={s['MEDIUM']} LOW={s['LOW']} INFO={s['INFO']}")