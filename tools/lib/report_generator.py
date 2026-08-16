#!/usr/bin/env python3
"""
多平台漏洞报告生成器 v2.0
支持: 补天(butian) / 漏洞盒子(vulbox/QZSRC) / 通杀(universal)
"""
import json, argparse, os, sys
from datetime import datetime

LEVEL_MAP = {
    "butian": {"高危": "高危", "中危": "中危", "低危": "低危"},
    "vulbox": {"高危": "高危", "中危": "中危", "低危": "低危"},
    "universal": {"高危": "CRITICAL/HIGH", "中危": "MEDIUM", "低危": "LOW"},
}

STANDARD_INFO = {
    "butian": {
        "name": "补天漏洞响应平台",
        "url": "https://www.butian.net/Help/plan",
        "high_risk": "getshell、RCE、通用型SQL注入、任意文件上传",
        "medium_risk": "越权访问、信息泄露、任意文件操作",
        "low_risk": "反射XSS、逻辑漏洞、安全配置缺陷",
        "notes": "同系统同类型漏洞仅前3个正常收取，后续降级"
    },
    "vulbox": {
        "name": "漏洞盒子(QZSRC)",
        "url": "https://qzsrc.vulbox.com/news/detail-568-2",
        "high_risk": "命令执行、上传webshell、代码执行、重要DB的SQL注入、任意账号密码更改",
        "medium_risk": "存储型XSS、任意文件读写删除、越权修改资料、敏感信息泄露",
        "low_risk": "普通逻辑漏洞、反射型XSS",
        "notes": "同系统同类型漏洞前3个正常，后续降级"
    }
}

def generate_report(target, platform, findings):
    """生成漏洞报告"""
    info = STANDARD_INFO.get(platform, STANDARD_INFO["butian"])
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    # 统计
    high = sum(1 for f in findings if f.get("level") == "高危")
    med = sum(1 for f in findings if f.get("level") == "中危")
    low = sum(1 for f in findings if f.get("level") == "低危")
    info_cnt = sum(1 for f in findings if f.get("level") == "信息")

    # 按优先级排序
    priority_order = {"高危": 0, "中危": 1, "低危": 2, "信息": 3}
    findings.sort(key=lambda x: priority_order.get(x.get("level", "信息"), 99))

    report = {
        "target": target,
        "platform": info["name"],
        "platform_url": info["url"],
        "scan_time": now,
        "standard": {
            "高危定义": info["high_risk"],
            "中危定义": info["medium_risk"],
            "低危定义": info["low_risk"],
            "注意事项": info["notes"]
        },
        "summary": {
            "高危": high, "中危": med, "低危": low, "信息": info_cnt
        },
        "findings": []
    }

    for f in findings:
        entry = {
            "id": f.get("id", len(report["findings"]) + 1),
            "level": f.get("level", "信息"),
            "title": f.get("title", ""),
            "cwe": f.get("cwe", ""),
            "cvss_score": f.get("cvss_score", ""),
            "affected_url": f.get("affected_url", ""),
            "status": f.get("status", "已验证"),
            "description": f.get("description", ""),
            "reproduction": f.get("reproduction", ""),
            "impact": f.get("impact", ""),
            "fix": f.get("fix", ""),
            "pass_review_probability": f.get("pass_review_probability", ""),
        }
        # 漏洞盒子额外字段
        if platform == "vulbox" and "qzsrc_category" in f:
            entry["qzsrc_category"] = f["qzsrc_category"]
        report["findings"].append(entry)

    # 生成提交策略
    submission_priority = [f for f in findings if f.get("level") in ("高危", "中危", "低危")]
    report["submission_strategy"] = {
        "优先提交": [f"#{f.get('id')} {f.get('title','')[:50]} ({f.get('level')})" for f in submission_priority[:5]],
        "合并提交": [f"#{f.get('id')} {f.get('title','')[:50]}" for f in submission_priority if f.get("level") == "信息"],
        "提交建议": f"建议按优先级逐条提交，避免同类型漏洞集中提交触发平台降级机制"
    }

    return report


def generate_finding_template(vuln_type, target, **kwargs):
    """生成指定漏洞类型的发现条目模板"""
    templates = {
        "cookie_audit": {
            "level": "中危",
            "title": "Cookie安全属性缺失",
            "cwe": "CWE-614",
            "cvss_score": "5.3",
            "affected_url": f"https://{target}/",
            "status": "已验证",
            "description": kwargs.get("description", "Cookie缺少Secure/HttpOnly/SameSite属性，敏感Cookie可被脚本窃取或通过非HTTPS通道泄露"),
            "reproduction": kwargs.get("reproduction", f"curl -skI https://{target}/ | grep -i set-cookie"),
            "impact": "攻击者可通过XSS窃取Cookie，或通过SSL Strip截获Cookie",
            "fix": "为所有Set-Cookie添加Secure、HttpOnly、SameSite=Lax/Strict属性",
            "pass_review_probability": "高",
            "details": kwargs.get("details", {}),
        },
        "protocol_downgrade_chain": {
            "level": "低危",
            "title": "协议降级链",
            "cwe": "CWE-319",
            "cvss_score": "4.0",
            "affected_url": f"https://{target}/",
            "status": "已验证",
            "description": kwargs.get("description", "完整重定向链跟踪发现HTTPS→HTTP→HTTPS协议降级模式，中间环节存在明文传输风险"),
            "reproduction": kwargs.get("reproduction", f"curl -skIL -o /dev/null -w '%{{redirect_url}}\\n' https://{target}/"),
            "impact": "中间环节的HTTP请求可能被中间人攻击篡改",
            "fix": "统一使用HTTPS，确保所有跳转步骤均为HTTPS",
            "pass_review_probability": "中",
            "redirect_chain": kwargs.get("redirect_chain", []),
        },
        "404_info_leak": {
            "level": "低危",
            "title": "404页面信息泄露",
            "cwe": "CWE-200",
            "cvss_score": "3.7",
            "affected_url": f"https://{target}/{kwargs.get('path', 'notexist')}",
            "status": "已验证",
            "description": kwargs.get("description", "默认404页面泄露了内部端口、服务器主机名、服务器类型（Tengine/Apache）等敏感信息"),
            "reproduction": kwargs.get("reproduction", f"curl -sk https://{target}/{kwargs.get('path', 'notexist')}"),
            "impact": "攻击者可利用泄露信息进行针对性攻击，如端口扫描、服务器指纹识别",
            "fix": "自定义404页面，不显示内部技术信息",
            "pass_review_probability": "高",
            "leaked_info": kwargs.get("leaked_info", {}),
        },
        "oss_bucket_leak": {
            "level": "低危",
            "title": "OSS Bucket信息泄露",
            "cwe": "CWE-200",
            "cvss_score": "3.7",
            "affected_url": f"https://{target}/",
            "status": "已验证",
            "description": kwargs.get("description", "从阿里云OSS XML错误响应中提取到Bucket名称，可能用于后续Bucket遍历攻击"),
            "reproduction": kwargs.get("reproduction", f"curl -sk https://{kwargs.get('bucket', 'example')}.oss-cn-hangzhou.aliyuncs.com/"),
            "impact": "Bucket名称泄露后，攻击者可尝试列举文件或进行权限绕过",
            "fix": "配置OSS Bucket为私有访问，使用CDN或自定义域名，关闭公共列举",
            "pass_review_probability": "高",
            "bucket_name": kwargs.get("bucket", ""),
        },
        "internal_port_exposure": {
            "level": "低危",
            "title": "内部端口暴露",
            "cwe": "CWE-200",
            "cvss_score": "3.3",
            "affected_url": f"https://{target}:{kwargs.get('port', '86')}/",
            "status": "已验证",
            "description": kwargs.get("description", f"从404页面URL字段提取到内部端口（{kwargs.get('port', '86')}），该端口可能运行管理后台或内部服务"),
            "reproduction": kwargs.get("reproduction", f"curl -sk https://{target}:{kwargs.get('port', '86')}/"),
            "impact": "暴露非标准端口可能扩大攻击面",
            "fix": "关闭非必要端口，或使用防火墙限制访问来源",
            "pass_review_probability": "高",
        },
        "site_redirect": {
            "level": "信息",
            "title": "全站跳转检测",
            "cwe": "",
            "cvss_score": "",
            "affected_url": f"https://{target}/",
            "status": "已验证",
            "description": kwargs.get("description", f"目标域名302跳转到另一个域名（{kwargs.get('redirect_target', '')}），可能是品牌迁移或CDN分发"),
            "reproduction": kwargs.get("reproduction", f"curl -skI https://{target}/ | grep -i location"),
            "impact": "用户需确认跳转是否预期，避免误报",
            "fix": "无需修复，但扫描时已自动继续扫描目标域名本身",
            "pass_review_probability": "高",
            "redirect_url": kwargs.get("redirect_target", ""),
        },
        "catch_all_redirect": {
            "level": "信息",
            "title": "开放重定向Catch-All模式（误报排除）",
            "cwe": "",
            "cvss_score": "",
            "affected_url": f"https://{target}/",
            "status": "已验证",
            "description": "所有参数返回相同Location，属于catch-all误报模式，非真实开放重定向",
            "reproduction": kwargs.get("reproduction", f"curl -skI 'https://{target}/?redirect=https://evil.com'"),
            "impact": "无安全影响，已标记为误报",
            "fix": "无需修复",
            "pass_review_probability": "高",
        },
        "vite_spa": {
            "level": "信息",
            "title": "Vite SPA应用识别",
            "cwe": "",
            "cvss_score": "",
            "affected_url": f"https://{target}/",
            "status": "已识别",
            "description": "检测到Vite构建产物特征（/assets/index-*.js、import.meta等），确认为Vite SPA应用",
            "reproduction": kwargs.get("reproduction", f"curl -sk https://{target}/ | grep -oP '/assets/index-[a-f0-9]{{8}}\\.js'"),
            "impact": "无直接安全影响，但JS分析时需处理Vite特有的chunk加载和路由拦截",
            "fix": "无需修复",
            "pass_review_probability": "高",
        },
        "server_hostname_leak": {
            "level": "低危",
            "title": "Server头/404页面主机名泄露",
            "cwe": "CWE-200",
            "cvss_score": "3.3",
            "affected_url": f"https://{target}/",
            "status": "已验证",
            "description": kwargs.get("description", f"从404页面或Server头提取到内部主机名（{kwargs.get('hostname', '')}），泄露了服务器内部标识"),
            "reproduction": kwargs.get("reproduction", f"curl -sk https://{target}/notexist"),
            "impact": "内部主机名泄露可辅助攻击者进行内网渗透",
            "fix": "自定义错误页面，隐藏Server头中的内部主机名",
            "pass_review_probability": "高",
            "hostname": kwargs.get("hostname", ""),
        },
    }
    return templates.get(vuln_type, {})

def main():
    parser = argparse.ArgumentParser(description="多平台漏洞报告生成器 v2.0")
    parser.add_argument("target", help="目标域名")
    parser.add_argument("-p", "--platform", choices=["butian", "vulbox", "universal"], default="butian", help="平台")
    parser.add_argument("-i", "--input", help="输入JSON文件 (findings)")
    parser.add_argument("-o", "--output", help="输出文件路径")
    parser.add_argument("--demo", action="store_true", help="生成示例报告")
    args = parser.parse_args()

    if args.demo:
        # 示例数据
        findings = [
            {
                "id": 1, "level": "中危", "title": "前端JS硬编码API认证密钥",
                "cwe": "CWE-798", "cvss_score": "6.5",
                "affected_url": "https://static.example.com/js/app.js",
                "status": "已验证 ✅",
                "description": "前端JavaScript中硬编码了AES加密密钥和HMAC签名密钥",
                "reproduction": "curl -sk https://static.example.com/js/app.js | grep -oP 'secret[A-Za-z0-9+/=]{16,}'",
                "impact": "攻击者可伪造API请求签名，绕过认证",
                "fix": "将密钥迁移到服务端，使用STS临时密钥",
                "pass_review_probability": "高",
                "qzsrc_category": "比较严重的信息泄漏漏洞"
            },
            {
                "id": 2, "level": "低危", "title": "全站HSTS缺失",
                "cwe": "CWE-319", "cvss_score": "4.3",
                "affected_url": "https://www.example.com/",
                "description": "所有域名均未配置Strict-Transport-Security头",
                "reproduction": "curl -skI https://www.example.com/ | grep -i strict-transport",
                "impact": "SSL Strip中间人攻击",
                "fix": "添加 HSTS: max-age=31536000; includeSubDomains",
                "pass_review_probability": "高"
            },
            {
                "id": 3, "level": "中危", "title": "Cookie安全属性缺失",
                "cwe": "CWE-614", "cvss_score": "5.3",
                "affected_url": "https://www.example.com/",
                "description": "Cookie缺少Secure/HttpOnly/SameSite属性，敏感Cookie可被脚本窃取或通过非HTTPS通道泄露",
                "reproduction": "curl -skI https://www.example.com/ | grep -i set-cookie",
                "impact": "攻击者可通过XSS窃取Cookie，或通过SSL Strip截获Cookie",
                "fix": "为所有Set-Cookie添加Secure、HttpOnly、SameSite=Lax/Strict属性",
                "pass_review_probability": "高"
            },
            {
                "id": 4, "level": "低危", "title": "协议降级链（HTTPS→HTTP→HTTPS）",
                "cwe": "CWE-319", "cvss_score": "4.0",
                "affected_url": "https://www.example.com/",
                "description": "完整重定向链跟踪发现HTTPS→HTTP→HTTPS协议降级模式，中间环节存在明文传输风险",
                "reproduction": "curl -skIL -o /dev/null -w '%{redirect_url}\\n' https://www.example.com/",
                "impact": "中间环节的HTTP请求可能被中间人攻击篡改",
                "fix": "统一使用HTTPS，确保所有跳转步骤均为HTTPS",
                "pass_review_probability": "中"
            },
            {
                "id": 5, "level": "低危", "title": "404页面信息泄露",
                "cwe": "CWE-200", "cvss_score": "3.7",
                "affected_url": "https://www.example.com/notexist",
                "description": "默认404页面泄露了内部端口、服务器主机名、服务器类型（Tengine/Apache）等敏感信息",
                "reproduction": "curl -sk https://www.example.com/notexist",
                "impact": "攻击者可利用泄露信息进行针对性攻击，如端口扫描、服务器指纹识别",
                "fix": "自定义404页面，不显示内部技术信息",
                "pass_review_probability": "高"
            },
            {
                "id": 6, "level": "低危", "title": "OSS Bucket信息泄露",
                "cwe": "CWE-200", "cvss_score": "3.7",
                "affected_url": "https://www.example.com/",
                "description": "从阿里云OSS XML错误响应中提取到Bucket名称，可能用于后续Bucket遍历攻击",
                "reproduction": "curl -sk https://<bucket>.oss-cn-hangzhou.aliyuncs.com/",
                "impact": "Bucket名称泄露后，攻击者可尝试列举文件或进行权限绕过",
                "fix": "配置OSS Bucket为私有访问，使用CDN或自定义域名，关闭公共列举",
                "pass_review_probability": "高"
            },
            {
                "id": 7, "level": "低危", "title": "内部端口暴露",
                "cwe": "CWE-200", "cvss_score": "3.3",
                "affected_url": "https://www.example.com:86/",
                "description": "从404页面URL字段提取到内部端口（86），该端口可能运行管理后台或内部服务",
                "reproduction": "curl -sk https://www.example.com:86/",
                "impact": "暴露非标准端口可能扩大攻击面",
                "fix": "关闭非必要端口，或使用防火墙限制访问来源",
                "pass_review_probability": "高"
            },
            {
                "id": 8, "level": "信息", "title": "全站跳转检测",
                "cwe": "", "cvss_score": "",
                "affected_url": "https://www.example.com/",
                "description": "目标域名302跳转到另一个域名（example.org），可能是品牌迁移或CDN分发",
                "reproduction": "curl -skI https://www.example.com/ | grep -i location",
                "impact": "用户需确认跳转是否预期，避免误报",
                "fix": "无需修复，但扫描时已自动继续扫描目标域名本身",
                "pass_review_probability": "高"
            },
        ]
        report = generate_report(args.target, args.platform, findings)
    else:
        if not args.input:
            print("[!] 需要 --input 或 --demo")
            sys.exit(1)
        with open(args.input, "r") as f:
            findings = json.load(f)
        report = generate_report(args.target, args.platform, findings)

    if args.output:
        with open(args.output, "w") as f:
            json.dump(report, f, ensure_ascii=False, indent=2)
        print(f"[+] 报告已保存到: {args.output}")
    else:
        print(json.dumps(report, ensure_ascii=False, indent=2))

if __name__ == "__main__":
    main()