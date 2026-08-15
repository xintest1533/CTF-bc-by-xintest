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
            }
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