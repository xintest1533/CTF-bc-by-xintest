#!/bin/bash
# ============================================================
# 漏洞扫描工具集 主控脚本 v2.0
# 用法: ./vuln-kit.sh <command> [args]
# ============================================================

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
TOOLDIR="$SCRIPT_DIR"

usage() {
    echo "漏洞扫描工具集 v2.0"
    echo "基于三目标实战: ihep.cas.cn + bpeg.cn + didachuxing.com"
    echo ""
    echo "命令:"
    echo "  scan <domain>              全量扫描 (子域名+路径+安全头+JS分析+CORS)"
    echo "  scan <domain> --quick      快速扫描 (跳过子域名枚举+重定向+PHP参数)"
    echo ""
    echo "  sqli <url> -p <param>      SQL注入检测 (MD5 Diff引擎)"
    echo "   示例: vuln-kit.sh sqli https://target.com/page.php?id -p id"
    echo ""
    echo "  js-secrets <url|file>      JS密钥提取"
    echo "   示例: vuln-kit.sh js-secrets https://target.com/app.js"
    echo "   示例: vuln-kit.sh js-secrets /path/to/file.js"
    echo ""
    echo "  report <domain> <file>     生成报告 (从findings.json)"
    echo "   示例: vuln-kit.sh report example.com findings.json --platform vulbox"
    echo ""
    echo "  payloads                    查看Payload库"
    echo "  子命令: sqli | xss | paths  查看对应Payload"
    echo ""
    echo "平台选项 (scan/report):"
    echo "  --platform butian    补天标准 (默认)"
    echo "  --platform vulbox    漏洞盒子(QZSRC)标准"
    echo "  --platform universal 通用标准"
    echo ""
    echo "实战验证:"
    echo "  ✓ WAF绕过: 内联注释/*!50000*/ | 无空格 | 双重编码 | 宽字节"
    echo "  ✓ SQL注入: MD5 Diff引擎排除误报 (参数化查询/反射误判)"
    echo "  ✓ JS密钥: 自动提取 AES/HMAC/Credential/API端点"
    echo "  ✓ 协议降级: HTTPS→HTTP 301检测"
    echo "  ✓ 安全头: 主站vs子路径差异对比 (PHP vs Nuxt)"
}

case "${1:-}" in
    scan)
        shift
        bash "$TOOLDIR/scan_engine.sh" "$@"
        ;;
    sqli)
        shift
        python3 "$TOOLDIR/lib/sqli_diff_engine.py" "$@"
        ;;
    js-secrets)
        shift
        python3 "$TOOLDIR/lib/js_secrets_finder.py" "$@"
        ;;
    report)
        shift
        python3 "$TOOLDIR/lib/report_generator.py" "$@"
        ;;
    payloads)
        case "${2:-}" in
            sqli)
                echo "=== SQL注入Payload库 ==="
                python3 -c "
import json
with open('$TOOLDIR/payloads/waf_bypass_sqli.json') as f:
    d = json.load(f)
print(f\"版本: {d['version']}\")
print(f\"来源: {d['based_on']}\")
print()
for cat, info in d['categories'].items():
    print(f'[{cat}] {info[\"description\"]}')
    for p in info['payloads'][:3]:
        print(f'  {p[\"name\"]}: {p[\"payload\"][:60]}')
    print()
print('[决策树]')
for step in d['decision_tree']['steps']:
    print(f'  {step}')
" 2>/dev/null
                ;;
            xss)
                echo "=== XSS Payload库 ==="
                python3 -c "
import json
with open('$TOOLDIR/payloads/xss_misc.json') as f:
    d = json.load(f)
for cat, info in d['categories'].items():
    print(f'\n[{cat}]')
    if isinstance(info, dict):
        for subcat, items in info.items():
            print(f'  [{subcat}]')
            for item in items[:2]:
                print(f'    {item[\"name\"]}: {item[\"payload\"][:60]}')
" 2>/dev/null
                ;;
            paths)
                echo "=== 敏感路径库 ==="
                echo "参考扫描引擎内置路径列表: scan_engine.sh phase3_paths()"
                echo "共 80+ 个敏感路径覆盖:"
                echo "  .git/config .env Web.config 备份文件 管理后台"
                echo "  API文档 Swagger Actuator 编辑器上传"
                echo "  PHP信息 日志文件 WEB-INF GraphQL"
                ;;
            *)
                echo "可用payload: sqli | xss | paths"
                ;;
        esac
        ;;
    *)
        usage
        ;;
esac