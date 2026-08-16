#!/usr/bin/env python3
"""
JS密钥提取器 v2.2
基于多目标实战验证：支持 Vite SPA检测、OSS Bucket检测、0B重试+代理、
内部环境命名规则(prep/test/docker/prod/gateway)、微服务路径识别
"""
import sys, re, json, argparse, urllib.request, ssl, os, time

ssl._create_default_https_context = ssl._create_unverified_context

RULES = {
    "加密密钥": [
        {"name": "AES密钥 (base64)", "pattern": r"[A-Za-z0-9+/=]{16,}={1,2}", "filter": lambda x: any(c.isupper() for c in x) and any(c.islower() for c in x) and len(x) >= 16},
        {"name": "AES密钥 (hex)", "pattern": r"[0-9a-fA-F]{32,64}", "filter": lambda x: any(c.isalpha() for c in x)},
        {"name": "HMAC密钥", "pattern": r"TC3[0-9a-fA-F]{60,}", "filter": None},
        {"name": "DES密钥", "pattern": r"[A-Za-z0-9+/]{8}={1,2}", "filter": None},
        {"name": "RSA私钥头", "pattern": r"-----BEGIN (RSA |EC )?PRIVATE KEY-----", "filter": None},
    ],
    "API认证": [
        {"name": "API Key", "pattern": r"(api[_-]?key|apikey|api_secret|secret_key|access_key)[\"']?\s*[:=]\s*[\"']([A-Za-z0-9_\-]{16,})[\"']", "group": 2},
        {"name": "Bearer Token", "pattern": r"Bearer\s+([A-Za-z0-9_\-\.]{20,})", "group": 1},
        {"name": "JWT Token", "pattern": r"eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+", "filter": None},
        {"name": "Credential ID", "pattern": r"[0-9a-f]{64}", "filter": None},
        {"name": "Authorization头", "pattern": r"Authorization['\"]?\s*:\s*['\"]([^'\"]+)['\"]", "group": 1},
    ],
    "端点/URL": [
        {"name": "内部API地址", "pattern": r"https?://(localhost|127\.0\.0\.1|10\.\d+|172\.(1[6-9]|2\d|3[01])|192\.168\.)[^\"'\s]+", "filter": None},
        {"name": "API路径", "pattern": r"['\"](/api/v\d+/[^\"'\s]+)['\"]", "group": 1},
        {"name": "Web路径", "pattern": r"['\"](/web/[^\"'\s]+)['\"]", "group": 1},
        {"name": "GraphQL端点", "pattern": r"['\"](/graphql[^\"'\s]*)['\"]", "group": 1},
        {"name": "Swagger/OpenAPI", "pattern": r"['\"](/[^\"'\s]*(?:swagger|openapi|api-docs)[^\"'\s]*)['\"]", "group": 1},
        {"name": "WebSocket", "pattern": r"wss?://[a-zA-Z0-9._\-]+(:\d+)?/[^\"'\s]+", "filter": None},
        {"name": "OSS Bucket URL", "pattern": r"https?://[a-zA-Z0-9._\-]+\.(oss-[a-z0-9\-]+\.aliyuncs\.com|s3[^\"'\s]*\.amazonaws\.com|storage\.(googleapis|bunnycdn)\.com)[^\"'\s]*", "filter": None},
    ],
    "环境信息": [
        {"name": "环境判断变量", "pattern": r"isEnv\w+", "filter": None},
        {"name": "域名列表", "pattern": r"(didapinche|didachuxing|didacar|dida-pinche|didataxi)\.com", "filter": None},
        {"name": "ECS/测试环境", "pattern": r"(www-ecs|web-ecs|web-simu|staging|dev-|test-)\.\w+\.\w+", "filter": None},
        {"name": "预发布环境命名(prep-)", "pattern": r"https?://prep[-][a-zA-Z0-9_\-]+\.[a-zA-Z0-9_\-]+\.[a-zA-Z]+", "filter": None},
        {"name": "测试环境命名(test-/docker-)", "pattern": r"https?://(test[-_]|docker[-_]|uat[-_]|qa[-_]|staging[-_])[a-zA-Z0-9_\-]*\.[a-zA-Z0-9_\-]+\.[a-zA-Z]+", "filter": None},
        {"name": "内部API网关(gateway-)", "pattern": r"https?://gateway[a-zA-Z0-9_\-]*\.[a-zA-Z0-9_\-]+\.[a-zA-Z]+", "filter": None},
        {"name": "生产环境命名(prod-)", "pattern": r"https?://prod[-][a-zA-Z0-9_\-]+\.[a-zA-Z0-9_\-]+\.[a-zA-Z]+", "filter": None},
        {"name": "微服务路径识别", "pattern": r"['\"](/(?:prod|test|dev|uat|staging|api)/[a-zA-Z0-9_\-]+/[a-zA-Z0-9_\-/]+)['\"]", "group": 1, "filter": lambda x: len(x) > 15},
        {"name": "版本号", "pattern": r"version['\"]?\s*[:=]\s*['\"]([0-9]+\.[0-9]+\.[0-9]+)['\"]", "group": 1},
        {"name": "Vite环境变量", "pattern": r"import\.meta\.env\.(VITE_[A-Z_]+)", "group": 1},
        {"name": "Vite环境变量2", "pattern": r"__VITE_[A-Z_]+__", "filter": None},
    ],
    "配置/密码": [
        {"name": "数据库密码", "pattern": r"(password|passwd|pwd|db_pass|db_password)[\"']?\s*[:=]\s*[\"']([^\"']{3,})[\"']", "group": 2},
        {"name": "连接字符串", "pattern": r"(mysql|postgres|mongodb|redis|jdbc):[^\"'\s]+", "filter": None},
        {"name": "Access Token", "pattern": r"access_token", "filter": None},
        {"name": "Cookie名", "pattern": r"(Set-Cookie|document\.cookie|localStorage\.(get|set)|sessionStorage\.(get|set))", "filter": None},
    ],
    "注释泄露": [
        {"name": "TODO/FIXME", "pattern": r"//\s*(TODO|FIXME|HACK|XXX|BUG|TEMP|DEBUG):?\s*(.{10,50})", "group": 0},
        {"name": "注释中的URL", "pattern": r"//\s*https?://[^\"'\s]{10,}", "filter": None},
    ],
    "Vite/SPA特征": [
        {"name": "Vite入口文件", "pattern": r"/assets/index-[a-f0-9]{8}\.js", "filter": None},
        {"name": "Vite chunk引用", "pattern": r"/assets/[a-zA-Z0-9_-]+-[a-f0-9]{8}\.[a-z]+", "filter": None},
        {"name": "import.meta", "pattern": r"import\.meta\.(env|url|hot|glob)", "filter": None},
        {"name": "Vite模块热替换", "pattern": r"__vite__(_injectQuery|_css|_mapDeps|isCSSRequest)", "filter": None},
    ],
}

def fetch_content(source):
    """从URL或本地文件获取内容，支持0B重试和代理检测"""
    if source.startswith(("http://", "https://")):
        # 尝试直连，如果0B则重试+代理
        max_retries = 3
        proxies = []
        # 检测环境变量中的代理
        for var in ("HTTPS_PROXY", "HTTP_PROXY", "ALL_PROXY", "https_proxy", "http_proxy", "all_proxy"):
            val = os.environ.get(var, "")
            if val and val not in proxies:
                proxies.append(val)

        for attempt in range(max_retries):
            try:
                req = urllib.request.Request(source, headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0"})
                # 最后一次尝试使用代理（如有）
                if attempt == max_retries - 1 and proxies:
                    proxy = proxies[0]
                    proxy_handler = urllib.request.ProxyHandler({"https": proxy, "http": proxy})
                    opener = urllib.request.build_opener(proxy_handler)
                    with opener.open(req, timeout=15) as resp:
                        data = resp.read()
                else:
                    with urllib.request.urlopen(req, timeout=15) as resp:
                        data = resp.read()
                if len(data) == 0:
                    print(f"[!] 0B文件 (尝试{attempt+1}/{max_retries})，准备重试...")
                    time.sleep(1)
                    continue
                return data.decode("utf-8", errors="ignore")
            except Exception as e:
                if attempt < max_retries - 1:
                    print(f"[!] 下载失败 (尝试{attempt+1}/{max_retries}): {e}")
                    time.sleep(1)
                else:
                    print(f"[!] 下载失败 (已重试{max_retries}次): {e}")
                    return ""
        return ""
    elif os.path.isfile(source):
        content = open(source, "r", encoding="utf-8", errors="ignore").read()
        if len(content) == 0:
            print(f"[!] 警告: 本地文件 {source} 大小为0B")
        return content
    else:
        print(f"[!] 无效源: {source}")
        sys.exit(1)

def extract(content, rules):
    """提取匹配项"""
    results = {}
    seen = {}

    for category, rule_list in rules.items():
        results[category] = []
        for rule in rule_list:
            matches = re.findall(rule["pattern"], content, re.IGNORECASE)
            for match in matches:
                if isinstance(match, tuple):
                    g = rule.get("group", 0)
                    match = match[g] if g < len(match) else match[0]

                if rule.get("filter") and not rule["filter"](match):
                    continue
                if len(match) > 200:
                    match = match[:200] + "..."

                key = f"{rule['name']}:{match}"
                if key in seen:
                    continue
                seen[key] = True
                results[category].append({"name": rule["name"], "value": match})

    return results

def print_results(results, fmt="text"):
    """输出结果"""
    if fmt == "json":
        filtered = {k: v for k, v in results.items() if v}
        print(json.dumps(filtered, ensure_ascii=False, indent=2))
        return

    total = sum(len(v) for v in results.values())
    if total == 0:
        print("[!] 未发现任何敏感信息")
        return

    print(f"\n{'='*60}")
    print(f"  JS密钥提取器 v2.0 | 共发现 {total} 个敏感项")
    print(f"{'='*60}")

    for category, items in results.items():
        if not items:
            continue
        print(f"\n{'─'*50}")
        print(f"  [{category}] ({len(items)}项)")
        print(f"{'─'*50}")
        for item in items:
            print(f"    ■ {item['name']}")
            print(f"      {item['value']}")

def main():
    parser = argparse.ArgumentParser(description="JS密钥提取器 v2.0")
    parser.add_argument("source", help="URL或本地文件路径")
    parser.add_argument("-f", "--format", choices=["text", "json"], default="text")
    parser.add_argument("-o", "--output", help="输出文件路径")
    args = parser.parse_args()

    content = fetch_content(args.source)
    results = extract(content, RULES)

    if args.output:
        with open(args.output, "w") as f:
            if args.format == "json":
                filtered = {k: v for k, v in results.items() if v}
                json.dump(filtered, f, ensure_ascii=False, indent=2)
            else:
                f.write(f"总计: {sum(len(v) for v in results.values())} 个敏感项\n")
                for cat, items in results.items():
                    if items:
                        f.write(f"\n[{cat}]\n")
                        for item in items:
                            f.write(f"  {item['name']}: {item['value']}\n")
        print(f"[+] 结果已保存到: {args.output}")
    else:
        print_results(results, args.format)

if __name__ == "__main__":
    main()