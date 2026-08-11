# -*- coding: utf-8 -*-
"""
扫描引擎
负责执行规则扫描模式与全量扫描模式的全部检测逻辑。
通过回调函数将扫描进度与结果实时推送到 GUI。
"""

import socket
import ssl
import threading
import time
from urllib.parse import urlparse, urljoin, urlencode, parse_qs

import requests
from requests.packages import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

import rules


class ScanResult:
    """单条扫描结果"""
    LEVEL_INFO = "INFO"
    LEVEL_LOW = "LOW"
    LEVEL_MEDIUM = "MEDIUM"
    LEVEL_HIGH = "HIGH"
    LEVEL_CRITICAL = "CRITICAL"

    def __init__(self, target, check_name, level, title, detail=""):
        self.target = target
        self.check_name = check_name
        self.level = level
        self.title = title
        self.detail = detail
        self.timestamp = time.strftime("%Y-%m-%d %H:%M:%S")

    def __repr__(self):
        return f"[{self.level}] {self.title} ({self.target})"


class ScannerEngine:
    """扫描引擎主类"""

    def __init__(self, target, mode="rule", threads=10, timeout=8,
                 on_progress=None, on_result=None, on_log=None, on_finish=None):
        """
        :param target:      目标 URL，例如 https://example.com
        :param mode:        扫描模式 "rule" 或 "full"
        :param threads:     并发线程数
        :param timeout:     单请求超时秒数
        :param on_progress: 回调 (current, total, message)
        :param on_result:   回调 (ScanResult)
        :param on_log:      回调 (message)
        :param on_finish:   回调 (summary_dict)
        """
        self.target = self._normalize_target(target)
        self.mode = mode
        self.threads = threads
        self.timeout = timeout
        self.on_progress = on_progress
        self.on_result = on_result
        self.on_log = on_log
        self.on_finish = on_finish

        self._stop_event = threading.Event()
        self._session = requests.Session()
        self._session.headers.update({
            "User-Agent": "Mozilla/5.0 (compatible; VulnScanner/1.0; SecurityAudit)"
        })

        # 扫描统计
        self.stats = {
            "total": 0,
            "done": 0,
            "findings": 0,
            "by_level": {
                ScanResult.LEVEL_CRITICAL: 0,
                ScanResult.LEVEL_HIGH: 0,
                ScanResult.LEVEL_MEDIUM: 0,
                ScanResult.LEVEL_LOW: 0,
                ScanResult.LEVEL_INFO: 0,
            },
            "start_time": 0,
            "end_time": 0,
        }

        # 已发现子域名
        self.subdomains = set()
        # 已发现的表单/参数入口（用于 SQLi/XSS 注入测试）
        self.param_endpoints = []

    # ------------------------------------------------------------
    # 工具方法
    # ------------------------------------------------------------
    @staticmethod
    def _normalize_target(url):
        url = url.strip()
        if not url:
            raise ValueError("目标 URL 不能为空")
        if not url.startswith(("http://", "https://")):
            url = "http://" + url
        # 去掉末尾斜杠
        parsed = urlparse(url)
        base = f"{parsed.scheme}://{parsed.netloc}"
        return base

    def _log(self, msg):
        if self.on_log:
            self.on_log(msg)

    def _push_result(self, result):
        self.stats["findings"] += 1
        self.stats["by_level"][result.level] = (
            self.stats["by_level"].get(result.level, 0) + 1
        )
        if self.on_result:
            self.on_result(result)

    def _advance(self, message=""):
        self.stats["done"] += 1
        if self.on_progress:
            self.on_progress(self.stats["done"], self.stats["total"], message)

    def stop(self):
        self._stop_event.set()
        self._log("[!] 用户请求停止扫描")

    def _request(self, method, url, **kwargs):
        """统一请求封装，捕获异常，遵循 stop 事件"""
        if self._stop_event.is_set():
            return None
        kwargs.setdefault("timeout", self.timeout)
        kwargs.setdefault("verify", False)
        kwargs.setdefault("allow_redirects", True)
        try:
            resp = self._session.request(method, url, **kwargs)
            return resp
        except requests.exceptions.RequestException:
            return None
        except Exception:
            return None

    # ------------------------------------------------------------
    # 检测模块
    # ------------------------------------------------------------
    def check_sensitive_files(self, base_url):
        """敏感文件/目录泄露检测"""
        self._log(f"[*] 检测敏感文件泄露: {base_url}")
        total = len(rules.SENSITIVE_PATHS)
        for idx, path in enumerate(rules.SENSITIVE_PATHS):
            if self._stop_event.is_set():
                return
            url = base_url.rstrip("/") + path
            resp = self._request("GET", url)
            if resp is None:
                continue
            # 404 / 403 等通常不视为泄露
            if resp.status_code in (200, 301, 302, 401, 403):
                # 进一步判断 403 是否真实存在
                if resp.status_code == 403:
                    self._push_result(ScanResult(
                        url, "sensitive_files", ScanResult.LEVEL_LOW,
                        f"敏感路径存在但禁止访问 (403): {path}",
                        f"目标存在路径 {path}，返回 403。可能存在但被保护。"
                    ))
                elif resp.status_code in (200, 301, 302):
                    # 简单特征判断内容是否为真正的泄露
                    body_snippet = resp.text[:200] if resp.text else ""
                    self._push_result(ScanResult(
                        url, "sensitive_files", ScanResult.LEVEL_HIGH,
                        f"敏感文件可访问 ({resp.status_code}): {path}",
                        f"响应长度 {len(resp.text)} 字节。内容片段: {body_snippet!r}"
                    ))
                elif resp.status_code == 401:
                    self._push_result(ScanResult(
                        url, "sensitive_files", ScanResult.LEVEL_INFO,
                        f"敏感路径需要认证 (401): {path}",
                        f"目标存在路径 {path}，返回 401。"
                    ))
            self._advance(f"敏感文件 {idx + 1}/{total}: {path}")

    def check_security_headers(self, base_url):
        """安全响应头检测"""
        self._log(f"[*] 检测安全响应头: {base_url}")
        resp = self._request("GET", base_url)
        if resp is None:
            self._advance("安全响应头检测跳过（请求失败）")
            return
        total = len(rules.SECURITY_HEADERS)
        for idx, header in enumerate(rules.SECURITY_HEADERS):
            if self._stop_event.is_set():
                return
            if header not in resp.headers:
                self._push_result(ScanResult(
                    base_url, "security_headers", ScanResult.LEVEL_MEDIUM,
                    f"缺失安全响应头: {header}",
                    f"响应未包含 {header} 头，可能存在对应安全风险。"
                ))
            self._advance(f"响应头 {idx + 1}/{total}: {header}")

    def check_server_info(self, base_url):
        """服务器信息泄露检测"""
        self._log(f"[*] 检测服务器信息泄露: {base_url}")
        resp = self._request("GET", base_url)
        if resp is None:
            self._advance("服务器信息检测跳过")
            return
        server = resp.headers.get("Server", "")
        xpb = resp.headers.get("X-Powered-By", "")
        if server:
            self._push_result(ScanResult(
                base_url, "server_info", ScanResult.LEVEL_LOW,
                f"Server 头泄露: {server}",
                f"响应包含 Server 头: {server}，可能暴露后端技术栈。"
            ))
        if xpb:
            self._push_result(ScanResult(
                base_url, "server_info", ScanResult.LEVEL_LOW,
                f"X-Powered-By 头泄露: {xpb}",
                f"响应包含 X-Powered-By 头: {xpb}，可能暴露后端技术栈。"
            ))
        self._advance("服务器信息检测完成")

    def check_sqli(self, base_url):
        """SQL 注入检测：对收集到的参数端点逐个注入测试"""
        self._log(f"[*] 检测 SQL 注入: {base_url}")
        endpoints = self._collect_param_endpoints(base_url)
        if not endpoints:
            self._advance("SQL 注入检测跳过（无可用参数端点）")
            return
        payloads = rules.SQLI_PAYLOADS
        signatures = rules.SQLI_SIGNATURES
        total = len(endpoints) * len(payloads)
        idx = 0
        for endpoint in endpoints:
            for payload in payloads:
                if self._stop_event.is_set():
                    return
                idx += 1
                self._test_injection(
                    endpoint, payload, signatures,
                    check_name="sql_injection",
                    vuln_title="SQL 注入",
                    level=ScanResult.LEVEL_HIGH,
                )
                self._advance(f"SQLi {idx}/{total}")

    def check_xss(self, base_url):
        """XSS 检测"""
        self._log(f"[*] 检测 XSS: {base_url}")
        endpoints = self._collect_param_endpoints(base_url)
        if not endpoints:
            self._advance("XSS 检测跳过（无可用参数端点）")
            return
        payloads = rules.XSS_PAYLOADS
        total = len(endpoints) * len(payloads)
        idx = 0
        for endpoint in endpoints:
            for payload in payloads:
                if self._stop_event.is_set():
                    return
                idx += 1
                self._test_reflected_xss(endpoint, payload)
                self._advance(f"XSS {idx}/{total}")

    def check_directory_traversal(self, base_url):
        """目录穿越检测"""
        self._log(f"[*] 检测目录穿越: {base_url}")
        endpoints = self._collect_param_endpoints(base_url)
        if not endpoints:
            self._advance("目录穿越检测跳过")
            return
        payloads = rules.TRAVERSAL_PAYLOADS
        signatures = rules.TRAVERSAL_SIGNATURES
        total = len(endpoints) * len(payloads)
        idx = 0
        for endpoint in endpoints:
            for payload in payloads:
                if self._stop_event.is_set():
                    return
                idx += 1
                self._test_injection(
                    endpoint, payload, signatures,
                    check_name="directory_traversal",
                    vuln_title="目录穿越",
                    level=ScanResult.LEVEL_HIGH,
                )
                self._advance(f"Traversal {idx}/{total}")

    def check_command_injection(self, base_url):
        """命令注入检测"""
        self._log(f"[*] 检测命令注入: {base_url}")
        endpoints = self._collect_param_endpoints(base_url)
        if not endpoints:
            self._advance("命令注入检测跳过")
            return
        payloads = rules.CMDI_PAYLOADS
        signatures = rules.CMDI_SIGNATURES
        total = len(endpoints) * len(payloads)
        idx = 0
        for endpoint in endpoints:
            for payload in payloads:
                if self._stop_event.is_set():
                    return
                idx += 1
                self._test_injection(
                    endpoint, payload, signatures,
                    check_name="command_injection",
                    vuln_title="命令注入",
                    level=ScanResult.LEVEL_CRITICAL,
                )
                self._advance(f"CmdInj {idx}/{total}")

    def check_open_redirect(self, base_url):
        """开放重定向检测"""
        self._log(f"[*] 检测开放重定向: {base_url}")
        endpoints = self._collect_param_endpoints(base_url)
        if not endpoints:
            self._advance("开放重定向检测跳过")
            return
        payloads = rules.OPEN_REDIRECT_PAYLOADS
        total = len(endpoints) * len(payloads)
        idx = 0
        for endpoint in endpoints:
            for payload in payloads:
                if self._stop_event.is_set():
                    return
                idx += 1
                self._test_open_redirect(endpoint, payload)
                self._advance(f"OpenRedir {idx}/{total}")

    def check_subdomain_enum(self):
        """子域名枚举（仅全量模式）"""
        parsed = urlparse(self.target)
        domain = parsed.hostname
        if not domain:
            self._advance("子域名枚举跳过")
            return
        self._log(f"[*] 枚举子域名: {domain}")
        wordlist = rules.SUBDOMAIN_WORDLIST
        total = len(wordlist)
        for idx, sub in enumerate(wordlist):
            if self._stop_event.is_set():
                return
            candidate = f"{sub}.{domain}"
            try:
                resolved = socket.gethostbyname(candidate)
            except socket.gaierror:
                resolved = None
            except Exception:
                resolved = None
            if resolved:
                self.subdomains.add(candidate)
                self._push_result(ScanResult(
                    candidate, "subdomain_enum", ScanResult.LEVEL_INFO,
                    f"发现子域名: {candidate}",
                    f"解析到 IP: {resolved}"
                ))
            self._advance(f"子域名 {idx + 1}/{total}: {candidate}")

    def check_subdomain_takeover(self):
        """子域名接管检测（仅全量模式）"""
        self._log(f"[*] 检测子域名接管")
        if not self.subdomains:
            self._advance("子域名接管检测跳过（无子域名）")
            return
        total = len(self.subdomains)
        for idx, sub in enumerate(list(self.subdomains)):
            if self._stop_event.is_set():
                return
            for scheme in ("http", "https"):
                url = f"{scheme}://{sub}"
                resp = self._request("GET", url)
                if resp is None:
                    continue
                body = resp.text.lower() if resp.text else ""
                for provider, sigs in rules.SUBDOMAIN_TAKEOVER_SIGNATURES.items():
                    for sig in sigs:
                        if sig.lower() in body:
                            self._push_result(ScanResult(
                                url, "subdomain_takeover",
                                ScanResult.LEVEL_CRITICAL,
                                f"疑似子域名接管 ({provider}): {sub}",
                                f"响应命中 {provider} 接管特征: {sig}"
                            ))
                            break
                # 一个子域名命中一次即可
                if resp is not None:
                    break
            self._advance(f"子域名接管 {idx + 1}/{total}: {sub}")

    def check_ssl_info(self):
        """SSL/TLS 信息检测"""
        self._log(f"[*] 检测 SSL 信息")
        parsed = urlparse(self.target)
        host = parsed.hostname
        if not host:
            self._advance("SSL 检测跳过")
            return
        if parsed.scheme != "https":
            # 尝试 HTTPS
            https_url = f"https://{host}"
            resp = self._request("GET", https_url)
            if resp is None:
                self._push_result(ScanResult(
                    self.target, "ssl_info", ScanResult.LEVEL_LOW,
                    "目标未启用 HTTPS",
                    f"目标 {host} 似乎未启用 HTTPS 服务。"
                ))
                self._advance("SSL 检测完成")
                return
        port = 443
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            with socket.create_connection((host, port), timeout=self.timeout) as sock:
                with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                    cert = ssock.getpeercert()
                    version = ssock.version()
            if cert:
                subject = dict(x[0] for x in cert.get("subject", []))
                issuer = dict(x[0] for x in cert.get("issuer", []))
                not_after = cert.get("notAfter", "")
                self._push_result(ScanResult(
                    f"https://{host}", "ssl_info", ScanResult.LEVEL_INFO,
                    f"SSL 证书信息: {subject.get('commonName', host)}",
                    f"版本: {version}, 颁发者: {issuer.get('commonName','')}, "
                    f"有效期至: {not_after}"
                ))
                # 检查过期
                try:
                    expire_date = time.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
                    now = time.time()
                    expire_ts = time.mktime(expire_date)
                    if expire_ts < now:
                        self._push_result(ScanResult(
                            f"https://{host}", "ssl_info",
                            ScanResult.LEVEL_HIGH,
                            "SSL 证书已过期",
                            f"证书已于 {not_after} 过期"
                        ))
                except Exception:
                    pass
        except Exception as e:
            self._push_result(ScanResult(
                self.target, "ssl_info", ScanResult.LEVEL_MEDIUM,
                "SSL/TLS 连接异常",
                f"建立 SSL 连接失败: {e}"
            ))
        self._advance("SSL 检测完成")

    # ------------------------------------------------------------
    # 注入测试辅助
    # ------------------------------------------------------------
    def _collect_param_endpoints(self, base_url):
        """
        收集带参数的入口：
        1. 目标 URL 自身的 query 参数
        2. 抓取首页与常见路径的链接，提取带 query 的 URL
        3. 解析页面中常见测试参数（id, q, name, search 等）
        """
        if self.param_endpoints:
            return self.param_endpoints

        endpoints = []
        # 目标 URL 自身参数
        parsed = urlparse(base_url)
        if parsed.query:
            endpoints.append({"url": base_url, "params": list(parse_qs(parsed.query).keys())})

        # 抓取首页与常见路径下的链接
        seed_urls = [base_url]
        # 简单从首页抓链接
        resp = self._request("GET", base_url)
        if resp is not None and resp.text:
            import re
            links = re.findall(r'href=["\']([^"\']+)["\']', resp.text, re.I)
            for link in links[:50]:
                abs_url = urljoin(base_url, link)
                p = urlparse(abs_url)
                if p.netloc == urlparse(base_url).netloc and p.query:
                    params = list(parse_qs(p.query).keys())
                    ep = {"url": abs_url, "params": params}
                    if ep not in endpoints:
                        endpoints.append(ep)

        # 如果首页无任何带参端点，则补一个常见测试参数端点
        if not endpoints:
            for test_param in ("id", "q", "page", "search", "name", "cat"):
                endpoints.append({"url": base_url, "params": [test_param]})

        self.param_endpoints = endpoints
        return endpoints

    def _test_injection(self, endpoint, payload, signatures,
                        check_name, vuln_title, level):
        """通用注入测试：在 GET 参数上附加 payload 并检查响应特征"""
        url = endpoint["url"]
        parsed = urlparse(url)
        qs = parse_qs(parsed.query, keep_blank_values=True)
        if not qs:
            # 没有参数，强制给第一个参数附加
            qs = {endpoint["params"][0] if endpoint["params"] else "id": [""]}
        # 替换第一个参数值为 payload
        keys = list(qs.keys())
        first_key = keys[0]
        qs[first_key] = [payload]
        new_query = urlencode({k: v[0] if isinstance(v, list) else v for k, v in qs.items()})
        test_url = parsed._replace(query=new_query).geturl()

        resp = self._request("GET", test_url)
        if resp is None:
            return
        body = resp.text or ""
        body_lower = body.lower()
        for sig in signatures:
            if sig.lower() in body_lower:
                self._push_result(ScanResult(
                    test_url, check_name, level,
                    f"疑似 {vuln_title} 漏洞",
                    f"参数 {first_key} 注入 payload {payload!r} 后响应命中特征: {sig}"
                ))
                return
        # 时延型注入判断（针对 SLEEP/WAITFOR）
        if "SLEEP" in payload.upper() or "WAITFOR" in payload.upper():
            if resp.elapsed.total_seconds() >= 2.5:
                self._push_result(ScanResult(
                    test_url, check_name, level,
                    f"疑似时延型 {vuln_title}",
                    f"参数 {first_key} 注入 {payload!r} 后响应耗时 "
                    f"{resp.elapsed.total_seconds():.2f}s"
                ))

    def _test_reflected_xss(self, endpoint, payload):
        """XSS 反射检测：检查 payload 是否原样出现在响应中"""
        url = endpoint["url"]
        parsed = urlparse(url)
        qs = parse_qs(parsed.query, keep_blank_values=True)
        if not qs:
            qs = {endpoint["params"][0] if endpoint["params"] else "q": [""]}
        keys = list(qs.keys())
        first_key = keys[0]
        qs[first_key] = [payload]
        new_query = urlencode({k: v[0] if isinstance(v, list) else v for k, v in qs.items()})
        test_url = parsed._replace(query=new_query).geturl()

        resp = self._request("GET", test_url)
        if resp is None:
            return
        body = resp.text or ""
        if payload in body:
            self._push_result(ScanResult(
                test_url, "xss", ScanResult.LEVEL_HIGH,
                "疑似反射型 XSS 漏洞",
                f"参数 {first_key} 注入 payload {payload!r} 后被原样反射回页面"
            ))

    def _test_open_redirect(self, endpoint, payload):
        """开放重定向检测：检查是否被重定向到外部域"""
        url = endpoint["url"]
        parsed = urlparse(url)
        qs = parse_qs(parsed.query, keep_blank_values=True)
        if not qs:
            qs = {endpoint["params"][0] if endpoint["params"] else "next": [""]}
        keys = list(qs.keys())
        first_key = keys[0]
        qs[first_key] = [payload]
        new_query = urlencode({k: v[0] if isinstance(v, list) else v for k, v in qs.items()})
        test_url = parsed._replace(query=new_query).geturl()

        # 不跟随重定向以观察 Location
        resp = self._session.get(test_url, timeout=self.timeout,
                                 verify=False, allow_redirects=False)
        if resp is None:
            return
        location = resp.headers.get("Location", "")
        target_host = urlparse(payload).hostname or ""
        base_host = urlparse(self.target).hostname or ""
        if location and target_host and target_host != base_host:
            self._push_result(ScanResult(
                test_url, "open_redirect", ScanResult.LEVEL_MEDIUM,
                "疑似开放重定向漏洞",
                f"参数 {first_key}={payload!r} 触发 30x 重定向到 {location}"
            ))

    # ------------------------------------------------------------
    # 主扫描流程
    # ------------------------------------------------------------
    def _estimate_total(self, checks):
        """粗略预估总任务数用于进度展示"""
        total = 0
        if "sensitive_files" in checks:
            total += len(rules.SENSITIVE_PATHS)
        if "security_headers" in checks:
            total += len(rules.SECURITY_HEADERS)
        if "server_info" in checks:
            total += 1
        if "sql_injection" in checks:
            ep_n = max(1, len(self._collect_param_endpoints(self.target)))
            total += ep_n * len(rules.SQLI_PAYLOADS)
        if "xss" in checks:
            ep_n = max(1, len(self._collect_param_endpoints(self.target)))
            total += ep_n * len(rules.XSS_PAYLOADS)
        if "directory_traversal" in checks:
            ep_n = max(1, len(self._collect_param_endpoints(self.target)))
            total += ep_n * len(rules.TRAVERSAL_PAYLOADS)
        if "command_injection" in checks:
            ep_n = max(1, len(self._collect_param_endpoints(self.target)))
            total += ep_n * len(rules.CMDI_PAYLOADS)
        if "open_redirect" in checks:
            ep_n = max(1, len(self._collect_param_endpoints(self.target)))
            total += ep_n * len(rules.OPEN_REDIRECT_PAYLOADS)
        if "subdomain_enum" in checks:
            total += len(rules.SUBDOMAIN_WORDLIST)
        if "subdomain_takeover" in checks:
            total += 1  # 子域名运行时才知道数量
        if "ssl_info" in checks:
            total += 1
        return max(1, total)

    def run(self):
        """主扫描入口"""
        self.stats["start_time"] = time.time()
        self._log(f"[*] 开始扫描: {self.target} (模式: {self.mode})")

        checks = rules.RULE_SCAN_CHECKS if self.mode == "rule" else rules.FULL_SCAN_CHECKS
        self.stats["total"] = self._estimate_total(checks)
        self._log(f"[*] 预计任务数: {self.stats['total']}")

        # 扫描目标本身
        self._scan_host(self.target, checks)

        # 全量模式：对发现的子域名（http/https 可访问者）也执行漏洞检测
        if self.mode == "full" and self.subdomains and not self._stop_event.is_set():
            self._log(f"[*] 对 {len(self.subdomains)} 个子域名执行漏洞检测")
            for sub in list(self.subdomains):
                if self._stop_event.is_set():
                    break
                # 探测可访问的 scheme
                sub_base = None
                for scheme in ("https", "http"):
                    resp = self._request("GET", f"{scheme}://{sub}")
                    if resp is not None:
                        sub_base = f"{scheme}://{sub}"
                        break
                if not sub_base:
                    continue
                self._log(f"[*] 扫描子域名: {sub_base}")
                # 子域名复用除子域名枚举/接管/SSL 外的检测项
                sub_checks = [c for c in checks
                              if c not in ("subdomain_enum", "subdomain_takeover", "ssl_info")]
                self._scan_host(sub_base, sub_checks)

        self.stats["end_time"] = time.time()
        elapsed = self.stats["end_time"] - self.stats["start_time"]
        self._log(f"[*] 扫描完成，耗时 {elapsed:.1f}s")
        if self.on_finish:
            self.on_finish({
                "target": self.target,
                "mode": self.mode,
                "elapsed": elapsed,
                "findings": self.stats["findings"],
                "by_level": self.stats["by_level"],
            })

    def _scan_host(self, base_url, checks):
        """对单个主机执行指定检测项"""
        for check in checks:
            if self._stop_event.is_set():
                return
            if check == "sensitive_files":
                self.check_sensitive_files(base_url)
            elif check == "security_headers":
                self.check_security_headers(base_url)
            elif check == "server_info":
                self.check_server_info(base_url)
            elif check == "sql_injection":
                self.check_sqli(base_url)
            elif check == "xss":
                self.check_xss(base_url)
            elif check == "directory_traversal":
                self.check_directory_traversal(base_url)
            elif check == "command_injection":
                self.check_command_injection(base_url)
            elif check == "open_redirect":
                self.check_open_redirect(base_url)
            elif check == "subdomain_enum":
                self.check_subdomain_enum()
            elif check == "subdomain_takeover":
                self.check_subdomain_takeover()
            elif check == "ssl_info":
                self.check_ssl_info()
