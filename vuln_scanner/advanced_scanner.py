#!/usr/bin/env python3
"""
升级版漏洞扫描引擎 v3.0
10 模块一体化扫描：信息收集 | SSL/TLS | 安全响应头 | 会话安全 | 信息泄露 |
敏感路径 | 前端安全 | 后端指纹 | HTTP 配置 | 供应链
每个漏洞含截图URL、CVSS向量、复现步骤、修复方案
"""
import requests
import urllib3
import json
import os
import sys
import re
import socket
import ssl
import datetime
import time
import hashlib
from urllib.parse import urlparse, urljoin, quote

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

TIMEOUT = 10
REQUEST_DELAY = 0.8
USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"

# ============================================================
# CVSS 3.1 向量库
# ============================================================
CVSS_VECTORS = {
    "sql_query_exposure": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
    "sql_injection": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    "cookie_insecure": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:N",
    "missing_hsts": "CVSS:3.1/AV:A/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N",
    "missing_csp": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N",
    "missing_xfo": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:N",
    "missing_xcto": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:N",
    "cors_dangerous": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:N",
    "dangerous_http_methods": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N",
    "jquery_xss": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
    "robots_misconfig": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
    "email_system_exposure": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
    "ssl_subdomain_errors": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
    "email_disclosure": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
    "external_http_link": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N",
    "server_version_disclosure": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
    "source_leak_git": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
    "source_leak_env": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    "directory_listing": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
    "error_info_leak": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
    "debug_mode": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
    "path_disclosure": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
    "backup_leak": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
    "apikey_leak": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
    "internal_ip_leak": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
    "cms_vuln_hint": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N",
    "frontend_leak": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
    "third_party_leak": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
    "cache_poison": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N",
    "trace_method": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:N",
    "default_page": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
    "http_no_https": "CVSS:3.1/AV:A/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N",
    "session_info_leak": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
    "sensitive_path": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
    "dns_no_record": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
    "service_unavailable": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
    "ssl_cert_error": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
    "dns_info_leak": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
    "no_security_headers": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N",
    "no_mx_record": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N",
    "no_spf_dmarc": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:N",
    "no_dnssec": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:L/A:N",
    "proxy_error_disclosure": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
    "domain_registration": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N",
}

CWE_MAP = {
    "sql_query_exposure": "CWE-209 / CWE-89",
    "sql_injection": "CWE-89",
    "cookie_insecure": "CWE-614 / CWE-1004",
    "missing_hsts": "CWE-319",
    "missing_csp": "CWE-1021",
    "missing_xfo": "CWE-1021",
    "missing_xcto": "CWE-16",
    "cors_dangerous": "CWE-942",
    "dangerous_http_methods": "CWE-749",
    "jquery_xss": "CWE-79 / CWE-1104",
    "robots_misconfig": "CWE-538",
    "email_system_exposure": "CWE-200",
    "ssl_subdomain_errors": "CWE-295",
    "email_disclosure": "CWE-200",
    "external_http_link": "CWE-319",
    "server_version_disclosure": "CWE-200",
    "source_leak_git": "CWE-538",
    "source_leak_env": "CWE-538",
    "directory_listing": "CWE-548",
    "error_info_leak": "CWE-209",
    "debug_mode": "CWE-489",
    "path_disclosure": "CWE-200",
    "backup_leak": "CWE-538",
    "apikey_leak": "CWE-798",
    "internal_ip_leak": "CWE-200",
    "cms_vuln_hint": "CWE-1104",
    "frontend_leak": "CWE-200",
    "third_party_leak": "CWE-200",
    "cache_poison": "CWE-444",
    "trace_method": "CWE-749",
    "default_page": "CWE-489",
    "http_no_https": "CWE-319",
    "session_info_leak": "CWE-200",
    "sensitive_path": "CWE-200",
    "dns_no_record": "CWE-200",
    "service_unavailable": "CWE-N/A",
    "ssl_cert_error": "CWE-295",
    "dns_info_leak": "CWE-200",
    "no_security_headers": "CWE-16",
    "no_mx_record": "CWE-290",
    "no_spf_dmarc": "CWE-290",
    "no_dnssec": "CWE-345",
    "proxy_error_disclosure": "CWE-209",
    "domain_registration": "CWE-N/A",
}


class Vulnerability:
    def __init__(self, level, check_name, title, description="", screenshot_url="",
                 reproduction_steps="", fix_suggestion="", cvss_score="", cvss_vector="",
                 cwe="", affected_url=""):
        self.level = level
        self.check_name = check_name
        self.title = title
        self.description = description
        self.screenshot_url = screenshot_url
        self.reproduction_steps = reproduction_steps
        self.fix_suggestion = fix_suggestion
        self.cvss_score = cvss_score or self._calc_score()
        self.cvss_vector = cvss_vector or CVSS_VECTORS.get(check_name, "")
        self.cwe = cwe or CWE_MAP.get(check_name, "CWE-N/A")
        self.affected_url = affected_url
        self.timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    def _calc_score(self):
        v = CVSS_VECTORS.get(self.check_name, "")
        if "C:H/I:H/A:H" in v:
            return "9.8"
        elif "C:H/I:N/A:N" in v:
            return "7.5"
        elif "C:N/I:N/A:H" in v:
            return "7.5"
        elif "C:H/I:N/A:N" in v:
            return "6.5"
        elif "C:N/I:H/A:N" in v:
            return "6.5"
        elif "C:L/I:L/A:N" in v:
            return "6.1"
        elif "C:L/I:N/A:N" in v:
            return "5.3"
        elif "C:L/I:L" in v:
            return "5.3"
        elif "C:N/I:L" in v:
            return "4.3"
        return "N/A"

    def to_dict(self):
        return {
            "level": self.level, "check_name": self.check_name, "title": self.title,
            "description": self.description, "screenshot_url": self.screenshot_url,
            "reproduction_steps": self.reproduction_steps, "fix_suggestion": self.fix_suggestion,
            "cvss_score": self.cvss_score, "cvss_vector": self.cvss_vector,
            "cwe": self.cwe, "affected_url": self.affected_url, "timestamp": self.timestamp,
        }


class AdvancedScanner:
    LEVEL_CRITICAL = "CRITICAL"
    LEVEL_HIGH = "HIGH"
    LEVEL_MEDIUM = "MEDIUM"
    LEVEL_LOW = "LOW"
    LEVEL_INFO = "INFO"

    def __init__(self, target):
        self.target = target
        if not target.startswith("http"):
            target = "https://" + target
        self.base_url = target.rstrip("/")
        self.hostname = urlparse(self.base_url).hostname
        self.results = []
        self.session = requests.Session()
        self.session.headers.update({"User-Agent": USER_AGENT})
        self.session.verify = False
        self.session.timeout = TIMEOUT
        self._resp = None

    def add(self, level, check_name, title, **kw):
        if not kw.get("screenshot_url"):
            kw["screenshot_url"] = self.base_url
        if not kw.get("affected_url"):
            kw["affected_url"] = self.base_url
        v = Vulnerability(level=level, check_name=check_name, title=title, **kw)
        self.results.append(v)
        emoji = {"CRITICAL": "💀", "HIGH": "🔴", "MEDIUM": "🟡", "LOW": "🟢", "INFO": "🔵"}
        print(f"  {emoji.get(level, '')} [{level}] {check_name}: {title}")
        time.sleep(REQUEST_DELAY * 0.3)

    def run_all(self):
        print(f"\n{'='*70}")
        print(f"  升级版扫描 v3.0 | 目标: {self.hostname}")
        print(f"{'='*70}\n")

        # 先探测目标可达性
        reachable = self._probe_target()

        if reachable:
            print("[模块 1/10] 基础信息收集")
            self._mod_info_gathering()
            print("[模块 2/10] SSL/TLS 证书与配置")
            self._mod_ssl_tls()
            print("[模块 3/10] 安全响应头审计")
            self._mod_security_headers()
            print("[模块 4/10] Cookie 与会话安全")
            self._mod_cookie_session()
            print("[模块 5/10] 敏感信息泄露检测")
            self._mod_info_leak()
            print("[模块 6/10] 敏感路径/文件探测")
            self._mod_sensitive_paths()
            print("[模块 7/10] 前端安全检查")
            self._mod_frontend_security()
            print("[模块 8/10] 后端指纹与已知漏洞")
            self._mod_backend_fingerprint()
            print("[模块 9/10] HTTP 方法与配置缺陷")
            self._mod_http_methods()
            print("[模块 10/10] 第三方服务与供应链")
            self._mod_third_party()
        else:
            # 不可达目标，执行 DNS 级别探测
            self._mod_dns_only()

        self._print_summary()

    def _probe_target(self):
        """探测目标是否可达，502/503 视为不可达"""
        ok = False
        for proto in ["https://", "http://"]:
            try:
                r = self.session.get(proto + self.hostname, timeout=10, allow_redirects=True)
                self._resp = r
                if r.status_code < 500:
                    ok = True
                    break
            except requests.exceptions.SSLError:
                continue
            except:
                continue
        return ok

    def _mod_dns_only(self):
        """仅 DNS 级别探测（目标不可达时）"""
        print("[模块] DNS 级别探测（目标不可达）")

        # A 记录
        try:
            ips = socket.getaddrinfo(self.hostname, 80)
            if ips:
                ip_list = list(set([i[4][0] for i in ips]))
                self.add(self.LEVEL_INFO, "dns_resolve", f"DNS 解析: {', '.join(ip_list[:5])}")
        except:
            self.add(self.LEVEL_HIGH, "dns_no_record",
                     f"域名 {self.hostname} 无 A 记录，服务未部署 — 存在子域名接管风险",
                     description="DNS 无 A 记录，域名已注册但未配置服务器 IP。攻击者可利用此状态进行子域名接管攻击。",
                     fix_suggestion="配置 A 记录指向服务器 IP，或配置 SPF/DMARC 防止邮件欺诈",
                     screenshot_url=f"http://{self.hostname}/")

        # HTTP 探测
        try:
            r = self.session.get("http://" + self.hostname, timeout=10)
            if r.status_code == 502:
                self.add(self.LEVEL_HIGH, "service_unavailable",
                         "HTTP 返回 502 Bad Gateway — 服务不可用",
                         description=f"HTTP 请求返回 502，响应: {r.text[:100]}",
                         reproduction_steps=f"curl -v http://{self.hostname}/",
                         fix_suggestion="检查后端服务器和代理/CDN 配置")
        except:
            pass

        # HTTPS 探测
        try:
            self.session.get("https://" + self.hostname, timeout=10)
        except requests.exceptions.SSLError as e:
            self.add(self.LEVEL_HIGH, "ssl_cert_error",
                     "HTTPS 连接失败 — SSL/TLS 未正确配置",
                     description=f"SSL 错误: {str(e)[:80]}",
                     reproduction_steps=f"curl -v https://{self.hostname}/",
                     fix_suggestion="配置有效的 SSL 证书，确保 Web 服务器监听 443 端口",
                     screenshot_url=f"https://{self.hostname}/")

        # SOA / NS
        try:
            import subprocess
            r = subprocess.run(["dig", self.hostname, "SOA", "+short"], capture_output=True, text=True, timeout=5)
            if r.stdout.strip():
                self.add(self.LEVEL_MEDIUM, "dns_info_leak",
                         f"DNS 信息泄露: SOA={r.stdout.strip()[:100]}",
                         description="SOA 记录暴露域名托管商信息",
                         fix_suggestion="考虑启用 DNSSEC")
            r = subprocess.run(["dig", self.hostname, "NS", "+short"], capture_output=True, text=True, timeout=5)
            if r.stdout.strip():
                self.add(self.LEVEL_INFO, "dns_info", f"NS: {r.stdout.strip().replace(chr(10), ', ')}")
        except:
            pass

        # MX
        try:
            import subprocess
            r = subprocess.run(["dig", self.hostname, "MX", "+short"], capture_output=True, text=True, timeout=5)
            if not r.stdout.strip():
                self.add(self.LEVEL_MEDIUM, "no_mx_record",
                         "无 MX 记录 — 邮件服务未配置，存在邮件欺诈风险",
                         description="缺少 MX 记录，且无 SPF/DMARC，攻击者可伪造该域名发送钓鱼邮件",
                         fix_suggestion="配置 SPF: v=spf1 -all 和 DMARC: v=DMARC1; p=reject")
        except:
            pass

        # SPF / DMARC
        try:
            import subprocess
            r = subprocess.run(["dig", self.hostname, "TXT", "+short"], capture_output=True, text=True, timeout=5)
            txt = r.stdout.strip().lower()
            if "spf" not in txt and "dmarc" not in txt:
                self.add(self.LEVEL_LOW, "no_spf_dmarc",
                         "缺少 SPF/DMARC 记录 — 邮件欺诈风险",
                         fix_suggestion="添加 TXT: v=spf1 -all 和 v=DMARC1; p=reject;")
        except:
            pass

        # DNSSEC
        try:
            import subprocess
            r = subprocess.run(["dig", self.hostname, "DNSKEY", "+short"], capture_output=True, text=True, timeout=5)
            if not r.stdout.strip():
                self.add(self.LEVEL_LOW, "no_dnssec", "DNS 未启用 DNSSEC",
                         fix_suggestion="在域名注册商处启用 DNSSEC")
        except:
            pass

        # 502 错误信息泄露
        try:
            r = self.session.get("http://" + self.hostname, timeout=10)
            if r.status_code == 502 and len(r.text) > 20:
                self.add(self.LEVEL_LOW, "proxy_error_disclosure",
                         f"代理错误信息泄露: {r.text[:80]}",
                         fix_suggestion="配置自定义错误页面，隐藏内部错误信息")
        except:
            pass

        self.add(self.LEVEL_INFO, "domain_registration",
                 "域名已注册但 Web 服务未部署",
                 description="DNS 探测发现域名已注册但无可用 Web 服务，建议确认域名用途并正确配置",
                 fix_suggestion="联系域名管理员确认服务配置")

    def _print_summary(self):
        levels = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
        for r in self.results:
            levels[r.level] = levels.get(r.level, 0) + 1
        print(f"\n{'='*70}")
        print(f"  扫描完成 | 共 {len(self.results)} 个问题")
        print(f"  CRITICAL={levels['CRITICAL']} HIGH={levels['HIGH']} MEDIUM={levels['MEDIUM']} LOW={levels['LOW']} INFO={levels['INFO']}")
        print(f"{'='*70}\n")

    # ================================================================
    # 模块 1: 基础信息收集
    # ================================================================
    def _mod_info_gathering(self):
        try:
            ips = list(set([i[4][0] for i in socket.getaddrinfo(self.hostname, 80)]))
            self.add(self.LEVEL_INFO, "dns_resolve", f"DNS: {', '.join(ips[:5])}")
        except:
            pass

        if self._resp:
            self.add(self.LEVEL_INFO, "http_basics",
                     f"HTTP {self._resp.status_code}, {len(self._resp.text)}B, {self._resp.url}")
            if self._resp.history:
                chain = " -> ".join([f"{r.status_code}:{r.url}" for r in self._resp.history])
                self.add(self.LEVEL_INFO, "http_redirect", f"重定向: {chain}")

            server = self._resp.headers.get("Server", "")
            powered = self._resp.headers.get("X-Powered-By", "")
            aspnet = self._resp.headers.get("X-AspNet-Version", "")
            if server and re.search(r'\d+\.\d+', server):
                self.add(self.LEVEL_LOW, "server_version_disclosure", f"Server 泄露版本: {server}",
                         fix_suggestion="ServerTokens Prod")
            if powered:
                self.add(self.LEVEL_LOW, "server_version_disclosure", f"X-Powered-By: {powered}",
                         fix_suggestion="关闭 X-Powered-By")
            if aspnet:
                self.add(self.LEVEL_LOW, "server_version_disclosure", f"X-AspNet-Version: {aspnet}")

    # ================================================================
    # 模块 2: SSL/TLS
    # ================================================================
    def _mod_ssl_tls(self):
        try:
            ctx = ssl.create_default_context()
            with ctx.wrap_socket(socket.socket(), server_hostname=self.hostname) as s:
                s.settimeout(10)
                s.connect((self.hostname, 443))
                cert = s.getpeercert()
            if cert:
                not_after = cert.get("notAfter", "")
                subject = dict(x[0] for x in cert.get("subject", []))
                issuer = dict(x[0] for x in cert.get("issuer", []))
                san = [x[1] for x in cert.get("subjectAltName", [])]
                self.add(self.LEVEL_INFO, "ssl_cert", f"证书至: {not_after}")
                self.add(self.LEVEL_INFO, "ssl_cert", f"颁发者: {issuer.get('organizationName', 'N/A')}")
                self.add(self.LEVEL_INFO, "ssl_cert", f"CN: {subject.get('commonName', 'N/A')}")
                if san:
                    self.add(self.LEVEL_INFO, "ssl_cert", f"SAN: {', '.join(san[:6])}")
                expire = datetime.datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
                remaining = (expire - datetime.datetime.utcnow()).days
                if remaining < 0:
                    self.add(self.LEVEL_HIGH, "ssl_cert_expired", f"证书已过期 {abs(remaining)} 天",
                             fix_suggestion="立即续期 SSL 证书")
                elif remaining < 30:
                    self.add(self.LEVEL_MEDIUM, "ssl_cert_expiring", f"证书 {remaining} 天后过期",
                             fix_suggestion="尽快续期")
        except Exception as e:
            self.add(self.LEVEL_LOW, "ssl_cert", f"SSL 异常: {str(e)[:80]}")

    # ================================================================
    # 模块 3: 安全响应头
    # ================================================================
    def _mod_security_headers(self):
        if not self._resp:
            return
        headers = self._resp.headers
        security_headers = [
            ("Strict-Transport-Security", "HSTS缺失", "add_header Strict-Transport-Security \"max-age=31536000; includeSubDomains; preload\";", self.LEVEL_MEDIUM),
            ("X-Frame-Options", "Clickjacking风险", "add_header X-Frame-Options \"DENY\";", self.LEVEL_MEDIUM),
            ("Content-Security-Policy", "CSP缺失", "add_header Content-Security-Policy \"default-src 'self'\";", self.LEVEL_MEDIUM),
            ("X-Content-Type-Options", "MIME嗅探风险", "add_header X-Content-Type-Options \"nosniff\";", self.LEVEL_LOW),
            ("Referrer-Policy", "Referrer泄露", "add_header Referrer-Policy \"strict-origin-when-cross-origin\";", self.LEVEL_LOW),
            ("Permissions-Policy", "权限未限制", "add_header Permissions-Policy \"geolocation=(), microphone=(), camera=()\";", self.LEVEL_LOW),
            ("Cross-Origin-Resource-Policy", "资源可跨域加载", "add_header Cross-Origin-Resource-Policy \"same-origin\";", self.LEVEL_LOW),
            ("Cross-Origin-Opener-Policy", "跨域opener未限制", "add_header Cross-Origin-Opener-Policy \"same-origin\";", self.LEVEL_LOW),
            ("Cross-Origin-Embedder-Policy", "跨域资源未限制", "add_header Cross-Origin-Embedder-Policy \"require-corp\";", self.LEVEL_LOW),
            ("X-XSS-Protection", "旧版XSS过滤未启用", "add_header X-XSS-Protection \"1; mode=block\";", self.LEVEL_LOW),
        ]
        missing = 0
        for hdr, desc, fix, level in security_headers:
            if hdr not in headers:
                self.add(level, "security_headers", f"缺失响应头: {hdr} — {desc}",
                         reproduction_steps=f"curl -I {self.base_url} | grep -i '{hdr}'  # 无返回",
                         fix_suggestion=f"Nginx: {fix}",
                         screenshot_url=self.base_url)
                missing += 1
            else:
                self.add(self.LEVEL_INFO, "security_headers", f"安全头正常: {hdr} = {headers[hdr][:60]}")

        if missing >= 8:
            self.add(self.LEVEL_MEDIUM, "no_security_headers",
                     f"严重缺失 {missing} 个安全响应头", fix_suggestion="参考 OWASP Secure Headers Project 一次性配置")

        # CORS
        acao = headers.get("Access-Control-Allow-Origin", "")
        acac = headers.get("Access-Control-Allow-Credentials", "")
        if acao == "*" and acac.lower() == "true":
            self.add(self.LEVEL_HIGH, "cors_dangerous",
                     "CORS 危险: Allow-Origin=* 且 Allow-Credentials=true",
                     description="任何网站可携带凭证发起跨域请求",
                     fix_suggestion="将 Access-Control-Allow-Origin 设为具体白名单域名")

    # ================================================================
    # 模块 4: Cookie 与会话安全
    # ================================================================
    def _mod_cookie_session(self):
        if not self._resp:
            return
        cookies_raw = self._resp.headers.get("Set-Cookie", "")
        if not cookies_raw:
            return
        cookies = cookies_raw.split("\n") if isinstance(cookies_raw, str) else [cookies_raw]
        for cookie in cookies:
            cookie = cookie.strip()
            if not cookie or "=" not in cookie:
                continue
            name = cookie.split("=")[0]
            cl = cookie.lower()
            issues = []
            if "secure" not in cl:
                issues.append("Secure")
            if "httponly" not in cl:
                issues.append("HttpOnly")
            if "samesite" not in cl:
                issues.append("SameSite")
            if len(issues) >= 3:
                self.add(self.LEVEL_HIGH, "cookie_insecure",
                         f"Cookie [{name}] 严重不安全: 缺少 {', '.join(issues)}",
                         fix_suggestion="Set-Cookie: ...; Secure; HttpOnly; SameSite=Strict")
            elif len(issues) >= 2:
                self.add(self.LEVEL_MEDIUM, "cookie_insecure",
                         f"Cookie [{name}] 不安全: 缺少 {', '.join(issues)}",
                         fix_suggestion=f"添加: {', '.join(issues)}")
            elif len(issues) == 1:
                self.add(self.LEVEL_LOW, "cookie_insecure", f"Cookie [{name}] 缺少 {issues[0]}",
                         fix_suggestion=f"添加 {issues[0]} 标志")

    # ================================================================
    # 模块 5: 敏感信息泄露
    # ================================================================
    def _mod_info_leak(self):
        if not self._resp:
            return
        text = self._resp.text

        # .git
        try:
            r = self.session.get(urljoin(self.base_url, "/.git/HEAD"), timeout=5, allow_redirects=False)
            if r.status_code == 200 and "ref:" in r.text:
                self.add(self.LEVEL_HIGH, "source_leak_git", ".git 目录暴露！",
                         reproduction_steps=f"curl {urljoin(self.base_url, '/.git/HEAD')}",
                         fix_suggestion="location ~ /\\.git { deny all; return 404; }",
                         affected_url=urljoin(self.base_url, "/.git/HEAD"))
        except:
            pass

        # .env
        try:
            r = self.session.get(urljoin(self.base_url, "/.env"), timeout=5, allow_redirects=False)
            if r.status_code == 200 and ("APP_KEY" in r.text or "DB_" in r.text or "MAIL_" in r.text):
                self.add(self.LEVEL_HIGH, "source_leak_env", ".env 文件暴露！",
                         reproduction_steps=f"curl {urljoin(self.base_url, '/.env')}",
                         fix_suggestion="location ~ /\\.env { deny all; return 404; }",
                         affected_url=urljoin(self.base_url, "/.env"))
        except:
            pass

        # 备份文件
        for path in ["/www.zip", "/www.tar.gz", "/backup.zip"]:
            try:
                r = self.session.get(urljoin(self.base_url, path), timeout=5, allow_redirects=False)
                if r.status_code == 200:
                    self.add(self.LEVEL_HIGH, "backup_leak", f"备份文件暴露: {path}",
                             reproduction_steps=f"curl {urljoin(self.base_url, path)}",
                             fix_suggestion="删除公开可访问的备份文件",
                             affected_url=urljoin(self.base_url, path))
            except:
                pass

        # 错误信息
        for pat, desc, lvl in [
            (r'<b>Warning</b>:', "PHP Warning", self.LEVEL_MEDIUM),
            (r'<b>Fatal error</b>:', "PHP Fatal Error", self.LEVEL_MEDIUM),
            (r'SQLSTATE\[', "SQL 错误", self.LEVEL_MEDIUM),
            (r'Traceback \(most recent call last\):', "Python Traceback", self.LEVEL_MEDIUM),
        ]:
            if re.search(pat, text, re.I):
                self.add(lvl, "error_info_leak", desc, fix_suggestion="关闭 display_errors，设置自定义错误页面")

        # 内网 IP
        ips = re.findall(r'\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})\b', text)
        if ips:
            self.add(self.LEVEL_MEDIUM, "internal_ip_leak",
                     f"前端泄露内网 IP: {', '.join(list(set(ips))[:5])}",
                     fix_suggestion="避免在 HTML/JS 中硬编码内网 IP")

        # 邮箱
        emails = re.findall(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}', text)
        if emails:
            company_emails = [e for e in emails if self.hostname.split(".")[-2] in e]
            if company_emails:
                self.add(self.LEVEL_LOW, "email_disclosure",
                         f"页面暴露 {len(company_emails)} 个企业邮箱: {', '.join(list(set(company_emails))[:5])}",
                         fix_suggestion="使用联系表单代替直接暴露邮箱")

        # SQL 查询暴露
        self._check_sql_exposure()

    def _check_sql_exposure(self):
        try:
            search_url = urljoin(self.base_url, "/search/")
            r = self.session.get(search_url, params={"q": "test123"}, timeout=10)
            if r.status_code == 200:
                sql_pat = re.search(r"(?:q|title|content|keyword)\s+like\s+'%[^']*%'", r.text, re.I)
                if sql_pat:
                    idx = r.text.find("like '%")
                    ctx = r.text[max(0, idx - 200):idx + 200] if idx > 0 else sql_pat.group(0)
                    self.add(self.LEVEL_HIGH, "sql_query_exposure",
                             "搜索功能暴露完整 SQL 查询结构，泄露数据库 Schema",
                             description=f"搜索接口响应中暴露完整 SQL 语句: {ctx[:300]}",
                             reproduction_steps=f"curl '{search_url}?q=test123' | grep like",
                             fix_suggestion="禁止在响应中返回 SQL 语句，使用参数化查询",
                             affected_url=f"{search_url}?q=test123")
        except:
            pass

    # ================================================================
    # 模块 6: 敏感路径/文件
    # ================================================================
    def _mod_sensitive_paths(self):
        paths = [
            ("/.git/HEAD", "Git仓库", "HIGH"),
            ("/.env", "环境变量", "HIGH"),
            ("/WEB-INF/web.xml", "Java配置", "HIGH"),
            ("/druid/index.html", "Druid监控", "HIGH"),
            ("/actuator/env", "Spring环境变量", "HIGH"),
            ("/phpmyadmin/", "phpMyAdmin", "HIGH"),
            ("/adminer.php", "Adminer", "HIGH"),
            ("/config.json", "配置文件", "MEDIUM"),
            ("/swagger-ui.html", "Swagger文档", "MEDIUM"),
            ("/actuator/health", "Actuator健康检查", "MEDIUM"),
            ("/server-status", "Apache状态", "MEDIUM"),
            ("/nginx_status", "Nginx状态", "MEDIUM"),
            ("/phpinfo.php", "PHP信息", "MEDIUM"),
            ("/admin/", "管理后台", "MEDIUM"),
            ("/robots.txt", "robots.txt", "INFO"),
        ]
        found = []
        for path, desc, level in paths:
            try:
                r = self.session.get(urljoin(self.base_url, path), timeout=5, allow_redirects=False)
                if r.status_code == 200:
                    lvl = getattr(self, f"LEVEL_{level}")
                    self.add(lvl, "sensitive_path", f"敏感路径可访问: {path} ({desc})",
                             description=f"{path} 可被公开访问",
                             reproduction_steps=f"curl {urljoin(self.base_url, path)}",
                             fix_suggestion=f"限制 {path} 访问权限",
                             affected_url=urljoin(self.base_url, path))
                    found.append(path)
            except:
                pass
            time.sleep(0.15)

        # 目录列表
        for d in ["/images/", "/css/", "/js/"]:
            try:
                r = self.session.get(urljoin(self.base_url, d), timeout=5, allow_redirects=False)
                if r.status_code == 200 and ("Index of" in r.text or "Parent Directory" in r.text):
                    self.add(self.LEVEL_MEDIUM, "directory_listing", f"目录列表开启: {d}",
                             fix_suggestion="Nginx: autoindex off; Apache: Options -Indexes",
                             affected_url=urljoin(self.base_url, d))
            except:
                pass

    # ================================================================
    # 模块 7: 前端安全
    # ================================================================
    def _mod_frontend_security(self):
        if not self._resp:
            return
        text = self._resp.text

        # API Key 泄露
        api_patterns = [
            (r'(?:sk-[a-zA-Z0-9]{20,})', "OpenAI API Key"),
            (r'(?:ghp_[a-zA-Z0-9]{36})', "GitHub Token"),
            (r'(?:AKIA[0-9A-Z]{16})', "AWS Access Key"),
            (r'(?:xox[baprs]-[a-zA-Z0-9-]+)', "Slack Token"),
        ]
        for pat, desc in api_patterns:
            matches = re.findall(pat, text)
            if matches:
                self.add(self.LEVEL_HIGH, "apikey_leak", f"{desc} 泄露: {len(matches)} 处",
                         fix_suggestion="将所有 API 密钥移至后端环境变量")

        # SourceMap
        if 'sourceMappingURL' in text or 'source-map' in text:
            self.add(self.LEVEL_MEDIUM, "frontend_leak", "SourceMap 暴露",
                     fix_suggestion="生产环境禁止部署 .map 文件")

        # jQuery 版本
        jquery_ver = None
        m = re.search(r'jquery[^"]*?(\d+\.\d+\.\d+)', text, re.I)
        if m:
            jquery_ver = m.group(1)
        if not jquery_ver:
            try:
                r = self.session.get(urljoin(self.base_url, "/static/libs/jquery/jquery-3.4.1.min.js"), timeout=5)
                if r.status_code == 200:
                    vm = re.search(r'jQuery v(\d+\.\d+\.\d+)', r.text[:500])
                    if vm:
                        jquery_ver = vm.group(1)
            except:
                pass
        if jquery_ver:
            parts = jquery_ver.split(".")
            if int(parts[0]) < 3 or (int(parts[0]) == 3 and int(parts[1]) < 5):
                self.add(self.LEVEL_MEDIUM, "jquery_xss",
                         f"jQuery {jquery_ver} 存在已知 XSS (CVE-2020-11023/11022)",
                         fix_suggestion="升级 jQuery >= 3.5.0")

    # ================================================================
    # 模块 8: 后端指纹
    # ================================================================
    def _mod_backend_fingerprint(self):
        if not self._resp:
            return
        text = self._resp.text.lower()
        headers_str = str(self._resp.headers).lower()

        cms_fps = {
            "WordPress": ["wp-content", "wp-includes"],
            "Drupal": ["drupal", "sites/default"],
            "Joomla": ["joomla"],
            "DedeCMS": ["dedecms"],
            "ThinkPHP": ["thinkphp", "think_template"],
            "Laravel": ["laravel", "vendor/laravel"],
            "Spring": ["spring", "actuator"],
            "Spring Boot": ["spring-boot", "springboot"],
            "Struts": ["struts", ".action", ".do"],
            "Django": ["django", "csrfmiddlewaretoken"],
            "ASP.NET": ["__viewstate", "__eventvalidation"],
            "PHP": ["phpsessid", ".php"],
            "jQuery": ["jquery"],
            "Vue.js": ["vue", "v-bind"],
            "React": ["react", "react-dom"],
            "Angular": ["angular", "ng-app"],
            "Tomcat": ["tomcat", "jsessionid"],
        }
        detected = []
        for cms, sigs in cms_fps.items():
            for sig in sigs:
                if sig in text or sig in headers_str:
                    detected.append(cms)
                    break

        if detected:
            self.add(self.LEVEL_INFO, "cms_fingerprint", f"技术栈: {', '.join(list(set(detected)))}")

        cms_vulns = {
            "ThinkPHP": "ThinkPHP 已知 RCE: CVE-2022-25481, CVE-2018-20062, CVE-2019-9082",
            "Struts": "Struts 2 系列 RCE: S2-001~S2-062",
            "Spring": "Spring4Shell (CVE-2022-22965)",
            "Spring Boot": "Actuator 信息泄露，建议关闭 /actuator 端点",
            "Laravel": ".env 泄露、Debug 模式 RCE",
            "WordPress": "XML-RPC 攻击、插件漏洞",
            "jQuery": "jQuery < 3.5.0 XSS (CVE-2020-11023/11022)",
        }
        for cms in list(set(detected)):
            if cms in cms_vulns:
                self.add(self.LEVEL_MEDIUM, "cms_vuln_hint", cms_vulns[cms],
                         fix_suggestion=f"升级 {cms} 至最新版本")

    # ================================================================
    # 模块 9: HTTP 方法
    # ================================================================
    def _mod_http_methods(self):
        dangerous = []
        for method in ["PUT", "DELETE", "PATCH", "TRACE", "CONNECT"]:
            try:
                r = self.session.request(method, self.base_url, timeout=5)
                if r.status_code not in [405, 501]:
                    dangerous.append(method)
                    if method == "TRACE" and "TRACE" in r.text:
                        self.add(self.LEVEL_MEDIUM, "trace_method", "TRACE 方法启用 (XST 风险)",
                                 fix_suggestion="禁用 TRACE 方法")
            except:
                pass
        if dangerous:
            self.add(self.LEVEL_MEDIUM, "dangerous_http_methods",
                     f"允许危险 HTTP 方法: {', '.join(dangerous)}",
                     reproduction_steps=f"curl -X PUT {self.base_url} -v",
                     fix_suggestion="仅允许 GET/POST/HEAD 方法")

        # robots.txt
        try:
            r = self.session.get(urljoin(self.base_url, "/robots.txt"), timeout=5)
            if r.status_code == 200 and "Disallow: /" in r.text:
                self.add(self.LEVEL_MEDIUM, "robots_misconfig", "robots.txt 禁止全站爬取",
                         fix_suggestion="检查 robots.txt 配置")
        except:
            pass

    # ================================================================
    # 模块 10: 第三方
    # ================================================================
    def _mod_third_party(self):
        if not self._resp:
            return
        text = self._resp.text

        third_pat = [
            (r'https?://[^\s"\']*\.s3\.amazonaws\.com', "AWS S3"),
            (r'https?://[^\s"\']*\.blob\.core\.windows\.net', "Azure Blob"),
            (r'https?://[^\s"\']*\.storage\.googleapis\.com', "GCP Storage"),
            (r'https?://[^\s"\']*\.oss-', "阿里云 OSS"),
            (r'https?://[^\s"\']*firebaseio\.com', "Firebase"),
            (r'mongodb(?:\+srv)?://[^\s"\']+', "MongoDB 连接串"),
            (r'mysql://[^\s"\']+', "MySQL 连接串"),
            (r'redis://[^\s"\']+', "Redis 连接串"),
        ]
        for pat, desc in third_pat:
            matches = re.findall(pat, text, re.I)
            if matches:
                self.add(self.LEVEL_MEDIUM, "third_party_leak", f"{desc} 地址泄露: {len(matches)} 处",
                         fix_suggestion="避免在前端暴露第三方服务地址")

        # 外部脚本
        scripts = re.findall(r'src=["\'](https?://[^"\']+)["\']', text)
        ext_domains = set()
        for s in scripts:
            try:
                d = urlparse(s).hostname
                if d and d != self.hostname:
                    ext_domains.add(d)
            except:
                pass
        if len(ext_domains) > 8:
            self.add(self.LEVEL_LOW, "third_party", f"引用 {len(ext_domains)} 个外部域名，供应链攻击面较大",
                     fix_suggestion="减少外部依赖，使用 SRI 校验")

        # HTTP 明文链接
        http_links = re.findall(r'href=["\'](http://[^"\']+)["\']', text)
        if http_links:
            self.add(self.LEVEL_LOW, "external_http_link", f"HTTP 明文链接: {http_links[0][:80]}",
                     fix_suggestion="升级为 HTTPS")

    # ================================================================
    # 输出
    # ================================================================
    def to_dict(self):
        findings = [r.to_dict() for r in self.results]
        summary = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
        for r in self.results:
            summary[r.level] = summary.get(r.level, 0) + 1
        return {
            "target": self.hostname,
            "scan_time": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "scan_type": "advanced_v3",
            "total_findings": len(self.results),
            "summary": summary,
            "findings": findings,
        }

    def save_json(self, path):
        with open(path, "w", encoding="utf-8") as f:
            json.dump(self.to_dict(), f, indent=2, ensure_ascii=False)


def main():
    target = sys.argv[1] if len(sys.argv) > 1 else "www.zmj.com"
    output_dir = sys.argv[2] if len(sys.argv) > 2 else f"/workspace/reports/{target.replace('www.', '').replace('.com', '_com')}"
    os.makedirs(output_dir, exist_ok=True)
    scanner = AdvancedScanner(target)
    scanner.run_all()
    json_path = os.path.join(output_dir, "advanced_scan.json")
    scanner.save_json(json_path)
    print(f"JSON: {json_path}")
    return scanner


if __name__ == "__main__":
    main()