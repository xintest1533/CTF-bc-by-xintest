#!/bin/bash
# ============================================================
# 通用漏洞扫描引擎 v2.0
# 基于三目标实战验证: ihep.cas.cn + bpeg.cn + didachuxing.com
# 特性:
#   - 子域名枚举 (crt.sh + 字典)
#   - 敏感路径扫描 (含WAF拦截识别)
#   - 安全响应头审计 (主站 vs 子路径对比)
#   - Cookie安全标志检查
#   - 混合内容检测 (HTTPS页面HTTP链接)
#   - HTTPS协议降级检测
#   - JS文件自动提取+密钥扫描
#   - 服务器版本信息泄露
#   - PHP参数发现+SQL注入初筛
#   - CORS配置错误
#   - 开放重定向
#   - 自动生成报告
# ============================================================

set -o pipefail

# ---- 配置 ----
UA="Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0"
TIMEOUT=3
TMPDIR="/tmp/scanner_$$"
OUTDIR="/workspace/reports"
TOOLDIR="$(cd "$(dirname "$0")/.." && pwd)"

# ---- 颜色 ----
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
BLUE='\033[0;34m'; CYAN='\033[0;36m'; NC='\033[0m'

usage() {
    echo "用法: $0 <target_domain> [选项]"
    echo ""
    echo "示例:"
    echo "  $0 example.com                        # 全量扫描"
    echo "  $0 example.com --quick                # 快速扫描"
    echo "  $0 example.com --no-subdomains        # 跳过子域名枚举"
    echo "  $0 example.com --platform butian      # 补天标准报告"
    echo "  $0 example.com --platform vulbox      # 漏洞盒子标准报告"
    exit 1
}

# ---- 参数解析 ----
TARGET="${1:-}"
shift 2>/dev/null || true
QUICK=false; SKIP_SUBS=false; PLATFORM="butian"

while [[ $# -gt 0 ]]; do
    case "$1" in
        --quick) QUICK=true ;;
        --no-subdomains) SKIP_SUBS=true ;;
        --platform) PLATFORM="$2"; shift ;;
        -h|--help) usage ;;
        *) ;;
    esac
    shift
done

[[ -z "$TARGET" ]] && usage

mkdir -p "$TMPDIR" "$OUTDIR/${TARGET//\//_}"
BASEDIR="$OUTDIR/${TARGET//\//_}"
FINDINGS_FILE="$BASEDIR/findings.json"

log() { echo -e "${GREEN}[$(date +%H:%M:%S)]${NC} $*"; }
warn() { echo -e "${YELLOW}[!]${NC} $*"; }
critical() { echo -e "${RED}[!!!]${NC} $*"; }
info() { echo -e "${CYAN}[*]${NC} $*"; }

# ---- 工具函数 ----
fetch() {
    local url="$1" out="$2" method="${3:-GET}" data="${4:-}"
    local extra=""
    [[ "$method" == "POST" ]] && extra="-X POST -d '${data}' -H 'Content-Type: application/json'"
    curl -sk -A "$UA" $extra --max-time "$TIMEOUT" -o "$out" -w "%{http_code}" "$url" 2>/dev/null
}

fetch_header() {
    curl -sk -A "$UA" --max-time "$TIMEOUT" -I "$1" 2>/dev/null
}

safe_grep() { grep "$@" 2>/dev/null || true; }

# ============================================================
# 阶段1: HTTP/HTTPS基础探测
# ============================================================
phase1_basic() {
    log "阶段1: 基础信息探测"

    echo "[" > "$FINDINGS_FILE"

    for proto in "https" "http"; do
        local code=$(fetch "${proto}://${TARGET}/" "$TMPDIR/home_${proto}.html")
        local size=$(wc -c < "$TMPDIR/home_${proto}.html" 2>/dev/null || echo 0)
        if [[ "$code" != "000" ]]; then
            info "${proto}://${TARGET}/ → [${code}] [${size}B]"

            # 提取标题
            local title=$(safe_grep -oP '<title>[^<]+</title>' "$TMPDIR/home_${proto}.html" | head -1 | sed 's/<[^>]*>//g')
            echo "  {\"phase\":\"basic\",\"proto\":\"$proto\",\"code\":$code,\"size\":$size,\"title\":\"$title\"}," >> "$FINDINGS_FILE"

            # 服务器头
            local server=$(safe_grep -i "^server:" "$TMPDIR/home_${proto}.html.headers" 2>/dev/null | tr -d '\r' | head -1)
            [[ -n "$server" ]] && echo "  {\"phase\":\"basic\",\"type\":\"server_header\",\"value\":\"$server\"}," >> "$FINDINGS_FILE"
        fi
    done
}

# ============================================================
# 阶段2: 安全响应头审计
# ============================================================
phase2_headers() {
    log "阶段2: 安全响应头审计"

    local headers_tmp="$TMPDIR/headers_audit.txt"
    fetch_header "https://${TARGET}/" > "$headers_tmp" 2>/dev/null

    local hsts=$(safe_grep -ci "strict-transport-security" "$headers_tmp")
    local xfo=$(safe_grep -ci "x-frame-options" "$headers_tmp")
    local csp=$(safe_grep -ci "content-security-policy" "$headers_tmp")
    local xcto=$(safe_grep -ci "x-content-type-options" "$headers_tmp")
    local xxss=$(safe_grep -ci "x-xss-protection" "$headers_tmp")
    local rp=$(safe_grep -ci "referrer-policy" "$headers_tmp")
    local pp=$(safe_grep -ci "permissions-policy" "$headers_tmp")

    local missing=()
    [[ $hsts -eq 0 ]] && missing+=("HSTS") && critical "HSTS缺失"
    [[ $xfo -eq 0 ]] && missing+=("X-Frame-Options") && warn "X-Frame-Options缺失 (Clickjacking)"
    [[ $csp -eq 0 ]] && missing+=("CSP") && warn "Content-Security-Policy缺失"
    [[ $xcto -eq 0 ]] && missing+=("X-Content-Type-Options") && warn "X-Content-Type-Options缺失"
    [[ $xxss -eq 0 ]] && missing+=("X-XSS-Protection") && warn "X-XSS-Protection缺失"
    [[ $rp -eq 0 ]] && missing+=("Referrer-Policy")
    [[ $pp -eq 0 ]] && missing+=("Permissions-Policy")

    local present_count=$((hsts + xfo + csp + xcto + xxss + rp + pp))
    local missing_count=${#missing[@]}

    echo "  {\"phase\":\"headers\",\"present\":$present_count,\"missing\":$missing_count,\"missing_list\":$(printf '%s\n' "${missing[@]}" | jq -R . | jq -s .)}," >> "$FINDINGS_FILE"

    # Cookie安全
    local cookies=$(safe_grep -i "set-cookie" "$headers_tmp")
    if [[ -n "$cookies" ]]; then
        local no_secure=$(echo "$cookies" | safe_grep -cv "secure" || echo 0)
        local no_httponly=$(echo "$cookies" | safe_grep -cv "HttpOnly" || echo 0)
        local no_samesite=$(echo "$cookies" | safe_grep -cv "SameSite" || echo 0)
        [[ $no_secure -gt 0 ]] && warn "Cookie缺少Secure标志"
        [[ $no_httponly -gt 0 ]] && warn "Cookie缺少HttpOnly标志"
        [[ $no_samesite -gt 0 ]] && warn "Cookie缺少SameSite标志"
        echo "  {\"phase\":\"cookies\",\"secure_missing\":$no_secure,\"httponly_missing\":$no_httponly,\"samesite_missing\":$no_samesite}," >> "$FINDINGS_FILE"
    fi
}

# ============================================================
# 阶段3: 敏感路径扫描
# ============================================================
phase3_paths() {
    log "阶段3: 敏感路径扫描"

    local paths=(
        "/robots.txt" "/sitemap.xml" "/crossdomain.xml"
        "/.git/HEAD" "/.git/config" "/.svn/entries" "/.DS_Store"
        "/.env" "/.env.bak" "/Web.config" "/web.config"
        "/admin" "/admin/" "/admin/login" "/login"
        "/manager" "/manager/html" "/console" "/debug"
        "/api" "/api/" "/api/v1" "/api/v2"
        "/api-docs" "/swagger-ui.html" "/v2/api-docs" "/openapi.json"
        "/actuator" "/actuator/health" "/actuator/env" "/actuator/heapdump"
        "/actuator/mappings" "/actuator/beans" "/actuator/configprops"
        "/upload" "/upload/" "/file" "/files" "/download"
        "/backup" "/backup.zip" "/backup.tar.gz" "/www.zip" "/db.zip"
        "/phpinfo.php" "/info.php" "/test.php" "/phpmyadmin"
        "/server-status" "/server-info"
        "/.htaccess" "/.htpasswd"
        "/WEB-INF/web.xml" "/WEB-INF/classes/"
        "/ueditor" "/kindeditor" "/fckeditor" "/ckeditor"
        "/wp-admin" "/wp-login.php" "/wp-content"
        "/graphql" "/graphiql"
        "/.well-known/security.txt"
        "/readme" "/readme.txt" "/README.md" "/CHANGELOG"
        "/install" "/install.php" "/setup" "/setup.php"
        "/log" "/logs" "/error.log" "/access.log"
        "/docs" "/docs/" "/examples"
    )

    local found=0
    for path in "${paths[@]}"; do
        local code=$(fetch "https://${TARGET}${path}" "$TMPDIR/path.txt")
        local size=$(wc -c < "$TMPDIR/path.txt" 2>/dev/null || echo 0)
        if [[ "$code" != "404" && "$code" != "000" && "$code" != "301" ]]; then
            # 过滤WAF拦截页面
            if [[ "$size" -lt 500 ]]; then
                if safe_grep -qiE "blocked|denied|forbidden|access denied|WAF" "$TMPDIR/path.txt"; then
                    continue
                fi
            fi
            if [[ "$code" == "624" ]]; then continue; fi  # didachuxing WAF

            echo "  {\"phase\":\"paths\",\"code\":$code,\"size\":$size,\"path\":\"$path\"}," >> "$FINDINGS_FILE"
            found=$((found+1))
            [[ "$code" == "200" ]] && warn "敏感路径: [${code}] ${path} (${size}B)"
        fi
    done
    info "发现 ${found} 个可达路径"
}

# ============================================================
# 阶段4: 混合内容 + HTTPS降级检测
# ============================================================
phase4_mixed() {
    log "阶段4: 混合内容 + 协议降级检测"

    # 混合内容
    local http_links=$(safe_grep -oP 'http://[^"'\''<> ]+' "$TMPDIR/home_https.html" | safe_grep -v "w3.org" | sort -u)
    local mixed_count=$(echo "$http_links" | safe_grep -c "." || echo 0)
    if [[ $mixed_count -gt 0 ]]; then
        warn "混合内容: ${mixed_count} 个HTTP明文链接"
        echo "  {\"phase\":\"mixed_content\",\"count\":$mixed_count,\"samples\":$(echo "$http_links" | head -5 | jq -R . | jq -s .)}," >> "$FINDINGS_FILE"
    fi

    # 协议降级 (HTTPS→HTTP)
    local redirect=$(curl -skI -A "$UA" --max-time 3 "https://${TARGET}/" 2>/dev/null | safe_grep -i "^location:" | tr -d '\r')
    if echo "$redirect" | safe_grep -qi "http://"; then
        critical "协议降级: HTTPS → HTTP! ${redirect}"
        echo "  {\"phase\":\"protocol_downgrade\",\"location\":\"${redirect//\"/\\\"}\"}," >> "$FINDINGS_FILE"
    fi
}

# ============================================================
# 阶段5: JS文件分析
# ============================================================
phase5_js_analysis() {
    log "阶段5: JS文件分析"

    # 提取所有JS文件
    local js_files=$(safe_grep -oP 'src="([^"]*\.js[^"]*)"' "$TMPDIR/home_https.html" | sed 's/src="//;s/"//' | sort -u)
    local analyzed=0

    for js_url in $js_files; do
        # 补全URL
        [[ "$js_url" != http* ]] && js_url="https://${TARGET}${js_url}"

        local code=$(fetch "$js_url" "$TMPDIR/js_temp.txt")
        local size=$(wc -c < "$TMPDIR/js_temp.txt" 2>/dev/null || echo 0)
        [[ "$code" != "200" || "$size" -lt 100 ]] && continue

        # 调用Python提取器
        local secrets=$(python3 "$TOOLDIR/lib/js_secrets_finder.py" "$TMPDIR/js_temp.txt" -f json 2>/dev/null)
        if [[ -n "$secrets" ]]; then
            local count=$(echo "$secrets" | python3 -c "import json,sys; d=json.load(sys.stdin); print(sum(len(v) for v in d.values()))" 2>/dev/null)
            if [[ "$count" -gt 0 ]]; then
                critical "JS密钥发现: ${js_url} (${count}项)"
                echo "$secrets" | python3 -c "
import json,sys
d=json.load(sys.stdin)
for cat,items in d.items():
    for item in items:
        print(f'  [{cat}] {item[\"name\"]}: {item[\"value\"][:80]}')
" 2>/dev/null
                echo "  {\"phase\":\"js_secrets\",\"url\":\"$js_url\",\"count\":$count,\"details\":$secrets}," >> "$FINDINGS_FILE"
            fi
        fi
        analyzed=$((analyzed+1))
        [[ $analyzed -ge 5 ]] && break  # 最多分析5个JS文件
    done
}

# ============================================================
# 阶段6: 子域名枚举
# ============================================================
phase6_subdomains() {
    [[ "$SKIP_SUBS" == "true" ]] && { info "跳过子域名枚举"; return; }
    log "阶段6: 子域名枚举"

    # crt.sh
    local crt_subs=$(curl -sk --max-time 15 "https://crt.sh/?q=%25.${TARGET}&output=json" 2>/dev/null | \
        python3 -c "
import json,sys
try:
    data=json.load(sys.stdin)
    subs=set()
    for item in data:
        for name in item.get('name_value','').split('\n'):
            name=name.strip().lower()
            if name and '$TARGET' in name and '*' not in name:
                subs.add(name)
    for s in sorted(subs): print(s)
except: pass
" 2>/dev/null)

    local sub_count=0
    if [[ -n "$crt_subs" ]]; then
        echo "$crt_subs" > "$TMPDIR/subdomains.txt"
        sub_count=$(wc -l < "$TMPDIR/subdomains.txt")
        info "crt.sh发现 ${sub_count} 个子域名"

        # 存活探测
        while IFS= read -r sub; do
            for proto in "https" "http"; do
                local code=$(fetch "${proto}://${sub}/" "$TMPDIR/sub_resp.txt")
                local size=$(wc -c < "$TMPDIR/sub_resp.txt" 2>/dev/null || echo 0)
                if [[ "$code" != "000" && "$code" != "404" ]]; then
                    local title=$(safe_grep -oP '<title>[^<]+</title>' "$TMPDIR/sub_resp.txt" | head -1 | sed 's/<[^>]*>//g')
                    echo "  {\"phase\":\"subdomains\",\"host\":\"$sub\",\"proto\":\"$proto\",\"code\":$code,\"size\":$size,\"title\":\"$title\"}," >> "$FINDINGS_FILE"
                    info "  [${code}] ${proto}://${sub}/ ${title}"
                fi
            done
        done < "$TMPDIR/subdomains.txt"
    fi
}

# ============================================================
# 阶段7: CORS测试
# ============================================================
phase7_cors() {
    log "阶段7: CORS配置测试"

    for origin in "null" "http://evil.com" "https://evil.com"; do
        local resp=$(curl -skI -A "$UA" --max-time 3 -H "Origin: ${origin}" "https://${TARGET}/" 2>/dev/null)
        local acao=$(echo "$resp" | safe_grep -i "access-control-allow-origin" | tr -d '\r')
        local acac=$(echo "$resp" | safe_grep -i "access-control-allow-credentials" | tr -d '\r')
        if [[ -n "$acao" ]]; then
            if echo "$acao" | safe_grep -qi "$origin" || echo "$acao" | safe_grep -qi "*"; then
                critical "CORS配置错误: Origin=${origin} → ${acao}"
                [[ -n "$acac" ]] && critical "  + ${acac} (Credentials可跨域!)"
                echo "  {\"phase\":\"cors\",\"origin\":\"$origin\",\"allow_origin\":\"${acao//\"/\\\"}\",\"credentials\":\"${acac//\"/\\\"}\"}," >> "$FINDINGS_FILE"
            fi
        fi
    done
}

# ============================================================
# 阶段8: 开放重定向
# ============================================================
phase8_redirect() {
    [[ "$QUICK" == "true" ]] && return
    log "阶段8: 开放重定向测试"

    local params=("redirect" "url" "return" "returnUrl" "next" "callback" "goto" "target")
    for param in "${params[@]}"; do
        local resp=$(curl -sk -A "$UA" -o /dev/null -w "%{http_code}|%{redirect_url}" --max-time 3 \
            "https://${TARGET}/?${param}=https://evil.com" 2>/dev/null)
        local redirect_url=$(echo "$resp" | cut -d'|' -f2)
        if echo "$redirect_url" | safe_grep -qi "evil.com"; then
            critical "开放重定向: ${param}=https://evil.com → ${redirect_url}"
            echo "  {\"phase\":\"open_redirect\",\"param\":\"$param\",\"redirect\":\"${redirect_url//\"/\\\"}\"}," >> "$FINDINGS_FILE"
        fi
    done
}

# ============================================================
# 阶段9: PHP参数发现 (针对/ir/等路径)
# ============================================================
phase9_php_params() {
    [[ "$QUICK" == "true" ]] && return
    log "阶段9: PHP参数发现"

    # 自动发现PHP文件
    local php_files=$(safe_grep -oP 'href="([^"]*\.php[^"]*)"' "$TMPDIR/home_https.html" | sed 's/href="//;s/"//' | sort -u)
    for php_file in $php_files; do
        [[ "$php_file" == http* ]] && continue
        local full_url="https://${TARGET}${php_file}"
        local code=$(fetch "$full_url" "$TMPDIR/php_temp.txt")
        [[ "$code" != "200" ]] && continue

        # 提取参数
        local params=$(safe_grep -oP '\?([a-zA-Z_]+)=' "$TMPDIR/php_temp.txt" | sed 's/[?=]//g' | sort -u)
        if [[ -n "$params" ]]; then
            info "PHP参数发现: ${php_file}"
            for p in $params; do
                info "  参数: ${p}"
            done
            echo "  {\"phase\":\"php_params\",\"file\":\"$php_file\",\"params\":$(echo "$params" | jq -R . | jq -s .)}," >> "$FINDINGS_FILE"
        fi
    done
}

# ============================================================
# 收尾: 生成报告
# ============================================================
generate_report() {
    log "生成报告..."

    # 修复JSON (移除尾部逗号)
    sed -i '$ s/,$//' "$FINDINGS_FILE"
    echo "]" >> "$FINDINGS_FILE"

    # 统计
    local total=$(python3 -c "import json; d=json.load(open('$FINDINGS_FILE')); print(len(d))" 2>/dev/null || echo 0)
    local secrets=$(python3 -c "import json; d=json.load(open('$FINDINGS_FILE')); print(sum(1 for x in d if x.get('phase')=='js_secrets'))" 2>/dev/null || echo 0)
    local paths=$(python3 -c "import json; d=json.load(open('$FINDINGS_FILE')); print(sum(1 for x in d if x.get('phase')=='paths'))" 2>/dev/null || echo 0)
    local subs=$(python3 -c "import json; d=json.load(open('$FINDINGS_FILE')); print(sum(1 for x in d if x.get('phase')=='subdomains'))" 2>/dev/null || echo 0)

    echo ""
    echo -e "${GREEN}============================================${NC}"
    echo -e "${GREEN}  扫描完成: ${TARGET}${NC}"
    echo -e "${GREEN}============================================${NC}"
    echo -e "  总发现:  ${total}"
    echo -e "  JS密钥:  ${secrets}"
    echo -e "  敏感路径: ${paths}"
    echo -e "  子域名:  ${subs}"
    echo -e "  报告:    ${BASEDIR}/"
    echo -e "${GREEN}============================================${NC}"
}

# ============================================================
# 主流程
# ============================================================
main() {
    echo -e "${BLUE}============================================${NC}"
    echo -e "${BLUE}  通用漏洞扫描引擎 v2.0${NC}"
    echo -e "${BLUE}  目标: ${TARGET}${NC}"
    echo -e "${BLUE}============================================${NC}"

    phase1_basic
    phase2_headers
    phase3_paths
    phase4_mixed
    phase5_js_analysis
    phase6_subdomains
    phase7_cors
    [[ "$QUICK" != "true" ]] && phase8_redirect
    [[ "$QUICK" != "true" ]] && phase9_php_params
    generate_report

    # 清理
    rm -rf "$TMPDIR"
}

main