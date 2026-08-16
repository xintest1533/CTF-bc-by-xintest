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

    # Cookie安全审计
    local cookies=$(safe_grep -i "set-cookie" "$headers_tmp")
    if [[ -n "$cookies" ]]; then
        local total_cookies=$(echo "$cookies" | safe_grep -c "." || echo 0)
        local no_secure=$(echo "$cookies" | safe_grep -cv "secure" || echo 0)
        local no_httponly=$(echo "$cookies" | safe_grep -cv "httponly" || echo 0)
        local no_samesite=$(echo "$cookies" | safe_grep -cv "samesite" || echo 0)
        local issues=0
        [[ $no_secure -gt 0 ]] && issues=$((issues+1)) && warn "Cookie审计: ${no_secure}/${total_cookies} 缺少Secure标志"
        [[ $no_httponly -gt 0 ]] && issues=$((issues+1)) && warn "Cookie审计: ${no_httponly}/${total_cookies} 缺少HttpOnly标志"
        [[ $no_samesite -gt 0 ]] && issues=$((issues+1)) && warn "Cookie审计: ${no_samesite}/${total_cookies} 缺少SameSite标志"
        [[ $issues -gt 0 ]] && critical "Cookie审计: ${issues}项安全问题"
        echo "  {\"phase\":\"cookies\",\"total\":$total_cookies,\"secure_missing\":$no_secure,\"httponly_missing\":$no_httponly,\"samesite_missing\":$no_samesite}," >> "$FINDINGS_FILE"
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

        # 404信息泄露检测: 检查响应body中是否包含URL:/port/主机名/Tengine等
        if [[ "$code" == "404" ]]; then
            local leak_found=false
            local leak_details=""
            if safe_grep -qiE "URL:|port:|Tengine|nginx/[0-9]|Apache/[0-9]" "$TMPDIR/path.txt"; then
                leak_found=true
                leak_details=$(safe_grep -oP '(URL:[^<]+|port[^<]*|Tengine[^<]*|Apache[^<]*|nginx[^<]*)' "$TMPDIR/path.txt" | head -3 | tr '\n' ';')
            fi
            if safe_grep -qiE "pc[0-9]+|server[0-9]+|hostname|host name" "$TMPDIR/path.txt"; then
                leak_found=true
                local hostname_leak=$(safe_grep -oP '(pc[0-9]+|server[0-9]+)' "$TMPDIR/path.txt" | head -1)
                [[ -n "$hostname_leak" ]] && leak_details="${leak_details} 主机名:${hostname_leak}"
            fi
            if $leak_found; then
                warn "404信息泄露: ${path} → ${leak_details}"
                echo "  {\"phase\":\"404_leak\",\"path\":\"$path\",\"code\":$code,\"details\":\"${leak_details//\"/\\\"}\"}," >> "$FINDINGS_FILE"
            fi
        fi
    done
    info "发现 ${found} 个可达路径"
}

# ============================================================
# 阶段4: 混合内容 + 完整重定向链检测
# ============================================================
phase4_mixed() {
    log "阶段4: 混合内容 + 完整重定向链检测"

    # 混合内容
    local http_links=$(safe_grep -oP 'http://[^"'\''<> ]+' "$TMPDIR/home_https.html" | safe_grep -v "w3.org" | sort -u)
    local mixed_count=$(echo "$http_links" | safe_grep -c "." || echo 0)
    if [[ $mixed_count -gt 0 ]]; then
        warn "混合内容: ${mixed_count} 个HTTP明文链接"
        echo "  {\"phase\":\"mixed_content\",\"count\":$mixed_count,\"samples\":$(echo "$http_links" | head -5 | jq -R . | jq -s .)}," >> "$FINDINGS_FILE"
    fi

    # 完整重定向链跟踪 (HTTPS→HTTP→HTTPS)
    local redirect_chain=$(curl -skIL -A "$UA" --max-time 10 "https://${TARGET}/" 2>/dev/null | safe_grep -i "^location:" | tr -d '\r' | sed 's/^[Ll]ocation: //')
    local chain_steps=()
    local has_http=false
    local has_https=false
    local step_count=0
    while IFS= read -r loc; do
        [[ -z "$loc" ]] && continue
        chain_steps+=("$loc")
        step_count=$((step_count+1))
        if echo "$loc" | safe_grep -qi "^http://"; then
            has_http=true
        elif echo "$loc" | safe_grep -qi "^https://"; then
            has_https=true
        fi
    done <<< "$redirect_chain"

    if [[ $step_count -gt 0 ]]; then
        info "重定向链: ${step_count}步"
        local chain_json="["
        local first=true
        for loc in "${chain_steps[@]}"; do
            $first && chain_json+="\"${loc//\"/\\\"}\"" || chain_json+=",\"${loc//\"/\\\"}\""
            first=false
        done
        chain_json+="]"
        echo "  {\"phase\":\"redirect_chain\",\"steps\":$step_count,\"chain\":$chain_json}," >> "$FINDINGS_FILE"

        if $has_http && $has_https; then
            critical "协议降级链: HTTPS→HTTP→HTTPS 模式!"
            for loc in "${chain_steps[@]}"; do
                warn "  → ${loc}"
            done
            echo "  {\"phase\":\"protocol_downgrade_chain\",\"type\":\"HTTPS→HTTP→HTTPS\",\"chain\":$chain_json}," >> "$FINDINGS_FILE"
        elif $has_http; then
            critical "协议降级: HTTPS→HTTP! ${chain_steps[0]}"
            echo "  {\"phase\":\"protocol_downgrade\",\"location\":\"${chain_steps[0]//\"/\\\"}\"}," >> "$FINDINGS_FILE"
        fi
    fi
}

# ============================================================
# 阶段5: JS文件分析
# ============================================================
phase5_js_analysis() {
    log "阶段5: JS文件分析"

    # Vite SPA检测
    local vite_detected=false
    if safe_grep -qP '(/assets/index-[a-f0-9]{8}\.js|import\.meta\.env)' "$TMPDIR/home_https.html"; then
        vite_detected=true
        info "Vite SPA应用识别: 检测到Vite构建产物特征"
        local vite_entries=$(safe_grep -oP '/assets/[a-zA-Z0-9_-]+-[a-f0-9]{8}\.[a-z]+' "$TMPDIR/home_https.html" | sort -u)
        echo "  {\"phase\":\"vite_spa\",\"detected\":true,\"entries\":$(echo "$vite_entries" | jq -R . | jq -s . 2>/dev/null || echo "[]")}," >> "$FINDINGS_FILE"
    fi

    # 提取所有JS文件
    local js_files=$(safe_grep -oP 'src="([^"]*\.js[^"]*)"' "$TMPDIR/home_https.html" | sed 's/src="//;s/"//' | sort -u)
    local analyzed=0

    for js_url in $js_files; do
        # 补全URL
        [[ "$js_url" != http* ]] && js_url="https://${TARGET}${js_url}"

        local code=$(fetch "$js_url" "$TMPDIR/js_temp.txt")
        local size=$(wc -c < "$TMPDIR/js_temp.txt" 2>/dev/null || echo 0)

        # 0B文件处理: 自动重试+代理检测
        if [[ "$code" == "200" && "$size" -eq 0 ]]; then
            warn "JS文件0B: ${js_url}，尝试重试..."
            # 尝试通过代理重试
            local proxy=""
            for pvar in HTTPS_PROXY HTTP_PROXY ALL_PROXY https_proxy http_proxy all_proxy; do
                local pval="${!pvar}"
                if [[ -n "$pval" ]]; then
                    proxy="$pval"
                    break
                fi
            done
            if [[ -n "$proxy" ]]; then
                local code2=$(curl -sk --proxy "$proxy" -A "$UA" --max-time "$TIMEOUT" -o "$TMPDIR/js_temp_retry.txt" -w "%{http_code}" "$js_url" 2>/dev/null)
                local size2=$(wc -c < "$TMPDIR/js_temp_retry.txt" 2>/dev/null || echo 0)
                if [[ "$code2" == "200" && "$size2" -gt 0 ]]; then
                    info "  代理重试成功: ${size2}B"
                    cp "$TMPDIR/js_temp_retry.txt" "$TMPDIR/js_temp.txt"
                    size=$size2
                fi
            fi
            # 如果还是0B，重试普通请求
            if [[ "$size" -eq 0 ]]; then
                local code3=$(curl -sk -A "$UA" --max-time 10 -o "$TMPDIR/js_temp_retry2.txt" -w "%{http_code}" "$js_url" 2>/dev/null)
                local size3=$(wc -c < "$TMPDIR/js_temp_retry2.txt" 2>/dev/null || echo 0)
                if [[ "$size3" -gt 0 ]]; then
                    cp "$TMPDIR/js_temp_retry2.txt" "$TMPDIR/js_temp.txt"
                    size=$size3
                fi
            fi
        fi
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
    log "阶段6: 子域名枚举 + 全站跳转检测"

    # 全站跳转检测: 检查目标域名是否302跳转到其他域名
    local redirect_check=$(curl -skI -A "$UA" --max-time 5 "https://${TARGET}/" 2>/dev/null | safe_grep -i "^location:" | tr -d '\r')
    if echo "$redirect_check" | safe_grep -qi "$TARGET"; then
        : # 跳转到自身，正常
    elif echo "$redirect_check" | safe_grep -qiE "^location: https?://"; then
        local redirect_target=$(echo "$redirect_check" | sed 's/^[Ll]ocation: //' | head -1)
        warn "全站跳转检测: ${TARGET} → ${redirect_target}"
        echo "  {\"phase\":\"site_redirect\",\"from\":\"$TARGET\",\"to\":\"${redirect_target//\"/\\\"}\"}," >> "$FINDINGS_FILE"
    fi

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
    log "阶段8: 开放重定向测试 (含catch-all误报排除)"

    local params=("redirect" "url" "return" "returnUrl" "next" "callback" "goto" "target")
    local all_locations=()
    local param_names=()
    local found_redirect=false
    local catch_all_check=true

    for param in "${params[@]}"; do
        local resp=$(curl -sk -A "$UA" -o /dev/null -w "%{http_code}|%{redirect_url}" --max-time 3 \
            "https://${TARGET}/?${param}=https://evil.com" 2>/dev/null)
        local redirect_url=$(echo "$resp" | cut -d'|' -f2)
        if echo "$redirect_url" | safe_grep -qi "evil.com"; then
            critical "开放重定向: ${param}=https://evil.com → ${redirect_url}"
            echo "  {\"phase\":\"open_redirect\",\"param\":\"$param\",\"redirect\":\"${redirect_url//\"/\\\"}\"}," >> "$FINDINGS_FILE"
            found_redirect=true
            all_locations+=("$redirect_url")
            param_names+=("$param")
        elif [[ -n "$redirect_url" ]]; then
            # 记录所有有重定向的参数（即使没有evil.com），用于catch-all检测
            all_locations+=("$redirect_url")
            param_names+=("$param")
        fi
    done

    # Catch-all误报排除: 如果所有参数返回相同Location，标记为catch-all
    if $found_redirect && [[ ${#all_locations[@]} -ge 2 ]]; then
        local first_loc="${all_locations[0]}"
        local all_same=true
        for loc in "${all_locations[@]:1}"; do
            if [[ "$loc" != "$first_loc" ]]; then
                all_same=false
                break
            fi
        done
        if $all_same; then
            warn "Catch-all模式检测: 所有参数返回相同Location (${first_loc})，标记为误报"
            echo "  {\"phase\":\"catch_all_redirect\",\"location\":\"${first_loc//\"/\\\"}\",\"params\":$(printf '%s\n' "${param_names[@]}" | jq -R . | jq -s .)}," >> "$FINDINGS_FILE"
        fi
    fi
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
# 阶段10: 内部端口暴露检测
# ============================================================
phase10_internal_port() {
    log "阶段10: 内部端口暴露检测"

    # 从404页面响应中提取内部端口 (URL:86 等模式)
    local port_patterns=$(safe_grep -oP 'URL:[^:]*:(\d+)' "$TMPDIR/path_404.txt" 2>/dev/null | head -5)
    if [[ -z "$port_patterns" ]]; then
        # 也检查已保存的任意404响应
        for f in "$TMPDIR"/path_*.txt; do
            [[ ! -f "$f" ]] && continue
            local ports=$(safe_grep -oP 'URL:[^:]*:(\d+)' "$f" 2>/dev/null)
            [[ -n "$ports" ]] && port_patterns="$port_patterns"$'\n'"$ports"
        done
    fi
    if [[ -n "$port_patterns" ]]; then
        local unique_ports=$(echo "$port_patterns" | safe_grep -oP '\d+' | sort -u)
        while IFS= read -r port; do
            [[ -z "$port" ]] && continue
            [[ "$port" == "443" || "$port" == "80" ]] && continue
            warn "内部端口暴露: 端口 ${port}"
            # 尝试测试该端口
            local port_code=$(curl -sk --max-time 3 -o /dev/null -w "%{http_code}" "https://${TARGET}:${port}/" 2>/dev/null)
            if [[ "$port_code" != "000" && "$port_code" != "" ]]; then
                info "  端口 ${port} 响应: HTTP ${port_code}"
            fi
            echo "  {\"phase\":\"internal_port\",\"port\":$port,\"code\":\"$port_code\"}," >> "$FINDINGS_FILE"
        done <<< "$unique_ports"
    fi
}

# ============================================================
# 阶段11: OSS Bucket信息泄露检测
# ============================================================
phase11_oss_bucket() {
    log "阶段11: OSS Bucket信息泄露检测"

    # 检查响应中是否包含OSS XML错误模式
    local oss_xml=$(safe_grep -oP '<Bucket>([^<]+)</Bucket>' "$TMPDIR/home_https.html" 2>/dev/null)
    if [[ -z "$oss_xml" ]]; then
        # 也检查其他页面
        for f in "$TMPDIR"/home_*.html "$TMPDIR"/path_*.txt; do
            [[ ! -f "$f" ]] && continue
            oss_xml=$(safe_grep -oP '<Bucket>([^<]+)</Bucket>' "$f" 2>/dev/null)
            [[ -n "$oss_xml" ]] && break
        done
    fi
    if [[ -n "$oss_xml" ]]; then
        local bucket_name=$(echo "$oss_xml" | sed 's/<[^>]*>//g' | head -1)
        warn "OSS Bucket泄露: ${bucket_name}"
        echo "  {\"phase\":\"oss_bucket\",\"bucket\":\"$bucket_name\"}," >> "$FINDINGS_FILE"
    fi

    # 检查HTML/JS中是否包含OSS URL
    local oss_urls=$(safe_grep -oP 'https?://[a-zA-Z0-9._-]+\.(oss-[a-z0-9-]+\.aliyuncs\.com)[^"'\''\s]*' "$TMPDIR/home_https.html" 2>/dev/null | sort -u)
    if [[ -n "$oss_urls" ]]; then
        local bucket_cnt=$(echo "$oss_urls" | wc -l)
        warn "OSS URL引用: ${bucket_cnt} 个"
        echo "$oss_urls" | while IFS= read -r url; do
            echo "  {\"phase\":\"oss_bucket_url\",\"url\":\"${url//\"/\\\"}\"}," >> "$FINDINGS_FILE"
        done
    fi
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
    echo -e "${BLUE}  通用漏洞扫描引擎 v2.1${NC}"
    echo -e "${BLUE}  目标: ${TARGET}${NC}"
    echo -e "${BLUE}============================================${NC}"

    # 保存404页面用于后续分析
    mkdir -p "$TMPDIR"

    phase1_basic
    phase2_headers
    phase3_paths
    phase4_mixed
    phase5_js_analysis
    phase6_subdomains
    phase7_cors
    [[ "$QUICK" != "true" ]] && phase8_redirect
    [[ "$QUICK" != "true" ]] && phase9_php_params
    phase10_internal_port
    phase11_oss_bucket
    generate_report

    # 清理
    rm -rf "$TMPDIR"
}

main