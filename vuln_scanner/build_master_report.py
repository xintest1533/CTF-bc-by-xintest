#!/usr/bin/env python3
"""生成提交用漏洞汇总文档：MD + CSV + HTML"""
import json, os, datetime, csv

LEVEL_EMOJI = {"CRITICAL": "💀", "HIGH": "🔴", "MEDIUM": "🟡", "LOW": "🟢", "INFO": "🔵"}
LEVEL_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}

with open("/workspace/reports/master_all_findings.json", "r", encoding="utf-8") as f:
    master = json.load(f)

findings = master["findings"]
summary = master["summary"]
total = master["total_findings"]
ts = master["generated"]

# Sort
findings.sort(key=lambda x: (LEVEL_ORDER.get(x["level"], 99), x["domain"]))

# ============================================================
# 1. Markdown 提交文档
# ============================================================
md = f"""# 漏洞扫描汇总报告 — 提交版

> **扫描引擎**: 升级版 v3.0 (10模块一体化)
> **生成时间**: {ts}
> **扫描域名**: 4 个
> **漏洞总数**: {total} 个
> **授权方式**: 低频被动探测 + 深度检测（无高压，不影响业务）

---

## 一、总体统计

| 等级 | 数量 | 占比 |
|------|------|------|
| 💀 CRITICAL | {summary['CRITICAL']} | {summary['CRITICAL']*100//max(total,1)}% |
| 🔴 HIGH | {summary['HIGH']} | {summary['HIGH']*100//max(total,1)}% |
| 🟡 MEDIUM | {summary['MEDIUM']} | {summary['MEDIUM']*100//max(total,1)}% |
| 🟢 LOW | {summary['LOW']} | {summary['LOW']*100//max(total,1)}% |
| 🔵 INFO | {summary['INFO']} | {summary['INFO']*100//max(total,1)}% |
| **总计** | **{total}** | **100%** |

| 域名 | CRITICAL | HIGH | MEDIUM | LOW | INFO | 合计 |
|------|----------|------|--------|-----|------|------|
| zmj.com | 0 | 1 | 9 | 9 | 4 | 23 |
| dahuatech.com | 0 | 1 | 4 | 8 | 6 | 19 |
| mos400.com | 0 | 3 | 1 | 3 | 1 | 8 |
| cht-group.net | 2 | 4 | 4 | 3 | 2 | 15 |

---

## 二、扫描模块覆盖

| 模块 | 检测内容 |
|------|---------|
| 模块 1 | 基础信息收集（DNS、HTTP、Server 指纹） |
| 模块 2 | SSL/TLS 证书与配置 |
| 模块 3 | 安全响应头审计（HSTS、CSP、XFO 等 10 项） |
| 模块 4 | Cookie 与会话安全 |
| 模块 5 | 敏感信息泄露（源码、备份、错误信息、SQL查询暴露） |
| 模块 6 | 敏感路径/文件探测（30+ 路径） |
| 模块 7 | 前端安全（API Key、SourceMap、jQuery 版本） |
| 模块 8 | 后端指纹与已知漏洞 |
| 模块 9 | HTTP 方法与配置缺陷 |
| 模块 10 | 第三方服务与供应链 |

---

## 三、CRITICAL 级漏洞详情（{summary['CRITICAL']} 个）

"""

# CRITICAL
crit = [f for f in findings if f["level"] == "CRITICAL"]
if crit:
    for i, f in enumerate(crit, 1):
        md += f"""### CRITICAL-{i}: {f['title']}

| 属性 | 值 |
|------|-----|
| **域名** | {f['domain']} |
| **检查项** | {f.get('check_name','')} |
| **CWE** | {f.get('cwe','')} |
| **CVSS** | {f.get('cvss_score','')} |
| **CVSS向量** | `{f.get('cvss_vector','')}` |
| **受影响URL** | {f.get('affected_url','')} |
| **截图URL** | {f.get('screenshot_url','')} |
| **发现时间** | {f.get('timestamp','')} |

**漏洞描述**:
{f.get('description','')}

**复现步骤**:
```
{f.get('reproduction_steps','')}
```

**修复建议**:
```
{f.get('fix_suggestion','')}
```

---
"""
else:
    md += "无 CRITICAL 级漏洞。\n\n---\n\n"

# HIGH
high = [f for f in findings if f["level"] == "HIGH"]
md += f"## 四、HIGH 级漏洞详情（{len(high)} 个）\n\n"
for i, f in enumerate(high, 1):
    md += f"""### HIGH-{i}: {f['title']}

| 属性 | 值 |
|------|-----|
| **域名** | {f['domain']} |
| **检查项** | {f.get('check_name','')} |
| **CWE** | {f.get('cwe','')} |
| **CVSS** | {f.get('cvss_score','')} |
| **CVSS向量** | `{f.get('cvss_vector','')}` |
| **受影响URL** | {f.get('affected_url','')} |
| **截图URL** | {f.get('screenshot_url','')} |

**漏洞描述**: {f.get('description','')}

**复现步骤**:
```
{f.get('reproduction_steps','')}
```

**修复建议**:
```
{f.get('fix_suggestion','')}
```

---
"""

# MEDIUM
med = [f for f in findings if f["level"] == "MEDIUM"]
md += f"## 五、MEDIUM 级漏洞列表（{len(med)} 个）\n\n"
md += "| # | 域名 | 标题 | CWE | CVSS |\n"
md += "|---|------|------|-----|------|\n"
for i, f in enumerate(med, 1):
    md += f"| {i} | {f['domain']} | {f['title']} | {f.get('cwe','')} | {f.get('cvss_score','')} |\n"

# LOW
low = [f for f in findings if f["level"] == "LOW"]
md += f"\n## 六、LOW 级漏洞列表（{len(low)} 个）\n\n"
md += "| # | 域名 | 标题 | CWE | CVSS |\n"
md += "|---|------|------|-----|------|\n"
for i, f in enumerate(low, 1):
    md += f"| {i} | {f['domain']} | {f['title']} | {f.get('cwe','')} | {f.get('cvss_score','')} |\n"

# INFO
info = [f for f in findings if f["level"] == "INFO"]
md += f"\n## 七、INFO 级信息列表（{len(info)} 个）\n\n"
md += "| # | 域名 | 标题 |\n"
md += "|---|------|------|\n"
for i, f in enumerate(info, 1):
    md += f"| {i} | {f['domain']} | {f['title']} |\n"

# 风险等级说明
md += f"""
---

## 八、风险等级说明

| 等级 | 说明 |
|------|------|
| CRITICAL | 可直接导致服务器被控制、数据完全泄露、或重大隐私违规 |
| HIGH | 可导致重要数据泄露或权限绕过 |
| MEDIUM | 存在安全隐患但利用条件较苛刻 |
| LOW | 信息泄露或配置不当，风险较低 |
| INFO | 提示信息，建议关注 |

---

## 九、文件清单

```
/workspace/reports/
├── master_all_findings.json          # 全量漏洞数据 (65个)
├── master_submission_report.md       # 本提交文档
├── master_submission_report.csv      # CSV 表格
├── master_submission_report.html     # 可视化报告
│
├── zmj_com/                          # zmj.com 全部报告
├── dahuatech_com/                    # dahuatech.com 全部报告
├── mos400_com/                       # mos400.com 全部报告
└── cht_group_net/                    # cht-group.net 全部报告
```

---

*报告由自动化漏洞扫描系统 v3.0 生成 | 仅供授权安全测试使用*
"""

# Write MD
outdir = "/workspace/reports"
with open(os.path.join(outdir, "master_submission_report.md"), "w", encoding="utf-8") as f:
    f.write(md)
print("MD: master_submission_report.md")

# ============================================================
# 2. CSV
# ============================================================
csv_path = os.path.join(outdir, "master_submission_report.csv")
with open(csv_path, "w", newline="", encoding="utf-8-sig") as f:
    w = csv.writer(f)
    w.writerow(["#", "等级", "域名", "标题", "CWE", "CVSS", "CVSS向量", "受影响URL", "截图URL", "描述", "复现步骤", "修复建议", "时间"])
    for i, f in enumerate(findings, 1):
        w.writerow([i, f.get("level",""), f.get("domain",""), f.get("title",""),
                    f.get("cwe",""), f.get("cvss_score",""), f.get("cvss_vector",""),
                    f.get("affected_url",""), f.get("screenshot_url",""),
                    f.get("description",""), f.get("reproduction_steps",""),
                    f.get("fix_suggestion",""), f.get("timestamp","")])
print("CSV: master_submission_report.csv")

# ============================================================
# 3. HTML
# ============================================================
rows = ""
for i, f in enumerate(findings, 1):
    lv = f.get("level", "INFO").lower()
    rows += f"""
    <tr class="row-{lv}">
      <td>{i}</td>
      <td><span class="badge badge-{lv}">{f['level']}</span></td>
      <td>{f['domain']}</td>
      <td>{f['title']}</td>
      <td>{f.get('cwe','')}</td>
      <td>{f.get('cvss_score','')}</td>
      <td><a href="{f.get('screenshot_url','')}" target="_blank">🔗</a></td>
      <td><details><summary>详情</summary>
        <p><b>描述:</b> {f.get('description','')}</p>
        <p><b>复现:</b> <code>{f.get('reproduction_steps','')}</code></p>
        <p><b>修复:</b> <code>{f.get('fix_suggestion','')}</code></p>
        <p><b>CVSS:</b> <code>{f.get('cvss_vector','')}</code></p>
        <p><b>URL:</b> {f.get('affected_url','')}</p>
      </details></td>
    </tr>"""

html = f"""<!DOCTYPE html>
<html lang="zh-CN">
<head><meta charset="UTF-8"><title>漏洞扫描汇总 — 提交版</title>
<style>
*{{margin:0;padding:0;box-sizing:border-box}}
body{{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;background:#0f1923;color:#e0e0e0;padding:20px}}
h1{{color:#4fc3f7;text-align:center;margin-bottom:5px}}
.meta{{text-align:center;color:#78909c;font-size:13px;margin-bottom:20px}}
.summary{{display:flex;gap:10px;justify-content:center;margin-bottom:20px;flex-wrap:wrap}}
.card{{background:#1a2a3a;border-radius:8px;padding:15px 25px;text-align:center;min-width:80px}}
.card .n{{font-size:28px;font-weight:bold}}
.card .l{{font-size:11px;color:#78909c}}
.card.critical{{border:2px solid #e53935}}.card.critical .n{{color:#e53935}}
.card.high{{border:2px solid #ef5350}}.card.high .n{{color:#ef5350}}
.card.medium{{border:2px solid #ffa726}}.card.medium .n{{color:#ffa726}}
.card.low{{border:2px solid #66bb6a}}.card.low .n{{color:#66bb6a}}
.card.info{{border:2px solid #42a5f5}}.card.info .n{{color:#42a5f5}}
table{{width:100%;border-collapse:collapse;background:#1a2a3a;border-radius:8px;overflow:hidden}}
th{{background:#0d1b2a;padding:10px;text-align:left;font-size:12px;color:#78909c}}
td{{padding:8px 10px;font-size:13px;border-bottom:1px solid #2a3a4a}}
tr:hover{{background:#1e3040}}
.badge{{padding:2px 8px;border-radius:3px;font-size:11px;font-weight:bold}}
.badge-high{{background:#ef5350;color:#fff}}
.badge-medium{{background:#ffa726;color:#1a1a1a}}
.badge-low{{background:#66bb6a;color:#1a1a1a}}
.badge-info{{background:#42a5f5;color:#fff}}
.badge-critical{{background:#e53935;color:#fff}}
details{{cursor:pointer}}details p{{margin:4px 0;font-size:12px}}
code{{background:#0d1b2a;padding:2px 6px;border-radius:3px;font-size:11px;display:inline-block;max-width:600px;overflow-x:auto;white-space:pre-wrap}}
a{{color:#4fc3f7}}
.domain-table td{{font-size:13px}}
.footer{{text-align:center;color:#546e7a;font-size:11px;margin-top:20px;padding-top:10px;border-top:1px solid#2a3a4a}}
</style></head><body>
<h1>漏洞扫描汇总报告 — 提交版</h1>
<div class="meta">扫描时间: {ts} | 4 个域名 | {total} 个漏洞 | 引擎 v3.0</div>

<div class="summary">
  <div class="card critical"><div class="n">{summary['CRITICAL']}</div><div class="l">CRITICAL</div></div>
  <div class="card high"><div class="n">{summary['HIGH']}</div><div class="l">HIGH</div></div>
  <div class="card medium"><div class="n">{summary['MEDIUM']}</div><div class="l">MEDIUM</div></div>
  <div class="card low"><div class="n">{summary['LOW']}</div><div class="l">LOW</div></div>
  <div class="card info"><div class="n">{summary['INFO']}</div><div class="l">INFO</div></div>
</div>

<h3 style="color:#4fc3f7;margin-bottom:8px">各域名统计</h3>
<table class="domain-table" style="margin-bottom:20px">
<tr><th>域名</th><th>CRITICAL</th><th>HIGH</th><th>MEDIUM</th><th>LOW</th><th>INFO</th><th>合计</th></tr>
<tr><td>zmj.com</td><td>0</td><td>1</td><td>9</td><td>9</td><td>4</td><td>23</td></tr>
<tr><td>dahuatech.com</td><td>0</td><td>1</td><td>4</td><td>8</td><td>6</td><td>19</td></tr>
<tr><td>mos400.com</td><td>0</td><td>3</td><td>1</td><td>3</td><td>1</td><td>8</td></tr>
<tr><td>cht-group.net</td><td>2</td><td>4</td><td>4</td><td>3</td><td>2</td><td>15</td></tr>
</table>

<h3 style="color:#4fc3f7;margin-bottom:8px">全部漏洞详情</h3>
<table><thead><tr><th>#</th><th>等级</th><th>域名</th><th>标题</th><th>CWE</th><th>CVSS</th><th>截图</th><th>详情</th></tr></thead><tbody>{rows}</tbody></table>

<div class="footer">自动化漏洞扫描系统 v3.0 | 10模块覆盖 | 仅供授权安全测试使用</div>
</body></html>"""

with open(os.path.join(outdir, "master_submission_report.html"), "w", encoding="utf-8") as f:
    f.write(html)
print("HTML: master_submission_report.html")

print("\n全部提交文档生成完毕！")