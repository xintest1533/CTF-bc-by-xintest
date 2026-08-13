#!/usr/bin/env python3
"""报告生成器 v3.0 — 输出 HTML/MD/CSV/JSON 全格式"""
import json, os, sys, csv, datetime

LEVEL_EMOJI = {"CRITICAL": "💀", "HIGH": "🔴", "MEDIUM": "🟡", "LOW": "🟢", "INFO": "🔵"}
LEVEL_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}


def load(json_path):
    with open(json_path, "r", encoding="utf-8") as f:
        data = json.load(f)
    findings = data.get("findings", [])
    findings.sort(key=lambda x: LEVEL_ORDER.get(x.get("level", "INFO"), 99))
    return data, findings


def gen_html(domain, data, findings):
    s = data.get("summary", {})
    rows = ""
    for i, f in enumerate(findings):
        lv = f.get("level", "INFO")
        rows += f"""
    <tr class="row-{lv.lower()}">
      <td>{i+1}</td>
      <td><span class="badge badge-{lv.lower()}">{lv}</span></td>
      <td>{f.get('title','')}</td>
      <td>{f.get('cwe','')}</td>
      <td>{f.get('cvss_score','')}</td>
      <td><a href="{f.get('screenshot_url','')}" target="_blank">截图</a></td>
      <td><details><summary>详情</summary>
        <p><b>描述:</b> {f.get('description','')}</p>
        <p><b>复现:</b> <code>{f.get('reproduction_steps','')}</code></p>
        <p><b>修复:</b> <code>{f.get('fix_suggestion','')}</code></p>
        <p><b>CVSS向量:</b> <code>{f.get('cvss_vector','')}</code></p>
        <p><b>URL:</b> {f.get('affected_url','')}</p>
      </details></td>
    </tr>"""
    return f"""<!DOCTYPE html>
<html lang="zh-CN">
<head><meta charset="UTF-8"><title>{domain} 安全扫描报告</title>
<style>
*{{margin:0;padding:0;box-sizing:border-box}}
body{{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;background:#0f1923;color:#e0e0e0;padding:20px}}
h1{{color:#4fc3f7;text-align:center;margin-bottom:5px}}
.meta{{text-align:center;color:#78909c;font-size:13px;margin-bottom:20px}}
.summary{{display:flex;gap:10px;justify-content:center;margin-bottom:20px;flex-wrap:wrap}}
.card{{background:#1a2a3a;border-radius:8px;padding:15px 25px;text-align:center;min-width:80px}}
.card .n{{font-size:28px;font-weight:bold}}
.card .l{{font-size:11px;color:#78909c;margin-top:3px}}
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
code{{background:#0d1b2a;padding:2px 6px;border-radius:3px;font-size:11px;display:inline-block;max-width:100%;overflow-x:auto}}
a{{color:#4fc3f7}}
.footer{{text-align:center;color:#546e7a;font-size:11px;margin-top:20px;padding-top:10px;border-top:1px solid#2a3a4a}}
</style></head><body>
<h1>安全漏洞扫描报告</h1>
<div class="meta">目标: {domain} | 扫描时间: {data.get('scan_time','')} | 引擎: v3.0</div>
<div class="summary">
  <div class="card critical"><div class="n">{s.get('CRITICAL',0)}</div><div class="l">CRITICAL</div></div>
  <div class="card high"><div class="n">{s.get('HIGH',0)}</div><div class="l">HIGH</div></div>
  <div class="card medium"><div class="n">{s.get('MEDIUM',0)}</div><div class="l">MEDIUM</div></div>
  <div class="card low"><div class="n">{s.get('LOW',0)}</div><div class="l">LOW</div></div>
  <div class="card info"><div class="n">{s.get('INFO',0)}</div><div class="l">INFO</div></div>
</div>
<table><thead><tr><th>#</th><th>等级</th><th>标题</th><th>CWE</th><th>CVSS</th><th>截图</th><th>详情</th></tr></thead><tbody>{rows}</tbody></table>
<div class="footer">自动化漏洞扫描系统 v3.0 | 仅供授权安全测试使用</div>
</body></html>"""


def gen_md(domain, data, findings):
    s = data.get("summary", {})
    md = f"""# {domain} 安全漏洞扫描报告

> **引擎**: v3.0 | **时间**: {data.get('scan_time','')} | **低频被动 + 深度检测**

## 统计

| 等级 | 数量 |
|------|------|
| 💀 CRITICAL | {s.get('CRITICAL',0)} |
| 🔴 HIGH | {s.get('HIGH',0)} |
| 🟡 MEDIUM | {s.get('MEDIUM',0)} |
| 🟢 LOW | {s.get('LOW',0)} |
| 🔵 INFO | {s.get('INFO',0)} |
| **总计** | **{data.get('total_findings',0)}** |

## 漏洞详情

"""
    for i, f in enumerate(findings, 1):
        md += f"""### {i}. {LEVEL_EMOJI.get(f.get('level',''),'')} [{f.get('level','')}] {f.get('title','')}

| 属性 | 值 |
|------|-----|
| CWE | {f.get('cwe','')} |
| CVSS | {f.get('cvss_score','')} |
| CVSS向量 | `{f.get('cvss_vector','')}` |
| 受影响URL | {f.get('affected_url','')} |
| 截图URL | {f.get('screenshot_url','')} |

**描述**: {f.get('description','')}

**复现**:
```
{f.get('reproduction_steps','')}
```

**修复**:
```
{f.get('fix_suggestion','')}
```

---
"""
    md += "\n*报告由自动化漏洞扫描系统 v3.0 生成 | 仅供授权安全测试使用*\n"
    return md


def gen_csv(domain, findings, path):
    with open(path, "w", newline="", encoding="utf-8-sig") as f:
        w = csv.writer(f)
        w.writerow(["#", "等级", "检查项", "标题", "CWE", "CVSS", "CVSS向量", "受影响URL", "截图URL", "描述", "复现步骤", "修复建议", "时间"])
        for i, f in enumerate(findings, 1):
            w.writerow([i, f.get("level",""), f.get("check_name",""), f.get("title",""),
                        f.get("cwe",""), f.get("cvss_score",""), f.get("cvss_vector",""),
                        f.get("affected_url",""), f.get("screenshot_url",""),
                        f.get("description",""), f.get("reproduction_steps",""),
                        f.get("fix_suggestion",""), f.get("timestamp","")])
    return path


def generate_all(domain, json_path, output_dir):
    os.makedirs(output_dir, exist_ok=True)
    data, findings = load(json_path)
    results = {}

    html_p = os.path.join(output_dir, f"{domain.replace('.','_')}_report.html")
    with open(html_p, "w", encoding="utf-8") as f:
        f.write(gen_html(domain, data, findings))
    results["html"] = html_p

    md_p = os.path.join(output_dir, f"{domain.replace('.','_')}_report.md")
    with open(md_p, "w", encoding="utf-8") as f:
        f.write(gen_md(domain, data, findings))
    results["md"] = md_p

    csv_p = os.path.join(output_dir, f"{domain.replace('.','_')}_report.csv")
    gen_csv(domain, findings, csv_p)
    results["csv"] = csv_p

    json_p = os.path.join(output_dir, f"{domain.replace('.','_')}_report.json")
    with open(json_p, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)
    results["json"] = json_p

    for fmt, path in results.items():
        print(f"  {fmt}: {path}")
    return results


if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("用法: python3 report_generator_v3.py <domain> <json_path> [output_dir]")
        sys.exit(1)
    domain = sys.argv[1]
    json_path = sys.argv[2]
    out = sys.argv[3] if len(sys.argv) > 3 else f"/workspace/reports/{domain.replace('.','_')}"
    generate_all(domain, json_path, out)