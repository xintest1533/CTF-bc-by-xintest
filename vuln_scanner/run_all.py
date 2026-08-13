#!/usr/bin/env python3
"""一键扫描 + 报告生成 | 扫描三个域名并生成全格式报告"""
import os, sys, json, subprocess

DOMAINS = ["www.zmj.com", "www.dahuatech.com", "www.mos400.com"]

def run_scan(domain):
    label = domain.replace("www.", "").replace(".com", "_com")
    outdir = f"/workspace/reports/{label}"
    os.makedirs(outdir, exist_ok=True)
    print(f"\n{'='*60}")
    print(f"  扫描: {domain}")
    print(f"{'='*60}")
    cmd = f"python3 /workspace/vuln_scanner/advanced_scanner.py {domain} {outdir}"
    result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=600)
    print(result.stdout[-500:] if len(result.stdout) > 500 else result.stdout)
    if result.stderr:
        print("STDERR:", result.stderr[-300:])
    return outdir

def run_report(domain, outdir):
    json_path = os.path.join(outdir, "advanced_scan.json")
    if not os.path.exists(json_path):
        print(f"  SKIP {domain}: no advanced_scan.json")
        return
    print(f"\n  生成报告: {domain}")
    cmd = f"python3 /workspace/vuln_scanner/report_generator_v3.py {domain.replace('www.','')} {json_path} {outdir}"
    result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=60)
    print(result.stdout)

def main():
    for domain in DOMAINS:
        outdir = run_scan(domain)
        run_report(domain.replace("www.", ""), outdir)

    # 汇总
    print(f"\n{'='*60}")
    print("  全部扫描完成 | 汇总")
    print(f"{'='*60}")
    total = {"HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
    for domain in DOMAINS:
        label = domain.replace("www.", "").replace(".com", "_com")
        jp = f"/workspace/reports/{label}/{label}_report.json"
        if os.path.exists(jp):
            with open(jp) as f:
                d = json.load(f)
            s = d["summary"]
            for k in total:
                total[k] += s.get(k, 0)
            print(f"  {domain}: HIGH={s['HIGH']} MEDIUM={s['MEDIUM']} LOW={s['LOW']} INFO={s['INFO']} TOTAL={d['total_findings']}")
    print(f"  {'总计':>20}: HIGH={total['HIGH']} MEDIUM={total['MEDIUM']} LOW={total['LOW']} INFO={total['INFO']}")

if __name__ == "__main__":
    main()