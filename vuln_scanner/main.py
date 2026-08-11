# -*- coding: utf-8 -*-
"""
GUI 主程序
基于 Tkinter 实现跨平台（Windows / Linux / macOS）图形界面。
提供规则扫描模式与全量扫描模式两种扫描模式。

启动：
    python main.py
"""

import csv
import os
import threading
import tkinter as tk
from tkinter import ttk, filedialog, messagebox, scrolledtext

from scanner_engine import ScannerEngine, ScanResult


# 漏洞等级 -> 颜色
LEVEL_COLORS = {
    ScanResult.LEVEL_CRITICAL: "#b00020",
    ScanResult.LEVEL_HIGH: "#d32f2f",
    ScanResult.LEVEL_MEDIUM: "#f57c00",
    ScanResult.LEVEL_LOW: "#1565c0",
    ScanResult.LEVEL_INFO: "#616161",
}


class VulnScannerApp:
    def __init__(self, root):
        self.root = root
        self.root.title("漏洞扫描器 VulnScanner v1.0")
        self.root.geometry("1100x720")
        self.root.minsize(900, 600)

        self.engine = None
        self.scan_thread = None
        self.results = []  # 保存 ScanResult 列表

        self._build_ui()

    # ------------------------------------------------------------
    # UI 构建
    # ------------------------------------------------------------
    def _build_ui(self):
        # 顶部控制区
        ctrl = ttk.Frame(self.root, padding=10)
        ctrl.pack(side=tk.TOP, fill=tk.X)

        ttk.Label(ctrl, text="目标 URL:").grid(row=0, column=0, sticky=tk.W)
        self.target_var = tk.StringVar(value="https://example.com")
        ttk.Entry(ctrl, textvariable=self.target_var, width=50).grid(
            row=0, column=1, columnspan=3, sticky=tk.EW, padx=5)

        ttk.Label(ctrl, text="扫描模式:").grid(row=1, column=0, sticky=tk.W, pady=8)
        self.mode_var = tk.StringVar(value="rule")
        ttk.Radiobutton(ctrl, text="规则扫描模式（按预设轨迹检测常见漏洞，速度快）",
                        variable=self.mode_var, value="rule").grid(
            row=1, column=1, columnspan=3, sticky=tk.W, pady=2)
        ttk.Radiobutton(ctrl, text="全量扫描模式（尝试全部漏洞，包含子域名枚举与接管）",
                        variable=self.mode_var, value="full").grid(
            row=2, column=1, columnspan=3, sticky=tk.W, pady=2)

        ttk.Label(ctrl, text="并发线程:").grid(row=3, column=0, sticky=tk.W, pady=4)
        self.threads_var = tk.IntVar(value=10)
        ttk.Spinbox(ctrl, from_=1, to=50, textvariable=self.threads_var,
                    width=6).grid(row=3, column=1, sticky=tk.W, pady=4)

        ttk.Label(ctrl, text="超时(秒):").grid(row=3, column=2, sticky=tk.W, pady=4)
        self.timeout_var = tk.IntVar(value=8)
        ttk.Spinbox(ctrl, from_=3, to=60, textvariable=self.timeout_var,
                    width=6).grid(row=3, column=3, sticky=tk.W, pady=4)

        btn_frame = ttk.Frame(ctrl)
        btn_frame.grid(row=4, column=0, columnspan=4, sticky=tk.W, pady=8)
        self.start_btn = ttk.Button(btn_frame, text="开始扫描", command=self.start_scan)
        self.start_btn.pack(side=tk.LEFT, padx=4)
        self.stop_btn = ttk.Button(btn_frame, text="停止扫描", command=self.stop_scan,
                                   state=tk.DISABLED)
        self.stop_btn.pack(side=tk.LEFT, padx=4)
        self.export_btn = ttk.Button(btn_frame, text="导出报告 (CSV)",
                                     command=self.export_report, state=tk.DISABLED)
        self.export_btn.pack(side=tk.LEFT, padx=4)
        self.clear_btn = ttk.Button(btn_frame, text="清空结果", command=self.clear_results)
        self.clear_btn.pack(side=tk.LEFT, padx=4)

        # 进度条
        prog_frame = ttk.Frame(self.root, padding=(10, 0, 10, 5))
        prog_frame.pack(side=tk.TOP, fill=tk.X)
        self.progress = ttk.Progressbar(prog_frame, mode="determinate")
        self.progress.pack(side=tk.LEFT, fill=tk.X, expand=True)
        self.progress_label = ttk.Label(prog_frame, text="就绪", width=40)
        self.progress_label.pack(side=tk.LEFT, padx=8)

        # 统计信息
        stat_frame = ttk.Frame(self.root, padding=(10, 0, 10, 5))
        stat_frame.pack(side=tk.TOP, fill=tk.X)
        self.stat_label = ttk.Label(
            stat_frame,
            text="风险统计:  严重 0 | 高危 0 | 中危 0 | 低危 0 | 信息 0 | 共 0 项",
            font=("TkDefaultFont", 10, "bold"))
        self.stat_label.pack(side=tk.LEFT)

        # 主体：左侧日志，右侧结果列表
        body = ttk.Panedwindow(self.root, orient=tk.HORIZONTAL)
        body.pack(side=tk.TOP, fill=tk.BOTH, expand=True, padx=10, pady=5)

        # 日志区
        log_frame = ttk.LabelFrame(body, text="扫描日志", padding=4)
        self.log_text = scrolledtext.ScrolledText(
            log_frame, wrap=tk.WORD, height=20, font=("Consolas", 10))
        self.log_text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        body.add(log_frame, weight=1)

        # 结果区
        result_frame = ttk.LabelFrame(body, text="漏洞结果", padding=4)
        self._build_result_tree(result_frame)
        body.add(result_frame, weight=2)

        # 底部免责声明
        footer = ttk.Frame(self.root, padding=5)
        footer.pack(side=tk.BOTTOM, fill=tk.X)
        ttk.Label(
            footer,
            text="免责声明: 本工具仅供授权安全测试与教学使用，禁止用于未授权扫描。"
                 "使用本工具造成的任何后果由使用者自行承担。",
            foreground="#b00020").pack(side=tk.LEFT)

    def _build_result_tree(self, parent):
        columns = ("level", "check", "title", "target", "time")
        self.tree = ttk.Treeview(parent, columns=columns, show="headings", height=18)
        self.tree.heading("level", text="等级")
        self.tree.heading("check", text="检测项")
        self.tree.heading("title", text="漏洞标题")
        self.tree.heading("target", text="目标")
        self.tree.heading("time", text="时间")
        self.tree.column("level", width=70, anchor=tk.CENTER)
        self.tree.column("check", width=140, anchor=tk.W)
        self.tree.column("title", width=320, anchor=tk.W)
        self.tree.column("target", width=260, anchor=tk.W)
        self.tree.column("time", width=140, anchor=tk.CENTER)

        # 行标签样式（按等级着色）
        for level, color in LEVEL_COLORS.items():
            self.tree.tag_configure(level, foreground=color)

        self.tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        vsb = ttk.Scrollbar(parent, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=vsb.set)
        vsb.pack(side=tk.RIGHT, fill=tk.Y)

        # 详情区
        detail_frame = ttk.LabelFrame(parent, text="详情", padding=4)
        detail_frame.pack(side=tk.BOTTOM, fill=tk.X, pady=(5, 0))
        self.detail_text = scrolledtext.ScrolledText(
            detail_frame, wrap=tk.WORD, height=5, font=("Consolas", 10))
        self.detail_text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        self.tree.bind("<<TreeviewSelect>>", self._on_select_result)

    # ------------------------------------------------------------
    # 回调（在扫描线程中调用，需通过 root.after 切回主线程）
    # ------------------------------------------------------------
    def _on_log(self, msg):
        self.root.after(0, lambda: self._append_log(msg))

    def _on_progress(self, current, total, message):
        self.root.after(0, lambda: self._update_progress(current, total, message))

    def _on_result(self, result):
        self.root.after(0, lambda: self._add_result(result))

    def _on_finish(self, summary):
        self.root.after(0, lambda: self._scan_finished(summary))

    # ------------------------------------------------------------
    # UI 操作
    # ------------------------------------------------------------
    def _append_log(self, msg):
        self.log_text.insert(tk.END, msg + "\n")
        self.log_text.see(tk.END)

    def _update_progress(self, current, total, message):
        if total > 0:
            self.progress["maximum"] = total
            self.progress["value"] = current
            pct = int(current * 100 / total)
            self.progress_label.config(text=f"{pct}%  {message}")
        else:
            self.progress_label.config(text=message)

    def _add_result(self, result):
        self.results.append(result)
        self.tree.insert(
            "", tk.END,
            values=(result.level, result.check_name, result.title,
                    result.target, result.timestamp),
            tags=(result.level,))
        self.tree.see(tk.END)
        self._update_stat()

    def _update_stat(self):
        by_level = {lvl: 0 for lvl in LEVEL_COLORS}
        for r in self.results:
            by_level[r.level] = by_level.get(r.level, 0) + 1
        self.stat_label.config(
            text=f"风险统计:  严重 {by_level.get(ScanResult.LEVEL_CRITICAL,0)} | "
                 f"高危 {by_level.get(ScanResult.LEVEL_HIGH,0)} | "
                 f"中危 {by_level.get(ScanResult.LEVEL_MEDIUM,0)} | "
                 f"低危 {by_level.get(ScanResult.LEVEL_LOW,0)} | "
                 f"信息 {by_level.get(ScanResult.LEVEL_INFO,0)} | "
                 f"共 {len(self.results)} 项")

    def _on_select_result(self, _event):
        sel = self.tree.selection()
        if not sel:
            return
        item = self.tree.item(sel[0])
        idx = self.tree.index(sel[0])
        if 0 <= idx < len(self.results):
            r = self.results[idx]
            self.detail_text.delete("1.0", tk.END)
            self.detail_text.insert(
                tk.END,
                f"等级: {r.level}\n"
                f"检测项: {r.check_name}\n"
                f"标题: {r.title}\n"
                f"目标: {r.target}\n"
                f"时间: {r.timestamp}\n"
                f"详情: {r.detail}\n")

    def _scan_finished(self, summary):
        self.start_btn.config(state=tk.NORMAL)
        self.stop_btn.config(state=tk.DISABLED)
        self.export_btn.config(state=tk.NORMAL)
        self.progress["value"] = self.progress["maximum"]
        self.progress_label.config(text=f"扫描完成，耗时 {summary['elapsed']:.1f}s")
        self._append_log(
            f"[*] 完成。共发现 {summary['findings']} 个风险项，耗时 {summary['elapsed']:.1f}s")
        messagebox.showinfo(
            "扫描完成",
            f"扫描完成！\n\n目标: {summary['target']}\n模式: {summary['mode']}\n"
            f"耗时: {summary['elapsed']:.1f}s\n"
            f"发现风险: {summary['findings']} 项\n"
            f"  严重: {summary['by_level'].get(ScanResult.LEVEL_CRITICAL,0)}\n"
            f"  高危: {summary['by_level'].get(ScanResult.LEVEL_HIGH,0)}\n"
            f"  中危: {summary['by_level'].get(ScanResult.LEVEL_MEDIUM,0)}\n"
            f"  低危: {summary['by_level'].get(ScanResult.LEVEL_LOW,0)}\n"
            f"  信息: {summary['by_level'].get(ScanResult.LEVEL_INFO,0)}"
        )

    # ------------------------------------------------------------
    # 用户操作
    # ------------------------------------------------------------
    def start_scan(self):
        target = self.target_var.get().strip()
        if not target:
            messagebox.showwarning("提示", "请输入目标 URL")
            return
        if not target.startswith(("http://", "https://")):
            if messagebox.askyesno(
                "确认", "目标未指定协议，是否自动补全 http:// ?"):
                target = "http://" + target
                self.target_var.set(target)
            else:
                return

        confirm = messagebox.askyesno(
            "授权确认",
            f"请确认您已获得对该目标 {target} 的合法授权进行安全测试。\n\n"
            "本工具仅供授权测试与教学使用。是否继续？")
        if not confirm:
            return

        # 清空上次结果
        self.clear_results()

        try:
            self.engine = ScannerEngine(
                target=target,
                mode=self.mode_var.get(),
                threads=self.threads_var.get(),
                timeout=self.timeout_var.get(),
                on_progress=self._on_progress,
                on_result=self._on_result,
                on_log=self._on_log,
                on_finish=self._on_finish,
            )
        except Exception as e:
            messagebox.showerror("错误", f"初始化扫描器失败: {e}")
            return

        self.start_btn.config(state=tk.DISABLED)
        self.stop_btn.config(state=tk.NORMAL)
        self.export_btn.config(state=tk.DISABLED)
        self.progress["value"] = 0
        self._append_log(f"[*] 启动扫描线程，目标: {target}")

        self.scan_thread = threading.Thread(target=self.engine.run, daemon=True)
        self.scan_thread.start()

    def stop_scan(self):
        if self.engine:
            self.engine.stop()
        self.stop_btn.config(state=tk.DISABLED)

    def clear_results(self):
        self.results.clear()
        for item in self.tree.get_children():
            self.tree.delete(item)
        self.log_text.delete("1.0", tk.END)
        self.detail_text.delete("1.0", tk.END)
        self.progress["value"] = 0
        self.progress_label.config(text="就绪")
        self._update_stat()

    def export_report(self):
        if not self.results:
            messagebox.showinfo("提示", "暂无结果可导出")
            return
        default_name = f"vuln_report_{self.target_var.get().replace('://','_').replace('/','_')}.csv"
        path = filedialog.asksaveasfilename(
            title="保存报告",
            defaultextension=".csv",
            filetypes=[("CSV 文件", "*.csv"), ("所有文件", "*.*")],
            initialfile=default_name,
        )
        if not path:
            return
        try:
            with open(path, "w", newline="", encoding="utf-8-sig") as f:
                writer = csv.writer(f)
                writer.writerow(["等级", "检测项", "标题", "目标", "时间", "详情"])
                for r in self.results:
                    writer.writerow([r.level, r.check_name, r.title, r.target,
                                     r.timestamp, r.detail])
            messagebox.showinfo("成功", f"报告已导出至:\n{path}")
        except Exception as e:
            messagebox.showerror("错误", f"导出失败: {e}")


def main():
    root = tk.Tk()
    # 在 Windows / 高 DPI 屏幕上更清晰
    try:
        root.tk.call("tk", "scaling", 1.2)
    except Exception:
        pass
    VulnScannerApp(root)
    root.mainloop()


if __name__ == "__main__":
    main()
