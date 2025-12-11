import tkinter as tk
from tkinter import ttk, filedialog, messagebox, scrolledtext
import yaml
import paramiko
import logging
import threading
import queue
import os
import json
import time
import re
import datetime
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed

# ============================
# 0. 全局路径与配置
# ============================
def get_exe_dir():
    if getattr(sys, 'frozen', False):
        return os.path.dirname(sys.executable)
    return os.path.dirname(os.path.abspath(__file__))

BASE_DIR = get_exe_dir()
CONFIG_FILE = os.path.join(BASE_DIR, "config.yaml")
HOSTS_DATA_FILE = os.path.join(BASE_DIR, "hosts_data.json")
LOG_FILE_NAME = os.path.join(BASE_DIR, "ssh_debug.log")

DEFAULT_CONFIG_CONTENT = """# 全局配置文件
settings:
  max_host_limit: 500
  max_threads: 20
  timeout: 10

defaults:
  ssh_port: 22
  user: root
  login_passwords:
    - "123456"
  root_passwords:
    - "root123"
  su_prompt_regex: "(Password|密码|password|Passwort).*?[:：]"

commands:
  - "whoami"
  - "uptime"
"""

def setup_global_logging():
    with open(LOG_FILE_NAME, 'w', encoding='utf-8') as f:
        f.write(f"=== Log Started at {datetime.datetime.now()} ===\n")
    logger = logging.getLogger("SSH_Tool_Core")
    logger.setLevel(logging.DEBUG)
    fh = logging.FileHandler(LOG_FILE_NAME, encoding='utf-8')
    fh.setFormatter(logging.Formatter('%(asctime)s - [%(levelname)s] - %(message)s'))
    logger.addHandler(fh)
    logging.getLogger("paramiko").setLevel(logging.WARNING)
    return logger

sys_logger = setup_global_logging()

# ============================
# 1. 核心 SSH 业务逻辑 (保持不变)
# ============================
class TaskStatus:
    WAITING = "等待中"
    RUNNING = "执行中"
    SUCCESS = "✅ 成功"
    FAIL_LOGIN = "❌ 登录失败"
    FAIL_ROOT = "❌ 提权失败"
    FAIL_CMD = "⚠️ 命令报错"
    STOPPED = "⏹ 已停止"
    
    @classmethod
    def all_statuses(cls):
        return ["所有状态", cls.WAITING, cls.RUNNING, cls.SUCCESS, cls.FAIL_LOGIN, cls.FAIL_ROOT, cls.FAIL_CMD, cls.STOPPED]

class SSHWorker:
    def __init__(self, host_info, config, log_callback, status_callback):
        self.ip = host_info['ip']
        self.user = host_info['user']
        self.pwd = host_info['pwd']
        self.root_pwd = host_info['root_pwd']
        self.hostname = host_info.get('hostname', '')
        self.config = config
        self.log_cb = log_callback
        self.status_cb = status_callback
        self.defaults = config.get('defaults', {})
        self.commands = config.get('commands', [])
        self.timeout = config.get('settings', {}).get('timeout', 10)
        self.client = None; self.shell = None

    def log(self, msg):
        ts = datetime.datetime.now().strftime("%H:%M:%S")
        self.log_cb(self.ip, f"[{ts}] {msg}")
        clean_msg = re.sub(r'\x1b\[[0-9;]*[mK]', '', msg)
        sys_logger.info(f"[{self.ip}] {clean_msg}")

    def ensure_str_list(self, raw_data):
        if raw_data is None: return []
        if not isinstance(raw_data, (list, tuple)): raw_data = [raw_data]
        return [str(item).strip() for item in raw_data if item is not None and str(item).strip()]

    def run(self):
        self.status_cb(self.ip, TaskStatus.RUNNING)
        self.log(f"开始执行任务...")
        try:
            final_user = str(self.user).strip() if self.user else str(self.defaults.get('user', 'root')).strip()
            default_pwds = self.ensure_str_list(self.defaults.get('login_passwords', []))
            host_pwds = self.ensure_str_list(self.pwd)
            login_pwds = list(dict.fromkeys(host_pwds + default_pwds))
            default_root = self.ensure_str_list(self.defaults.get('root_passwords', []))
            host_root = self.ensure_str_list(self.root_pwd)
            root_pwds = list(dict.fromkeys(host_root + default_root))

            if not self._connect(final_user, login_pwds):
                self.status_cb(self.ip, TaskStatus.FAIL_LOGIN)
                self.log("❌ 错误：SSH 连接失败")
                return

            if final_user == 'root':
                self.log("当前为 root，跳过切换。")
            else:
                current_user = self._get_whoami()
                self.log(f"登录成功，用户: {current_user}")
                if "root" not in current_user.lower():
                    if not self._switch_to_root(root_pwds):
                        self.status_cb(self.ip, TaskStatus.FAIL_ROOT)
                        self.log("❌ 错误：Root 提权失败")
                        return
                    self.log("Root 切换成功")
            
            self.log(f"执行 {len(self.commands)} 条命令...")
            if self._execute_commands():
                self.status_cb(self.ip, TaskStatus.SUCCESS); self.log("✅ 任务完成。")
            else:
                self.status_cb(self.ip, TaskStatus.FAIL_CMD); self.log("⚠️ 部分命令异常。")

        except Exception as e:
            self.status_cb(self.ip, TaskStatus.FAIL_LOGIN); self.log(f"💥 异常: {str(e)}")
        finally:
            if self.client:
                try: self.client.close()
                except: pass

    def _connect(self, user, passwords):
        self.client = paramiko.SSHClient()
        self.client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        for i, pwd in enumerate(passwords):
            try:
                self.log(f"连接中... (密码 {i+1}/{len(passwords)})")
                self.client.connect(hostname=self.ip, port=int(self.defaults.get('ssh_port', 22)), username=user, password=str(pwd), timeout=15, banner_timeout=60, auth_timeout=30, look_for_keys=False, allow_agent=False, gss_auth=False)
                return True
            except: continue
        return False

    def _get_whoami(self):
        try:
            stdin, stdout, stderr = self.client.exec_command("whoami", timeout=10)
            return stdout.read().decode().strip()
        except: return "unknown"

    def _read_shell(self, pattern, timeout=10):
        buf = ""; end = time.time() + timeout
        while time.time() < end:
            if self.shell.recv_ready():
                raw = self.shell.recv(4096).decode('utf-8', errors='ignore')
                buf += raw
                clean = re.sub(r'\x1b\[[0-9;]*[mK]', '', buf)
                if re.search(pattern, clean): return buf
            time.sleep(0.1)
        return buf

    def _switch_to_root(self, passwords):
        regex = self.defaults.get('su_prompt_regex', r"(Password|密码|password|Passwort).*?[:：]")
        try:
            self.shell = self.client.invoke_shell(width=300, height=100)
            time.sleep(1)
            self._read_shell(r"[\$>] ?$", timeout=5)
            self.shell.send("su -\n")
            if not re.search(regex, self._read_shell(regex, timeout=10)): return False
            for pwd in passwords:
                self.shell.send(f"{str(pwd)}\n")
                out = self._read_shell(r"(#|failure|认证失败|鉴定故障|incorrect)", timeout=5)
                clean = re.sub(r'\x1b\[[0-9;]*[mK]', '', out)
                if "#" in clean and not re.search(r"(failure|认证失败|鉴定故障|incorrect)", clean, re.IGNORECASE): return True
                self.shell.send("su -\n"); self._read_shell(regex)
            return False
        except: return False

    def _execute_commands(self):
        all_ok = True
        for cmd in self.commands:
            self.log(f">>> CMD: {cmd}")
            try:
                output = ""
                if self.shell:
                    marker = "CMD_END"
                    self.shell.send(f"{cmd}; echo {marker}\n")
                    raw = self._read_shell(marker, timeout=30)
                    output = raw.replace(f"{cmd}; echo {marker}", "").replace(marker, "").strip()
                else:
                    stdin, stdout, stderr = self.client.exec_command(cmd, timeout=30)
                    output = stdout.read().decode() + stderr.read().decode()
                self.log(f"{output.strip()}\n")
            except: all_ok = False
        return all_ok

# ============================
# 2. ANSI 渲染器
# ============================
class AnsiColorHandler:
    def __init__(self, text_widget):
        self.text_widget = text_widget
        self.color_map = {'30':'black','31':'red','32':'#008000','33':'#B8860B','34':'#0000FF','35':'#800080','36':'#008080','37':'gray','90':'gray','91':'#FF4500','92':'#32CD32','93':'#FFD700','94':'#1E90FF','95':'#FF1493','96':'#00CED1','97':'black','0':'black','00':'black'}
        self.configure_tags()

    def configure_tags(self):
        for code, color in self.color_map.items(): self.text_widget.tag_config(f"fg_{code}", foreground=color)
        self.text_widget.tag_config("bold", font=('Consolas', 10, 'bold'))

    def insert_ansi_text(self, content):
        parts = re.split(r'(\x1b\[[0-9;]*[a-zA-Z])', content)
        current_tags = []
        for part in parts:
            if not part: continue
            if part.startswith('\x1b['):
                if part.endswith('m'):
                    codes = part[2:-1].split(';')
                    for c in codes:
                        if c in ['0','00']: current_tags = []
                        elif c in ['1','01']: current_tags.append('bold')
                        elif c in self.color_map:
                            current_tags = [t for t in current_tags if not t.startswith('fg_')]
                            current_tags.append(f"fg_{c}")
                elif part.endswith('K'): pass
            else: self.text_widget.insert('end', part, tuple(current_tags))

# ============================
# 3. 界面逻辑 (功能增强)
# ============================
class SmartParser:
    @staticmethod
    def parse_text(text):
        hosts = []
        for line in text.split('\n'):
            line = line.strip()
            if not line or line.startswith("#"): continue
            parts = re.split(r'[,\s，;\t]+', line)
            parts = [p for p in parts if p]
            if not parts or len(parts[0]) < 7: continue
            ip = parts[0]
            user = parts[1] if len(parts) > 1 else ""
            pwd = parts[2] if len(parts) > 2 else ""
            root_pwd = parts[3] if len(parts) > 3 else ""
            hostname = parts[4] if len(parts) > 4 else ""
            hosts.append({'ip': ip, 'user': user, 'pwd': pwd, 'root_pwd': root_pwd, 'hostname': hostname})
        return hosts

class ModernGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("SSH 批量运维工具 v5.0 (多选与复制增强)")
        self.root.geometry("1280x850")
        
        self.ensure_config()
        self.config = self.load_config()
        self.host_logs = {} 
        self.data_store = {} 
        self.host_statuses = {} 
        self.is_running = False
        self.stop_flag = False
        self.gui_queue = queue.Queue()
        
        self.setup_styles()
        self.create_layout()
        # 注意：不要在 init 里调用 create_context_menu，改为动态创建
        self.load_history()
        self.root.after(100, self.process_gui_queue)

    def center_window(self, win, width, height):
        win.update_idletasks()
        x = self.root.winfo_x() + (self.root.winfo_width() - width) // 2
        y = self.root.winfo_y() + (self.root.winfo_height() - height) // 2
        win.geometry(f"{width}x{height}+{x}+{y}")

    def ensure_config(self):
        if not os.path.exists(CONFIG_FILE):
            with open(CONFIG_FILE, 'w', encoding='utf-8') as f: f.write(DEFAULT_CONFIG_CONTENT)
    
    def load_config(self):
        try: 
            with open(CONFIG_FILE, 'r', encoding='utf-8') as f: return yaml.safe_load(f)
        except:
            return {}

    def setup_styles(self):
        style = ttk.Style()
        style.configure("Treeview", rowheight=28, font=('Microsoft YaHei', 10))
        self.tag_colors = {TaskStatus.WAITING: "black", TaskStatus.RUNNING: "#0000FF", TaskStatus.SUCCESS: "#008000", TaskStatus.FAIL_LOGIN: "#FF0000", TaskStatus.FAIL_ROOT: "#8B0000", TaskStatus.FAIL_CMD: "#FF8C00"}

    def create_layout(self):
        # 1. 顶部操作栏
        toolbar = ttk.Frame(self.root, padding=5)
        toolbar.pack(fill="x")
        ttk.Button(toolbar, text="📝 智能导入/编辑", command=self.show_smart_import_editor).pack(side="left", padx=2)
        ttk.Button(toolbar, text="🗑️ 清空", command=self.clear_list).pack(side="left", padx=2)
        
        # 新增复制按钮
        ttk.Separator(toolbar, orient="vertical").pack(side="left", fill="y", padx=10)
        ttk.Button(toolbar, text="📋 复制表格信息", command=self.copy_filtered_hosts).pack(side="left", padx=2)
        
        ttk.Separator(toolbar, orient="vertical").pack(side="left", fill="y", padx=10)
        ttk.Button(toolbar, text="⚙️ 配置", command=self.open_config).pack(side="left", padx=2)
        ttk.Button(toolbar, text="🔄 重载", command=self.reload_config).pack(side="left", padx=2)
        
        self.btn_run = ttk.Button(toolbar, text="🚀 全部执行", command=self.run_all_hosts)
        self.btn_run.pack(side="right", padx=5)
        self.btn_stop = ttk.Button(toolbar, text="⏹ 停止", state="disabled", command=self.stop_tasks)
        self.btn_stop.pack(side="right", padx=5)

        # 2. 筛选栏
        filter_frame = ttk.LabelFrame(self.root, text="🔍 筛选条件", padding=5)
        filter_frame.pack(fill="x", padx=5, pady=2)
        
        ttk.Label(filter_frame, text="IP:").pack(side="left", padx=5)
        self.filter_ip_var = tk.StringVar(); ttk.Entry(filter_frame, textvariable=self.filter_ip_var, width=15).pack(side="left")
        ttk.Label(filter_frame, text="Hostname:").pack(side="left", padx=5)
        self.filter_host_var = tk.StringVar(); ttk.Entry(filter_frame, textvariable=self.filter_host_var, width=15).pack(side="left")
        ttk.Label(filter_frame, text="Status:").pack(side="left", padx=5)
        self.filter_status_var = tk.StringVar(value="所有状态")
        ttk.Combobox(filter_frame, textvariable=self.filter_status_var, values=TaskStatus.all_statuses(), state="readonly", width=12).pack(side="left")
        
        ttk.Button(filter_frame, text="🔎 查询", command=self.apply_filter).pack(side="left", padx=10)
        ttk.Button(filter_frame, text="❌ 重置", command=self.reset_filter).pack(side="left", padx=5)

        self.progress_var = tk.DoubleVar()
        ttk.Progressbar(self.root, variable=self.progress_var, maximum=100).pack(fill="x")

        paned = ttk.PanedWindow(self.root, orient="horizontal")
        paned.pack(fill="both", expand=True)

        # 左侧列表
        left = ttk.Frame(paned)
        paned.add(left, weight=1)
        
        cols = ("ip", "hostname", "status", "user", "pwd", "root_pwd")
        # selectmode='extended' 允许 Shift/Ctrl 多选
        self.tree = ttk.Treeview(left, columns=cols, show="headings", selectmode="extended")
        self.tree.heading("ip", text="IP"); self.tree.column("ip", width=110)
        self.tree.heading("hostname", text="主机名"); self.tree.column("hostname", width=100)
        self.tree.heading("status", text="状态"); self.tree.column("status", width=80)
        self.tree.heading("user", text="用户"); self.tree.column("user", width=60)
        self.tree.heading("pwd", text="密码"); self.tree.column("pwd", width=60)
        self.tree.heading("root_pwd", text="Root密码"); self.tree.column("root_pwd", width=60)
        
        vsb = ttk.Scrollbar(left, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=vsb.set)
        self.tree.pack(side="left", fill="both", expand=True); vsb.pack(side="right", fill="y")
        
        self.tree.bind("<<TreeviewSelect>>", self.on_select_host)
        # 绑定右键 (在点击时动态生成菜单)
        self.tree.bind("<Button-3>", self.show_context_menu)

        # 右侧日志
        right = ttk.LabelFrame(paned, text="详情日志 (支持 ANSI 颜色)", padding=5)
        paned.add(right, weight=2)
        self.log_area = scrolledtext.ScrolledText(right, state="disabled", font=('Consolas', 10))
        self.log_area.pack(fill="both", expand=True)
        self.ansi_renderer = AnsiColorHandler(self.log_area)

    # --- 筛选逻辑 ---
    def apply_filter(self):
        f_ip = self.filter_ip_var.get().strip()
        f_host = self.filter_host_var.get().strip()
        f_stat = self.filter_status_var.get()
        self.tree.delete(*self.tree.get_children())
        for ip, data in self.data_store.items():
            current_status = self.host_statuses.get(ip, TaskStatus.WAITING)
            if f_ip and f_ip not in ip: continue
            if f_host and f_host not in data.get('hostname', ''): continue
            if f_stat != "所有状态" and f_stat != current_status: continue
            self.insert_tree_item(data, current_status)

    def reset_filter(self):
        self.filter_ip_var.set(""); self.filter_host_var.set(""); self.filter_status_var.set("所有状态")
        self.apply_filter()

    # --- 列表操作 ---
    def insert_host_row(self, h):
        ip = h['ip']
        self.data_store[ip] = h
        if ip not in self.host_statuses: self.host_statuses[ip] = TaskStatus.WAITING
        if ip not in self.host_logs: self.host_logs[ip] = f"--- Ready ---\n"
        self.apply_filter()

    def insert_tree_item(self, data, status):
        ip = data['ip']
        if self.tree.exists(ip): self.tree.delete(ip)
        self.tree.insert("", "end", iid=ip, values=(ip, data.get('hostname',''), status, data['user'], "***" if data['pwd'] else "", "***" if data['root_pwd'] else ""))
        self.tree.item(ip, tags=(status,))
        color = self.tag_colors.get(status, "black")
        self.tree.tag_configure(status, foreground=color)

    # --- 新增功能：批量复制 ---
    def copy_filtered_hosts(self):
        """复制当前 Treeview 中可见的所有主机信息"""
        # 获取所有可见项 (iid 就是 IP)
        visible_ips = self.tree.get_children()
        
        if not visible_ips:
            messagebox.showinfo("提示", "当前列表为空，无法复制。")
            return
            
        lines = ["IP\tHostname\t状态\t用户\t密码\tRoot密码"]
        for ip in visible_ips:
            # 从后台数据源拿真实数据
            d = self.data_store.get(ip, {})
            status = self.host_statuses.get(ip, "Unknown")
            # 拼接成 Tab 分隔的字符串 (方便 Excel 粘贴)
            line = f"{ip}\t{d.get('hostname','')}\t{status}\t{d.get('user','')}\t{d.get('pwd','')}\t{d.get('root_pwd','')}"
            lines.append(line)
        
        # 写入剪贴板
        copy_text = "\n".join(lines)
        self.root.clipboard_clear()
        self.root.clipboard_append(copy_text)
        messagebox.showinfo("成功", f"已复制 {len(visible_ips)} 条数据到剪贴板！\n(包含真实密码，请妥善使用)")

    # --- 升级版右键菜单 (支持多选) ---
    def show_context_menu(self, event):
        # 识别鼠标点击的行
        clicked_item = self.tree.identify_row(event.y)
        if not clicked_item: return

        # 核心逻辑：
        # 如果点击的行不在当前选中范围内 -> 选中该行（取消其他选中）
        # 如果点击的行已经在选中范围内 -> 保持当前的多选状态
        current_selection = self.tree.selection()
        if clicked_item not in current_selection:
            self.tree.selection_set(clicked_item)
            current_selection = [clicked_item] # 更新为单选
        
        # 动态创建菜单
        menu = tk.Menu(self.root, tearoff=0)
        
        if len(current_selection) > 1:
            # === 多选模式 ===
            menu.add_command(label=f"批量运行 ({len(current_selection)} 台)", accelerator="▶️", command=self.run_selected_hosts)
            menu.add_separator()
            # 禁用编辑 (多选不可编辑)
            menu.add_command(label="编辑 (多选不可用)", state="disabled")
            menu.add_command(label=f"批量删除 ({len(current_selection)} 台)", accelerator="🗑️", command=self.delete_selected_hosts)
        else:
            # === 单选模式 ===
            menu.add_command(label="仅运行此主机", accelerator="▶️", command=self.run_selected_hosts)
            menu.add_separator()
            menu.add_command(label="编辑主机信息", accelerator="✏️", command=self.edit_selected_host)
            menu.add_command(label="删除当前主机", accelerator="🗑️", command=self.delete_selected_hosts)
            
        menu.post(event.x_root, event.y_root)

    # --- 批量操作逻辑 ---
    def run_selected_hosts(self):
        sel = self.tree.selection()
        if sel: self.execute_targets(sel)

    def delete_selected_hosts(self):
        sel = self.tree.selection()
        if not sel: return
        
        msg = f"确定要删除选中的 {len(sel)} 台主机吗？"
        if messagebox.askyesno("批量删除", msg):
            for ip in sel:
                if ip in self.data_store: del self.data_store[ip]
                if ip in self.host_statuses: del self.host_statuses[ip]
                if ip in self.host_logs: del self.host_logs[ip]
                self.tree.delete(ip)
            self.save_history()

    def run_all_hosts(self):
        ips = self.tree.get_children()
        self.execute_targets(ips)

    def execute_targets(self, ips_list):
        if self.is_running: return messagebox.showwarning("提示", "任务运行中...")
        if not ips_list: return
        self.is_running = True; self.stop_flag = False
        self.btn_run.config(state="disabled"); self.btn_stop.config(state="normal")
        
        for ip in ips_list:
            self.update_data_status(ip, TaskStatus.WAITING)
            self.host_logs[ip] = f"--- Started at {datetime.datetime.now()} ---\n"
        
        threading.Thread(target=self.run_thread, args=(ips_list,), daemon=True).start()

    # --- 编辑与导入 ---
    def show_smart_import_editor(self):
        win = tk.Toplevel(self.root); win.title("智能导入/编辑")
        self.center_window(win, 700, 500)
        ttk.Label(win, text="每行一台：IP [User] [Pwd] [RootPwd] [Hostname]", foreground="blue").pack(pady=5)
        txt = scrolledtext.ScrolledText(win)
        txt.pack(fill="both", expand=True, padx=10)
        curr = ""
        for ip, d in self.data_store.items():
            curr += f"{d['ip']} {d['user']} {d['pwd']} {d['root_pwd']} {d.get('hostname','')}\n"
        txt.insert("1.0", curr if curr else "# 示例: 192.168.1.100 root 123456 root123 my-server\n")

        def do_update():
            new_hosts = SmartParser.parse_text(txt.get("1.0", "end"))
            self.data_store = {}; self.host_statuses = {}; self.host_logs = {}
            self.tree.delete(*self.tree.get_children())
            for h in new_hosts: self.insert_host_row(h)
            self.save_history()
            messagebox.showinfo("成功", f"更新了 {len(new_hosts)} 台主机"); win.destroy()
        ttk.Button(win, text="💾 更新列表", command=do_update).pack(pady=10)

    def edit_selected_host(self):
        # 仅当单选时可用
        sel = self.tree.selection()
        if len(sel) == 1: self.show_edit_dialog(self.data_store.get(sel[0]))

    def show_edit_dialog(self, data=None):
        win = tk.Toplevel(self.root); win.title("编辑")
        self.center_window(win, 350, 300)
        tk.Label(win, text="IP:").pack(); e1=tk.Entry(win); e1.pack(); 
        if data: e1.insert(0, data['ip'])
        tk.Label(win, text="Hostname:").pack(); e_host=tk.Entry(win); e_host.pack(); 
        if data: e_host.insert(0, data.get('hostname',''))
        tk.Label(win, text="User:").pack(); e2=tk.Entry(win); e2.pack(); 
        if data: e2.insert(0, data['user'])
        tk.Label(win, text="Pwd:").pack(); e3=tk.Entry(win); e3.pack(); 
        if data: e3.insert(0, data['pwd'])
        tk.Label(win, text="RootPwd:").pack(); e4=tk.Entry(win); e4.pack(); 
        if data: e4.insert(0, data['root_pwd'])
        def sv():
            old_ip = data['ip'] if data else None; new_ip = e1.get().strip()
            if old_ip and old_ip != new_ip:
                if old_ip in self.data_store: del self.data_store[old_ip]
                if old_ip in self.host_statuses: del self.host_statuses[old_ip]
            h={'ip': new_ip, 'user': e2.get().strip(), 'pwd': e3.get().strip(), 'root_pwd': e4.get().strip(), 'hostname': e_host.get().strip()}
            self.insert_host_row(h); self.save_history(); win.destroy()
        ttk.Button(win, text="保存", command=sv).pack(pady=10)

    # --- 基础操作 ---
    def reload_config(self): self.config = self.load_config(); messagebox.showinfo("成功", "配置已重载")
    def open_config(self):
        try: os.startfile(CONFIG_FILE)
        except: pass
    def clear_list(self):
        if messagebox.askyesno("确认", "清空?"):
            self.tree.delete(*self.tree.get_children())
            self.data_store = {}; self.host_statuses = {}; self.host_logs = {}; self.save_history()
    
    def on_select_host(self, event):
        # 仅显示选中的第一个主机的日志
        sel = self.tree.selection()
        if not sel: return
        ip = sel[0]
        self.log_area.config(state="normal")
        self.log_area.delete("1.0", "end")
        self.ansi_renderer.insert_ansi_text(self.host_logs.get(ip, ""))
        self.log_area.see("end"); self.log_area.config(state="disabled")

    def save_history(self):
        with open(HOSTS_DATA_FILE, 'w') as f: json.dump(list(self.data_store.values()), f)
    def load_history(self):
        if os.path.exists(HOSTS_DATA_FILE):
            try:
                with open(HOSTS_DATA_FILE, 'r') as f:
                    for h in json.load(f): self.insert_host_row(h)
            except: pass
    def stop_tasks(self):
        if self.is_running: self.stop_flag = True

    # --- 线程与更新 ---
    def run_thread(self, ips_list):
        max_t = self.config.get('settings', {}).get('max_threads', 5)
        done = 0
        with ThreadPoolExecutor(max_workers=max_t) as pool:
            futures = []
            for ip in ips_list:
                if self.stop_flag: break
                worker = SSHWorker(self.data_store[ip], self.config, self.cb_log, self.cb_status)
                futures.append(pool.submit(worker.run))
            for f in as_completed(futures):
                done += 1; self.gui_queue.put(("PROG", (done/len(ips_list))*100))
        self.is_running = False; self.gui_queue.put(("DONE", None))

    def cb_log(self, ip, m): self.gui_queue.put(("LOG", (ip, m)))
    def cb_status(self, ip, s): self.gui_queue.put(("STAT", (ip, s)))

    def process_gui_queue(self):
        while not self.gui_queue.empty():
            try:
                t, d = self.gui_queue.get_nowait()
                if t == "LOG":
                    ip, m = d
                    self.host_logs[ip] += m + "\n"
                    # 如果当前选中了该IP，实时渲染
                    sel = self.tree.selection()
                    if sel and sel[0] == ip:
                        self.log_area.config(state="normal")
                        self.ansi_renderer.insert_ansi_text(m + "\n")
                        self.log_area.see("end"); self.log_area.config(state="disabled")
                elif t == "STAT": self.update_data_status(*d)
                elif t == "PROG": self.progress_var.set(d)
                elif t == "DONE": 
                    self.btn_run.config(state="normal"); self.btn_stop.config(state="disabled")
                    messagebox.showinfo("完成", "任务结束")
            except: pass
        self.root.after(100, self.process_gui_queue)

    def update_data_status(self, ip, s):
        self.host_statuses[ip] = s
        if self.tree.exists(ip):
            vals = list(self.tree.item(ip, "values"))
            vals[2] = s
            self.tree.item(ip, values=vals, tags=(s,))
            color = self.tag_colors.get(s, "black")
            self.tree.tag_configure(s, foreground=color)

if __name__ == "__main__":
    root = tk.Tk()
    try:
        from ctypes import windll
        windll.shcore.SetProcessDpiAwareness(1)
    except: pass
    app = ModernGUI(root)
    root.mainloop()