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
    """获取程序运行真实路径(兼容打包后的环境)"""
    if getattr(sys, 'frozen', False):
        return os.path.dirname(sys.executable)
    return os.path.dirname(os.path.abspath(__file__))


BASE_DIR = get_exe_dir()
CONFIG_FILE = os.path.join(BASE_DIR, "config.yaml")
HOSTS_DATA_FILE = os.path.join(BASE_DIR, "hosts_data.json")
LOG_FILE_NAME = os.path.join(BASE_DIR, "ssh_debug.log")

DEFAULT_CONFIG_CONTENT = """# 全局配置文件
settings:
  max_host_limit: 200     # 最大主机数
  max_threads: 10         # 并发线程数
  timeout: 10             # SSH连接超时(秒)

defaults:
  ssh_port: 22
  # 默认账户（若输入只有IP，将使用此用户）
  user: host
  # 默认登录密码列表（按顺序尝试）
  login_passwords:
    - "12host!@"
    - "Zh#86ji"
  # 默认Root切换密码列表
  root_passwords:
    - "Ro#86ot"
    - "Test#x86"
  # SU 切换正则 (自动兼容中英文冒号)
  su_prompt_regex: "(Password|密码|password|Passwort).*?[:：]"

commands:
  # 只有成功获得 Root 权限后才会执行
  - "whoami"
  - "uptime"
  - "ls -l /tmp"
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
# 1. 核心 SSH 业务逻辑
# ============================
class TaskStatus:
    WAITING = "等待中"
    RUNNING = "执行中"
    SUCCESS = "✅ 成功"
    FAIL_LOGIN = "❌ 登录失败"
    FAIL_ROOT = "❌ 提权失败"
    FAIL_CMD = "⚠️ 命令报错"


class SSHWorker:
    def __init__(self, host_info, config, log_callback, status_callback):
        self.ip = host_info['ip']
        self.user = host_info['user']
        self.pwd = host_info['pwd']
        self.root_pwd = host_info['root_pwd']
        self.config = config
        self.log_cb = log_callback
        self.status_cb = status_callback

        self.defaults = config.get('defaults', {})
        self.commands = config.get('commands', [])
        self.timeout = config.get('settings', {}).get('timeout', 10)

        self.client = None
        self.shell = None

    def log(self, msg):
        ts = datetime.datetime.now().strftime("%H:%M:%S")
        self.log_cb(self.ip, f"[{ts}] {msg}")
        clean_msg = re.sub(r'\x1b\[[0-9;]*[mK]', '', msg)
        sys_logger.info(f"[{self.ip}] {clean_msg}")

    # ---【核心优化 1：强力数据清洗函数】---
    def ensure_str_list(self, raw_data):
        """
        无论 YAML 里写的是整数、字符串、列表还是 None，
        统统转成 [str, str, ...] 格式
        """
        if raw_data is None:
            return []

        # 如果是单个原子类型 (str, int, float)，转为列表
        if not isinstance(raw_data, (list, tuple)):
            raw_data = [raw_data]

        # 强制转字符串并过滤空值
        clean_list = []
        for item in raw_data:
            if item is not None and str(item).strip():
                clean_list.append(str(item).strip())

        return clean_list

    def run(self):
        self.status_cb(self.ip, TaskStatus.RUNNING)
        self.log(f"开始执行任务...")

        try:
            # 1. 准备账户 (优先用指定的，没有则用默认)
            final_user = str(self.user).strip() if self.user else str(self.defaults.get('user', 'root')).strip()

            # ---【核心优化 2：密码合并逻辑】---
            # 获取默认密码列表 (从 yaml)
            default_pwds_raw = self.defaults.get('login_passwords', [])
            # 获取单机密码 (从 GUI/导入)
            host_pwd_raw = self.pwd

            # 使用清洗函数标准化
            list_defaults = self.ensure_str_list(default_pwds_raw)
            list_host = self.ensure_str_list(host_pwd_raw)

            # 合并：优先尝试单机密码，再尝试默认列表
            # 列表去重（保持顺序）
            login_pwds = list(dict.fromkeys(list_host + list_defaults))

            # Root 密码同理
            default_root_raw = self.defaults.get('root_passwords', [])
            host_root_raw = self.root_pwd
            root_pwds = list(
                dict.fromkeys(self.ensure_str_list(host_root_raw) + self.ensure_str_list(default_root_raw)))

            # 调试日志：让您知道到底加载了几个密码 (不打印明文)
            self.log(
                f"加载配置: 用户=[{final_user}], 待试登录密码数=[{len(login_pwds)}], 待试Root密码数=[{len(root_pwds)}]")

            if not login_pwds:
                self.log("❌ 错误: 未配置任何有效的登录密码！")
                self.status_cb(self.ip, TaskStatus.FAIL_LOGIN)
                return

            # 2. SSH 连接
            if not self._connect(final_user, login_pwds):
                self.status_cb(self.ip, TaskStatus.FAIL_LOGIN)
                self.log("❌ 错误：SSH 连接失败 (所有密码均尝试无效)")
                return

            # 3. 权限判断
            if final_user == 'root':
                self.log("当前配置为 root，跳过切换。")
            else:
                current_user = self._get_whoami()
                self.log(f"登录成功，当前用户: {current_user}")

                if "root" not in current_user.lower():
                    if not root_pwds:
                        self.log("⚠️ 警告: 需要切换 Root 但未配置 Root 密码")
                        self.status_cb(self.ip, TaskStatus.FAIL_ROOT)
                        return

                    self.log("尝试 su 切换...")
                    if not self._switch_to_root(root_pwds):
                        self.status_cb(self.ip, TaskStatus.FAIL_ROOT)
                        self.log("❌ 错误：Root 提权失败")
                        return
                    self.log("Root 切换成功")

            # 4. 命令执行
            self.log(f"执行 {len(self.commands)} 条命令...")
            if self._execute_commands():
                self.status_cb(self.ip, TaskStatus.SUCCESS)
                self.log("✅ 任务全部完成。")
            else:
                self.status_cb(self.ip, TaskStatus.FAIL_CMD)
                self.log("⚠️ 警告：部分命令异常。")

        except Exception as e:
            self.status_cb(self.ip, TaskStatus.FAIL_LOGIN)
            self.log(f"💥 异常: {str(e)}")
            sys_logger.error(f"[{self.ip}] Exception", exc_info=True)
        finally:
            if self.client:
                try:
                    self.client.close()
                except:
                    pass

    # ---【核心优化 3：兼容性最强的连接函数】---
    def _connect(self, user, passwords):
        self.client = paramiko.SSHClient()
        self.client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

        for i, pwd in enumerate(passwords):
            # 再次确保是字符串
            pwd_str = str(pwd)
            print(pwd_str)
            try:
                # 记录尝试进度
                self.log(f"正在连接... (尝试第 {i + 1}/{len(passwords)} 个密码)")

                self.client.connect(
                    hostname=self.ip,
                    port=int(self.defaults.get('ssh_port', 22)),  # 确保端口是int
                    username=user,
                    password=pwd_str,

                    # 麒麟/欧拉/CentOS高版本 必加参数
                    timeout=15,
                    banner_timeout=60,
                    auth_timeout=30,
                    look_for_keys=False,  # 禁止公钥防止中断
                    allow_agent=False,  # 禁止代理
                    gss_auth=False  # 禁止GSSAPI
                )
                self.log("SSH 连接建立成功！")
                return True

            except paramiko.AuthenticationException:
                # 密码错误，静默重试下一个
                sys_logger.warning(f"[{self.ip}] 密码 {i + 1} 验证失败")
                continue
            except Exception as e:
                # 其他错误（网络、协议）
                self.log(f"连接尝试报错: {str(e)}")
                # 如果是网络不通，通常换密码也没用，但为了稳健可以继续试，或者break
                # 这里选择 continue 以防万一
                continue

        return False

    def _get_whoami(self):
        try:
            stdin, stdout, stderr = self.client.exec_command("whoami", timeout=10)
            return stdout.read().decode().strip()
        except:
            return "unknown"

    def _read_shell(self, pattern, timeout=10):
        buf = "";
        end = time.time() + timeout
        while time.time() < end:
            if self.shell.recv_ready():
                raw = self.shell.recv(4096).decode('utf-8', errors='ignore')
                buf += raw
                clean_check = re.sub(r'\x1b\[[0-9;]*[mK]', '', buf)
                if re.search(pattern, clean_check): return buf
            time.sleep(0.1)
        return buf

    def _switch_to_root(self, passwords):
        regex = self.defaults.get('su_prompt_regex', r"(Password|密码|password|Passwort).*?[:：]")
        try:
            # width=300 防止自动换行截断提示符
            self.shell = self.client.invoke_shell(width=300, height=100)
            time.sleep(1)

            # 先等待普通的 shell 提示符 ($ 或 >)，跳过 Banner
            user_prompt = r"[\$>] ?$"
            self._read_shell(user_prompt, timeout=5)

            self.shell.send("su -\n")

            # 等待密码输入提示
            if not re.search(regex, self._read_shell(regex, timeout=10)):
                self.log("未检测到 su 密码输入提示符")
                return False

            for pwd in passwords:
                self.shell.send(f"{str(pwd)}\n")

                # 等待结果
                out = self._read_shell(r"(#|failure|认证失败|鉴定故障|incorrect)", timeout=5)
                clean_out = re.sub(r'\x1b\[[0-9;]*[mK]', '', out)

                if "#" in clean_out and not re.search(r"(failure|认证失败|鉴定故障|incorrect)", clean_out,
                                                      re.IGNORECASE):
                    return True

                self.log(f"Root密码尝试失败...")
                # 失败后重新触发 su
                self.shell.send("su -\n")
                self._read_shell(regex)
            return False
        except Exception as e:
            self.log(f"提权异常: {e}")
            return False

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
            except:
                all_ok = False
        return all_ok

# ============================
# 2. ANSI 颜色渲染器 (UI核心增强)
# ============================
class AnsiColorHandler:
    """将 Linux ANSI 颜色转为 Tkinter Tags"""

    def __init__(self, text_widget):
        self.text_widget = text_widget
        self.color_map = {
            '30': 'black', '31': 'red', '32': '#008000', '33': '#B8860B',
            '34': '#0000FF', '35': '#800080', '36': '#008080', '37': 'gray',
            '90': 'gray', '91': '#FF4500', '92': '#32CD32', '93': '#FFD700',
            '94': '#1E90FF', '95': '#FF1493', '96': '#00CED1', '97': 'black',
            '0': 'black', '00': 'black'  # Reset
        }
        self.configure_tags()

    def configure_tags(self):
        for code, color in self.color_map.items():
            self.text_widget.tag_config(f"fg_{code}", foreground=color)
        self.text_widget.tag_config("bold", font=('Consolas', 10, 'bold'))

    def insert_ansi_text(self, content):
        # 修复核心：正则改为匹配 m (颜色) 和 K (清除行) 等所有控制符
        # [0-9;]*  匹配数字和分号
        # [a-zA-Z] 匹配结尾的字母 (m, K, H, J 等)
        parts = re.split(r'(\x1b\[[0-9;]*[a-zA-Z])', content)

        current_tags = []

        for part in parts:
            if not part: continue

            if part.startswith('\x1b['):
                # === 处理控制符 ===

                # 情况A: 颜色代码 (以 m 结尾) -> 更新颜色Tag
                if part.endswith('m'):
                    codes = part[2:-1].split(';')
                    for c in codes:
                        if c in ['0', '00']:
                            current_tags = []  # 重置
                        elif c in ['1', '01']:
                            current_tags.append('bold')  # 粗体
                        elif c in self.color_map:
                            # 移除旧颜色，应用新颜色
                            current_tags = [t for t in current_tags if not t.startswith('fg_')]
                            current_tags.append(f"fg_{c}")

                # 情况B: 清除行代码 (以 K 结尾) -> 忽略，不显示
                # \x1b[K 是导致不换行的罪魁祸首，这里直接忽略它
                elif part.endswith('K'):
                    pass

                # 其他控制符也忽略
                else:
                    pass

            else:
                # === 处理普通文本 ===
                # 这里 part 可能包含 \r\n，Tkinter 会正确处理换行
                self.text_widget.insert('end', part, tuple(current_tags))


# ============================
# 3. 界面逻辑
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
            hosts.append({'ip': ip, 'user': user, 'pwd': pwd, 'root_pwd': root_pwd})
        return hosts


class ModernGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("SSH 批量运维工具 v4.0 (彩色终端版)")
        self.root.geometry("1200x800")

        self.ensure_config()
        self.config = self.load_config()

        self.host_logs = {}  # 存储原始含ANSI的日志
        self.data_store = {}
        self.is_running = False
        self.stop_flag = False
        self.gui_queue = queue.Queue()

        self.setup_styles()
        self.create_layout()
        self.create_context_menu()
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
            with open(CONFIG_FILE, 'r', encoding='utf-8') as f:
                return yaml.safe_load(f)
        except:
            return {}

    def setup_styles(self):
        style = ttk.Style()
        style.configure("Treeview", rowheight=28, font=('Microsoft YaHei', 10))
        self.tag_colors = {
            TaskStatus.WAITING: "black", TaskStatus.RUNNING: "#0000FF",
            TaskStatus.SUCCESS: "#008000", TaskStatus.FAIL_LOGIN: "#FF0000",
            TaskStatus.FAIL_ROOT: "#8B0000", TaskStatus.FAIL_CMD: "#FF8C00"
        }

    def create_layout(self):
        # 工具栏
        toolbar = ttk.Frame(self.root, padding=5)
        toolbar.pack(fill="x")
        ttk.Button(toolbar, text="📝 智能导入/编辑", command=self.show_smart_import_editor).pack(side="left", padx=2)
        ttk.Button(toolbar, text="🗑️ 清空", command=self.clear_list).pack(side="left", padx=2)
        ttk.Separator(toolbar, orient="vertical").pack(side="left", fill="y", padx=10)
        ttk.Button(toolbar, text="⚙️ 打开配置", command=self.open_config).pack(side="left", padx=2)
        ttk.Button(toolbar, text="🔄 重载配置", command=self.reload_config).pack(side="left", padx=2)

        self.btn_run = ttk.Button(toolbar, text="🚀 全部执行", command=self.run_all_hosts)
        self.btn_run.pack(side="right", padx=5)
        self.btn_stop = ttk.Button(toolbar, text="⏹ 停止", state="disabled", command=self.stop_tasks)
        self.btn_stop.pack(side="right", padx=5)

        # 进度条
        self.progress_var = tk.DoubleVar()
        ttk.Progressbar(self.root, variable=self.progress_var, maximum=100).pack(fill="x")

        # 分屏
        paned = ttk.PanedWindow(self.root, orient="horizontal")
        paned.pack(fill="both", expand=True)

        # 左侧列表
        left = ttk.LabelFrame(paned, text="主机列表 (右键菜单可用)", padding=5)
        paned.add(left, weight=1)
        cols = ("ip", "status", "user", "pwd", "root_pwd")
        self.tree = ttk.Treeview(left, columns=cols, show="headings")
        self.tree.heading("ip", text="IP");
        self.tree.column("ip", width=120)
        self.tree.heading("status", text="状态");
        self.tree.column("status", width=80)
        self.tree.heading("user", text="用户");
        self.tree.column("user", width=70)
        self.tree.heading("pwd", text="密码");
        self.tree.column("pwd", width=70)
        self.tree.heading("root_pwd", text="Root密码");
        self.tree.column("root_pwd", width=70)

        vsb = ttk.Scrollbar(left, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=vsb.set)
        self.tree.pack(side="left", fill="both", expand=True);
        vsb.pack(side="right", fill="y")

        self.tree.bind("<<TreeviewSelect>>", self.on_select_host)
        self.tree.bind("<Button-3>", self.show_context_menu)

        # 右侧日志
        right = ttk.LabelFrame(paned, text="详情日志 (支持 ANSI 颜色)", padding=5)
        paned.add(right, weight=2)
        self.log_area = scrolledtext.ScrolledText(right, state="disabled", font=('Consolas', 10))
        self.log_area.pack(fill="both", expand=True)

        # 初始化 ANSI 渲染器
        self.ansi_renderer = AnsiColorHandler(self.log_area)

    def create_context_menu(self):
        self.context_menu = tk.Menu(self.root, tearoff=0)
        self.context_menu.add_command(label="仅运行此主机", accelerator="▶️", command=self.run_selected_host)
        self.context_menu.add_separator()
        self.context_menu.add_command(label="编辑主机信息", accelerator="✏️", command=self.edit_selected_host)
        self.context_menu.add_command(label="删除当前主机", accelerator="🗑️", command=self.delete_selected_host)

    def show_context_menu(self, event):
        item = self.tree.identify_row(event.y)
        if item:
            self.tree.selection_set(item)
            self.context_menu.post(event.x_root, event.y_root)

    # --- 交互逻辑 ---
    def run_all_hosts(self):
        self.execute_targets(self.tree.get_children())

    def run_selected_host(self):
        sel = self.tree.selection()
        if sel: self.execute_targets([sel[0]])

    def execute_targets(self, ips_list):
        if self.is_running:
            messagebox.showwarning("提示", "任务运行中...");
            return
        if not ips_list: return
        self.is_running = True;
        self.stop_flag = False
        self.btn_run.config(state="disabled");
        self.btn_stop.config(state="normal")

        for ip in ips_list:
            self.update_ui_status(ip, TaskStatus.WAITING)
            self.host_logs[ip] = f"--- Started at {datetime.datetime.now()} ---\n"

        threading.Thread(target=self.run_thread, args=(ips_list,), daemon=True).start()

    def show_smart_import_editor(self):
        win = tk.Toplevel(self.root);
        win.title("智能导入/编辑")
        self.center_window(win, 600, 500)
        lbl = ttk.Label(win, text="格式：IP [用户] [密码] [Root密码]", foreground="blue");
        lbl.pack(pady=5)
        txt = scrolledtext.ScrolledText(win)
        txt.pack(fill="both", expand=True, padx=10)

        curr = ""
        for c in self.tree.get_children():
            if c in self.data_store:
                d = self.data_store[c]
                curr += f"{d['ip']} {d['user']} {d['pwd']} {d['root_pwd']}\n"
        txt.insert("1.0", curr if curr else "# 示例: 192.168.1.100 root 123456\n")

        def do_update():
            new_hosts = SmartParser.parse_text(txt.get("1.0", "end"))
            self.tree.delete(*self.tree.get_children())
            self.data_store = {};
            self.host_logs = {}
            for h in new_hosts: self.insert_host_row(h)
            self.save_history()
            messagebox.showinfo("成功", f"更新了 {len(new_hosts)} 台主机");
            win.destroy()

        ttk.Button(win, text="💾 更新列表", command=do_update).pack(pady=10)

    # --- 基础操作 ---
    def reload_config(self):
        self.config = self.load_config()
        messagebox.showinfo("成功", "配置已重载")

    def open_config(self):
        try:
            os.startfile(CONFIG_FILE)
        except:
            pass

    def edit_selected_host(self):
        sel = self.tree.selection()
        if sel: self.show_edit_dialog(self.data_store.get(sel[0]))

    def delete_selected_host(self):
        sel = self.tree.selection()
        if sel and messagebox.askyesno("删除", "确定删除?"):
            self.remove_host_by_ip(sel[0]);
            self.save_history()

    def show_edit_dialog(self, data=None):
        win = tk.Toplevel(self.root);
        win.title("编辑")
        self.center_window(win, 300, 250)
        tk.Label(win, text="IP:").pack();
        e1 = tk.Entry(win);
        e1.pack();
        if data: e1.insert(0, data['ip'])
        tk.Label(win, text="User:").pack();
        e2 = tk.Entry(win);
        e2.pack();
        if data: e2.insert(0, data['user'])
        tk.Label(win, text="Pwd:").pack();
        e3 = tk.Entry(win);
        e3.pack();
        if data: e3.insert(0, data['pwd'])
        tk.Label(win, text="RootPwd:").pack();
        e4 = tk.Entry(win);
        e4.pack();
        if data: e4.insert(0, data['root_pwd'])

        def sv():
            h = {'ip': e1.get(), 'user': e2.get(), 'pwd': e3.get(), 'root_pwd': e4.get()}
            if data and data['ip'] != h['ip']: self.remove_host_by_ip(data['ip'])
            self.insert_host_row(h);
            self.save_history();
            win.destroy()

        ttk.Button(win, text="保存", command=sv).pack(pady=10)

    def insert_host_row(self, h):
        if self.tree.exists(h['ip']): self.tree.delete(h['ip'])
        self.tree.insert("", "end", iid=h['ip'], values=(
        h['ip'], TaskStatus.WAITING, h['user'], "***" if h['pwd'] else "", "***" if h['root_pwd'] else ""))
        self.host_logs[h['ip']] = f"--- {h['ip']} Ready ---\n"
        if not hasattr(self, 'data_store'): self.data_store = {}
        self.data_store[h['ip']] = h

    def remove_host_by_ip(self, ip):
        if self.tree.exists(ip): self.tree.delete(ip)
        if ip in self.data_store: del self.data_store[ip]
        if ip in self.host_logs: del self.host_logs[ip]

    def clear_list(self):
        if messagebox.askyesno("确认", "清空?"):
            self.tree.delete(*self.tree.get_children())
            self.data_store = {};
            self.host_logs = {};
            self.save_history()

    def on_select_host(self, event):
        sel = self.tree.selection()
        if not sel: return
        ip = sel[0]
        # 刷新右侧日志，带颜色渲染
        self.log_area.config(state="normal")
        self.log_area.delete("1.0", "end")
        self.ansi_renderer.insert_ansi_text(self.host_logs.get(ip, ""))
        self.log_area.see("end")
        self.log_area.config(state="disabled")

    def save_history(self):
        with open(HOSTS_DATA_FILE, 'w') as f: json.dump(list(self.data_store.values()), f)

    def load_history(self):
        if os.path.exists(HOSTS_DATA_FILE):
            try:
                with open(HOSTS_DATA_FILE, 'r') as f:
                    for h in json.load(f): self.insert_host_row(h)
            except:
                pass

    def stop_tasks(self):
        if self.is_running: self.stop_flag = True

    # --- 多线程逻辑 ---
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
                done += 1;
                self.gui_queue.put(("PROG", (done / len(ips_list)) * 100))
        self.is_running = False;
        self.gui_queue.put(("DONE", None))

    def cb_log(self, ip, m):
        self.gui_queue.put(("LOG", (ip, m)))

    def cb_status(self, ip, s):
        self.gui_queue.put(("STAT", (ip, s)))

    def process_gui_queue(self):
        while not self.gui_queue.empty():
            try:
                t, d = self.gui_queue.get_nowait()
                if t == "LOG":
                    ip, m = d
                    self.host_logs[ip] += m + "\n"
                    if self.tree.selection() and self.tree.selection()[0] == ip:
                        self.log_area.config(state="normal")
                        self.ansi_renderer.insert_ansi_text(m + "\n")
                        self.log_area.see("end");
                        self.log_area.config(state="disabled")
                elif t == "STAT":
                    self.update_ui_status(*d)
                elif t == "PROG":
                    self.progress_var.set(d)
                elif t == "DONE":
                    self.btn_run.config(state="normal");
                    self.btn_stop.config(state="disabled")
                    messagebox.showinfo("完成", "任务结束")
            except:
                pass
        self.root.after(100, self.process_gui_queue)

    def update_ui_status(self, ip, s):
        if self.tree.exists(ip):
            vals = list(self.tree.item(ip, "values"))
            vals[1] = s
            self.tree.item(ip, values=vals, tags=(s,))
            if s in self.tag_colors:
                self.tree.tag_configure(s, foreground=self.tag_colors[s])
            else:
                self.tree.tag_configure(s, foreground="black")


if __name__ == "__main__":
    root = tk.Tk()
    try:
        from ctypes import windll

        windll.shcore.SetProcessDpiAwareness(1)
    except:
        pass
    app = ModernGUI(root)
    root.mainloop()