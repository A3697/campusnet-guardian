"""campusnet 图形界面（给完全不懂命令行的人用）。

设计原则：

- 双击就能用：第一次运行自动引导填账号，之后一键连接；
- **所有**报错都翻译成大白话，技术细节落到本地日志文件里；
- 只依赖标准库（tkinter）。``keyring`` 可选 —— 打包版自带，
  用来把密码存进系统凭据管理器，磁盘上不留明文。

打包方式见 ``release/build_exe.py``。
"""

from __future__ import annotations

import base64
import datetime
import os
import queue
import sys
import threading
import time
import traceback
from typing import Any, Dict, List, Optional, Tuple

from . import __version__, autostart, carrier, policy, singleton
from . import wifi as _wifi
from .config import Config, _keyring_set, has_keyring, runtime_log_dir
from .runner import Runner

APP_TITLE = "校园网连接守护"
#: 冒烟自检用的环境变量：值为"秒数"（如 "2"），加 ",setup" 表示同时打开设置页
SMOKE_ENV = "CAMPUSNET_GUI_SMOKE"
ERROR_LOG_NAME = "gui-errors.log"

# ---------------------------------------------------------------- 主题色
# 冷灰纸面 + 青墨主色：靠留白和 1px 细线分层，不堆阴影和渐变
BG = "#f1f3f6"
CARD = "#ffffff"
BORDER = "#e3e7ed"
TEXT = "#161b22"
MUTED = "#6b7480"
FAINT = "#9aa3af"
GREEN = "#0f7a5a"
RED = "#b42318"
AMBER = "#b45309"
BLUE = "#0f766e"
BLUE_DARK = "#0b5b55"
BLUE_SOFT = "#e8f3f1"
GRAY_BTN = "#eef1f5"
GRAY_BTN_DARK = "#e1e7ee"

FONT_FAMILY = "Microsoft YaHei UI"
FONT = (FONT_FAMILY, 10)
FONT_SMALL = (FONT_FAMILY, 9)
FONT_LABEL = (FONT_FAMILY, 9, "bold")
FONT_BOLD = (FONT_FAMILY, 10, "bold")
FONT_TITLE = (FONT_FAMILY, 18, "bold")
FONT_PAGE = (FONT_FAMILY, 15, "bold")


# ---------------------------------------------------------------- 错误与日志
def _error_log_path() -> str:
    return os.path.join(runtime_log_dir(), ERROR_LOG_NAME)


def _write_error_log(detail: str) -> str:
    """把技术细节追加到本地日志，返回路径（失败返回空串）。"""
    try:
        path = _error_log_path()
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "a", encoding="utf-8") as fh:
            fh.write("\n---- {} ----\n{}\n".format(
                datetime.datetime.now().isoformat(timespec="seconds"), detail))
        return path
    except Exception:  # noqa: BLE001 - 日志写不进去也不能二次报错
        return ""


def friendly_message(exc: BaseException) -> str:
    """把异常翻译成人话。"""
    import socket
    import urllib.error

    if isinstance(exc, (urllib.error.URLError, socket.timeout,
                        ConnectionError, TimeoutError, OSError)):
        return ("连不上校园网认证服务。\n\n"
                "请先确认电脑已经连上校园 Wi-Fi（或插着校园网线），"
                "然后回到窗口再点一次「立即重新认证」。")
    if isinstance(exc, ValueError):
        return ("本机的配置文件读不出来（可能被误改坏了）。\n\n"
                "点「账号设置」重新保存一遍账号密码，就能修复。")
    return ("程序遇到了一个没预料到的问题，你的账号信息不受影响。\n\n"
            "可以再试一次；如果反复出现，请把日志文件发给会电脑的人帮忙看看。")


# ---------------------------------------------------------------- 界面
class App:
    """一个窗口两块面板：主面板（日常用） + 设置面板（首次/改账号）。"""

    def __init__(self, root: "tk.Tk", start_in_tray: bool = False,
                 activation: Optional[singleton.DesktopActivation] = None) -> None:  # noqa: F821
        self.root = root
        self._activation = activation
        if start_in_tray:
            self.root.withdraw()
        self.q: "queue.Queue[Tuple]" = queue.Queue()
        self._config_error = ""
        self.cfg = self._load_config()
        self._busy = False
        self._active_job = None
        self._state_pending = False
        self._state_revision = 0
        self._last_status_started = 0.0
        self._page = "main"
        self._closing = False
        self._logs_open = False
        self._watch_log_offset = None
        self._icon_ref: Any = None
        # 双击自动连接只做一次：连不上就交给用户看日志手动处理，
        # 不然状态刷新会让它无限重试
        # At sign-in the watcher owns authentication, including its pause/time policy.
        self._auto_connect_done = start_in_tray
        self._tray: Any = None
        self._policy_win: Any = None
        self._policy_canvas: Any = None

        self._build_window()
        self._build_main()
        self._build_setup()
        self._build_log()
        self._build_feedback()

        # 关窗口不等于退出：有托盘就藏起来，没有托盘才真的退出
        self.root.protocol("WM_DELETE_WINDOW", self.hide_to_tray)

        self.root.after(80, self._poll_queue)
        if self._configured():
            self.show_main()
        else:
            self.show_setup(first_time=True)
        self._start_tray()
        if start_in_tray and self._tray is None:
            self.show_window()
        if getattr(sys, "frozen", False):
            self._spawn(self._ensure_watch)
        self.root.bind("<F5>", lambda _e: self._request_state())
        self.root.bind("<Control-Return>", self._primary_shortcut)
        self._wheel_tag = "CampusnetScroll{}".format(id(self))
        self.root.bind_class(self._wheel_tag, "<MouseWheel>", self._scroll_page)
        self.root.bind_class(self._wheel_tag, "<FocusIn>", self._reveal_focus)
        self._install_scroll_bindings(self.root)
        self.root.after(5000, self._periodic_refresh)

    def _ensure_watch(self) -> None:
        if autostart.ensure_desktop_watch(self.cfg.path):
            self.q.put(("log", "已启动后台自动重连监测", "ok"))

    # ------------------------------------------------------------ 基础
    def _load_config(self) -> Config:
        try:
            return Config.load()
        except (OSError, ValueError) as exc:
            self._config_error = str(exc)
            return Config()

    def _configured(self) -> bool:
        return bool(self.cfg.username) and bool(self.cfg.resolve_password(prompt=False))

    def _runner(self) -> Runner:
        def log(msg: str, level: str = "info") -> None:
            self.q.put(("log", msg, level))

        return Runner(self.cfg, logger=log)

    def _spawn(self, fn, *args) -> None:
        revision = self._state_revision
        def safe() -> None:
            try:
                fn(*args)
            except Exception as exc:  # noqa: BLE001 - 线程里的错必须兜住
                detail = traceback.format_exc()
                path = _write_error_log(detail)
                if fn == self._job_state:
                    kind = "state_error"
                elif fn in (self._job_connect, self._job_health, self._job_save_setup, self._job_toggle_autostart):
                    kind = "fatal"
                else:
                    kind = "background_error"
                self.q.put((kind, friendly_message(exc), detail, path, revision))

        threading.Thread(target=safe, daemon=True).start()

    # ------------------------------------------------------------ 窗口骨架
    def _build_window(self) -> None:
        self.root.title("{} v{}".format(APP_TITLE, __version__))
        # 本机可能是 125%/150% 缩放：字号按点放大，像素尺寸也得跟着放大，
        # 否则 580px 的窗口装不下加粗放大后的文字（按钮会被裁掉）
        self._scale = max(1.0, self.root.winfo_fpixels("1i") / 96.0)
        scale = self._scale
        avail = (self.root.winfo_screenheight() - self._px(80)) / scale
        height = int(min(780, max(500, avail)) * scale)
        self.root.geometry("{}x{}".format(self._px(660), height))
        # 可缩放 + 设下限：小屏/高缩放本子上内容放得下放不下，用户都能自救
        self.root.resizable(True, True)
        self.root.minsize(self._px(540), self._px(460))
        self.root.configure(bg=BG)
        try:
            from ._icon_data import ICON_PNG_B64
            self._icon_ref = self.root.tk.PhotoImage(data=base64.b64decode(ICON_PNG_B64))
            self.root.iconphoto(True, self._icon_ref)
        except Exception:  # noqa: BLE001 - 图标只是锦上添花
            pass
        self._style_ttk()

    def _px(self, value: float) -> int:
        """把设计稿里的逻辑像素换算成当前屏幕的物理像素。"""
        return int(round(value * getattr(self, "_scale", 1.0)))

    def _style_ttk(self) -> None:
        """把 ttk 输入控件统一成扁平的纸面风格（系统主题自带的灰底块会和卡片打架）。"""
        from tkinter import ttk

        style = ttk.Style(self.root)
        try:
            style.theme_use("clam")
        except Exception:  # noqa: BLE001 - 极端情况下沿用系统主题
            pass
        style.configure(".", font=FONT, background=BG, foreground=TEXT)
        style.configure("TFrame", background=BG)
        style.configure("TLabel", background=BG, foreground=TEXT)
        style.configure("TEntry", fieldbackground=CARD, foreground=TEXT,
                        bordercolor=BORDER, lightcolor=BORDER, darkcolor=BORDER,
                        insertcolor=TEXT, padding=(self._px(9), self._px(7)))
        style.map("TEntry",
                  bordercolor=[("focus", BLUE)],
                  lightcolor=[("focus", BLUE)],
                  darkcolor=[("focus", BLUE)])
        style.configure("TCombobox", fieldbackground=CARD, background=CARD,
                        foreground=TEXT, bordercolor=BORDER, arrowcolor=MUTED,
                        padding=(self._px(9), self._px(6)),
                        arrowsize=self._px(14))
        style.map("TCombobox",
                  fieldbackground=[("readonly", CARD)],
                  foreground=[("readonly", TEXT)],
                  background=[("active", CARD)],
                  bordercolor=[("focus", BLUE), ("hover", BLUE)])
        style.configure("TSpinbox", fieldbackground=CARD, background=CARD,
                        foreground=TEXT, bordercolor=BORDER, arrowcolor=MUTED,
                        padding=(self._px(9), self._px(7)), arrowsize=self._px(12))
        style.map("TSpinbox",
                  bordercolor=[("focus", BLUE)],
                  background=[("active", CARD)])
        style.configure("TCheckbutton", background=CARD, foreground=TEXT,
                        font=FONT_SMALL, focuscolor=CARD)
        style.map("TCheckbutton",
                  background=[("active", CARD)],
                  foreground=[("active", TEXT)])
        style.configure("Vertical.TScrollbar", background=GRAY_BTN,
                        troughcolor=BG, bordercolor=BG, arrowcolor=MUTED,
                        gripcount=0, arrowsize=self._px(12))
        self.root.option_add("*TCombobox*Listbox.background", CARD)
        self.root.option_add("*TCombobox*Listbox.foreground", TEXT)
        self.root.option_add("*TCombobox*Listbox.selectBackground", BLUE)
        self.root.option_add("*TCombobox*Listbox.selectForeground", "#ffffff")
        self.root.option_add("*TCombobox*Listbox.font", FONT)

    def _label(self, parent, text: str = "", **kw) -> "tk.Label":  # noqa: F821
        kw.setdefault("bg", kw.pop("bg_", BG))
        kw.setdefault("fg", TEXT)
        kw.setdefault("font", FONT)
        kw.setdefault("anchor", "w")
        kw.setdefault("bd", 0)
        import tkinter as tk
        return tk.Label(parent, text=text, **kw)

    def _card(self, parent, padx: int = 20, pady: int = 16) -> "tk.Frame":  # noqa: F821
        """白卡片：1px 细边 + 足够内边距，靠留白而不是阴影分层。"""
        import tkinter as tk
        return tk.Frame(parent, bg=CARD, padx=self._px(padx), pady=self._px(pady),
                        highlightbackground=BORDER, highlightthickness=1)

    def _rule(self, parent, pady: Tuple[int, int] = (8, 8)) -> "tk.Frame":  # noqa: F821
        """卡片内部的分隔细线。"""
        import tkinter as tk
        line = tk.Frame(parent, bg=BORDER, height=1)
        line.pack(fill="x", pady=(self._px(pady[0]), self._px(pady[1])))
        return line


    def _button(self, parent, text: str, command, kind: str = "normal") -> "tk.Button":  # noqa: F821
        import tkinter as tk
        # (底色, 字色, 悬停底色, 描边色, 悬停描边色) —— 描边恒为 1px，各按钮等高
        skins = {
            "primary": (BLUE, "#ffffff", BLUE_DARK, BLUE, BLUE_DARK),
            "normal": (GRAY_BTN, TEXT, GRAY_BTN_DARK, BORDER, BORDER),
            "danger": (CARD, RED, "#fbf0ee", BORDER, BORDER),
        }
        bg, fg, hover, edge, edge_hover = skins.get(kind, skins["normal"])

        def alive() -> bool:
            try:
                return str(btn["state"]) != "disabled"
            except Exception:  # noqa: BLE001 - 按钮已销毁
                return False

        def on_enter(_e=None) -> None:
            if alive():
                btn.configure(bg=hover, highlightbackground=edge_hover)

        def on_leave(_e=None) -> None:
            if alive():
                btn.configure(bg=bg, highlightbackground=edge)

        btn = tk.Button(parent, text=text, command=command, font=FONT_BOLD,
                        bg=bg, fg=fg, activebackground=hover, activeforeground=fg,
                        relief="flat", cursor="hand2",
                        padx=self._px(16), pady=self._px(8),
                        bd=0, highlightthickness=1,
                        highlightbackground=edge,
                        highlightcolor=BLUE, takefocus=1)
        btn.bind("<Enter>", on_enter)
        btn.bind("<Leave>", on_leave)
        return btn

    def _reveal_focus(self, event) -> None:
        widget = event.widget
        for canvas in (getattr(self, "_main_canvas", None), getattr(self, "_setup_canvas", None),
                       self._policy_canvas):
            if canvas is None or not str(widget).startswith(str(canvas) + ".") or not canvas.winfo_ismapped():
                continue
            canvas.update_idletasks()
            top = widget.winfo_rooty() - canvas.winfo_rooty()
            bottom = top + widget.winfo_height()
            delta = min(top - self._px(8), 0) + max(bottom - canvas.winfo_height() + self._px(8), 0)
            bounds = canvas.bbox("all")
            if delta and bounds:
                canvas.yview_moveto(canvas.yview()[0] + delta / max(1, bounds[3]))
            return

    # ------------------------------------------------------------ 主面板
    def _build_main(self) -> None:
        import tkinter as tk
        from tkinter import ttk

        self.main_frame = tk.Frame(self.root, bg=BG)
        self._main_canvas = tk.Canvas(self.main_frame, bg=BG, highlightthickness=0)
        scrollbar = ttk.Scrollbar(self.main_frame, command=self._main_canvas.yview)
        self._main_canvas.configure(yscrollcommand=scrollbar.set)
        scrollbar.pack(side="right", fill="y")
        self._main_canvas.pack(side="left", fill="both", expand=True)
        content = tk.Frame(self._main_canvas, bg=BG)
        self._main_content = content
        self._main_canvas.create_window((0, 0), window=content, anchor="nw", tags="content")
        content.bind("<Configure>", lambda _e: self._main_canvas.configure(
            scrollregion=self._main_canvas.bbox("all")))
        self._main_canvas.bind("<Configure>", lambda e: self._main_canvas.itemconfigure("content", width=e.width))

        head = tk.Frame(content, bg=BG)
        head.pack(fill="x", padx=self._px(24), pady=(self._px(20), self._px(10)))
        self._label(head, APP_TITLE, font=FONT_BOLD).pack(side="left")
        self.lbl_updated = self._label(head, "正在读取状态", fg=MUTED, font=FONT_SMALL)
        self.lbl_updated.pack(side="right")

        status_card = self._card(content, pady=18)
        status_card.pack(fill="x", padx=self._px(24))
        status_row = tk.Frame(status_card, bg=CARD)
        status_row.pack(fill="x")
        self._dot = tk.Canvas(status_row, width=self._px(14), height=self._px(14),
                              bg=CARD, highlightthickness=0)
        self._dot_item = self._dot.create_oval(2, 2, self._px(12), self._px(12), fill=FAINT, outline="")
        self._dot.pack(side="left", padx=(0, self._px(10)))
        self.lbl_status = self._label(status_row, "正在检查网络", bg_=CARD, font=FONT_TITLE)
        self.lbl_status.pack(side="left")
        self.lbl_detail = self._label(status_card, "正在核对校园网会话和网页访问。",
                                      bg_=CARD, fg=MUTED, font=FONT_SMALL, justify="left")
        self.lbl_detail.pack(fill="x", pady=(self._px(8), self._px(14)))
        self.lbl_detail.bind("<Configure>", lambda e: self.lbl_detail.configure(wraplength=max(100, e.width)))
        actions = tk.Frame(status_card, bg=CARD)
        actions.pack(fill="x")
        actions.columnconfigure(0, weight=2)
        actions.columnconfigure(1, weight=1)
        self.btn_connect = self._button(actions, "连接校园网", lambda: self.connect(True), "primary")
        self.btn_connect.grid(row=0, column=0, sticky="ew", padx=(0, self._px(10)))
        self.btn_health = self._button(actions, "检测网络", self.health_check)
        self.btn_health.grid(row=0, column=1, sticky="ew")

        card = self._card(content, pady=14)
        card.pack(fill="x", padx=self._px(24), pady=self._px(12))
        title = tk.Frame(card, bg=CARD)
        title.pack(fill="x", pady=(0, self._px(8)))
        self._label(title, "上网账号", bg_=CARD, font=FONT_BOLD).pack(side="left")
        self.btn_setup = self._button(title, "账号设置", lambda: self.show_setup(False))
        self.btn_setup.pack(side="right")
        self.var_show_pw = tk.BooleanVar(value=True)
        self._saved_password = ""
        self.info_vars = {}
        for key, label in (("username", "账号"), ("password", "密码"), ("carrier", "运营商"), ("portal", "认证门户")):
            row = tk.Frame(card, bg=CARD)
            row.pack(fill="x", pady=self._px(4))
            row.columnconfigure(1, weight=1)
            self._label(row, label, bg_=CARD, fg=MUTED, font=FONT_SMALL, width=8).grid(row=0, column=0, sticky="nw")
            value = self._label(row, "…", bg_=CARD, width=1, justify="left")
            value.grid(row=0, column=1, sticky="ew")
            value.bind("<Configure>", lambda e, value=value: value.configure(wraplength=max(80, e.width)))
            self.info_vars[key] = value
            if key == "password":
                ttk.Checkbutton(row, text="显示密码", variable=self.var_show_pw,
                                command=self._refresh_password_visibility).grid(row=0, column=2, padx=(self._px(12), 0))

        card = self._card(content, pady=14)
        card.pack(fill="x", padx=self._px(24))
        title = tk.Frame(card, bg=CARD)
        title.pack(fill="x")
        self._label(title, "自动连接", bg_=CARD, font=FONT_BOLD).pack(side="left")
        self.btn_policy = self._button(title, "重连策略", self.show_policy)
        self.btn_policy.pack(side="right")
        for key, label in (("watch", "后台监测"), ("autostart", "登录自启")):
            row = tk.Frame(card, bg=CARD)
            row.pack(fill="x", pady=self._px(4))
            self._label(row, label, bg_=CARD, fg=MUTED, font=FONT_SMALL, width=8).pack(side="left")
            self.info_vars[key] = self._label(row, "正在检查", bg_=CARD)
            self.info_vars[key].pack(side="left")
            if key == "autostart":
                self.btn_autostart = self._button(row, "开启自启", self.toggle_autostart)
                self.btn_autostart.pack(side="right")
        self.info_vars["policy"] = self._label(card, "", bg_=CARD, fg=MUTED, font=FONT_SMALL, justify="left")
        self.info_vars["policy"].pack(fill="x", pady=(self._px(6), self._px(10)))
        self.info_vars["policy"].bind("<Configure>", lambda e: self.info_vars["policy"].configure(wraplength=max(100, e.width)))
        self._rule(card, (0, 10))
        pause = tk.Frame(card, bg=CARD)
        pause.pack(fill="x")
        self.var_pause = tk.StringVar(value="30")
        self.spin_pause = ttk.Spinbox(pause, from_=1, to=1440, width=5, textvariable=self.var_pause, font=FONT, justify="center")
        self.spin_pause.pack(side="left")
        self.spin_pause.bind("<Return>", lambda _e: self._pause_from_input())
        self._label(pause, "分钟", bg_=CARD, fg=MUTED, font=FONT_SMALL).pack(side="left", padx=self._px(8))
        self.btn_pause = self._button(pause, "暂停重连", self._pause_from_input)
        self.btn_pause.pack(side="left", padx=(0, self._px(8)))
        self.btn_resume = self._button(pause, "恢复重连", self.resume_reconnect)
        self.btn_resume.pack(side="left")

    # ------------------------------------------------------------ 设置面板
    def _build_setup(self) -> None:
        import tkinter as tk
        from tkinter import ttk

        self.setup_frame = tk.Frame(self.root, bg=BG)
        form = tk.Frame(self.setup_frame, bg=BG)

        # 表单比窗口高时（小屏 / 150% 缩放的本子）必须能滚动，否则填不到底。
        # 滚轮在 show_setup 里绑定、切走时解绑，避免劫持日志区的滚动。
        canvas = tk.Canvas(form, bg=BG, highlightthickness=0)
        vsb = ttk.Scrollbar(form, orient="vertical", command=canvas.yview)
        canvas.configure(yscrollcommand=vsb.set)
        vsb.pack(side="right", fill="y")
        canvas.pack(side="left", fill="both", expand=True)
        inner = tk.Frame(canvas, bg=BG)
        canvas.create_window((0, 0), window=inner, anchor="nw", tags="inner")
        inner.bind("<Configure>",
                   lambda _e: canvas.configure(scrollregion=canvas.bbox("all")))
        canvas.bind("<Configure>",
                    lambda _e: canvas.itemconfigure("inner", width=_e.width))
        self._setup_canvas = canvas
        self._setup_inner = inner

        head = self._label(inner, "账号设置",
                           bg_=BG, font=FONT_PAGE)
        head.pack(pady=(self._px(24), self._px(4)))
        self._label(inner, "保存上网信息，可选择立即连接。",
                    bg_=BG, fg=MUTED,
                    font=FONT_SMALL).pack(pady=(0, self._px(14)))

        card = self._card(inner)
        card.pack(fill="x", padx=self._px(24))

        self.var_username = tk.StringVar()
        self.var_password = tk.StringVar()
        self._setup_saved_password = ""
        self.var_username.trace_add("write", self._on_setup_username_change)
        self.var_ssid = tk.StringVar()
        self.var_autostart = tk.BooleanVar(value=True)

        def field(row: int, title: str, widget, hint: str = "") -> None:
            self._label(card, title, bg_=CARD, font=FONT_BOLD)\
                .grid(row=row, column=0, sticky="w",
                      pady=(self._px(12), self._px(3)))
            widget.grid(row=row + 1, column=0, sticky="ew", pady=(0, self._px(3)))
            card.grid_rowconfigure(row + 1, weight=0)
            if hint:
                self._label(card, hint, bg_=CARD, fg=MUTED, font=FONT_SMALL)\
                    .grid(row=row + 2, column=0, sticky="w",
                          pady=(0, self._px(2)))

        ent_user = ttk.Entry(card, textvariable=self.var_username, font=FONT)
        self.ent_user = ent_user
        field(0, "校园网账号", ent_user, "与校园网认证网页使用的账号一致。")

        self.ent_pw = ttk.Entry(card, textvariable=self.var_password, font=FONT)
        field(3, "上网密码", self.ent_pw)

        chk_show = ttk.Checkbutton(card, text="显示密码", variable=self.var_show_pw,
                                   command=self._refresh_password_visibility)
        chk_show.grid(row=5, column=0, sticky="w", pady=(1, 2))

        self.carrier_map: Dict[str, str] = {}
        for code, label_text in list(carrier.CHOICES) + list(carrier.EXTRA_CHOICES):
            self.carrier_map[label_text] = code
        combo = ttk.Combobox(card, font=FONT, state="readonly",
                             values=list(self.carrier_map))
        combo.current(0)
        self.var_carrier_widget = combo
        field(6, "宽带运营商", combo, "选择与你在学校认证网页上使用的服务一致的运营商。")

        ent_ssid = ttk.Entry(card, textvariable=self.var_ssid, font=FONT)
        field(9, "校园 Wi-Fi 名称（可留空）", ent_ssid,
              "无线接入时自动切换至该网络；有线接入可留空。")

        chk_auto = ttk.Checkbutton(card, text="登录 Windows 后启动托盘和后台监测",
                                   variable=self.var_autostart)
        chk_auto.grid(row=12, column=0, sticky="w",
                      pady=(self._px(14), self._px(2)))
        card.grid_columnconfigure(0, weight=1)
        self._setup_inputs = [ent_user, self.ent_pw, combo, ent_ssid, chk_auto]

        self.lbl_setup_error = self._label(inner, "", bg_=BG,
                                           fg=RED, font=FONT_SMALL)
        self.lbl_setup_error.pack(fill="x", padx=self._px(26),
                                  pady=(self._px(8), 0))
        self.lbl_setup_error.bind("<Configure>", lambda e: self.lbl_setup_error.configure(wraplength=max(100, e.width)))

        btns = tk.Frame(self.setup_frame, bg=BG)
        btns.pack(side="bottom", fill="x", padx=self._px(24), pady=self._px(14))
        form.pack(fill="both", expand=True)
        self.btn_save_connect = self._button(btns, "保存并连接",
                                            lambda: self.save_setup(connect_after=True), "primary")
        self.btn_save_connect.pack(side="left")
        self.btn_save = self._button(btns, "保存设置", self.save_setup)
        self.btn_save.pack(side="left", padx=(self._px(10), 0))
        self.btn_back = self._button(btns, "取消", self.show_main)
        self.btn_back.pack(side="left", padx=(self._px(10), 0))
        self._hint_stored = self._label(
            inner, "", bg_=BG, fg=MUTED, font=FONT_SMALL)
        self._hint_stored.pack(fill="x", padx=self._px(26),
                               pady=(self._px(2), self._px(10)))

    # ------------------------------------------------------------ 日志区
    def _build_log(self) -> None:
        import tkinter as tk
        from tkinter import ttk

        header = tk.Frame(self._main_content, bg=BG)
        header.pack(fill="x", padx=self._px(24), pady=(self._px(12), self._px(8)))
        self.btn_log = self._button(header, "展开运行日志", self.toggle_log)
        self.btn_log.pack(side="left")
        self._label(header, "F5 刷新状态", fg=MUTED, font=FONT_SMALL).pack(side="right")
        self.log_wrap = tk.Frame(self._main_content, bg=BG)
        self.log_box = tk.Text(self.log_wrap, height=8, font=FONT_SMALL, relief="flat",
                               bg=CARD, fg=TEXT, state="disabled", wrap="word",
                               highlightbackground=BORDER, highlightthickness=1,
                               padx=self._px(12), pady=self._px(10), bd=0)
        scroll = ttk.Scrollbar(self.log_wrap, command=self.log_box.yview)
        self.log_box.configure(yscrollcommand=scroll.set)
        scroll.pack(side="right", fill="y")
        self.log_box.pack(side="left", fill="both", expand=True)
        for tag, color in (("info", MUTED), ("ok", GREEN), ("warn", AMBER), ("error", RED), ("debug", FAINT)):
            self.log_box.tag_configure(tag, foreground=color)

    def toggle_log(self, opened=None) -> None:
        self._logs_open = not self._logs_open if opened is None else bool(opened)
        if self._logs_open:
            self.log_wrap.pack(fill="both", padx=self._px(24), pady=(0, self._px(16)))
            self._read_watch_log()
        else:
            self.log_wrap.pack_forget()
        self.btn_log.configure(text="收起运行日志" if self._logs_open else "展开运行日志")

    def _read_watch_log(self) -> None:
        path = os.path.join(runtime_log_dir(), "watch.log")
        try:
            with open(path, "rb") as fh:
                size = fh.seek(0, 2)
                offset = self._watch_log_offset
                if offset is None or offset > size:
                    offset = 0
                start = max(offset, size - 16000)
                fh.seek(start)
                raw = fh.read(16000)
                self._watch_log_offset = fh.tell()
            if raw:
                lines = raw.decode("utf-8", "replace").splitlines()
                if start > offset:
                    lines = lines[1:]
                self._append_log("后台记录\n" + "\n".join(lines[-40:]))
        except OSError:
            pass

    def _build_feedback(self) -> None:
        import tkinter as tk
        from tkinter import ttk
        frame = tk.Frame(self.root, bg=BLUE_SOFT, padx=self._px(24), pady=self._px(10))
        frame.pack(side="bottom", fill="x")
        self.lbl_feedback = self._label(frame, "就绪", bg_=BLUE_SOFT, fg=MUTED,
                                        font=FONT_SMALL, justify="left")
        self.lbl_feedback.pack(fill="x")
        self.lbl_feedback.bind("<Configure>", lambda e: self.lbl_feedback.configure(wraplength=max(100, e.width)))
        self.progress = ttk.Progressbar(frame, mode="indeterminate")

    def _feedback(self, message: str, level: str = "info") -> None:
        self.lbl_feedback.configure(text=message, fg={"ok":GREEN, "warn":AMBER, "error":RED}.get(level, MUTED))

    def _install_scroll_bindings(self, parent) -> None:
        # Run before Tk's Text/Spinbox/Combobox class handlers can consume the wheel.
        tags = parent.bindtags()
        if self._wheel_tag not in tags:
            parent.bindtags((self._wheel_tag,) + tags)
        for child in parent.winfo_children():
            self._install_scroll_bindings(child)

    def _scroll_page(self, event):
        top = event.widget.winfo_toplevel()
        if top == self.root:
            canvas = self._setup_canvas if self._page == "setup" else self._main_canvas
        elif top == self._policy_win:
            canvas = self._policy_canvas
        else:
            return
        if canvas is None or not event.delta:
            return "break"
        direction = -1 if event.delta > 0 else 1
        canvas.update_idletasks()
        in_log = str(event.widget) == str(self.log_wrap) or str(event.widget).startswith(str(self.log_wrap) + ".")
        if canvas == self._main_canvas and in_log:
            y = self.log_box.winfo_rooty() - canvas.winfo_rooty()
            fully_visible = y >= 0 and y + self.log_box.winfo_height() <= canvas.winfo_height()
            first, last = self.log_box.yview()
            can_scroll = first > 0 if direction < 0 else last < 1
            if fully_visible and can_scroll:
                lines = max(1, round(abs(event.delta) / 120 * 3))
                self.log_box.yview_scroll(direction * lines, "units")
                return "break"
        first, last = canvas.yview()
        if (direction < 0 and first > 0) or (direction > 0 and last < 1):
            pixels = max(1, round(abs(event.delta) / 120 * self._px(48)))
            bounds = canvas.bbox("all")
            if bounds:
                canvas.yview_moveto(first + direction * pixels / max(1, bounds[3] - bounds[1]))
        return "break"

    def _primary_shortcut(self, _event=None):
        if self._page == "setup":
            self.save_setup(connect_after=True)
        else:
            self.connect(True)
        return "break"

    # ------------------------------------------------------------ 显示切换
    def show_main(self) -> None:
        self._page = "main"
        self.setup_frame.pack_forget()
        self.main_frame.pack(fill="both", expand=True)
        self._request_state()

    def show_setup(self, first_time: bool = False) -> None:
        if self._busy:
            return
        self._page = "setup"
        self.main_frame.pack_forget()
        self.setup_frame.pack(fill="both", expand=True)
        self.lbl_setup_error.configure(text=self._config_error)
        self._fresh_cfg()
        self.var_autostart.set(autostart.status().startswith("已安装"))
        self.var_username.set(self.cfg.username or "")
        self._setup_saved_password = self.cfg.resolve_password(prompt=False) if self.cfg.username else ""
        self.var_password.set(self._setup_saved_password)
        self.var_ssid.set(self.cfg.wifi_ssid or "")
        code = self.cfg.options.get("carrier") or "campus"
        for label_text, c in self.carrier_map.items():
            if c == code:
                self.var_carrier_widget.set(label_text)
                break
        self._hint_stored.configure(text="" if not self.cfg.username
                                    else "密码留空表示沿用已保存的密码。")
        self.btn_back.configure(
            text="取消", command=self.show_main)
        if first_time or not self.var_ssid.get():
            self._spawn(self._job_prefill_ssid)
        self._setup_canvas.yview_moveto(0)
        self.ent_user.focus_set()

    def _refresh_password_visibility(self) -> None:
        visible = self.var_show_pw.get()
        self.ent_pw.configure(show="" if visible else "●")
        text = self._saved_password
        if text and not visible:
            text = "●●●●●●"
        self.info_vars["password"].configure(text=text or "未设置")

    def _on_setup_username_change(self, *_args) -> None:
        if (self.var_username.get().strip() != self.cfg.username
                and self.var_password.get() == self._setup_saved_password):
            self.var_password.set("")


    # ------------------------------------------------------------ 队列与刷新
    def _poll_queue(self) -> None:
        if self._closing:
            return
        try:
            if self._activation and self._activation.show_requested():
                self.show_window()
            while True:
                msg = self.q.get_nowait()
                self._dispatch(msg)
        except queue.Empty:
            pass
        except Exception as exc:  # noqa: BLE001 - 刷新循环绝不能死
            _write_error_log(traceback.format_exc())
            sys.stderr and sys.stderr.write("gui loop error: {}\n".format(exc))
        if not self._closing:
            self.root.after(80, self._poll_queue)

    def _dispatch(self, msg: Tuple) -> None:
        kind = msg[0]
        if kind == "log":
            self._append_log(msg[1], msg[2])
        elif kind == "state":
            self._state_pending = False
            if len(msg) > 2 and msg[2] is not None and msg[2] != self._state_revision:
                self._request_state()
                return
            self._apply_state(msg[1])
        elif kind in ("state_error", "background_error"):
            if kind == "state_error":
                self._state_pending = False
            self._append_log(msg[1], "warn")
            if not self._busy and msg[4] == self._state_revision:
                self._feedback("状态读取未完成，可按 F5 重试。", "warn")
        elif kind == "connect":
            self._set_busy(False, "")
            self._on_connect_done(msg[1], msg[2], msg[3])
        elif kind == "health":
            self._set_busy(False, "")
            self._on_health(msg[1])
        elif kind == "fatal":
            self._state_pending = False
            self._set_busy(False, "")
            self._feedback("操作未完成，请展开日志查看原因。", "error")
            self._append_log(msg[1] + "\n" + msg[2], "error")
            if self._page == "setup":
                self.lbl_setup_error.configure(text=msg[1])
        elif kind == "prefill":
            if msg[1].get("ssid") and not self.var_ssid.get():
                self.var_ssid.set(msg[1]["ssid"])
        elif kind == "autostart_done":
            self._set_busy(False, "")
            self._append_log(msg[1], "info")
            self._feedback(msg[1], "ok")
            self._request_state()
        elif kind == "setup_error":
            self._set_busy(False, "")
            self.lbl_setup_error.configure(text=msg[1])
            self._feedback(msg[1], "error")
        elif kind == "saved":
            self.cfg = msg[1]
            self._auto_connect_done = True
            self._set_busy(False, "")
            self.show_main()
            warning = msg[3]
            self._feedback(warning or "账号设置已保存。", "warn" if warning else "ok")
            if warning:
                self._append_log(warning, "warn")
            if msg[2]:
                self.connect(force=True)
        elif kind == "call":
            msg[1]()

    def _append_log(self, text: str, level: str = "info") -> None:
        from tkinter import TclError
        try:
            for secret in (self._saved_password, self._setup_saved_password):
                if secret:
                    text = text.replace(secret, "[密码已隐藏]")
            self.log_box.configure(state="normal")
            stamp = datetime.datetime.now().strftime("%H:%M:%S")
            self.log_box.insert("end", "{}  {}\n".format(stamp, text), (level,))
            lines = int(self.log_box.index("end-1c").split(".")[0])
            if lines > 300:
                self.log_box.delete("1.0", "{}.0".format(lines - 300))
            self.log_box.see("end")
            self.log_box.configure(state="disabled")
        except TclError:
            pass

    def _set_busy(self, busy: bool, text: str) -> None:
        self._busy = busy
        if not busy:
            self._active_job = None
        state = "disabled" if busy else "normal"
        for btn in (self.btn_connect, self.btn_health, self.btn_setup, self.btn_autostart,
                    self.btn_save, self.btn_save_connect, self.btn_back, self.btn_policy):
            btn.configure(state=state)
        for widget in self._setup_inputs:
            widget.configure(state="disabled" if busy else
                             ("readonly" if widget is self.var_carrier_widget else "normal"))
        if busy:
            self.progress.pack(fill="x", pady=(self._px(6), 0))
            self.progress.start(12)
        else:
            self.progress.stop()
            self.progress.pack_forget()
        if text:
            self._feedback(text)
            self._append_log(text)

    def _start_action(self, fn, message: str, *args) -> bool:
        if self._busy or self._closing:
            return False
        self._state_revision += 1
        self._active_job = fn
        self._set_busy(True, message)
        self._spawn(fn, *args)
        return True

    def _request_state(self) -> None:
        if self._busy or self._state_pending or self._closing or self._page != "main":
            return
        self._state_pending = True
        self._last_status_started = time.monotonic()
        self._spawn(self._job_state, self._state_revision)

    def _periodic_refresh(self) -> None:
        if self._closing:
            return
        if self.root.state() != "withdrawn" and self._page == "main" and not self._busy:
            self._refresh_policy_row()
            if self._logs_open:
                self._read_watch_log()
            if time.monotonic() - self._last_status_started >= 20:
                self._request_state()
        else:
            self._update_tray_title()
        self.root.after(5000, self._periodic_refresh)

    # ------------------------------------------------------------ 后台任务
    def _job_state(self, revision=None) -> None:
        cfg = self.cfg
        password = cfg.resolve_password(prompt=False)
        installed = autostart.status().startswith("已安装")
        if installed and getattr(sys, "frozen", False) and "-m campusnet" in autostart.status():
            autostart.install(cfg.path)
            installed = autostart.status().startswith("已安装")
        data = {
            "online": None, "detail": "", "username": cfg.username or "未设置",
            "carrier": "未设置", "portal": cfg.portal_ip or "自动探测",
            "autostart": installed, "configured": bool(cfg.username and password),
            "policy": policy.describe(self._disk_options()), "display_password": password,
            "watch_running": singleton.windows_watch_running(),
        }
        code = cfg.options.get("carrier")
        if code and carrier.is_known(code):
            data["carrier"] = carrier.label(code)
        try:
            status = Runner(cfg).status()
            data["online"] = status.online
            data["detail"] = status.describe()
        except Exception as exc:
            data["online"] = False
            data["detail"] = "网络检查失败 {}".format(exc)
        self.q.put(("state", data, revision))

    def _job_prefill_ssid(self) -> None:
        ssid = _wifi.current_ssid() or ""
        self.q.put(("prefill", {"ssid": ssid}))

    def _job_connect(self, force: bool) -> None:
        cfg = self._fresh_cfg()
        runner = self._runner()
        self.q.put(("log", "使用 {} 认证，门户 {}".format(cfg.provider, cfg.portal_ip or "自动探测"), "info"))
        result = runner.ensure_online(force=force)
        if result.ok and result.detection and result.detection.portal and not cfg.portal_ip:
            cfg.portal_ip = result.detection.portal
            try:
                cfg.save()
                self.q.put(("log", "已保存认证门户。", "ok"))
            except OSError:
                self.q.put(("log", "已连接，但认证门户未能保存。", "warn"))
        attempts = "\n".join(a.short() for a in result.attempts)
        self.q.put(("connect", result.ok, result.message, attempts))

    def _job_health(self) -> None:
        cfg = self._fresh_cfg()
        lines = ["上网账号已填写。" if cfg.username else "请在账号设置中填写账号。"]
        lines.append("密码已保存。" if cfg.resolve_password(prompt=False) else "请在账号设置中填写密码。")
        lines.append("登录自启已开启。" if autostart.status().startswith("已安装") else "登录自启未开启。")
        lines.append("后台监测正在运行。" if singleton.windows_watch_running() else "后台监测未运行。")
        lines.append("自动重连策略  " + policy.describe(cfg))
        if cfg.wifi_ssid:
            lines.append("校园 Wi-Fi  " + cfg.wifi_ssid + "\n当前 Wi-Fi  " + (_wifi.current_ssid() or "未连接"))
        runner = Runner(cfg)
        status = runner.status()
        lines.append("网络检测  " + status.describe())
        if cfg.portal_ip:
            lines.append("已配置认证门户  " + cfg.portal_ip)
        elif not status.online:
            detected = runner.detect(status)
            lines.append("检测到认证门户  " + detected.portal if detected.portal else "请检查校园网线或校园 Wi-Fi 是否已连接。")
        self.q.put(("health", "\n".join(lines)))

    def _job_toggle_autostart(self) -> None:
        installed = autostart.status().startswith("已安装")
        text = autostart.uninstall() if installed else autostart.install(self.cfg.path)
        if autostart.status().startswith("已安装") == installed:
            raise OSError(text)
        if not installed:
            self._ensure_watch()
        self.q.put(("autostart_done", "已关闭登录自启。" if installed else "已开启登录自启，登录 Windows 后将进入托盘。"))

    def _job_save_setup(self, username: str, password: str, carrier_code: str,
                        ssid: str, want_autostart: bool, connect_after: bool = False) -> None:
        previous = self._fresh_cfg()
        cfg = Config.from_dict(previous.to_dict(include_password=True), path=previous.path)
        cfg.password_source = previous.password_source
        if password:
            if not has_keyring() or not _keyring_set(username, password):
                self.q.put(("setup_error", "Windows 凭据管理器未能保存密码，请重试。"))
                return
            cfg.password = ""
            cfg.password_source = "keyring"
        cfg.username = username
        cfg.options["carrier"] = carrier_code
        cfg.wifi_ssid = ssid
        try:
            cfg.save()
        except OSError as exc:
            self.q.put(("setup_error", "配置未能保存，请检查安装目录权限。{}".format(exc)))
            return
        warning = ""
        try:
            if want_autostart:
                autostart.install(cfg.path)
                autostart.ensure_desktop_watch(cfg.path)
            else:
                autostart.uninstall()
            if autostart.status().startswith("已安装") != want_autostart:
                raise OSError("启动项状态未改变")
        except OSError:
            warning = "账号设置已保存，登录自启修改未成功，请在主界面重试。"
        self.q.put(("log", "账号设置已保存。", "ok"))
        self.q.put(("saved", cfg, connect_after, warning))

    # ------------------------------------------------------------ 按钮动作
    def connect(self, force: bool = True) -> None:
        if self._busy:
            return
        if not self._configured():
            self.show_setup(first_time=True)
            self.lbl_setup_error.configure(text="请先填写上网账号和密码。")
            self._feedback("填写账号后，可选择保存并连接。", "warn")
            return
        self._start_action(self._job_connect, "正在认证，请稍候…", force)

    def health_check(self) -> None:
        self._start_action(self._job_health, "正在检查账号、后台和网络…")

    def toggle_autostart(self) -> None:
        self._start_action(self._job_toggle_autostart, "正在更新登录自启设置…")

    def save_setup(self, connect_after: bool = False) -> None:
        if self._busy:
            return
        if self._config_error:
            try:
                self.cfg = Config.load()
            except (ValueError, OSError) as exc:
                self.lbl_setup_error.configure(text=str(exc))
                return
            self._config_error = ""
        username = self.var_username.get().strip()
        password = self.var_password.get()
        if not username:
            self.lbl_setup_error.configure(text="上网账号还没填 —— 一般就是你的学号。")
            return
        stored_password = self.cfg.resolve_password(prompt=False) if username == self.cfg.username else ""
        if not password and not stored_password:
            self.lbl_setup_error.configure(text="密码还没填。就是连校园网时输的那个密码。")
            return
        if password == stored_password:
            password = ""  # 查看已有密码或只改其他设置时，沿用现有凭据。
        ssid = self.var_ssid.get().strip()
        carrier_code = self.carrier_map.get(self.var_carrier_widget.get(), "campus")
        self._start_action(self._job_save_setup, "正在保存账号设置…", username,
                           password, carrier_code, ssid, self.var_autostart.get(), connect_after)
        # 保存线程完成后会发 "saved" 消息，由它切回主界面并自动连接一次

    # ------------------------------------------------------------ 结果呈现
    def _apply_state(self, data: Dict[str, Any]) -> None:
        if data["online"] is True:
            self.lbl_status.configure(text="已连接，可以上网了", fg=GREEN)
            dot = GREEN
        elif data["online"] is False:
            self.lbl_status.configure(text="还没连上校园网", fg=RED)
            dot = RED
        else:
            self.lbl_status.configure(text="正在检查网络…", fg=TEXT)
            dot = FAINT
        try:  # 状态点跟着一起变色
            self._dot.itemconfigure(self._dot_item, fill=dot)
        except Exception:  # noqa: BLE001
            pass
        self.lbl_detail.configure(text=data.get("detail") or "")
        # 双击打开就应该自己连：已配置、没联网、还没自动试过 —— 来一次
        # （只试一次，失败不循环重试；用户要看详情/手动再来点「立即重新认证」）
        first_check = not self._auto_connect_done
        self._auto_connect_done = True
        if (first_check and self._page == "main" and data.get("online") is False
                and data.get("configured") and not self._busy
                and not singleton.windows_watch_running()
                and not policy.block_reason(self._fresh_cfg())):
            self._auto_connect_done = True
            self._append_log("检测到还没联网，自动帮你连接一次…", "info")
            self.connect(force=False)
        self.info_vars["username"].configure(text=data["username"])
        self._saved_password = data.get("display_password") or ""
        self._refresh_password_visibility()
        self.info_vars["carrier"].configure(text=data["carrier"])
        self.info_vars["portal"].configure(text=data["portal"])
        self.info_vars["autostart"].configure(
            text="已开启" if data["autostart"] else "已关闭",
            fg=GREEN if data["autostart"] else MUTED)
        self.info_vars["policy"].configure(text=data.get("policy") or "")
        self.btn_autostart.configure(
            text="关闭自启" if data["autostart"] else "开启自启")
        self.lbl_updated.configure(text="检查于 " + datetime.datetime.now().strftime("%H:%M:%S"))
        self.btn_connect.configure(text="重新认证" if data["online"] else "连接校园网")
        self._refresh_policy_row()

    def _on_connect_done(self, ok: bool, message: str, attempts: str) -> None:
        if not ok:
            self.toggle_log(True)
        self._append_log(message, "ok" if ok else "error")
        if attempts:
            self._append_log(attempts, "info" if ok else "error")
        self._feedback("已连接，校园网可以正常使用。" if ok else
                       "连接未完成，请检查账号或展开日志查看原因。", "ok" if ok else "error")
        self._request_state()

    def _on_health(self, text: str) -> None:
        self.toggle_log(True)
        self._append_log(text)
        self._feedback("网络检测已完成，详情见运行日志。")
        self.root.after_idle(lambda: self._main_canvas.yview_moveto(1))
        self._request_state()

    # ------------------------------------------------------------ 重连策略
    def _fresh_cfg(self) -> Config:
        """从磁盘重读配置：托盘和策略窗口可能在守护进程改过配置之后才打开。"""
        try:
            fresh = Config.load(self.cfg.path or None)
        except Exception:  # noqa: BLE001 - 配置坏了就沿用内存里的
            return self.cfg
        self.cfg = fresh
        return self.cfg

    def _disk_options(self) -> Dict[str, Any]:
        """只读地取磁盘上的 options —— 托盘菜单渲染时用，不碰 self.cfg。"""
        try:
            return dict(Config.load(self.cfg.path or None).options)
        except Exception:  # noqa: BLE001
            return self.cfg.options

    def _refresh_policy_row(self) -> None:
        cfg = self._fresh_cfg()
        self.info_vars["policy"].configure(text=policy.describe(cfg))
        block = policy.block_reason(cfg)
        running = singleton.windows_watch_running()
        state = "监测中" if running else "未运行"
        if running and block:
            state = "已暂停" if policy.pause_remaining() > 0 else "等待设定时间"
        self.info_vars["watch"].configure(text=state, fg=AMBER if block else (GREEN if running else MUTED))
        self.btn_resume.configure(state="normal" if policy.pause_remaining() > 0 else "disabled")
        self._update_tray_title()

    def pause_reconnect(self, minutes: int) -> None:
        try:
            policy.pause_for(minutes * 60)
        except OSError as exc:
            self._feedback("暂停未能保存，请检查安装目录权限。", "error")
            self._append_log(str(exc), "error")
            return
        message = "已暂停自动重连，将在 {} 恢复。".format(policy.format_time(policy.paused_until()))
        self._append_log(message)
        self._feedback(message)
        self._refresh_policy_row()

    def _pause_from_input(self) -> None:
        try:
            minutes = int(self.var_pause.get().strip())
        except (TypeError, ValueError):
            minutes = 0
        if not 1 <= minutes <= 1440:
            self._feedback("暂停时长请填写 1 到 1440 之间的整数分钟。", "error")
            self.spin_pause.focus_set()
            return
        self.pause_reconnect(minutes)

    def resume_reconnect(self) -> None:
        try:
            policy.resume()
        except OSError as exc:
            self._feedback("恢复操作未能保存，请检查安装目录权限。", "error")
            self._append_log(str(exc), "error")
            return
        self._append_log("已恢复自动重连。", "ok")
        self._feedback("已恢复自动重连，将按设定的时间和间隔检查网络。", "ok")
        self._refresh_policy_row()

    def pause_until_morning(self) -> None:
        now = datetime.datetime.now()
        target = now.replace(hour=7, minute=0, second=0, microsecond=0)
        if target <= now:
            target += datetime.timedelta(days=1)
        try:
            policy.pause_until(target.timestamp(), "到早上 7 点")
        except OSError as exc:
            self._feedback("暂停未能保存，请检查安装目录权限。", "error")
            self._append_log(str(exc), "error")
            return
        self._append_log("已暂停自动重连至 {}".format(target.strftime("%m-%d %H:%M")), "info")
        self._feedback("已暂停自动重连，将在 {} 恢复。".format(target.strftime("%m-%d %H:%M")))
        self._refresh_policy_row()

    def _tray_set(self, **values: Any) -> None:
        if self._busy:
            return
        cfg = self._fresh_cfg()
        updates: Dict[str, Any] = {}
        if "interval" in values:
            updates[policy.KEY_INTERVAL] = values["interval"]
        if "delay" in values:
            updates[policy.KEY_DELAY] = values["delay"]
        if "windows" in values:
            updates[policy.KEY_WINDOWS] = values["windows"]
        try:
            policy.set_options(cfg, **updates)
            self._append_log("重连策略已更新：{}".format(policy.describe(cfg)), "ok")
            self._feedback("重连策略已更新。", "ok")
        except Exception as exc:  # noqa: BLE001
            self._append_log("策略保存失败：{}".format(exc), "error")
            self._feedback("重连策略未能保存，详情见运行日志。", "error")
        self._refresh_policy_row()

    def show_policy(self) -> None:
        import math
        import tkinter as tk
        from tkinter import ttk

        if self._busy:
            return
        if self._policy_win is not None and self._policy_win.winfo_exists():
            self._policy_win.deiconify()
            self._policy_win.lift()
            return
        cfg = self._fresh_cfg()
        win = tk.Toplevel(self.root)
        self._policy_win = win
        win.title("重连策略")
        win.configure(bg=BG)
        win.geometry("{}x{}".format(self._px(560), min(self._px(680), self.root.winfo_screenheight()-self._px(80))))
        win.minsize(self._px(480), self._px(440))
        win.transient(self.root)
        bottom = tk.Frame(win, bg=BG)
        bottom.pack(side="bottom", fill="x", padx=self._px(24), pady=self._px(14))
        canvas = tk.Canvas(win, bg=BG, highlightthickness=0)
        self._policy_canvas = canvas
        scroll = ttk.Scrollbar(win, command=canvas.yview)
        canvas.configure(yscrollcommand=scroll.set)
        scroll.pack(side="right", fill="y")
        canvas.pack(fill="both", expand=True)
        body = tk.Frame(canvas, bg=BG)
        canvas.create_window((0, 0), window=body, anchor="nw", tags="body")
        body.bind("<Configure>", lambda _e: canvas.configure(scrollregion=canvas.bbox("all")))
        canvas.bind("<Configure>", lambda e: canvas.itemconfigure("body", width=e.width))
        self._label(body, "自动重连策略", font=FONT_PAGE).pack(anchor="w", padx=self._px(24), pady=(self._px(22), self._px(6)))
        self._label(body, "手动点击连接会立即认证。登录 Windows 后也会先尝试认证。",
                    fg=MUTED, font=FONT_SMALL, wraplength=self._px(450), justify="left").pack(
                        fill="x", padx=self._px(24), pady=(0, self._px(14)))
        card = self._card(body)
        card.pack(fill="x", padx=self._px(24))
        card.columnconfigure(0, weight=1)
        var_interval = tk.StringVar(value=str(policy.interval_minutes(cfg)))
        var_delay = tk.StringVar(value="{:g}".format(policy.reconnect_delay(cfg)))
        current_windows = policy.windows(cfg)
        var_on = tk.BooleanVar(value=bool(current_windows))
        self._policy_vars = (var_interval, var_delay, var_on)
        for row, label, var, minimum, maximum, hint in (
                (0, "检查间隔 · 分钟", var_interval, 1, 1440, "联网正常时，按这个间隔检查。"),
                (3, "掉线后等待 · 秒", var_delay, 0, 3600, "日常掉线时先等待，给手机留出使用时间。")):
            self._label(card, label, bg_=CARD, font=FONT_BOLD).grid(row=row, column=0, sticky="w", pady=(self._px(8), self._px(4)))
            ttk.Spinbox(card, from_=minimum, to=maximum, width=12, textvariable=var, font=FONT).grid(row=row+1, column=0, sticky="w")
            self._label(card, hint, bg_=CARD, fg=MUTED, font=FONT_SMALL).grid(row=row+2, column=0, sticky="w", pady=(self._px(4), self._px(10)))
        time_rows = []
        self._policy_time_rows = time_rows
        hint_time = self._label(card, "", bg_=CARD, fg=MUTED,
                                font=FONT_SMALL, justify="left", wraplength=self._px(390))
        hint_time.grid(row=7, column=0, sticky="ew", pady=(self._px(6), self._px(4)))
        time_box = tk.Frame(card, bg=CARD)
        time_box.grid(row=8, column=0, sticky="ew")

        def sync():
            enabled = var_on.get()
            for index, row in enumerate(time_rows, 1):
                row["title"].configure(text="时段 {}".format(index))
                for spin in row["spins"]:
                    spin.configure(state="normal" if enabled else "disabled")
                row["remove"].configure(state="normal" if enabled and len(time_rows)>1 else "disabled")
            add_time.configure(state="normal" if enabled else "disabled")
            hint_time.configure(text=("分别填写小时和分钟；结束早于开始表示跨午夜。暂停期间仍会等待。"
                                       if enabled else "当前全天可自动重连。勾选上方选项后，可设置下方时间。暂停期间仍会等待。"))

        def remove_time(row):
            if len(time_rows)>1:
                time_rows.remove(row)
                row["frame"].destroy()
                sync()

        def add_window(start=23*60, end=7*60):
            frame = tk.Frame(time_box, bg=CARD)
            frame.pack(fill="x", pady=(self._px(8), self._px(4)))
            heading = tk.Frame(frame, bg=CARD)
            heading.pack(fill="x")
            title = self._label(heading, "", bg_=CARD, fg=MUTED, font=FONT_SMALL)
            title.pack(side="left")
            row = {"frame":frame, "title":title, "spins":[], "vars":[]}
            remove = self._button(heading, "删除", lambda:remove_time(row))
            remove.pack(side="right")
            row["remove"] = remove
            fields = tk.Frame(frame, bg=CARD)
            fields.pack(fill="x", pady=(self._px(4), 0))
            fields.columnconfigure((0,1), weight=1, uniform="time")
            for column, (caption, minutes) in enumerate((("开始时间", start), ("结束时间", end))):
                group = tk.Frame(fields, bg=CARD)
                group.grid(row=0, column=column, sticky="w", padx=(0, self._px(12)))
                self._label(group, caption, bg_=CARD, font=FONT_SMALL).pack(anchor="w", pady=(0,self._px(4)))
                parts = tk.Frame(group, bg=CARD)
                parts.pack(anchor="w")
                for value, maximum, unit in ((minutes//60,23,"时"),(minutes%60,59,"分")):
                    variable = tk.StringVar(value="{:02d}".format(value))
                    spin = ttk.Spinbox(parts, from_=0, to=maximum, textvariable=variable,
                                       width=3, format="%02.0f", font=FONT, justify="center")
                    spin.pack(side="left")
                    self._label(parts, unit, bg_=CARD, fg=MUTED, font=FONT_SMALL).pack(
                        side="left", padx=(self._px(4),self._px(8)))
                    row["vars"].append(variable)
                    row["spins"].append(spin)
            time_rows.append(row)
            self._install_scroll_bindings(frame)
            sync()

        ttk.Checkbutton(card, text="限定自动重连时间", variable=var_on).grid(row=6, column=0, sticky="w")
        add_time = self._button(card, "添加时间段", lambda:add_window(12*60,13*60))
        add_time.grid(row=9, column=0, sticky="w", pady=(self._px(8),0))
        self._add_policy_window = add_window
        self._remove_policy_window = remove_time
        var_on.trace_add("write", lambda *_:sync())
        for start, end in current_windows or [(23*60,7*60)]:
            add_window(start,end)
        sync()
        error = self._label(bottom, "", fg=RED, font=FONT_SMALL, justify="left")
        error.pack(fill="x", pady=(0, self._px(8)))
        error.bind("<Configure>", lambda e: error.configure(wraplength=max(100, e.width)))
        self._policy_error = error

        def close():
            self._policy_win = None
            self._policy_canvas = None
            win.destroy()

        def save():
            if self._busy:
                error.configure(text="请等待当前操作完成后再保存。")
                return
            try:
                interval = int(var_interval.get().strip())
                delay = float(var_delay.get().strip())
                if interval < 1 or not math.isfinite(delay) or delay < 0:
                    raise ValueError("检查间隔应为正整数，等待秒数应为非负数。")
                windows = []
                if var_on.get():
                    for index, row in enumerate(time_rows, 1):
                        try:
                            values = [int(variable.get().strip()) for variable in row["vars"]]
                            if any(value<0 or value>maximum for value,maximum in zip(values,(23,59,23,59))):
                                raise ValueError()
                        except ValueError:
                            raise ValueError("时段 {}：小时请填 0–23，分钟请填 0–59 的整数。".format(index)) from None
                        windows.append("{:02d}:{:02d}-{:02d}:{:02d}".format(*values))
                text = ",".join(windows)
                policy.parse_windows(text)
                latest = self._fresh_cfg()
                policy.set_options(latest, **{policy.KEY_INTERVAL:interval, policy.KEY_DELAY:delay,
                                              policy.KEY_WINDOWS:text})
            except (ValueError, OSError) as exc:
                error.configure(text=str(exc))
                return
            self._refresh_policy_row()
            self._feedback("重连策略已保存。", "ok")
            self._append_log("重连策略已保存  " + policy.describe(latest), "ok")
            close()

        self._button(bottom, "保存策略", save, "primary").pack(side="right")
        self._button(bottom, "取消", close).pack(side="right", padx=self._px(8))
        self._save_policy = save
        win.protocol("WM_DELETE_WINDOW", close)
        win.bind("<Escape>", lambda _e: close())
        self._install_scroll_bindings(win)

    # ------------------------------------------------------------ 系统托盘
    def _post(self, fn) -> None:
        """把托盘线程里的动作丢回 tkinter 主线程执行。"""
        self.q.put(("call", fn))

    def _start_tray(self) -> None:
        try:
            import pystray
        except Exception:  # noqa: BLE001 - 没装托盘组件就退化成普通窗口
            self._tray = None
            return
        try:
            self._tray = pystray.Icon("campusnet", self._tray_image(),
                                      APP_TITLE, self._build_tray_menu(pystray))
            threading.Thread(target=self._run_tray, name="campusnet-tray",
                             daemon=True).start()
            self._update_tray_title()
        except Exception:  # noqa: BLE001
            _write_error_log(traceback.format_exc())
            self._tray = None

    def _run_tray(self) -> None:
        try:
            self._tray.run()
        except Exception:
            _write_error_log(traceback.format_exc())
            self._tray = None
            self._post(self.show_window)

    def _tray_image(self):
        import io

        from PIL import Image

        from ._icon_data import ICON_PNG_B64
        return Image.open(io.BytesIO(base64.b64decode(ICON_PNG_B64))).convert("RGBA")

    def _update_tray_title(self) -> None:
        if self._tray is None:
            return
        try:
            text = APP_TITLE
            if policy.pause_remaining() > 0:
                text += "（已暂停至 {}）".format(policy.format_time(policy.paused_until()))
            self._tray.title = text
        except Exception:  # noqa: BLE001
            pass

    def _build_tray_menu(self, pystray):
        Menu, Item = pystray.Menu, pystray.MenuItem

        def show(icon=None, item=None) -> None:
            self._post(self.show_window)

        def connect_now(icon=None, item=None) -> None:
            self._post(lambda: self.connect(force=True))

        def pause(minutes: int):
            return lambda icon=None, item=None: self._post(
                lambda: self.pause_reconnect(minutes))

        def resume(icon=None, item=None) -> None:
            self._post(self.resume_reconnect)

        def pause_morning(icon=None, item=None) -> None:
            self._post(self.pause_until_morning)

        def set_interval(minutes: int):
            return lambda icon=None, item=None: self._post(
                lambda: self._tray_set(interval=minutes))

        def set_delay(seconds: int):
            return lambda icon=None, item=None: self._post(
                lambda: self._tray_set(delay=seconds))

        def set_windows(text: str):
            return lambda icon=None, item=None: self._post(
                lambda: self._tray_set(windows=text))

        def interval_checked(minutes: int):
            return lambda item: policy.interval_minutes(self._disk_options()) == minutes

        def delay_checked(seconds: int):
            return lambda item: int(policy.reconnect_delay(self._disk_options())) == seconds

        def windows_checked(text: str):
            return lambda item: policy.windows_text(self._disk_options()).replace(" ", "") \
                == text.replace(" ", "")

        def open_policy(icon=None, item=None) -> None:
            self._post(self.show_policy)

        def quit_app(icon=None, item=None) -> None:
            self._post(self.quit_app)

        return Menu(
            Item("显示主界面", show, default=True),
            Item("立即认证", connect_now, enabled=lambda item: not self._busy),
            Menu.SEPARATOR,
            Item("暂停自动重连", Menu(
                Item("30 分钟", pause(30)),
                Item("1 小时", pause(60)),
                Item("2 小时", pause(120)),
                Item("4 小时", pause(240)),
                Item("到明天早上 7 点", pause_morning),
                Menu.SEPARATOR,
                Item("恢复自动重连", resume),
            )),
            Item("检查间隔", Menu(*[
                Item("{} 分钟".format(m), set_interval(m),
                     checked=interval_checked(m), radio=True)
                for m in (5, 10, 15, 30, 60, 120)
            ])),
            Item("离线后延时", Menu(*[
                Item(label, set_delay(sec), checked=delay_checked(sec), radio=True)
                for sec, label in ((0, "不延时（立即重连）"), (30, "30 秒"),
                                   (60, "1 分钟"), (120, "2 分钟"), (300, "5 分钟"))
            ])),
            Item("定时重连时间段", Menu(
                Item("全天都重连", set_windows(""), checked=windows_checked(""),
                     radio=True),
                Item("23:00-07:00", set_windows("23:00-07:00"),
                     checked=windows_checked("23:00-07:00"), radio=True),
                Item("22:00-07:00", set_windows("22:00-07:00"),
                     checked=windows_checked("22:00-07:00"), radio=True),
                Item("00:00-08:00", set_windows("00:00-08:00"),
                     checked=windows_checked("00:00-08:00"), radio=True),
                Menu.SEPARATOR,
                Item("自定义…", open_policy),
            )),
            Menu.SEPARATOR,
            Item("打开重连策略…", open_policy, enabled=lambda item: not self._busy),
            Item("退出", quit_app),
        )

    def show_window(self) -> None:
        try:
            self.root.deiconify()
            self.root.lift()
            self.root.focus_force()
            self._request_state()
        except Exception:  # noqa: BLE001
            pass

    def hide_to_tray(self) -> None:
        if self._tray is None:
            self.quit_app()
            return
        if self._policy_win is not None:
            self._policy_win.destroy()
            self._policy_win = None
            self._policy_canvas = None
            self._policy_win = None
        self.root.withdraw()
        self._append_log("已最小化到系统托盘，双击托盘图标可以重新打开", "info")

    def quit_app(self) -> None:
        if self._active_job == self._job_save_setup:
            self.show_window()
            self._feedback("正在保存账号设置，完成后可退出。", "warn")
            return
        self._closing = True
        if self._tray is not None:
            try:
                self._tray.stop()
            except Exception:  # noqa: BLE001
                pass
            self._tray = None
        try:
            self.root.destroy()
        except Exception:  # noqa: BLE001
            pass


# ---------------------------------------------------------------- 入口
def _run_cli_passthrough(argv: List[str]) -> int:
    from .cli import main as cli_main
    return cli_main(argv)


def run(argv: Optional[List[str]] = None) -> int:
    """Open the window, start in the tray, or dispatch the remaining arguments to the CLI."""
    argv = list(sys.argv[1:] if argv is None else argv)
    start_in_tray = argv == ["--tray"]
    if argv and not start_in_tray:
        return _run_cli_passthrough(argv)

    activation = None
    if os.name == "nt" and getattr(sys, "frozen", False):
        activation = singleton.DesktopActivation(sys.executable, show_existing=not start_in_tray)
    try:
        if activation and not activation.primary:
            return 0
        return _run_gui(start_in_tray, activation)
    finally:
        if activation:
            activation.close()


def _run_gui(start_in_tray: bool, activation: Optional[singleton.DesktopActivation]) -> int:
    if os.name == "nt":
        try:
            from ctypes import windll
            windll.shcore.SetProcessDpiAwareness(1)
        except Exception:  # noqa: BLE001 - 老系统没有这个 API
            pass

    try:
        import tkinter as tk
        from tkinter import messagebox  # noqa: F401
    except Exception:  # noqa: BLE001
        detail = traceback.format_exc()
        path = _write_error_log(detail)
        text = ("窗口界面打不开：系统缺少图形组件（tkinter）。\n\n"
                "这通常说明 Python 安装不完整。请重新安装 Python，"
                "安装时勾选「tcl/tk and IDLE」。\n")
        if path:
            text += "\n技术细节已保存到：{}".format(path)
        _fallback_msgbox(APP_TITLE, text)
        return 1

    # --noconsole 打包后 stdout/stderr 是 None，print 会崩，换成黑洞
    if sys.stdout is None:
        sys.stdout = open(os.devnull, "w", encoding="utf-8")  # noqa: SIM115
    if sys.stderr is None:
        sys.stderr = open(os.devnull, "w", encoding="utf-8")  # noqa: SIM115

    root = tk.Tk()
    app = App(root, start_in_tray, activation)

    def report_exception(exc_type, exc, tb) -> None:  # noqa: ANN001
        detail = "".join(traceback.format_exception(exc_type, exc, tb))
        path = _write_error_log(detail)
        text = friendly_message(exc)
        if path:
            text += "\n\n日志文件：{}".format(path)
        try:
            from tkinter import messagebox
            messagebox.showerror(APP_TITLE, text, parent=root)
        except Exception:  # noqa: BLE001
            _fallback_msgbox(APP_TITLE, text)

    root.report_callback_exception = report_exception

    smoke = os.environ.get(SMOKE_ENV, "")
    if smoke:
        try:
            parts = smoke.split(",")
            delay = max(0.5, float(parts[0]))
            if len(parts) > 1 and parts[1] == "setup":
                app.show_setup(first_time=False)
            root.after(int(delay * 1000), root.destroy)
        except Exception:  # noqa: BLE001
            pass

    root.mainloop()
    return 0


def _fallback_msgbox(title: str, text: str) -> None:
    """tkinter 都没有时的最后防线：直接调 Win32 弹窗。"""
    try:
        import ctypes
        ctypes.windll.user32.MessageBoxW(0, text, title, 0x10)
    except Exception:  # noqa: BLE001
        sys.stderr and sys.stderr.write("{}: {}\n".format(title, text))
