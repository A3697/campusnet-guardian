"""自动重连策略：暂停 / 延时 / 定时时间段 / 检查间隔。

为什么单独一个模块：这套策略要被三处共用 —— 守护进程（watch）、
命令行（pause / resume / policy）、图形界面（托盘菜单）。

三条策略解决的是同一个问题：**电脑和手机不能同时在线**，谁后登录谁把对方踢掉。
所以要让电脑"别那么积极"：

- 检查间隔 ``reconnect_interval``：多久看一次网络（分钟）；
- 延时重连 ``reconnect_delay``：发现掉线后先等一会儿再抢，把时间留给手机；
- 定时重连 ``reconnect_windows``：只在指定时间段内自动认证（如 ``23:00-07:00``）；
- 暂停：临时关掉自动重连一段时间，到点自动恢复。

暂停状态写在单独的状态文件里，**不写进配置** —— 它是临时状态，
重启程序也要保留，但不该污染用户手写的配置。
"""

from __future__ import annotations

import datetime
import json
import math
import os
import re
import tempfile
import time
from typing import Any, Dict, List, Optional, Tuple

from .config import Config, config_dir

#: 配置里的键名（都在 ``cfg.options`` 下）
KEY_INTERVAL = "reconnect_interval"
KEY_DELAY = "reconnect_delay"
KEY_WINDOWS = "reconnect_windows"

#: 守护进程每轮会重新读这几个键，改配置不用重启
POLICY_KEYS = (KEY_INTERVAL, KEY_DELAY, KEY_WINDOWS)

DEFAULT_INTERVAL = 10   # 分钟
DEFAULT_DELAY = 60      # 秒

STATE_NAME = "policy_state.json"

_UNIT_SECONDS = {
    "s": 1, "秒": 1,
    "m": 60, "分": 60, "分钟": 60,
    "h": 3600, "小时": 3600,
}
_DURATION_RE = re.compile(r"(\d+(?:\.\d+)?)\s*(秒|分钟|小时|[smhSMH])?")
_WINDOW_RE = re.compile(r"(\d{1,2})[:：](\d{2})\s*-\s*(\d{1,2})[:：](\d{2})")


# -------------------------------------------------------------------- 时长
def parse_duration(text: str) -> float:
    """把 ``30m`` / ``1h30m`` / ``90s`` / ``45`` 解析成秒。

    纯数字按**分钟**算（``pause 45`` 就是 45 分钟），这是最符合直觉的默认。
    """
    raw = (text or "").strip().lower()
    if not raw:
        raise ValueError("时长不能为空")
    total = 0.0
    pos = 0
    for match in _DURATION_RE.finditer(raw):
        if match.start() != pos:
            raise ValueError("看不懂的时长：{}".format(text))
        value = float(match.group(1))
        unit = match.group(2) or "m"
        total += value * _UNIT_SECONDS.get(unit.lower() if len(unit) == 1 else unit, 60)
        pos = match.end()
    if pos != len(raw) or total <= 0:
        raise ValueError("看不懂的时长：{}".format(text))
    return total


def format_duration(seconds: float) -> str:
    seconds = max(0, int(round(seconds)))
    hours, rest = divmod(seconds, 3600)
    minutes, secs = divmod(rest, 60)
    if hours:
        text = "{} 小时".format(hours)
        if minutes:
            text += " {} 分钟".format(minutes)
        return text
    if minutes:
        return "{} 分钟{}".format(minutes, " {} 秒".format(secs) if secs else "")
    return "{} 秒".format(secs)


def format_time(ts: float) -> str:
    return datetime.datetime.fromtimestamp(ts).strftime("%m-%d %H:%M")


# -------------------------------------------------------------------- 时间窗
def parse_windows(text: str) -> List[Tuple[int, int]]:
    """``"23:00-07:00,12:00-13:00"`` → ``[(1380, 420), (720, 780)]``（分钟）。

    跨午夜（结束时间早于开始时间）是支持的。
    """
    raw = (text or "").strip()
    if not raw:
        return []
    out: List[Tuple[int, int]] = []
    for chunk in re.split(r"[,;，；\s]+", raw):
        if not chunk:
            continue
        match = _WINDOW_RE.fullmatch(chunk)
        if not match:
            raise ValueError("时间段格式应为 23:00-07:00：{}".format(chunk))
        h1, m1, h2, m2 = (int(part) for part in match.groups())
        if h1 > 23 or h2 > 23 or m1 > 59 or m2 > 59:
            raise ValueError("时间超出范围：{}".format(chunk))
        if h1 == h2 and m1 == m2:
            raise ValueError("起止时间相同：{}".format(chunk))
        out.append((h1 * 60 + m1, h2 * 60 + m2))
    return out


def format_windows(windows: List[Tuple[int, int]]) -> str:
    return "、".join(
        "{:02d}:{:02d}-{:02d}:{:02d}".format(s // 60, s % 60, e // 60, e % 60)
        for s, e in windows
    )


def in_window(now: datetime.datetime, windows: List[Tuple[int, int]]) -> bool:
    if not windows:
        return True
    current = now.hour * 60 + now.minute
    for start, end in windows:
        if start < end:
            if start <= current < end:
                return True
        else:  # 跨午夜，如 23:00-07:00
            if current >= start or current < end:
                return True
    return False


# -------------------------------------------------------------------- 暂停状态
def state_path() -> str:
    return os.path.join(config_dir(), STATE_NAME)


def load_state() -> Dict[str, Any]:
    path = state_path()
    if not os.path.exists(path):
        return {}
    try:
        with open(path, "r", encoding="utf-8") as fh:
            data = json.load(fh)
        return data if isinstance(data, dict) else {}
    except (OSError, ValueError):
        return {}


def save_state(state: Dict[str, Any]) -> None:
    path = state_path()
    directory = os.path.dirname(path)
    os.makedirs(directory, exist_ok=True)
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", dir=directory,
                                         prefix=".policy-", suffix=".tmp", delete=False) as fh:
            temporary = fh.name
            json.dump(state, fh, ensure_ascii=False, indent=2)
            fh.write("\n")
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(temporary, path)
    finally:
        if temporary and os.path.exists(temporary):
            os.unlink(temporary)


def paused_until() -> float:
    try:
        return float(load_state().get("paused_until") or 0)
    except (TypeError, ValueError):
        return 0.0


def pause_until(timestamp: float, reason: str = "") -> float:
    state = load_state()
    state["paused_until"] = float(timestamp)
    state["reason"] = reason
    save_state(state)
    return float(timestamp)


def pause_for(seconds: float, reason: str = "") -> float:
    return pause_until(time.time() + max(0.0, seconds), reason)


def resume() -> None:
    state = load_state()
    state["paused_until"] = 0
    state.pop("reason", None)
    save_state(state)


def pause_remaining(now: Optional[float] = None) -> float:
    return max(0.0, paused_until() - (now if now is not None else time.time()))


# -------------------------------------------------------------------- 配置读取
def _number(value: Any, default: float) -> float:
    try:
        number = float(value)
        return number if math.isfinite(number) else default
    except (TypeError, ValueError):
        return default


def _options(cfg: Any) -> Dict[str, Any]:
    """允许直接传 ``cfg.options`` 这种字典（托盘菜单里只读判断用）。"""
    if isinstance(cfg, dict):
        return cfg
    return getattr(cfg, "options", {}) or {}


def interval_minutes(cfg: Config) -> int:
    return max(1, int(_number(_options(cfg).get(KEY_INTERVAL), DEFAULT_INTERVAL)))


def reconnect_delay(cfg: Config) -> float:
    return max(0.0, _number(_options(cfg).get(KEY_DELAY), DEFAULT_DELAY))


def windows_text(cfg: Config) -> str:
    return str(_options(cfg).get(KEY_WINDOWS, "") or "")


def windows(cfg: Config) -> List[Tuple[int, int]]:
    try:
        return parse_windows(windows_text(cfg))
    except ValueError:
        return []


def set_options(cfg: Config, **values: Any) -> str:
    """写回配置。值为空串 / ``None`` 表示删掉这项。"""
    updated = Config.from_dict(cfg.to_dict(include_password=True), path=cfg.path)
    updated.password_source = cfg.password_source
    for key, value in values.items():
        if value is None or value == "":
            updated.options.pop(key, None)
        else:
            updated.options[key] = value
    path = updated.save()
    cfg.options = updated.options
    cfg.path = updated.path
    return path


# -------------------------------------------------------------------- 判断
def block_reason(cfg: Config, now: Optional[datetime.datetime] = None) -> str:
    """现在能不能自动重连。能就返回空串，不能就返回一句人话。"""
    remaining = pause_remaining()
    if remaining > 0:
        return "已暂停自动重连，{} 后恢复".format(format_time(paused_until()))
    wins = windows(cfg)
    if wins:
        now = now or datetime.datetime.now()
        if not in_window(now, wins):
            return "不在定时重连时间段内（{}）".format(format_windows(wins))
    return ""


def describe(cfg: Config) -> str:
    parts = ["每 {} 分钟检查".format(interval_minutes(cfg))]
    delay = reconnect_delay(cfg)
    parts.append("离线后等 {}再重连".format(format_duration(delay)) if delay > 0 else "离线立即重连")
    wins = windows(cfg)
    if wins:
        parts.append("仅在 {} 重连".format(format_windows(wins)))
    remaining = pause_remaining()
    if remaining > 0:
        parts.append("已暂停至 {}".format(format_time(paused_until())))
    return " · ".join(parts)
