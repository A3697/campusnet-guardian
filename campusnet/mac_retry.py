"""Windows 随机 MAC 后备重试：只处理当前物理网卡，失败恢复原值。"""

from __future__ import annotations

import json
import os
import re
import secrets
import subprocess
import sys
import time
from contextlib import contextmanager
from pathlib import Path

from .config import Config
from .windows_network import inspect_adapter, run_powershell as _ps

OPTION = "random_mac_retry"
COOLDOWN = 1800


def random_mac() -> str:
    value = bytearray(secrets.token_bytes(6))
    value[0] = (value[0] | 2) & 0xfe  # Locally administered, unicast.
    return value.hex().upper()


def _mac(value) -> str:
    result = str(value or "").replace("-", "").replace(":", "").upper()
    if result and not re.fullmatch(r"[0-9A-F]{12}", result):
        raise ValueError("网卡返回了无效的 MAC 地址")
    return result


def _directory(cfg) -> Path:
    if not cfg.path:
        raise ValueError("请先保存账号设置，再使用随机 MAC 重试")
    return Path(cfg.path).resolve().parent


def _read(path) -> dict:
    if not path.exists():
        return {}
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError("MAC 恢复记录格式不正确，请保留该文件并查看诊断信息")
    return value


def _write(path, value):
    temporary = path.with_suffix(".tmp")
    with temporary.open("w", encoding="utf-8") as stream:
        json.dump(value, stream, ensure_ascii=False, indent=2)
        stream.flush()
        os.fsync(stream.fileno())
    os.replace(temporary, path)


@contextmanager
def _lock(path):
    """Released by Windows even if the process crashes; GUI and watcher share it."""
    import msvcrt

    with path.open("a+b") as stream:
        if stream.tell() == 0:
            stream.write(b"0")
            stream.flush()
        stream.seek(0)
        try:
            msvcrt.locking(stream.fileno(), msvcrt.LK_NBLCK, 1)
        except OSError:
            raise RuntimeError("已有一次 MAC 重试或恢复正在进行，请等待完成") from None
        try:
            yield
        finally:
            stream.seek(0)
            msvcrt.locking(stream.fileno(), msvcrt.LK_UNLCK, 1)


class WindowsAdapter:
    def inspect(self, guid=""):
        return inspect_adapter(guid)

    def apply(self, snapshot, address):
        guid = snapshot["guid"]
        if not re.fullmatch(r"[0-9a-fA-F-]{36}", guid):
            raise ValueError("无效的网卡标识")
        address = _mac(address)
        action = ("Set-NetAdapterAdvancedProperty -InputObject $property -RegistryValue '" + address + "' -NoRestart;"
                  if address else "Reset-NetAdapterAdvancedProperty -InputObject $property -NoRestart;")
        _ps("""
            $adapter=@(Get-NetAdapter -Physical | Where-Object { [guid]$_.InterfaceGuid -eq [guid]'""" + guid + """' });
            if ($adapter.Count -ne 1) { throw '原网卡已不存在，未修改其他网卡。'; }
            $property=Get-NetAdapterAdvancedProperty -Name $adapter[0].Name -RegistryKeyword 'NetworkAddress';
        """ + action + "Restart-NetAdapter -InputObject $adapter[0] -Confirm:$false;", timeout=60)
        from .windows_network import clear_cache
        clear_cache()

    def wait_ready(self, snapshot, address, seconds=35):
        end = time.monotonic() + seconds
        while time.monotonic() < end:
            current = self.inspect(snapshot["guid"])
            if current["up"] and current["ready"] and _mac(current["mac"]) == _mac(address):
                return
            time.sleep(2)
        raise RuntimeError("网卡未在等待时间内恢复地址和网关")

    def restore(self, snapshot):
        self.apply(snapshot, snapshot["override"])
        self.wait_ready(snapshot, snapshot["mac"])


def _admin():
    import ctypes
    return os.name == "nt" and bool(ctypes.windll.shell32.IsUserAnAdmin())


def _launch(cfg, token):
    """Elevate only this bounded retry. Never install a privileged task/service."""
    import ctypes
    from ctypes import wintypes

    class ExecuteInfo(ctypes.Structure):
        _fields_ = [("cbSize", wintypes.DWORD), ("fMask", wintypes.ULONG), ("hwnd", wintypes.HWND),
                    ("lpVerb", wintypes.LPCWSTR), ("lpFile", wintypes.LPCWSTR),
                    ("lpParameters", wintypes.LPCWSTR), ("lpDirectory", wintypes.LPCWSTR),
                    ("nShow", ctypes.c_int), ("hInstApp", wintypes.HINSTANCE),
                    ("lpIDList", wintypes.LPVOID), ("lpClass", wintypes.LPCWSTR),
                    ("hkeyClass", wintypes.HKEY), ("dwHotKey", wintypes.DWORD),
                    ("hIcon", wintypes.HANDLE), ("hProcess", wintypes.HANDLE)]

    args = ["mac-retry", "--config", str(Path(cfg.path).resolve()), "--task", token]
    if not getattr(sys, "frozen", False):
        args = ["-m", "campusnet"] + args
    shell = ctypes.WinDLL("shell32", use_last_error=True)
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    shell.ShellExecuteExW.argtypes = [ctypes.POINTER(ExecuteInfo)]
    shell.ShellExecuteExW.restype = wintypes.BOOL
    kernel.WaitForSingleObject.argtypes = [wintypes.HANDLE, wintypes.DWORD]
    kernel.CloseHandle.argtypes = [wintypes.HANDLE]
    info = ExecuteInfo()
    info.cbSize, info.fMask, info.lpVerb = ctypes.sizeof(info), 0x40, "runas"
    info.lpFile, info.lpParameters = sys.executable, subprocess.list2cmdline(args)
    info.lpDirectory, info.nShow = str(Path(__file__).resolve().parent.parent), 0
    previous = os.environ.get("PYINSTALLER_RESET_ENVIRONMENT")
    os.environ["PYINSTALLER_RESET_ENVIRONMENT"] = "1"
    try:
        if not shell.ShellExecuteExW(ctypes.byref(info)):
            code = ctypes.get_last_error()
            if code == 1223:
                raise RuntimeError("已取消管理员授权，网卡未修改")
            raise ctypes.WinError(code)
    finally:
        if previous is None:
            os.environ.pop("PYINSTALLER_RESET_ENVIRONMENT", None)
        else:
            os.environ["PYINSTALLER_RESET_ENVIRONMENT"] = previous
    try:
        # Do not kill a helper that might still be restoring the adapter.
        if kernel.WaitForSingleObject(info.hProcess, 300000) != 0:
            raise RuntimeError("MAC 重试仍在处理，请稍后查看日志；恢复记录已保留")
    finally:
        kernel.CloseHandle(info.hProcess)


def request(cfg, logger=None, restore=False):
    """Return only public result fields; credentials never enter the task files."""
    log = logger or (lambda *args: None)
    if os.name != "nt":
        return {"ok": False, "message": "随机 MAC 重试仅支持 Windows"}
    try:
        directory = _directory(cfg)
        with _lock(directory / "mac-retry-request.lock"):
            state_path = directory / "mac-retry-state.json"
            state = _read(state_path)
            if not restore and time.time() - state.get("last_attempt", 0) < COOLDOWN:
                return {"ok": False, "message": "本轮未找到登录入口；随机 MAC 重试每 30 分钟最多执行一次"}
            if not restore:
                adapter = WindowsAdapter().inspect()
                if not adapter.get("supported") or not adapter.get("dhcp"):
                    return {"ok": False, "message": "当前网卡未提供 MAC 修改功能或未启用 DHCP，已跳过后备重试"}
            else:
                journal = _read(directory / "mac-retry-recovery.json")
                if journal.get("phase") not in ("pending", "recovery_required", "committed"):
                    return {"ok": False, "message": "没有需要恢复的 MAC 修改记录"}
                adapter = journal["adapter"]
            token = secrets.token_hex(16)
            task = {"token": token, "created": time.time(), "guid": adapter["guid"],
                    "gateway": adapter.get("gateway"), "restore": restore}
            _write(directory / "mac-retry-task.json", task)
            if not restore:
                _write(state_path, {"last_attempt": time.time()})
            log("正在请求管理员权限恢复原 MAC。" if restore else
                "未找到登录入口，将请求管理员权限，使用随机 MAC 重试；失败后恢复原设置。", "warn")
            if _admin():
                worker(cfg, token)
            else:
                _launch(cfg, token)
            result = _read(directory / "mac-retry-result.json")
            if result.get("token") != token:
                raise RuntimeError("MAC 重试未返回结果；如网卡没有恢复，请在重连策略中点击恢复原 MAC")
            return result
    except Exception as exc:
        return {"ok": False, "message": str(exc)}


def transaction(cfg, task, backend, runner_factory, journal_path):
    """Network transaction, separated from elevation so rollback is fully testable."""
    journal = _read(journal_path)
    if journal.get("phase") in ("pending", "recovery_required") or task.get("restore"):
        if journal.get("phase") not in ("pending", "recovery_required", "committed"):
            return {"ok": False, "message": "没有需要恢复的 MAC 修改记录"}
        try:
            backend.restore(journal["adapter"])
        except Exception:
            journal["phase"] = "recovery_required"
            _write(journal_path, journal)
            return {"ok": False, "message": "原 MAC 尚未恢复，请保持网卡连接，使用重连策略中的恢复原 MAC 再试。"}
        journal["phase"] = "restored"
        _write(journal_path, journal)
        return {"ok": bool(task.get("restore")), "message": "已恢复修改前的 MAC。"}

    if not cfg.automatic_portal or not cfg.options.get(OPTION):
        return {"ok": False, "message": "已关闭随机 MAC 重试或改为手动登录地址，网卡未修改"}
    runner = runner_factory(cfg)
    status = runner.status()
    if status.online:
        return {"ok": True, "message": "网络已经恢复，无需修改 MAC"}
    detection = runner._detected or runner.detect(status)
    if detection.best:
        result = runner.ensure_online(allow_mac_retry=False)
        return {"ok": result.ok, "message": result.message, "provider": result.provider}
    adapter = backend.inspect()
    if (adapter["guid"] != task["guid"] or adapter.get("gateway") != task.get("gateway")
            or not adapter.get("supported")
            or not adapter.get("up") or not adapter.get("dhcp")):
        return {"ok": False, "message": "当前网卡已变化或不支持修改，已取消随机 MAC 重试"}
    if not cfg.username or not cfg.resolve_password(prompt=False):
        return {"ok": False, "message": "账号或密码未保存，网卡未修改"}
    address = random_mac()
    journal = {"phase": "pending", "adapter": adapter, "random": address, "created": time.time()}
    _write(journal_path, journal)  # No adapter mutation before the recovery record is durable.
    committed = False
    result = {"ok": False, "message": "随机 MAC 重试未能连通校园网"}
    try:
        backend.apply(adapter, address)
        backend.wait_ready(adapter, address)
        # A new Runner/HTTP session must rediscover the gateway and portal after DHCP.
        retry = runner_factory(cfg).ensure_online(allow_mac_retry=False)
        if retry.ok:
            journal["phase"] = "committed"
            _write(journal_path, journal)
            committed = True
            result = {"ok": True, "provider": retry.provider, "message": "随机 MAC 重试后已连接校园网"}
    except Exception:
        result = {"ok": False, "message": "随机 MAC 重试未成功"}
    finally:
        if not committed:
            try:
                backend.restore(adapter)
                journal["phase"] = "restored"
                result["message"] += "，已恢复修改前的 MAC"
            except Exception:
                journal["phase"] = "recovery_required"
                result["message"] += "；原 MAC 尚未恢复，请在重连策略中点击恢复原 MAC"
            _write(journal_path, journal)
    return result


def worker(cfg, token):
    if not _admin():
        raise RuntimeError("修改网卡需要管理员权限")
    if not re.fullmatch(r"[0-9a-f]{32}", token):
        raise ValueError("无效的 MAC 重试任务")
    from .runner import Runner

    directory = _directory(cfg)
    with _lock(directory / "mac-retry-operation.lock"):
        task = _read(directory / "mac-retry-task.json")
        if task.get("token") != token or not 0 <= time.time() - task.get("created", 0) < 300:
            raise ValueError("MAC 重试任务已过期，请重新操作")
        try:
            result = transaction(cfg, task, WindowsAdapter(), Runner, directory / "mac-retry-recovery.json")
        except Exception as exc:
            result = {"ok": False, "message": "MAC 重试未完成：" + str(exc)}
        result["token"] = token
        _write(directory / "mac-retry-result.json", result)
        return 0 if result["ok"] else 1
