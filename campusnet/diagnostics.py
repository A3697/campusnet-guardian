"""Read-only, bounded network evidence collection and local 7z export."""

from __future__ import annotations

import base64
import datetime
import hashlib
import html
import json
import os
import platform
import re
import subprocess
import sys
import tempfile
import threading
import time
import zlib
from dataclasses import asdict, dataclass
from pathlib import Path
from urllib.parse import parse_qsl, quote, quote_plus, urlsplit

from . import __version__, detector
from .config import Config, runtime_log_dir
from .procflags import no_window_kwargs
from .session import HttpError, Session

BODY_LIMIT = 2 * 1024 * 1024
LOG_LIMIT = 4 * 1024 * 1024
REQUEST_LIMIT = 32
NETWORK_SECONDS = 75
SEVEN_ZIP_SHA256 = "256feca8e274e5da655e2a284fabafd9f554365eb164862089dacd4e8276d282"
HIDDEN = "[已隐藏]"
SENSITIVE = (r"(?:user_?name|user_?account|account|u_name|login_?name|password|passwd|pass|pwd|"
             r"upass|u_pass|user_?password|secret|access_?token|refresh_?token|token|"
             r"session_?id|jsessionid|authorization|cookie|set-cookie|csrf\w*|xsrf\w*|"
             r"chksum|checksum|hmac|sign|signature|info|challenge|mac|mac_?address|"
             r"wlanusermac|user_?mac|phone|mobile|email|ssid|账号|账户|用户名|密码|口令|令牌|手机号)")


class ExportCancelled(Exception):
    pass


class ExportError(Exception):
    pass


def _check_cancel(cancel):
    if cancel.is_set():
        raise ExportCancelled("已取消采集，未生成导出文件。")


class Redactor:
    """Hide known credentials and common fields, keeping server paths and topology."""

    def __init__(self, secrets=()):
        values = set()
        for value in secrets:
            if not value:
                continue
            value = str(value)
            values.update((value, quote(value, safe=""), quote_plus(value), html.escape(value),
                           json.dumps(value, ensure_ascii=True)[1:-1]))
            if len(value) >= 4:
                values.add(base64.b64encode(value.encode()).decode())
        self.values = sorted(values, key=len, reverse=True)

    def text(self, value):
        text = str(value)
        for secret in self.values:
            text = text.replace(secret, HIDDEN)
        # Query parameters may themselves have been percent-encoded in a redirect.
        text = re.sub(r"(?i)(\b" + SENSITIVE + r"%3d)[^%\s\"<>]*(?:(?!%26|%23)%[0-9a-f]{2}[^%\s\"<>]*)*",
                      lambda m: m[1] + HIDDEN, text)
        text = re.sub(r"(?im)(\b(?:authorization|cookie|set-cookie)\s*:\s*)[^\r\n]+",
                      lambda m: m[1] + HIDDEN, text)
        text = re.sub(r"(?i)([\"']?\b" + SENSITIVE + r"\b[\"']?\s*[:=：]\s*)([\"'])(.*?)\2",
                      lambda m: m[1] + m[2] + HIDDEN + m[2], text, flags=re.S)
        text = re.sub(r"(?i)(\b" + SENSITIVE + r"\b\s*[:=：]\s*)(?![\"'\[])[^\s&,;<>\"'}，；]+",
                      lambda m: m[1] + HIDDEN, text)
        text = re.sub(r"(?is)((?:localStorage|sessionStorage)\.setItem\(\s*['\"][^'\"]+['\"]\s*,\s*)(['\"])(.*?)\2",
                      lambda m: m[1] + m[2] + HIDDEN + m[2], text)
        # Form defaults (including hidden tokens) and textarea contents are not needed.
        text = re.sub(r"(?is)<input\b[^>]*>", self._input, text)
        text = re.sub(r"(?is)(<textarea\b[^>]*>).*?(</textarea\s*>)", r"\1[已隐藏]\2", text)
        text = re.sub(r"(?i)(https?://)[^/\s@]+@", r"\1[已隐藏]@", text)
        text = re.sub(r"(?i)\b(?:[0-9a-f]{2}[:-]){5}[0-9a-f]{2}\b", HIDDEN, text)
        text = re.sub(r"(?i)\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b", HIDDEN, text)
        text = re.sub(r"(?i)([a-z]:[\\/]+Users[\\/]+)[^\\/\s\"<>]+", r"\1[已隐藏]", text)
        return text

    @staticmethod
    def _input(match):
        return re.sub(r"(?is)(\bvalue\s*=\s*)(?:\"[^\"]*\"|'[^']*'|[^\s>]+)",
                      r'\1"[已隐藏]"', match[0])

    def data(self, value):
        if isinstance(value, dict):
            return {str(k): HIDDEN if re.fullmatch(SENSITIVE, str(k), re.I) else self.data(v)
                    for k, v in value.items()}
        if isinstance(value, (list, tuple)):
            return [self.data(v) for v in value]
        return self.text(value) if isinstance(value, str) else value


def _write_text(path, text):
    with path.open("w", encoding="utf-8", newline="\n") as stream:
        stream.write(text)


def network_snapshot():
    if os.name != "nt":
        return {"note": "详细网卡、路由和 DNS 采集仅适用于 Windows。"}
    from .windows_network import run_powershell
    # Deliberately omit machine/user names, Wi-Fi profiles, GUIDs and MAC addresses.
    return run_powershell(r"""
        $adapters=@(Get-NetAdapter | Select-Object ifIndex,InterfaceDescription,Status,LinkSpeed,HardwareInterface);
        $ips=@(Get-NetIPAddress | Select-Object InterfaceIndex,AddressFamily,IPAddress,PrefixLength,AddressState);
        $routes=@(Get-NetRoute | Select-Object InterfaceIndex,AddressFamily,DestinationPrefix,NextHop,RouteMetric);
        $dns=@(Get-DnsClientServerAddress | Select-Object InterfaceIndex,AddressFamily,ServerAddresses);
        $proxy=Get-ItemProperty 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings' -ErrorAction SilentlyContinue;
        [ordered]@{adapters=$adapters; addresses=$ips; routes=$routes; dns=$dns;
          proxy=[ordered]@{enabled=$proxy.ProxyEnable; server=$proxy.ProxyServer;
            auto_config_url=$proxy.AutoConfigURL}} | ConvertTo-Json -Depth 6 -Compress
    """, timeout=20)


class CaptureSession(Session):
    def __init__(self, folder, redactor, cancel, progress, cfg):
        super().__init__(timeout=4, retries=0, use_proxy=cfg.use_proxy,
                         verify_tls=bool(cfg.options.get("verify_portal_tls", False)))
        self.folder = folder
        self.redactor = redactor
        self.cancel = cancel
        self.progress = progress
        self.records = []
        self.deadline = time.monotonic() + NETWORK_SECONDS
        self.truncated = False

    def _read(self, response):
        self.truncated = False
        chunks = []
        size = 0
        try:
            while size <= BODY_LIMIT:
                _check_cancel(self.cancel)
                if time.monotonic() >= self.deadline:
                    raise HttpError("采集时间已到，已保留此前结果。")
                chunk = response.read(min(65536, BODY_LIMIT + 1 - size))
                if not chunk:
                    break
                chunks.append(chunk)
                size += len(chunk)
            raw = b"".join(chunks)
            self.truncated = len(raw) > BODY_LIMIT
            encoding = (response.headers.get("Content-Encoding") or "").lower()
            if encoding in ("gzip", "deflate"):
                windows = (31,) if encoding == "gzip" else (zlib.MAX_WBITS, -zlib.MAX_WBITS)
                for window in windows:
                    try:
                        decoder = zlib.decompressobj(window)
                        raw = decoder.decompress(raw, BODY_LIMIT + 1)
                        self.truncated |= len(raw) > BODY_LIMIT or bool(decoder.unconsumed_tail)
                        break
                    except zlib.error:
                        continue
                else:
                    raise HttpError("网页压缩数据无法读取。")
            return raw[:BODY_LIMIT]
        finally:
            response.close()

    def request(self, url, method="GET", data=None, **kwargs):
        _check_cancel(self.cancel)
        if len(self.records) >= REQUEST_LIMIT or time.monotonic() >= self.deadline:
            raise HttpError("已达到采集上限，已保留此前结果。", url)
        item = {"url": self.redactor.text(url), "method": "GET"}
        self.records.append(item)
        start = time.monotonic()
        self.progress("正在采集网页及跳转记录（第 {} 次请求）…".format(len(self.records)))
        try:
            parts = urlsplit(url)
            pairs = parse_qsl(parts.query, keep_blank_values=True)
            unsafe = any(re.fullmatch(SENSITIVE, k, re.I) or
                         (k.lower() in ("action", "method", "op") and v.lower() in ("login", "logout", "unbind", "disconnect"))
                         for k, v in pairs)
            if (method != "GET" or data is not None or parts.scheme not in ("http", "https")
                    or parts.username is not None or unsafe
                    or re.search(r"(?i)/(?:logout|disconnect|unbind)(?:[/.?]|$)", parts.path)):
                raise HttpError("已跳过可能包含凭据或改变认证状态的请求。", url)
            kwargs["allow_redirects"] = False
            kwargs["timeout"] = min(float(kwargs.get("timeout") or 4), 4,
                                    max(.1, self.deadline - time.monotonic()))
            response = super().request(url, method="GET", **kwargs)
            item.update(status=response.status, response_url=self.redactor.text(response.url),
                        bytes_retained=len(response.body), truncated=self.truncated,
                        headers=self.redactor.data({k: v for k, v in response.headers.items()
                            if k in ("content-type", "content-encoding", "content-length", "server", "location", "refresh", "captive-portal")}))
            ctype = response.headers.get("content-type", "").lower()
            if response.body and (not ctype or any(t in ctype for t in ("text", "json", "javascript", "xml"))):
                name = "pages/{:02d}.txt".format(len(self.records))
                target = self.folder / name
                target.parent.mkdir(exist_ok=True)
                _write_text(target, self.redactor.text(response.text))
                item["body_file"] = name
            return response
        except ExportCancelled:
            raise
        except Exception as exc:
            item["error"] = self.redactor.text(str(exc))
            raise HttpError(item["error"], url) from exc
        finally:
            item["elapsed_ms"] = round((time.monotonic() - start) * 1000)


def seven_zip_executable():
    path = Path(__file__).resolve().parents[1] / "third_party/7zip/7zr.exe"
    if not path.is_file() or hashlib.sha256(path.read_bytes()).hexdigest() != SEVEN_ZIP_SHA256:
        raise ExportError("内置 7z 压缩组件缺失或损坏，请重新安装本应用后重试。")
    return path


def compress_7z(folder, destination, cancel):
    executable = seven_zip_executable()
    _check_cancel(cancel)
    process = subprocess.Popen([str(executable), "a", "-t7z", "-mx=5", "-mmt=2", "-md=16m",
                                "-bso0", "-bsp0", str(destination), "."], cwd=str(folder),
                               stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, **no_window_kwargs())
    deadline = time.monotonic() + 300
    try:
        while True:
            _check_cancel(cancel)
            if time.monotonic() > deadline:
                raise ExportError("7z 压缩超时，请更换本地保存位置后重试。")
            try:
                _, error = process.communicate(timeout=.2)
                break
            except subprocess.TimeoutExpired:
                continue
        if process.returncode:
            raise ExportError("7z 压缩失败（代码 {}），请检查保存位置和可用空间。".format(process.returncode))
    finally:
        if process.poll() is None:
            process.kill()
            process.communicate()
    with destination.open("rb") as stream:
        if stream.read(6) != b"7z\xbc\xaf\x27\x1c":
            raise ExportError("导出文件未通过 7z 格式检查。")


@dataclass
class ExportResult:
    path: str
    size: int
    requests: int
    warnings: int


def export_environment(cfg: Config, destination, *, cancel=None, progress=None, extra_secrets=(),
                       log_directory=None, ui_log=""):
    """Never log in, reset adapters, change config or upload the resulting archive."""
    cancel = cancel or threading.Event()
    progress = progress or (lambda _text: None)
    destination = Path(destination).absolute()
    if destination.suffix.lower() != ".7z":
        raise ExportError("导出文件名必须以 .7z 结尾。")
    if not destination.parent.is_dir():
        raise ExportError("保存文件夹不存在，请重新选择。")
    seven_zip_executable()  # Fail before collecting if the package is incomplete.
    _check_cancel(cancel)
    # Read credentials only to remove their occurrences from diagnostics.
    secrets = [cfg.username, cfg.password, cfg.wifi_ssid, *extra_secrets]
    try:
        secrets.append(cfg.resolve_password(prompt=False))
    except Exception:
        pass
    redact = Redactor(secrets)
    report = {"schema": 1, "application": "校园网连接守护", "version": __version__,
              "created_at": datetime.datetime.now().astimezone().isoformat(timespec="seconds"),
              "system": {"os": platform.system(), "release": platform.release(),
                         "version": platform.version(), "architecture": platform.machine(),
                         "python": platform.python_version(), "frozen": bool(getattr(sys, "frozen", False))},
              "limits": {"request_count": REQUEST_LIMIT, "network_seconds": NETWORK_SECONDS,
                         "response_bytes": BODY_LIMIT, "log_bytes_per_file": LOG_LIMIT},
              "configuration": {"portal_mode": "auto" if cfg.automatic_portal else "manual",
                                "manual_portal": "" if cfg.automatic_portal else cfg.portal_ip,
                                "provider": cfg.provider,
                                "use_proxy": cfg.use_proxy, "timeout": cfg.timeout,
                                "verify_tls": bool(cfg.options.get("verify_portal_tls", False)),
                                "carrier": cfg.options.get("carrier", "")},
              "warnings": [], "logs": []}
    with tempfile.TemporaryDirectory(prefix=".campusnet-export-", dir=destination.parent) as temporary:
        folder = Path(temporary) / "data"
        folder.mkdir()
        def write_json(name, data):
            _write_text(folder / name, json.dumps(redact.data(data), ensure_ascii=False, indent=2) + "\n")
        progress("正在读取网卡、路由、DNS 和代理设置…")
        try:
            report["network"] = network_snapshot()
        except Exception as exc:
            report["warnings"].append("网络配置读取未完成：" + str(exc))
        _check_cancel(cancel)
        capture = CaptureSession(folder, redact, cancel, progress, cfg)
        try:
            # A supplied address must get a chance even when every public probe times out.
            if not cfg.automatic_portal:
                report["detection"] = asdict(detector.detect(capture, cfg))
            status = detector.check_online(capture)
            report["connectivity"] = asdict(status)
            _check_cancel(cancel)
            if cfg.automatic_portal:
                report["detection"] = asdict(detector.detect(capture, cfg, status))
            if not report["detection"].get("scores"):
                report["warnings"].append(report["detection"].get("detail") or "未识别出已适配的认证方式。")
        except ExportCancelled:
            raise
        except Exception as exc:
            report["warnings"].append("入口采集未完成：" + str(exc))
        write_json("requests.json", capture.records)
        progress("正在整理和脱敏运行日志…")
        logs = Path(log_directory) if log_directory else Path(runtime_log_dir())
        for name in ("watch.log", "watch.log.1", "gui-errors.log"):
            _check_cancel(cancel)
            path = logs / name
            if not path.is_file() or path.is_symlink():
                continue
            try:
                with path.open("rb") as stream:
                    size = stream.seek(0, 2)
                    stream.seek(max(0, size - LOG_LIMIT))
                    raw = stream.read(LOG_LIMIT)
                if size > LOG_LIMIT:
                    raw = raw.partition(b"\n")[2]  # Don't export a partial first field.
                target = folder / "logs" / (name + ".txt")
                target.parent.mkdir(exist_ok=True)
                _write_text(target, redact.text(raw.decode("utf-8", "replace")))
                report["logs"].append({"file": target.relative_to(folder).as_posix(), "truncated": size > LOG_LIMIT})
            except OSError as exc:
                report["warnings"].append("日志读取未完成：" + str(exc))
        if ui_log:
            _write_text(folder / "window-log.txt", redact.text(ui_log[-131072:]))
        write_json("report.json", report)
        _write_text(folder / "阅读说明.txt",
            "校园网连接守护：网络环境数据\n\n"
            "report.json：系统版本、网卡、路由、DNS、代理及识别结果。\n"
            "requests.json：HTTP 状态、跳转、耗时和错误；pages：对应网页和脚本的文本副本。\n"
            "logs：近期运行日志；manifest.json：文件大小和 SHA-256。\n\n"
            "采集只读取配置和访问网页，不主动认证、注销或修改网卡；不自动上传文件。\n"
            "常见账号、密码、Cookie、令牌、MAC 和 Windows 用户目录已脱敏。\n"
            "文件仍包含认证服务器地址、IP、网关、DNS 和网页内容，请查看后发送给排障人员。\n"
            "网页和日志有大小及时间上限；错误、缺失项和截断信息会保留，不影响导出。\n"
            "已联网时可能没有认证跳转。若未找到页面，可在账号设置中填写地址后再次采集；无需先保存。\n"
            "本文件是现场排障资料，不是已支持该学校的保证。\n")
        manifest = []
        for path in sorted(folder.rglob("*")):
            if path.is_file():
                data = path.read_bytes()
                manifest.append({"file": path.relative_to(folder).as_posix(), "size": len(data),
                                 "sha256": hashlib.sha256(data).hexdigest()})
        write_json("manifest.json", manifest)
        progress("正在压缩为 7z 文件…")
        archive = Path(temporary) / "environment.7z"
        compress_7z(folder, archive, cancel)
        _check_cancel(cancel)
        size = archive.stat().st_size
        os.replace(archive, destination)
    return ExportResult(str(destination), size, len(capture.records), len(report["warnings"]))
