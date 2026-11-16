"""GitHub updates: validated metadata, cancellable downloads, and an in-place installer."""
from __future__ import annotations

import hashlib
import http.client
import json
import os
from pathlib import Path
import re
import ssl
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass

REPOSITORY = "A3697/campusnet-guardian"
PROJECT_URL = "https://github.com/" + REPOSITORY
APP_EXE = "校园网连接守护.exe"
MAX_INSTALLER_SIZE = 100 * 1024 * 1024
MAX_MANIFEST_SIZE = 64 * 1024
CHUNK_SIZE = 256 * 1024
MAX_DOWNLOAD_SECONDS = 30 * 60
VERSION_PATTERN = r"(\d+)\.(\d+)\.(\d+)(?:\+desktop\.(\d{8})\.(\d+))?"


class UpdateError(Exception):
    pass


class DownloadCancelled(UpdateError):
    pass


def version_key(value: str) -> tuple:
    match = re.fullmatch(VERSION_PATTERN, value or "")
    if not match:
        raise UpdateError("更新信息中的版本号无法识别。请稍后重新检查。")
    return tuple(int(part or 0) for part in match.groups())


@dataclass(frozen=True)
class UpdateInfo:
    version: str
    filename: str
    sha256: str
    size: int
    notes: str = ""

    def __post_init__(self):
        key = version_key(self.version)
        expected = "CampusNetGuardian-{}.{}-Setup.exe".format(key[3], key[4])
        if (not key[3] or self.filename != expected or
                not re.fullmatch(r"[0-9a-f]{64}", self.sha256) or
                type(self.size) is not int or not 2 <= self.size <= MAX_INSTALLER_SIZE or
                not isinstance(self.notes, str) or len(self.notes) > 4000):
            raise UpdateError("GitHub 上的更新信息不完整或格式不正确，未开始安装。")

    def newer_than(self, current_version: str) -> bool:
        return version_key(self.version) > version_key(current_version)


def parse_manifest(data: bytes) -> UpdateInfo:
    try:
        if len(data) > MAX_MANIFEST_SIZE:
            raise ValueError("manifest too large")
        value = json.loads(data.decode("utf-8-sig"))
        if value.get("schema") != 1:
            raise ValueError("unsupported schema")
        return UpdateInfo(value["version"], value["filename"], value["sha256"], value["size"], value.get("notes", ""))
    except (ValueError, TypeError, KeyError, AttributeError) as exc:
        raise UpdateError("GitHub 返回的更新信息无法读取。请稍后重试。") from exc


def _urls(filename: str):
    return (
        "https://raw.githubusercontent.com/{}/main/downloads/{}".format(REPOSITORY, filename),
        "https://api.github.com/repos/{}/contents/downloads/{}?ref=main".format(REPOSITORY, filename),
    )


def _trusted_url(url: str) -> bool:
    try:
        parts = urllib.parse.urlsplit(url)
        if parts.scheme != "https" or parts.username or parts.password or parts.port not in (None, 443):
            return False
        path = urllib.parse.unquote(parts.path)
        if "\\" in path or ".." in path.split("/"):
            return False
        prefixes = {
            "raw.githubusercontent.com": "/" + REPOSITORY + "/",
            "api.github.com": "/repos/" + REPOSITORY + "/contents/downloads/",
            "github.com": "/" + REPOSITORY + "/raw/",
        }
        prefix = prefixes.get(parts.hostname, "")
        return bool(prefix and path.lower().startswith(prefix.lower()))
    except ValueError:
        return False


class _GitHubRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        if not _trusted_url(newurl):
            raise UpdateError("下载跳转到了本项目以外的地址，已停止更新。")
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def _open(url: str, use_proxy: bool = True, offset: int = 0):
    if not _trusted_url(url):
        raise UpdateError("更新地址不属于本项目，已停止更新。")
    handlers = [_GitHubRedirect(), urllib.request.HTTPSHandler(context=ssl.create_default_context())]
    if not use_proxy:
        handlers.append(urllib.request.ProxyHandler({}))
    opener = urllib.request.build_opener(*handlers)
    request = urllib.request.Request(url, headers={
        "User-Agent": "CampusNetGuardian-Updater", "Accept": "application/vnd.github.raw+json",
        "Cache-Control": "no-cache", "Accept-Encoding": "identity",
    })
    if offset:
        request.add_header("Range", "bytes={}-".format(offset))
    return opener.open(request, timeout=15)


def _sources(filename: str):
    for url in _urls(filename):
        yield url, True
        if urllib.request.getproxies():
            yield url, False


def fetch_latest() -> UpdateInfo:
    last = None
    for url, use_proxy in _sources("latest.json"):
        try:
            with _open(url, use_proxy) as response:
                return parse_manifest(response.read(MAX_MANIFEST_SIZE + 1))
        except (OSError, ValueError, UpdateError, http.client.HTTPException) as exc:
            last = exc
    if isinstance(last, UpdateError):
        raise last
    raise UpdateError("无法从 GitHub 获取更新。请检查网络或代理设置后重试。") from last


def _cancelled(cancel) -> None:
    if cancel is not None and cancel.is_set():
        raise DownloadCancelled("已取消下载，当前版本未改变。")


def verify_file(path: Path, info: UpdateInfo, cancel=None) -> None:
    _cancelled(cancel)
    if path.stat().st_size != info.size:
        raise UpdateError("安装包大小与更新信息不一致，未开始安装。请重新下载。")
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        if stream.read(2) != b"MZ":
            raise UpdateError("下载的文件不是 Windows 安装程序，未开始安装。")
        stream.seek(0)
        while True:
            _cancelled(cancel)
            chunk = stream.read(CHUNK_SIZE)
            if not chunk:
                break
            digest.update(chunk)
    if digest.hexdigest() != info.sha256:
        raise UpdateError("安装包校验失败，未开始安装。请重新下载。")


def download(info: UpdateInfo, directory: Path, progress=None, cancel=None) -> Path:
    """Only publish a complete, verified file. Cancel/error removes this attempt's partial file."""
    _cancelled(cancel)
    directory = Path(directory)
    temporary = None
    try:
        directory.mkdir(parents=True, exist_ok=True)
        destination = directory / info.filename
        if destination.exists():
            try:
                verify_file(destination, info, cancel)
                if progress:
                    progress(info.size, info.size)
                return destination
            except UpdateError:
                _cancelled(cancel)
        deadline = time.monotonic() + MAX_DOWNLOAD_SECONDS
        last = None
        descriptor, temporary_name = tempfile.mkstemp(dir=directory, prefix="download-", suffix=".part")
        os.close(descriptor)
        temporary = Path(temporary_name)
        received = 0
        sources = list(_sources(info.filename))
        # Retry the last official route if its response was cut short.
        sources += sources[-1:] * 2
        for url, use_proxy in sources:
            _cancelled(cancel)
            if time.monotonic() >= deadline:
                break
            try:
                if progress:
                    progress(received, info.size)
                response = _open(url, use_proxy, received) if received else _open(url, use_proxy)
                with response:
                    status = getattr(response, "status", 200)
                    if status == 206:
                        span = re.fullmatch(r"bytes (\d+)-(\d+)/(\d+)", response.headers.get("Content-Range", ""))
                        if not span or tuple(map(int, span.groups())) != (received, info.size - 1, info.size):
                            raise UpdateError("续传的数据范围与安装包不一致，未开始安装。")
                    elif status == 200:
                        # A server may ignore Range; restart instead of appending a full file.
                        received = 0
                    else:
                        raise UpdateError("下载服务器返回了异常状态，未开始安装。")
                    with temporary.open("ab" if received else "wb") as stream:
                        while True:
                            _cancelled(cancel)
                            if time.monotonic() >= deadline:
                                raise UpdateError("下载超时，当前版本未改变。请稍后重试。")
                            chunk = response.read1(CHUNK_SIZE)
                            if not chunk:
                                break
                            received += len(chunk)
                            if received > info.size:
                                raise UpdateError("下载的文件大小异常，已停止更新。")
                            stream.write(chunk)
                            if progress:
                                progress(received, info.size)
                verify_file(temporary, info, cancel)
                _cancelled(cancel)
                os.replace(temporary, destination)
                return destination
            except DownloadCancelled:
                raise
            except (OSError, ValueError, UpdateError, http.client.HTTPException) as exc:
                if isinstance(exc, OSError) and exc.errno in (13, 28):
                    raise UpdateError("无法保存更新文件，请检查安装目录权限和磁盘空间。") from exc
                last = exc
                received = temporary.stat().st_size
                if received >= info.size:
                    # An oversized or corrupt complete response must never be resumed.
                    temporary.write_bytes(b"")
                    received = 0
        if isinstance(last, UpdateError):
            raise last
        raise UpdateError("安装包下载失败，当前版本未改变。请检查网络后重试。") from last
    except DownloadCancelled:
        raise
    except OSError as exc:
        raise UpdateError("无法保存更新文件，请检查安装目录权限和磁盘空间。") from exc
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)


def installation_dir() -> Path:
    if os.name != "nt" or not getattr(sys, "frozen", False):
        raise UpdateError("源码运行时不能覆盖安装。请从 GitHub 下载 Windows 安装包。")
    directory = Path(sys.executable).resolve().parent
    if not (directory / APP_EXE).is_file():
        raise UpdateError("无法确认当前安装目录，未开始更新。")
    return directory


def start_install(path: Path, info: UpdateInfo, directory: Path):
    """Recheck the downloaded bytes immediately before starting the existing installer."""
    directory = Path(directory).resolve()
    if os.name != "nt" or not (directory / APP_EXE).is_file() or not (directory / "profile").is_dir():
        raise UpdateError("无法确认当前安装目录，未开始更新。")
    verify_file(Path(path), info)
    log = directory / "profile" / "update-install.log"
    args = [str(Path(path).resolve()), "/SILENT", "/SUPPRESSMSGBOXES", "/NORESTART", "/SP-",
            "/UPDATE=1", "/TASKS=", "/DIR=" + str(directory), "/LOG=" + str(log)]
    try:
        return subprocess.Popen(args, cwd=directory, creationflags=subprocess.CREATE_NEW_PROCESS_GROUP)
    except OSError as exc:
        raise UpdateError("无法启动安装程序，当前版本仍可使用。请稍后重试。") from exc
