import hashlib
import io
import json
from pathlib import Path
import ssl
import threading
import urllib.error
import urllib.request

import pytest

from campusnet import updater


PAYLOAD = b"MZ" + b"synthetic-installer-bytes" * 13000


def info(payload=PAYLOAD, version="0.1.4+desktop.20261116.2"):
    key = updater.version_key(version)
    return updater.UpdateInfo(version, "CampusNetGuardian-{}.{}-Setup.exe".format(key[3], key[4]),
                              hashlib.sha256(payload).hexdigest(), len(payload), "测试更新说明")


def manifest():
    return dict(schema=1, **info().__dict__)


@pytest.mark.parametrize("before,after", [
    ("0.1.3+desktop.20261116.1", "0.1.4+desktop.20261116.2"),
    ("0.1.4+desktop.20261116.2", "0.1.4+desktop.20261116.10"),
    ("0.1.4+desktop.20261116.10", "0.1.4+desktop.20261117.1"),
    ("0.1.9+desktop.20261117.1", "0.2.0+desktop.20261118.1"),
])
def test_versions_compare_numerically(before, after):
    assert info(version=after).newer_than(before)
    assert not info(version=before).newer_than(after)
    assert not info(version=after).newer_than(after)


@pytest.mark.parametrize("field,value", [
    ("schema", 2), ("filename", "../../other.exe"), ("filename", "CampusNetGuardian-20261116.3-Setup.exe"),
    ("version", "next"), ("version", 12), ("sha256", "ab"), ("sha256", 42),
    ("size", 0), ("size", True), ("size", 101*1024*1024), ("notes", "x"*4001),
])
def test_rejects_invalid_release_metadata(field, value):
    data = manifest()
    data[field] = value
    with pytest.raises(updater.UpdateError):
        updater.parse_manifest(json.dumps(data).encode())


@pytest.mark.parametrize("data", [b"<html>login</html>", b"[]", b"{}", b"x"*65537])
def test_rejects_non_manifest_responses(data):
    with pytest.raises(updater.UpdateError):
        updater.parse_manifest(data)


@pytest.mark.parametrize("url", [
    "http://raw.githubusercontent.com/A3697/campusnet-guardian/main/downloads/latest.json",
    "https://github.com.evil.example/A3697/campusnet-guardian/raw/file",
    "https://raw.githubusercontent.com/another/project/main/update.exe",
    "https://name:secret@github.com/A3697/campusnet-guardian/raw/file",
    "https://github.com:8443/A3697/campusnet-guardian/raw/file",
    "https://raw.githubusercontent.com/A3697/campusnet-guardian/%2e%2e/other/file",
])
def test_rejects_untrusted_download_targets(url):
    assert not updater._trusted_url(url)
    redirect = updater._GitHubRedirect()
    with pytest.raises(updater.UpdateError):
        redirect.redirect_request(None, None, 302, "", {}, url)


def test_transport_keeps_tls_verification_and_sends_no_account_data(monkeypatch):
    recorded = {}
    class Opener:
        def open(self, request, timeout):
            recorded.update(headers=dict(request.header_items()), timeout=timeout)
            return io.BytesIO(b"ok")
    def build(*handlers):
        context = next(h._context for h in handlers if isinstance(h, urllib.request.HTTPSHandler))
        assert context.verify_mode == ssl.CERT_REQUIRED and context.check_hostname
        return Opener()
    monkeypatch.setattr(urllib.request, "build_opener", build)
    with updater._open(updater._urls("latest.json")[0]):
        pass
    assert "Authorization" not in recorded["headers"] and "Cookie" not in recorded["headers"]


def test_manifest_falls_back_to_github_api(monkeypatch):
    calls = []
    monkeypatch.setattr(urllib.request, "getproxies", lambda: {})
    def open_(url, proxy):
        calls.append(url)
        return io.BytesIO(b"blocked" if len(calls)==1 else json.dumps(manifest()).encode())
    monkeypatch.setattr(updater, "_open", open_)
    assert updater.fetch_latest() == info()
    assert len(calls)==2 and calls[1].startswith("https://api.github.com/")


def test_download_verified_and_cached_without_repeating_request(monkeypatch, tmp_path):
    calls, progress = [], []
    def open_(url, proxy):
        calls.append(url)
        return io.BytesIO(PAYLOAD)
    monkeypatch.setattr(updater, "_open", open_)
    path=updater.download(info(),tmp_path,lambda n,total:progress.append((n,total)))
    assert path.read_bytes()==PAYLOAD and progress[-1]==(len(PAYLOAD),len(PAYLOAD))
    assert updater.download(info(),tmp_path)==path and len(calls)==1
    assert not list(tmp_path.glob("*.part"))


@pytest.mark.parametrize("payload", [b"MZshort", b"XX"+PAYLOAD[2:], b"MZ"+b"0"*(len(PAYLOAD)-2), PAYLOAD+b"oversized"])
def test_bad_download_never_replaces_existing_file(monkeypatch,tmp_path,payload):
    monkeypatch.setattr(urllib.request,"getproxies",lambda:{})
    monkeypatch.setattr(updater,"_open",lambda *a:io.BytesIO(payload))
    original=tmp_path/info().filename
    original.write_bytes(b"existing-corrupt-download")
    marker=tmp_path/'unrelated.txt'
    marker.write_text('keep')
    with pytest.raises(updater.UpdateError):
        updater.download(info(),tmp_path)
    assert original.read_bytes()==b"existing-corrupt-download" and marker.read_text()=='keep'
    assert not list(tmp_path.glob("*.part"))


def test_cancel_removes_partial_download_and_never_installs(monkeypatch,tmp_path):
    cancel=threading.Event()
    monkeypatch.setattr(updater,"_open",lambda *a:io.BytesIO(PAYLOAD))
    def progress(received,total):
        if received:
            cancel.set()
    with pytest.raises(updater.DownloadCancelled):
        updater.download(info(),tmp_path,progress,cancel)
    assert list(tmp_path.iterdir())==[]


def test_network_failure_preserves_installed_application(monkeypatch,tmp_path):
    marker=tmp_path/updater.APP_EXE
    marker.write_bytes(b"current-version")
    def fail(*args):
        raise urllib.error.URLError("offline")
    monkeypatch.setattr(updater,"_open",fail)
    with pytest.raises(updater.UpdateError,match="下载失败"):
        updater.download(info(),tmp_path/'updates')
    assert marker.read_bytes()==b"current-version"


@pytest.mark.skipif(updater.os.name!="nt",reason="Windows installer command")
def test_installer_rechecks_file_and_preserves_installation_location(monkeypatch,tmp_path):
    target=tmp_path/'原目录 with spaces'
    (target/'profile').mkdir(parents=True)
    (target/updater.APP_EXE).write_bytes(b"current")
    installer=tmp_path/info().filename
    installer.write_bytes(PAYLOAD)
    calls=[]
    monkeypatch.setattr(updater.subprocess,"Popen",lambda args,**kwargs:calls.append((args,kwargs)))
    updater.start_install(installer,info(),target)
    args,kwargs=calls[0]
    assert '/UPDATE=1' in args and '/TASKS=' in args and '/NORESTART' in args
    assert '/DIR='+str(target.resolve()) in args and kwargs['cwd']==target.resolve()
    assert not kwargs.get('shell')
    installer.write_bytes(b'MZ'+b'0'*(len(PAYLOAD)-2))
    with pytest.raises(updater.UpdateError,match="校验失败"):
        updater.start_install(installer,info(),target)
    assert len(calls)==1


def test_source_run_cannot_replace_python_installation(monkeypatch):
    monkeypatch.setattr(updater.sys,"frozen",False,raising=False)
    with pytest.raises(updater.UpdateError,match="源码运行"):
        updater.installation_dir()
