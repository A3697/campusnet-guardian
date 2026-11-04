import hashlib
import hmac
import json
import os
import sys
from urllib.parse import parse_qs, urlsplit

import pytest

from conftest import FakeSession, make_response
from campusnet import autostart, singleton
from campusnet.config import Config, default_config_path, runtime_log_dir
from campusnet.runner import Runner
from campusnet.providers.srun import SrunProvider


@pytest.mark.skipif(os.name != "nt", reason="Windows portable profile")
def test_gui_and_watch_open_same_profile_regardless_of_package_redirect(monkeypatch, tmp_path):
    directory = tmp_path / "app"
    profile = directory / "profile"
    profile.mkdir(parents=True)
    Config(username="desktop", provider="srun", portal_ip="https://school.example").save(str(profile / "config.json"))
    monkeypatch.setattr(sys, "frozen", True, raising=False)
    monkeypatch.setattr(sys, "executable", str(directory / "campus.exe"))
    monkeypatch.setenv("CAMPUSNET_PROVIDER", "auto")
    for data in ("WindowsRoaming", "PackageVirtualRoaming"):
        monkeypatch.setenv("APPDATA", str(tmp_path / data))
        loaded = Config.load()
        assert loaded.provider == "srun" and loaded.username == "desktop"
        assert default_config_path() == str(profile / "config.json")
        assert runtime_log_dir() == str(profile)


def test_watch_round_authenticates_offline_account_at_pinned_portal(monkeypatch):
    portal = "https://school.example"
    token = "1234567890abcdef"
    ip = "100.78.1.2"
    cfg = Config(username="demo", password="sample-only", provider="srun", portal_ip=portal,
                 options={"carrier":"cmcc", "srun_domains":{"cmcc":"cmcc"}, "verify_srun_session":True,
                          "verify_delay":0, "reconnect_delay":0})
    monkeypatch.setattr(Config, "resolve_password", lambda self, **kw: self.password)
    monkeypatch.setattr(Runner, "client_ip", property(lambda self: "198.18.0.1"))
    runner = Runner(cfg)
    monkeypatch.setattr(runner, "detect", lambda *a: pytest.fail("Must not replace the pinned portal with the gateway"))

    class Campus:
        online = False
        logins = 0
        challenges = []

        def get(self, url, **kwargs):
            path = urlsplit(url)
            query = parse_qs(path.query)
            if path.path.startswith("/cgi-bin/"):
                assert path.scheme + "://" + path.netloc == portal
            if path.path.endswith("rad_user_info"):
                data = ({"error":"ok","online_ip":ip,"user_name":"demo","domain":"cmcc"}
                        if self.online else {"error":"not_online_error"})
                return make_response("jsonp(" + json.dumps(data) + ")")
            if path.path.endswith("get_challenge"):
                assert query["username"] == ["demo@cmcc"]
                self.challenges.append(query["ip"][0])
                return make_response("jsonp(" + json.dumps({"challenge":token,"client_ip":ip}) + ")")
            if path.path.endswith("srun_portal"):
                assert query["username"] == ["demo@cmcc"] and query["ip"] == [ip]
                assert query["password"] == ["{MD5}"+hmac.new(token.encode(), b"sample-only", hashlib.md5).hexdigest()]
                assert "domain" not in query
                self.logins += 1
                self.online = True
                return make_response('jsonp({"error":"ok","suc_msg":"login_ok"})')
            if path.path.endswith("generate_204"):
                return make_response("", status=204)
            if path.netloc == "www.baidu.com":
                return make_response("baidu")
            return make_response("Microsoft Connect Test")

    server = Campus()
    runner._session = server
    assert runner._watch_round(None) and server.logins == 1
    assert server.challenges == ["198.18.0.1", ip]
    assert runner._watch_round(None) and server.logins == 1


def test_session_requires_matching_account_and_operator():
    def provider(body):
        return SrunProvider(FakeSession([("rad_user_info",make_response("jsonp("+json.dumps(body)+")"))]),
                            {"carrier":"cmcc","srun_domains":{"cmcc":"cmcc"}})
    data = {"error":"ok","online_ip":"10.0.0.1","user_name":"other","domain":"cmcc"}
    assert provider(data).online_state("https://school.example", "demo") is False
    data.update(user_name="demo", domain="ctcc")
    assert provider(data).online_state("https://school.example", "demo") is False
    data.update(domain="cmcc")
    assert provider(data).online_state("https://school.example", "demo") is True
    assert not provider(data)._as_result(make_response('jsonp({"error":"E1234","error_msg":"在线终端数量超过上限"})'),"/").ok


@pytest.mark.skipif(os.name != "nt", reason="Windows watcher")
def test_gui_starts_only_its_enabled_watcher(monkeypatch):
    exe = r"D:\campusnet\校园网助手.exe"
    monkeypatch.setattr(sys, "frozen", True, raising=False)
    monkeypatch.setattr(sys, "executable", exe)
    calls = []
    monkeypatch.setattr(autostart.subprocess, "Popen", lambda args, **kw: calls.append((args,kw)))
    monkeypatch.setattr(singleton, "windows_watch_running", lambda: False)
    monkeypatch.setattr(autostart,"_status_windows", lambda: "未安装")
    assert not autostart.ensure_desktop_watch()
    monkeypatch.setattr(autostart,"_status_windows", lambda: '已安装\n  "'+exe+'" watch')
    assert autostart.ensure_desktop_watch("profile.json")
    assert calls[0][0] == [exe, "watch", "--config", "profile.json"]
    assert calls[0][1]["env"]["PYINSTALLER_RESET_ENVIRONMENT"] == "1"
    monkeypatch.setattr(singleton, "windows_watch_running", lambda: True)
    assert not autostart.ensure_desktop_watch() and len(calls) == 1
