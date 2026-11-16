import json
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlsplit

import pytest

from campusnet import detector, runner as runner_module
from campusnet.config import Config
from campusnet.detector import Detection, NetStatus, detect, normalize_portal, redirect_target
from campusnet.providers.base import LoginResult
from campusnet.runner import Runner
from campusnet.session import Session
from conftest import FakeSession, make_response


@pytest.fixture
def no_gateway(monkeypatch):
    monkeypatch.setattr(detector, "default_gateway", lambda: "")


@pytest.mark.parametrize("value", ["file:///etc/passwd", "javascript:alert(1)", "http://name:secret@school.example/", "http://school.example:bad/", "https://", "http://school.example/\nheader"])
def test_reject_invalid_portal_addresses(value):
    assert normalize_portal(value) == ""


@pytest.mark.parametrize("body,headers", [
    ("", {"location": "../login?ac_id=23&theme=pc"}),
    ('<meta http-equiv="refresh" content="0; URL=../login?ac_id=23&amp;theme=pc">', {}),
    ('<script>window.location.href="../login?ac_id=23&theme=pc";</script>', {}),
    ("<script>location.replace('../login?ac_id=23&theme=pc')</script>", {}),
])
def test_redirect_formats_keep_path_and_query(body, headers):
    response = make_response(body, 302 if headers else 200, headers, "http://school.example:8080/start/index")
    assert redirect_target(response) == "http://school.example:8080/login?ac_id=23&theme=pc"


def test_discover_js_parameters_and_operator_suffixes(no_gateway):
    first = "http://redirect.example/start"
    page = "http://campus.example:8080/login?ac_id=23"
    session = FakeSession([
        (lambda u: u == first, make_response("", 302, {"location": page}, first)),
        (lambda u: u == page, make_response('<select><option value="@mobile">中国移动</option></select><script src="/js/portal.js"></script>', url=page)),
        ("/js/portal.js", make_response('const login="/auth/cgi-bin/srun_portal"; const challenge="/auth/cgi-bin/get_challenge";')),
    ])
    result = detect(session, Config(portal_mode="auto"), NetStatus(portal_url=first))
    assert result.best == "srun" and result.portal == page
    assert result.notes["ac_id"] == "23"
    assert result.notes["srun_domains"] == {"cmcc": "mobile"}
    assert result.notes["srun_login_path"] == "/auth/cgi-bin/srun_portal"
    assert all(call[0] == "GET" for call in session.calls)


def test_redirect_loop_ends_and_uses_recognized_cached_page(no_gateway):
    cache = "http://cached.example/login"
    session = FakeSession([
        ("loop.example", make_response("", 302, {"location": "http://loop.example/"}, "http://loop.example/")),
        (cache, make_response('<form action="/eportal/InterFace.do?method=login"></form>', url=cache)),
    ])
    cfg = Config(portal_mode="auto", provider="srun", portal_ip=cache)
    result = detect(session, cfg, NetStatus(portal_url="http://loop.example/"))
    assert result.best == "ruijie" and result.portal == cache
    assert len(session.calls) == 2


def test_current_redirect_precedes_old_school_and_preserves_parameters(no_gateway):
    current = "http://new.example:8080/portal/login?wlan_user_ip=10.1.2.3&jsVersion=4"
    session = FakeSession([(current, make_response("portal/login wlan_user_ip jsVersion", url=current))])
    cfg = Config(provider="srun", portal_ip="https://old.example", portal_mode="auto")
    result = detect(session, cfg, NetStatus(portal_url=current))
    assert result.best == "eportal_portal" and result.portal == current
    assert not any("old.example" in url for url in session.urls)


def test_unknown_router_page_does_not_receive_credentials(monkeypatch, no_gateway):
    session = FakeSession(default=make_response("<title>Home router</title>"))
    cfg = Config(username="demo", password="fixture-only", portal_ip="http://router.example", portal_mode="auto")
    runner = Runner(cfg)
    runner._session = session
    monkeypatch.setattr(runner, "status", lambda: NetStatus(False))
    monkeypatch.setattr(Config, "resolve_password", lambda self, **kw: self.password)
    result = runner.ensure_online()
    assert not result.ok and not result.attempts and "自动获取" in result.message
    assert all("demo" not in url and "fixture-only" not in url for url in session.urls)


def test_manual_address_is_not_replaced_by_network_redirect(no_gateway):
    cfg = Config(portal_mode="manual", provider="srun", portal_ip="https://chosen.example/login")
    assert detector.portal_candidates(cfg, NetStatus(portal_url="http://redirect.example/")) == [cfg.portal_ip]


def test_missing_hidden_value_still_reads_access_controller_from_script(no_gateway):
    page = "https://campus.example/login"
    session = FakeSession([(page, make_response('<input name="ac_id" value><script>var ac_id=29; var path="/cgi-bin/srun_portal";</script>', url=page))])
    result = detect(session, Config(portal_mode="auto"), NetStatus(portal_url=page))
    assert result.best == "srun" and result.notes["ac_id"] == "29"


def test_windows_and_linux_numeric_gateway_routes():
    assert detector._parse_gateway("0.0.0.0 0.0.0.0 10.2.0.1 10.2.1.7 25") == "10.2.0.1"
    assert detector._parse_gateway("default via 10.3.0.1 dev eth0") == "10.3.0.1"


def test_frozen_profile_accepts_auto_and_migrates_old_desktop(monkeypatch, tmp_path):
    import campusnet.config as config_module
    profile = tmp_path / "profile"
    profile.mkdir()
    monkeypatch.setattr(config_module, "desktop_profile_dir", lambda: str(profile))
    path = profile / "config.json"
    assert Config.load(str(path)).automatic_portal
    path.write_text(json.dumps({"username":"demo", "provider":"srun", "portal_ip":"https://old.example"}))
    cfg = Config.load(str(path))
    assert cfg.automatic_portal and cfg.portal_ip == "https://old.example"
    cfg.portal_mode = "manual"
    cfg.save()
    assert not Config.load(str(path)).automatic_portal


def test_successful_cache_preserves_account_password_and_newer_policy(tmp_path):
    path = str(tmp_path / "config.json")
    cfg = Config(username="demo", password="fixture-only", portal_mode="auto", path=path,
                 options={"reconnect_interval": 5, "carrier":"cmcc"})
    cfg.save(include_password=True)
    fresh = Config.load(path)
    fresh.options["reconnect_interval"] = 17
    fresh.save(include_password=True)
    runner = Runner(cfg)
    runner._remember_portal(Detection(portal="https://new.example/login", notes={"ac_id":"23"}), "srun")
    saved = Config.load(path)
    assert saved.username == "demo" and saved.password == "fixture-only"
    assert saved.options["reconnect_interval"] == 17 and saved.automatic_portal
    assert saved.discovered_options == {"ac_id":"23"}


def test_cache_does_not_overwrite_manual_choice_made_during_login(tmp_path):
    path = str(tmp_path / "config.json")
    cfg = Config(username="demo", portal_mode="auto", path=path)
    Config(username="demo", portal_mode="manual", provider="srun", portal_ip="https://chosen.example").save(path)
    Runner(cfg)._remember_portal(Detection(portal="http://found.example/"), "srun")
    assert Config.load(path).portal_ip == "https://chosen.example"


def test_http_redirect_control_and_discovery_to_real_local_portal(monkeypatch, tmp_path):
    class Handler(BaseHTTPRequestHandler):
        online = False
        logins = 0
        paths = []

        def log_message(self, *args):
            pass

        def do_GET(self):
            cls = type(self)
            cls.paths.append(self.path)
            path = urlsplit(self.path)
            query = parse_qs(path.query)
            if path.path == "/probe" and not cls.online:
                self.send_response(302)
                self.send_header("Location", "/portal/login?ac_id=37")
                self.end_headers()
                return
            if path.path == "/probe":
                self.send_response(204)
                self.end_headers()
                return
            body = ""
            if path.path == "/portal/login":
                body = '<form action="/cgi-bin/srun_portal"></form><option value="@cmcc">中国移动</option>'
            elif path.path == "/cgi-bin/get_challenge":
                body = 'jsonp({"challenge":"1234567890abcdef","client_ip":"10.1.2.3"})'
            elif path.path == "/cgi-bin/srun_portal":
                assert query["ac_id"] == ["37"] and query["username"] == ["demo@cmcc"]
                cls.logins += 1
                cls.online = True
                body = 'jsonp({"error":"ok","suc_msg":"login_ok"})'
            elif path.path == "/cgi-bin/rad_user_info":
                body = ('jsonp({"error":"ok","online_ip":"10.1.2.3","user_name":"demo","domain":"cmcc"})'
                        if cls.online else 'jsonp({"error":"not_online_error"})')
            elif path.path == "/content":
                body = "fixture-online" if cls.online else "login required"
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.end_headers()
            self.wfile.write(body.encode())

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    worker = threading.Thread(target=server.serve_forever, daemon=True)
    worker.start()
    base = "http://127.0.0.1:" + str(server.server_port)
    try:
        session = Session(retries=0)
        assert session.get(base + "/probe").status == 302
        followed = session.get(base + "/probe", allow_redirects=True)
        assert followed.status == 200 and followed.url == base + "/portal/login?ac_id=37"
        monkeypatch.setattr(detector, "HIJACK_PROBES", [(base+"/probe", 204, None)])
        monkeypatch.setattr(detector, "CONTENT_PROBES", [(base+"/content", "fixture-online")])
        monkeypatch.setattr(detector, "default_gateway", lambda: "")
        monkeypatch.setattr(Runner, "client_ip", property(lambda self: "10.1.2.3"))
        monkeypatch.setattr(Config, "resolve_password", lambda self, **kw: self.password)
        cfg = Config(username="demo", password="fixture-only", portal_mode="auto", path=str(tmp_path/"config.json"),
                     options={"carrier":"cmcc", "verify_delay":0, "ac_id":"1"})
        cfg.save(include_password=True)
        runner = Runner(cfg)
        result = runner.ensure_online()
        assert result.ok and Handler.logins == 1
        assert cfg.portal_ip == base + "/portal/login?ac_id=37" and cfg.provider == "srun"
        assert runner.ensure_online().skipped and Handler.logins == 1
        # The same watcher must discover again after a cached address becomes stale.
        Handler.online = False
        cfg.portal_ip = base + "/gone"
        result = runner.ensure_online()
        assert result.ok and Handler.logins == 2 and cfg.portal_ip.endswith("ac_id=37")
    finally:
        server.shutdown()
        server.server_close()
        worker.join(timeout=3)
