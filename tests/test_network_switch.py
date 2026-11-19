import pytest

from campusnet import detector, runner as runner_module
from campusnet.config import Config
from campusnet.detector import NetStatus, detect
from campusnet.providers.base import LoginResult
from campusnet.runner import Runner
from conftest import FakeSession, make_response


OLD = "https://previous-school.example/login"
CURRENT = "http://10.9.0.1/"


@pytest.fixture
def different_school(monkeypatch):
    monkeypatch.setattr(detector, "default_gateway", lambda: "10.9.0.1")
    return Config(username="demo", password="fixture-only", provider="srun", portal_ip=OLD,
                  portal_mode="auto", discovered_options={"ac_id":"1","srun_domains":{"cmcc":"old-domain"}})


def test_current_gateway_used_without_contacting_previous_school(different_school):
    session = FakeSession([
        (OLD,make_response("srun_portal",url=OLD)),
        (CURRENT,make_response('<form action="/eportal/InterFace.do?method=login"></form>',url=CURRENT)),
    ])
    result = detect(session,different_school,NetStatus(False))
    assert result.best == "ruijie" and result.portal == CURRENT
    assert all("previous-school.example" not in url for url in session.urls)


def test_no_current_portal_never_falls_back_to_old_school_or_submits_credentials(different_school,monkeypatch):
    session = FakeSession([
        ("previous-school.example",make_response("srun_portal",url=OLD)),
        (CURRENT,make_response("<title>Home Router</title>",url=CURRENT)),
    ])
    monkeypatch.setattr(runner_module,"check_online",lambda *args:NetStatus(False))
    monkeypatch.setattr(Config,"resolve_password",lambda *args,**kwargs:"fixture-only")
    attempts = []
    class Provider:
        display_name="Test provider"
        def __init__(self,*args):
            pass
        def login(self,portal,*args):
            attempts.append(portal)
            return LoginResult(False,"srun","test")
    monkeypatch.setattr(runner_module,"get_provider",lambda name:Provider)
    runner = Runner(different_school)
    runner._session = session
    result = runner.ensure_online()
    assert not result.ok and not attempts
    assert all("previous-school.example" not in url for url in session.urls)


def test_online_new_network_does_not_check_old_school_session(different_school,monkeypatch):
    monkeypatch.setattr(runner_module,"check_online",lambda *args:NetStatus(True))
    session = FakeSession(default=make_response("<title>Home Router</title>"))
    runner = Runner(different_school)
    runner._session = session
    assert runner.status().online
    assert all("previous-school.example" not in url for url in session.urls)


def test_current_school_session_is_still_verified_when_probe_sites_are_allowed(different_school,monkeypatch):
    monkeypatch.setattr(runner_module,"check_online",lambda *args:NetStatus(True))
    session = FakeSession([(CURRENT,make_response("srun_portal",url=CURRENT))])
    checked = []
    def offline(self,portal,username):
        checked.append(portal)
        return False
    monkeypatch.setattr("campusnet.providers.srun.SrunProvider.online_state",offline)
    runner = Runner(different_school)
    runner._session = session
    status = runner.status()
    assert not status.online and status.portal_url == CURRENT
    assert checked == [CURRENT]


def test_school_specific_options_are_not_reused_in_auto_mode(different_school):
    different_school.options.update({"ac_id":"1","srun_domains":{"cmcc":"old-domain"},
                                    "srun_login_path":"/old/login","srun_challenge_path":"/old/challenge",
                                    "srun_status_path":"/old/status","carrier":"cmcc","reconnect_delay":60})
    options = Runner(different_school)._portal_options({"ac_id":"42"})
    assert options["ac_id"] == "42" and options["carrier"] == "cmcc" and options["reconnect_delay"] == 60
    assert not any(k in options for k in ("srun_domains","srun_login_path","srun_challenge_path","srun_status_path"))
    different_school.portal_mode = "manual"
    assert Runner(different_school)._portal_options({})["srun_login_path"] == "/old/login"


def test_physical_gateway_and_identity_win_over_virtual_adapter(monkeypatch):
    from campusnet import windows_network, session
    monkeypatch.setattr(windows_network, "current_network", lambda: {
        "gateway":"10.9.0.1", "ipv4":"10.9.1.2", "mac":"02-34-56-78-9A-BC"})
    monkeypatch.setattr(detector.platform, "system", lambda:"Windows")
    assert detector.default_gateway() == "10.9.0.1"
    assert session.local_ip() == "10.9.1.2"
    assert session.local_mac() == "023456789abc"


def test_physical_identity_cache_can_be_invalidated_after_mac_change(monkeypatch):
    from campusnet import windows_network
    values = iter([{"mac":"old"},{"mac":"new"}])
    monkeypatch.setattr(windows_network.os, "name", "nt")
    monkeypatch.setattr(windows_network, "inspect_adapter", lambda:next(values))
    monkeypatch.setattr(windows_network, "_cache", {})
    monkeypatch.setattr(windows_network, "_expires", 0)
    assert windows_network.current_network()["mac"] == "old"
    assert windows_network.current_network()["mac"] == "old"
    windows_network.clear_cache()
    assert windows_network.current_network()["mac"] == "new"
