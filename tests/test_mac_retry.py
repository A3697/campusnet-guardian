import json
import os
import time
from types import SimpleNamespace

import pytest

from campusnet import mac_retry
from campusnet.config import Config
from campusnet.detector import Detection, NetStatus
from campusnet.runner import Runner, RunResult


@pytest.fixture
def scenario(tmp_path, monkeypatch):
    cfg = Config(username="fixture-user", password="fixture-only-secret", portal_mode="auto",
                 path=str(tmp_path / "config.json"), options={mac_retry.OPTION: True})
    monkeypatch.setattr(Config, "resolve_password", lambda self, **kw: self.password)
    adapter = dict(guid="12345678-1234-1234-1234-123456789012", mac="00-11-22-33-44-55",
                   override="", supported=True, up=True, dhcp=True, ready=True)
    calls = []

    class Backend:
        def inspect(self):
            return dict(adapter)

        def apply(self, snapshot, address):
            calls.append(("apply", address))

        def wait_ready(self, snapshot, address):
            calls.append(("ready", address))

        def restore(self, snapshot):
            calls.append(("restore", dict(snapshot)))

    class FakeRunner:
        _detected = Detection()

        def status(self):
            return NetStatus(False)

        def ensure_online(self, **kwargs):
            assert kwargs == {"allow_mac_retry": False}
            calls.append(("login",))
            return RunResult(ok=False)

    state = SimpleNamespace(cfg=cfg, adapter=adapter, backend=Backend(), runner=FakeRunner(), calls=calls,
                            task={"guid": adapter["guid"]}, journal=tmp_path / "mac-retry-recovery.json")
    state.run = lambda: mac_retry.transaction(cfg, state.task, state.backend, lambda cfg: state.runner, state.journal)
    return state


def test_random_addresses_are_local_unicast_and_not_fixed():
    values = {mac_retry.random_mac() for _ in range(100)}
    assert len(values) == 100
    assert all(len(v) == 12 and int(v[:2], 16) & 3 == 2 for v in values)


def test_failed_retry_restores_prior_override_and_keeps_no_credentials(scenario):
    s = scenario
    s.adapter["override"] = "021122334455"
    result = s.run()
    assert not result["ok"] and "已恢复" in result["message"]
    assert [c[0] for c in s.calls] == ["apply", "ready", "login", "restore"]
    assert s.calls[-1][1]["override"] == "021122334455"
    text = s.journal.read_text(encoding="utf-8")
    assert s.cfg.password not in text and s.cfg.username not in text
    assert json.loads(text)["phase"] == "restored"


@pytest.mark.parametrize("failure", ["apply", "wait_ready", "login"])
def test_partial_failure_always_restores(scenario, monkeypatch, failure):
    s = scenario

    def fail(*args, **kwargs):
        raise RuntimeError("fixture failure")

    monkeypatch.setattr(s.runner if failure == "login" else s.backend,
                        "ensure_online" if failure == "login" else failure, fail)
    assert not s.run()["ok"]
    assert s.calls[-1][0] == "restore"
    assert json.loads(s.journal.read_text())["phase"] == "restored"


def test_success_keeps_address_only_after_verified_login(scenario, monkeypatch):
    s = scenario
    monkeypatch.setattr(s.runner, "ensure_online", lambda **kw: RunResult(ok=True, provider="srun"))
    assert s.run()["ok"]
    assert [c[0] for c in s.calls] == ["apply", "ready"]
    assert json.loads(s.journal.read_text())["phase"] == "committed"


def test_backup_failure_prevents_any_network_change(scenario, monkeypatch):
    monkeypatch.setattr(mac_retry, "_write", lambda *args: (_ for _ in ()).throw(OSError("disk full")))
    with pytest.raises(OSError):
        scenario.run()
    assert not scenario.calls


def test_failed_restore_preserves_recovery_record(scenario, monkeypatch):
    s = scenario
    monkeypatch.setattr(s.backend, "restore", lambda *args: (_ for _ in ()).throw(OSError("driver error")))
    result = s.run()
    assert not result["ok"] and "尚未恢复" in result["message"]
    assert json.loads(s.journal.read_text())["phase"] == "recovery_required"


@pytest.mark.parametrize("phase", ["pending", "recovery_required"])
def test_interrupted_transaction_restores_before_any_new_retry(scenario, phase):
    s = scenario
    mac_retry._write(s.journal, {"phase": phase, "adapter": s.adapter})
    result = s.run()
    assert not result["ok"] and "已恢复" in result["message"]
    assert [c[0] for c in s.calls] == ["restore"]


def test_explicit_restore_works_after_success_even_if_feature_disabled(scenario):
    s = scenario
    mac_retry._write(s.journal, {"phase": "committed", "adapter": s.adapter})
    s.task["restore"] = True
    s.cfg.options[mac_retry.OPTION] = False
    assert s.run()["ok"]
    assert [c[0] for c in s.calls] == ["restore"]


@pytest.mark.parametrize("change", ["online", "manual", "disabled", "unsupported", "static_ip", "network_changed", "no_password"])
def test_recheck_before_elevation_result_never_changes_wrong_network(scenario, monkeypatch, change):
    s = scenario
    if change == "online":
        monkeypatch.setattr(s.runner, "status", lambda: NetStatus(True))
    elif change == "manual":
        s.cfg.portal_mode = "manual"
    elif change == "disabled":
        s.cfg.options[mac_retry.OPTION] = False
    elif change == "unsupported":
        s.adapter["supported"] = False
    elif change == "static_ip":
        s.adapter["dhcp"] = False
    elif change == "network_changed":
        s.task["guid"] = "other-device"
    elif change == "no_password":
        s.cfg.password = ""
    s.run()
    assert not s.calls
    assert not s.journal.exists()


def test_portal_appearing_during_uac_is_used_without_changing_mac(scenario):
    s = scenario
    s.runner._detected = Detection(portal="http://current.example/", scores=[("srun", 1.0)])
    s.run()
    assert s.calls == [("login",)]


@pytest.mark.parametrize("online,force,enabled,allow,portal,expected", [
    (False, False, True, True, False, True),
    (True, False, True, True, False, False),
    (True, True, True, True, False, False),
    (False, False, False, True, False, False),
    (False, False, True, False, False, False),
    (False, False, True, True, True, False),
])
def test_runner_uses_mac_only_when_offline_and_no_portal(scenario, monkeypatch, online, force, enabled, allow, portal, expected):
    cfg = scenario.cfg
    cfg.options[mac_retry.OPTION] = enabled
    runner = Runner(cfg)
    monkeypatch.setattr(runner, "ensure_wifi", lambda **kw: None)
    monkeypatch.setattr(runner, "status", lambda: NetStatus(online))
    monkeypatch.setattr(runner, "detect", lambda *args: Detection(
        portal="http://current.example" if portal else "", scores=[("fixture-unknown", 1.0)] if portal else []))
    calls = []
    monkeypatch.setattr(mac_retry, "request", lambda *args: calls.append(True) or {"ok": False, "message": "fixture"})
    runner.ensure_online(force=force, allow_mac_retry=allow)
    assert bool(calls) is expected


@pytest.mark.skipif(os.name != "nt", reason="Windows elevation and file locks")
def test_cancelled_uac_is_rate_limited_and_lock_is_released(scenario, monkeypatch):
    s = scenario
    monkeypatch.setattr(mac_retry, "WindowsAdapter", lambda: s.backend)
    monkeypatch.setattr(mac_retry, "_admin", lambda: False)
    calls = []

    def cancel(*args):
        calls.append(True)
        raise RuntimeError("已取消管理员授权，网卡未修改")

    monkeypatch.setattr(mac_retry, "_launch", cancel)
    first = mac_retry.request(s.cfg)
    second = mac_retry.request(s.cfg)
    assert "已取消" in first["message"] and "30 分钟" in second["message"]
    assert len(calls) == 1 and not s.calls
    assert s.cfg.password not in (s.journal.parent / "mac-retry-task.json").read_text()


@pytest.mark.skipif(os.name != "nt", reason="Windows file locks")
def test_expired_task_cannot_change_adapter(scenario, monkeypatch):
    s = scenario
    monkeypatch.setattr(mac_retry, "_admin", lambda: True)
    token = "a" * 32
    mac_retry._write(s.journal.parent / "mac-retry-task.json", {"token": token, "created": time.time()-301})
    with pytest.raises(ValueError, match="已过期"):
        mac_retry.worker(s.cfg, token)
    assert not s.calls


@pytest.mark.skipif(os.name != "nt", reason="Windows file locks")
def test_concurrent_request_is_rejected(scenario):
    path = scenario.journal.parent / "request.lock"
    with mac_retry._lock(path):
        with pytest.raises(RuntimeError, match="已有一次"):
            with mac_retry._lock(path):
                pytest.fail("A concurrent retry acquired the same lock")


def test_adapter_commands_bind_input_object_explicitly(scenario, monkeypatch):
    scripts = []
    monkeypatch.setattr(mac_retry, "_ps", lambda script, **kw:scripts.append(script))
    backend = mac_retry.WindowsAdapter()
    backend.apply(scenario.adapter, "021122334455")
    backend.apply(scenario.adapter, "")
    assert "Set-NetAdapterAdvancedProperty -InputObject $property" in scripts[0]
    assert "Reset-NetAdapterAdvancedProperty -InputObject $property" in scripts[1]
    assert all("Restart-NetAdapter -InputObject $adapter[0]" in script for script in scripts)


def test_same_adapter_on_a_different_gateway_cancels_retry(scenario):
    scenario.task["gateway"] = "10.1.0.1"
    scenario.adapter["gateway"] = "10.2.0.1"
    assert not scenario.run()["ok"]
    assert not scenario.calls
