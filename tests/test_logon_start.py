import os
import sys

import pytest

from campusnet import autostart, gui, singleton
from campusnet.config import Config
from campusnet.detector import NetStatus
from campusnet.runner import Runner, RunResult
from campusnet.wifi import WifiResult


def test_logon_skips_delay_only_while_starting(monkeypatch):
    cfg = Config(options={"reconnect_delay": 60})
    runner = Runner(cfg)
    logins, waits = [], []
    monkeypatch.setattr(runner, "_reload_policy", lambda: None)
    monkeypatch.setattr(runner, "_policy_block", lambda: "")
    monkeypatch.setattr(runner, "status", lambda: NetStatus(online=False))
    monkeypatch.setattr(runner, "ensure_wifi", lambda **kw: WifiResult(ok=True))
    monkeypatch.setattr(runner, "_wait_with_policy", lambda seconds: waits.append(seconds) or True)
    monkeypatch.setattr(runner, "ensure_online", lambda **kw: logins.append(kw) or RunResult(ok=True))
    assert runner._watch_round(None, immediate_start=True) and not waits
    assert runner._watch_round(None) and waits == [60] and len(logins) == 2
    monkeypatch.setattr(runner, "_policy_block", lambda: "已暂停")
    assert not runner._watch_round(None, immediate_start=True)
    assert len(logins) == 2
    monkeypatch.setattr(runner, "status", lambda: NetStatus(online=True))
    assert runner._watch_round(None, immediate_start=True) and len(logins) == 2


@pytest.mark.skipif(os.name != "nt", reason="Windows login item")
def test_desktop_run_line_keeps_watch_options_and_quotes(monkeypatch):
    import winreg
    from contextlib import nullcontext

    path = r"D:\Campus app\校园网助手.exe"
    config = r"D:\Campus app\profile\config.json"
    monkeypatch.setattr(sys, "frozen", True, raising=False)
    monkeypatch.setattr(sys, "executable", path)
    monkeypatch.setattr(winreg, "OpenKey", lambda *args: nullcontext(object()))
    stored = []
    monkeypatch.setattr(winreg, "SetValueEx", lambda *args: stored.append(args[-1]))
    autostart._install_windows(config, 7)
    assert stored == [f'"{path}" watch --interval 7 --config "{config}" --desktop-startup']


@pytest.mark.skipif(os.name != "nt", reason="Windows desktop event")
def test_shortcut_reopens_existing_tray_and_duplicate_autostart_stays_quiet(tmp_path):
    path = str(tmp_path / "校园网助手.exe")
    primary = singleton.DesktopActivation(path, False)
    assert primary.primary
    try:
        for show in (False, True):
            second = singleton.DesktopActivation(path, show)
            try:
                assert not second.primary
                assert primary.show_requested() == show
                assert not primary.show_requested()
            finally:
                second.close()
    finally:
        primary.close()
    reopened = singleton.DesktopActivation(path, True)
    try:
        assert reopened.primary
    finally:
        reopened.close()


def test_tray_and_interactive_entry_are_separate_from_cli(monkeypatch):
    monkeypatch.delattr(sys, "frozen", raising=False)
    dispatched = []
    monkeypatch.setattr(gui, "_run_gui", lambda tray, activation: dispatched.append(tray) or 0)
    monkeypatch.setattr(gui, "_run_cli_passthrough", lambda argv: dispatched.append(argv) or 0)
    for args in (["--tray"], [], ["watch", "--help"]):
        assert gui.run(args) == 0
    assert dispatched == [True, False, ["watch", "--help"]]
