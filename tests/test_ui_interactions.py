import json
from pathlib import Path

import pytest

from campusnet import gui, policy
from campusnet.config import Config
from test_gui_password import app


def deny_write(*args, **kwargs):
    raise PermissionError("write denied")


def state(online=True):
    return {"online":online,"detail":"模拟检测结果","username":"demo-account","carrier":"中国移动",
            "portal":"https://example.edu","autostart":True,"configured":True,
            "display_password":"demo-pass","policy":"每 5 分钟检查"}


def test_fast_repeated_actions_start_one_job_and_disable_editing(app):
    calls = []
    app._spawn = lambda *args: calls.append(args)
    app.connect()
    app.connect()
    app.health_check()
    app.toggle_autostart()
    assert len(calls)==1 and app._busy
    assert str(app.ent_user.cget("state"))=="disabled"
    assert str(app.btn_back.cget("state"))=="disabled"
    app._set_busy(False, "")
    assert str(app.ent_user.cget("state"))=="normal"
    assert str(app.var_carrier_widget.cget("state"))=="readonly"


def test_old_network_reply_cannot_overwrite_action_state(app, monkeypatch):
    app._state_revision = 2
    app._busy = True
    app._state_pending = True
    monkeypatch.setattr(app, "_apply_state", lambda value: pytest.fail("Outdated response applied"))
    app._dispatch(("state",state(),1))
    assert not app._state_pending and app._busy


def test_passive_offline_refresh_does_not_override_watcher_delay(app, monkeypatch):
    connects=[]
    monkeypatch.setattr(app,"connect",lambda **kw:connects.append(kw))
    monkeypatch.setattr(gui.singleton,"windows_watch_running",lambda:False)
    app._auto_connect_done=False
    app._apply_state(state(True))
    app._apply_state(state(False))
    assert connects==[]
    app._auto_connect_done=False
    monkeypatch.setattr(gui.singleton,"windows_watch_running",lambda:True)
    app._apply_state(state(False))
    assert connects==[]
    app._auto_connect_done=False
    monkeypatch.setattr(gui.singleton,"windows_watch_running",lambda:False)
    monkeypatch.setattr(policy,"block_reason",lambda cfg:"")
    app._apply_state(state(False))
    app._apply_state(state(False))
    assert connects==[{"force":False}]


def test_settings_reload_actual_startup_choice(app, monkeypatch):
    monkeypatch.setattr(gui.autostart,"status",lambda:"未安装")
    app.var_autostart.set(True)
    app.show_setup()
    assert app.var_autostart.get() is False
    monkeypatch.setattr(gui.autostart,"status",lambda:"已安装")
    app.show_setup()
    assert app.var_autostart.get() is True


def test_save_only_and_save_connect_have_distinct_results(app, monkeypatch):
    calls=[]
    monkeypatch.setattr(app,"connect",lambda **kw:calls.append(kw))
    app._dispatch(("saved",app.cfg,False,""))
    assert not calls and app._page=="main" and app._auto_connect_done
    app._dispatch(("saved",app.cfg,True,""))
    assert calls==[{"force":True}]


def test_config_save_failure_leaves_active_config_unchanged(app, monkeypatch):
    original=app.cfg.to_dict()
    monkeypatch.setattr(Config, "save", deny_write)
    app._job_save_setup("changed-account","","cmcc","changed-wifi",False)
    message=app.q.get_nowait()
    assert message[0]=="setup_error" and app.cfg.to_dict()==original


def test_policy_preserves_multiple_windows_and_newer_account_options(app, tmp_path):
    app.cfg.path=str(tmp_path/"config.json")
    app.cfg.options.update(carrier="cmcc",reconnect_windows="23:00-07:00,12:00-13:00")
    app.cfg.save()
    app.show_policy()
    interval,delay,enabled=app._policy_vars
    assert enabled.get()
    assert [[v.get() for v in row["vars"]] for row in app._policy_time_rows] == [
        ["23","00","07","00"],["12","00","13","00"]]
    app.cfg.options["marker"]="changed-while-dialog-open"
    interval.set("7")
    delay.set("1.5")
    app._save_policy()
    saved=json.loads(Path(app.cfg.path).read_text(encoding="utf-8"))
    assert saved["options"]["reconnect_windows"]=="23:00-07:00,12:00-13:00"
    assert saved["options"]["reconnect_delay"]==1.5
    assert saved["options"]["reconnect_interval"]==7
    assert saved["options"]["marker"]=="changed-while-dialog-open"
    assert app._policy_win is None
    # Editing hours/minutes and removing a different row must preserve the retained interval.
    app.show_policy()
    first, second = app._policy_time_rows
    first["vars"][1].set("15")
    first["vars"][3].set("30")
    app._remove_policy_window(second)
    app._policy_vars[2].set(False)
    assert all(str(spin.cget("state"))=="disabled" for spin in first["spins"])
    app._policy_vars[2].set(True)
    app._save_policy()
    saved=json.loads(Path(app.cfg.path).read_text(encoding="utf-8"))
    assert saved["options"]["reconnect_windows"]=="23:15-07:30"
    assert saved["options"]["marker"]=="changed-while-dialog-open"


@pytest.mark.parametrize("interval,delay,windows",[
    ("1.5","60","23:00-07:00"),("0","60","23:00-07:00"),("5","nan","23:00-07:00"),
    ("5","inf","23:00-07:00"),("5","-1","23:00-07:00"),("5","60","24:00-07:00"),
    ("5","60","07:00-07:00"),("5","60",""),
])
def test_invalid_policy_stays_editable_and_does_not_write(app,tmp_path,interval,delay,windows):
    app.cfg.path=str(tmp_path/"config.json")
    app.cfg.save()
    before=Path(app.cfg.path).read_bytes()
    app.show_policy()
    values=app._policy_vars
    for variable,value in zip(values,(interval,delay,True)):
        variable.set(value)
    parts=windows.replace("-",":").split(":") if windows else [""]*4
    for variable,value in zip(app._policy_time_rows[0]["vars"],parts):
        variable.set(value)
    app._save_policy()
    assert app._policy_win is not None and app._policy_error.cget("text")
    assert Path(app.cfg.path).read_bytes()==before


def test_failed_pause_write_keeps_old_file_and_reports_failure(tmp_path,monkeypatch):
    path=tmp_path/"policy_state.json"
    path.write_text('{"paused_until":123}',encoding="utf-8")
    monkeypatch.setattr(policy,"state_path",lambda:str(path))
    monkeypatch.setattr(policy.os, "replace", deny_write)
    with pytest.raises(PermissionError):
        policy.pause_for(60)
    assert json.loads(path.read_text())=={"paused_until":123}
    assert list(tmp_path.iterdir())==[path]


def test_failed_policy_write_does_not_mutate_live_options(monkeypatch):
    cfg=Config(options={"reconnect_interval":5})
    monkeypatch.setattr(Config, "save", deny_write)
    with pytest.raises(PermissionError):
        policy.set_options(cfg,reconnect_interval=20)
    assert cfg.options=={"reconnect_interval":5}


def test_inline_feedback_does_not_open_modal_and_log_masks_password(app,monkeypatch):
    from tkinter import messagebox
    monkeypatch.setattr(messagebox,"showinfo",lambda *a,**k:pytest.fail("Modal success dialog"))
    monkeypatch.setattr(messagebox,"showerror",lambda *a,**k:pytest.fail("Modal failure dialog"))
    app._on_connect_done(True,"success","")
    assert "已连接" in app.lbl_feedback.cget("text")
    app._on_connect_done(False,"failure demo-pass","details")
    assert app._logs_open and "demo-pass" not in app.log_box.get("1.0","end")
    app._on_health("diagnostic result")
    assert "diagnostic result" in app.log_box.get("1.0","end")


@pytest.mark.parametrize("action", ["diagnostic", "failed_connect"])
def test_latest_action_result_follows_loaded_watch_history(app, monkeypatch, action):
    monkeypatch.setattr(app, "_read_watch_log", lambda: app._append_log("older watch history"))
    if action == "diagnostic":
        app._on_health("latest action result")
    else:
        app._on_connect_done(False, "latest action result", "")
    text = app.log_box.get("1.0", "end")
    assert text.index("older watch history") < text.index("latest action result")
    assert text.strip().endswith("latest action result")


def test_pause_validation_does_not_round_or_clamp_user_input(app,monkeypatch):
    saved=[]
    monkeypatch.setattr(app,"pause_reconnect",lambda mins:saved.append(mins))
    for value in ("1.5","nan","0","1441","-1",""):
        app.var_pause.set(value)
        app._pause_from_input()
    assert saved==[]
    app.var_pause.set("90")
    app._pause_from_input()
    assert saved==[90]


def test_background_error_cannot_unlock_an_active_user_action(app):
    app._set_busy(True, "正在认证")
    app._state_pending = True
    app._dispatch(("state_error", "检查失败", "", "", app._state_revision - 1))
    assert app._busy and not app._state_pending
    assert str(app.btn_connect.cget("state")) == "disabled"


def test_hidden_window_does_not_poll_network(app, monkeypatch):
    calls = []
    monkeypatch.setattr(app, "_request_state", lambda: calls.append(True))
    app.root.withdraw()
    app._periodic_refresh()
    assert calls == []


def test_exit_waits_for_account_save(app, monkeypatch):
    shown = []
    monkeypatch.setattr(app, "show_window", lambda: shown.append(True))
    app._active_job = app._job_save_setup
    app.quit_app()
    assert shown == [True] and not app._closing
    assert "保存" in app.lbl_feedback.cget("text")
