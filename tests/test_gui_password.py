import tkinter as tk

import pytest

from campusnet import gui
from campusnet.config import Config
from campusnet.detector import NetStatus


@pytest.fixture
def app(monkeypatch):
    # Synthetic credentials, isolated from Windows Credential Manager and the network.
    cfg = Config(username="demo-account", wifi_ssid="Demo-WiFi")
    monkeypatch.setattr(gui.App, "_load_config", lambda self: cfg)
    monkeypatch.setattr(gui.App, "_fresh_cfg", lambda self: self.cfg)
    monkeypatch.setattr(gui.App, "_disk_options", lambda self: dict(self.cfg.options))
    monkeypatch.setattr(Config, "resolve_password", lambda self, **kwargs: "demo-pass" if self.username == "demo-account" else "")
    monkeypatch.setattr(gui.App, "_spawn", lambda *args: None)
    monkeypatch.setattr(gui.App, "_start_tray", lambda self: None)
    monkeypatch.setattr(gui.autostart, "status", lambda: "未安装")
    monkeypatch.setattr(gui.Runner, "status", lambda self: NetStatus(online=True))
    root = tk.Tk()
    root.withdraw()
    try:
        window = gui.App(root)
        window._job_state()
        window._dispatch(window.q.get_nowait())
        yield window
    finally:
        for callback in root.tk.call("after", "info"):
            root.tk.call("after", "cancel", callback)
        root.destroy()


def test_saved_password_visible_and_visibility_agrees_between_pages(app):
    assert app.info_vars["password"].cget("text") == "demo-pass"
    app.show_setup()
    assert app.var_password.get() == "demo-pass" and app.ent_pw.cget("show") == ""
    app.var_show_pw.set(False)
    app._refresh_password_visibility()
    assert app.info_vars["password"].cget("text") == "●●●●●●"
    assert app.ent_pw.cget("show") == "●"
    app.show_main()
    app.var_show_pw.set(True)
    app._refresh_password_visibility()
    assert app.info_vars["password"].cget("text") == "demo-pass" and app.ent_pw.cget("show") == ""


def test_viewing_prefilled_password_does_not_rewrite_or_reuse_it_for_another_account(app):
    app.show_setup()
    requests = []
    app._spawn = lambda fn, *args: requests.append(args)
    app.save_setup()
    assert requests[0][:2] == ("demo-account", "")
    assert app._busy and str(app.ent_pw.cget("state")) == "disabled"
    app._set_busy(False, "")
    app.var_username.set("other-account")
    assert app.var_password.get() == ""
    app.save_setup()
    assert len(requests) == 1 and app.lbl_setup_error.cget("text")


def test_failed_credential_store_keeps_original_account_and_config(app, monkeypatch, tmp_path):
    app.cfg.path = str(tmp_path / "config.json")
    monkeypatch.setattr(gui, "has_keyring", lambda: True)
    monkeypatch.setattr(gui, "_keyring_set", lambda user, password: False)
    app._job_save_setup("other-account", "replacement", "campus", "Other Wi-Fi", True)
    app._dispatch(app.q.get_nowait())
    assert app.cfg.username == "demo-account" and app.cfg.wifi_ssid == "Demo-WiFi"
    assert not (tmp_path / "config.json").exists()
    assert app.lbl_setup_error.cget("text")
