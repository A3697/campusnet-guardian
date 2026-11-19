from campusnet.detector import Detection
from test_gui_password import app


def test_portal_controls_follow_mode_and_busy_state(app):
    app.show_setup()
    assert app.var_auto_portal.get()
    assert str(app.ent_portal.cget("state")) == "disabled"
    app.var_auto_portal.set(False)
    app._portal_mode_changed()
    assert str(app.ent_portal.cget("state")) == "normal"
    assert str(app.combo_provider.cget("state")) == "readonly"
    app._set_busy(True, "test")
    assert str(app.ent_portal.cget("state")) == "disabled"
    app._set_busy(False, "")
    assert str(app.ent_portal.cget("state")) == "normal"


def test_discovery_result_does_not_save_until_user_saves(app, monkeypatch):
    app.show_setup()
    before = app.cfg.to_dict()
    app._dispatch(("portal_found", Detection(portal="https://new.example/login", scores=[("srun", 1.0)], notes={"ac_id":"8"})))
    assert app.var_portal.get() == "https://new.example/login" and app.cfg.to_dict() == before
    app.show_main()
    app.show_setup()
    assert app.var_portal.get() == ""


def test_manual_portal_requires_valid_address_and_type(app):
    app.show_setup()
    app.var_auto_portal.set(False)
    app.var_portal.set("file:///invalid")
    calls = []
    app._spawn = lambda *args: calls.append(args)
    app.save_setup()
    assert not calls and "HTTP/HTTPS" in app.lbl_setup_error.cget("text")


def test_previous_school_is_not_shown_as_current_automatic_portal(app):
    app.cfg.portal_mode = "auto"
    app.cfg.portal_ip = "https://previous-school.example/login"
    app.cfg.provider = "srun"
    app.show_setup()
    assert app.var_portal.get() == ""
    app._job_state()
    data = app.q.get_nowait()[1]
    assert "previous-school" not in data["portal"] and "重新识别" in data["portal"]


def test_random_mac_setting_saves_with_existing_reconnect_options(app, tmp_path):
    app.cfg.path = str(tmp_path / "config.json")
    app.cfg.options["unrelated"] = "keep"
    app.show_policy()
    app._policy_mac.set(True)
    app._save_policy()
    from campusnet.config import Config
    saved = Config.load(app.cfg.path)
    assert saved.options["random_mac_retry"] is True and saved.options["unrelated"] == "keep"
