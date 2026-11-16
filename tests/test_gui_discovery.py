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
    assert app.var_portal.get() == before["portal_ip"]


def test_manual_portal_requires_valid_address_and_type(app):
    app.show_setup()
    app.var_auto_portal.set(False)
    app.var_portal.set("file:///invalid")
    calls = []
    app._spawn = lambda *args: calls.append(args)
    app.save_setup()
    assert not calls and "HTTP/HTTPS" in app.lbl_setup_error.cget("text")
