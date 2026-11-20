from tkinter import filedialog

from campusnet import diagnostics as d
from test_gui_password import app


def test_dialog_cancel_starts_no_collection(app, monkeypatch):
    monkeypatch.setattr(filedialog, "asksaveasfilename", lambda **kw: "")
    app.export_diagnostics()
    assert not app._busy and app._diagnostics_cancel is None


def test_manual_unsaved_input_is_captured_without_saving(app, monkeypatch, tmp_path):
    app.show_setup()
    app.var_auto_portal.set(False)
    app.var_portal.set("https://another-school.example/portal?ac_id=9")
    app.var_password.set("unsaved-secret")
    app._portal_mode_changed()
    before = app.cfg.to_dict(include_password=True)
    monkeypatch.setattr(filedialog, "asksaveasfilename", lambda **kw: str(tmp_path / "result.7z"))
    calls = []
    app._spawn = lambda fn, *args: calls.append((fn, args))
    app.export_diagnostics()
    cfg, path, cancel, secrets, ui_log = calls[0][1]
    assert cfg.portal_ip == app.var_portal.get() and not cfg.automatic_portal
    assert "unsaved-secret" in secrets and app.cfg.to_dict(include_password=True) == before
    assert app._busy and str(app.btn_export.cget("state")) == "disabled"
    app.export_diagnostics()
    assert len(calls) == 1
    app.cancel_diagnostics()
    assert cancel.is_set()
    app._dispatch(("export_error", "已取消采集"))
    assert not app._busy and app.var_password.get() == "unsaved-secret"


def test_export_success_and_error_leave_actions_available(app, tmp_path):
    app._set_busy(True, "")
    result = d.ExportResult(str(tmp_path / "env.7z"), 1234, 4, 1)
    app._dispatch(("export_done", result))
    assert not app._busy and app._diagnostics_path == result.path
    assert "7z" in app.lbl_export.cget("text") and "部分" in app.lbl_export.cget("text")
    app._set_busy(True, "")
    app._dispatch(("export_error", "磁盘空间不足"))
    assert not app._busy and "磁盘空间" in app.lbl_feedback.cget("text")


def test_worker_failure_has_export_specific_message(app, monkeypatch):
    monkeypatch.setattr(d, "export_environment", lambda *a, **kw: (_ for _ in ()).throw(OSError("disk full")))
    app._job_export(app.cfg, "unused.7z", None, (), "")
    message = app.q.get_nowait()
    assert message[0] == "export_error" and "导出失败" in message[1]


def test_quit_waits_for_cancel_and_cleanup(app, monkeypatch, tmp_path):
    monkeypatch.setattr(filedialog, "asksaveasfilename", lambda **kw: str(tmp_path / "env.7z"))
    app.export_diagnostics()
    app.quit_app()
    assert not app._closing and app._quit_after_diagnostics and app._diagnostics_cancel.is_set()
